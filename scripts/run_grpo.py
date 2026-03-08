#!/usr/bin/env python3
"""Standalone GRPO training script for remote GPU instances.

Runs Unsloth GRPO with progressive + binary reward functions on
Qwen3.5-4B (from SFT checkpoint). Self-contained -- no open-range imports needed.

Usage:
    python3 run_grpo.py
    python3 run_grpo.py --model /workspace/outputs/sft-merged
    python3 run_grpo.py --reward binary
"""

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("grpo")

os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MODEL = "/workspace/outputs/sft-merged"  # SFT checkpoint
DATA = "/workspace/data/grpo_combined.jsonl"
OUTPUT = "/workspace/outputs/grpo"
SEQ = 4096
COMP_LEN = 2048
NUM_GEN = 4
BATCH = 1
GRAD_ACCUM = 2
LR = 5e-6
BETA = 0.04
TEMP = 0.7
LORA_R = 16
LORA_ALPHA = 16
EPOCHS = 1

# ---------------------------------------------------------------------------
# Tool call parsing
# ---------------------------------------------------------------------------

_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*<function=(\w+)>(.*?)</function>\s*</tool_call>",
    re.DOTALL,
)
_PARAM_RE = re.compile(r"<parameter=(\w+)>(.*?)</parameter>", re.DOTALL)
_FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)


def parse_tool_calls(text):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    calls = []
    for m in _TOOL_CALL_RE.finditer(text):
        name = m.group(1)
        body = m.group(2)
        args = {}
        for pm in _PARAM_RE.finditer(body):
            args[pm.group(1)] = pm.group(2).strip()
        calls.append({"name": name, "arguments": args})
    return calls


def extract_flags(text):
    return _FLAG_RE.findall(text)


def completion_to_text(c):
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(m.get("content", "") if isinstance(m, dict) else str(m) for m in c)
    return str(c)


# ---------------------------------------------------------------------------
# Reward functions
# ---------------------------------------------------------------------------


def binary_reward_fn(completions, **kwargs):
    """1.0 if correct flag found, else 0.0."""
    gts = kwargs.get("ground_truth", [])
    rewards = []
    for i, c in enumerate(completions):
        gt = gts[i] if i < len(gts) else ""
        if not gt:
            rewards.append(0.0)
            continue
        text = completion_to_text(c)

        # Check tool call submissions
        found = False
        for tc in parse_tool_calls(text):
            if tc["name"] in ("submit_flag", "flag_found"):
                sub = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                if sub.strip() == gt.strip():
                    found = True
                    break
        if not found:
            flags = extract_flags(text)
            found = any(f.strip() == gt.strip() for f in flags)
        rewards.append(1.0 if found else 0.0)
    return rewards


def progressive_reward_fn(completions, **kwargs):
    """Multi-signal: flag(0.40) + format(0.15) + efficiency(0.10) + progression(0.15) + reasoning(0.10) - halluc(0.20)."""
    gts = kwargs.get("ground_truth", [])
    rewards = []

    recon_tools = {"shell_command", "exec_command", "web_search", "file_search", "grep", "read_file"}
    flag_tools = {"submit_flag", "flag_found"}

    for i, c in enumerate(completions):
        gt = gts[i] if i < len(gts) else ""
        text = completion_to_text(c)
        tcs = parse_tool_calls(text)
        score = 0.0

        # 1. Flag (0.40)
        flag_ok = False
        for tc in tcs:
            if tc["name"] in flag_tools:
                sub = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                if gt and sub.strip() == gt.strip():
                    flag_ok = True
                    break
        if not flag_ok and gt:
            flag_ok = any(f.strip() == gt.strip() for f in extract_flags(text))
        if flag_ok:
            score += 0.40

        # 2. Format (0.15)
        if tcs:
            score += 0.15
        elif "<tool_call>" in text:
            score += 0.05

        # 3. Efficiency (0.10) - gamma^n
        n = max(len(tcs), 1)
        score += 0.10 * (0.92 ** (n - 1))

        # 4. Progression (0.15)
        if tcs:
            names = [tc["name"] for tc in tcs]
            phases = 0.0
            third = max(len(names) // 3, 1)
            if any(n in recon_tools for n in names[:third]):
                phases += 0.33
            if len(names) > 1 and any(n in recon_tools | {"python_code", "write_stdin", "apply_patch"} for n in names[third:2*third]):
                phases += 0.33
            if any(n in flag_tools for n in names[-third:]):
                phases += 0.34
            score += 0.15 * min(phases, 1.0)

        # 5. Reasoning (0.10)
        if "<think>" in text and "</think>" in text:
            score += 0.10
        elif "<think>" in text:
            score += 0.05

        # 6. Hallucination (-0.20 per bad flag)
        if gt:
            bad = sum(
                1 for tc in tcs
                if tc["name"] in flag_tools
                and tc["arguments"].get("flag", tc["arguments"].get("value", "")).strip()
                and tc["arguments"].get("flag", tc["arguments"].get("value", "")).strip() != gt.strip()
            )
            score -= 0.20 * bad

        rewards.append(max(score, -1.0))
    return rewards


# ---------------------------------------------------------------------------
# OpenAI → qwen3_coder conversion
# ---------------------------------------------------------------------------


def convert_messages(messages):
    converted = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "") or ""
        tool_calls = msg.get("tool_calls")

        if role == "assistant" and tool_calls:
            parts = []
            for tc in tool_calls:
                func = tc.get("function", {})
                name = func.get("name", "unknown")
                args_raw = func.get("arguments", "{}")
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                params = "\n".join(f"<parameter={k}>{v}</parameter>" for k, v in args.items())
                parts.append(f"<tool_call>\n<function={name}>\n{params}\n</function>\n</tool_call>")
            xml = "\n".join(parts)
            full = f"{content}\n\n{xml}" if content else xml
            converted.append({"role": "assistant", "content": full})
        elif role == "tool":
            converted.append({"role": "user", "content": f"<tool_response>\n{content}\n</tool_response>"})
        elif role in ("system", "user", "assistant"):
            converted.append({"role": role, "content": content})
    return converted


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Unsloth GRPO for CTF training")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--data", default=DATA)
    parser.add_argument("--output", default=OUTPUT)
    parser.add_argument("--reward", default="progressive", choices=["binary", "progressive", "both"])
    parser.add_argument("--seq", type=int, default=SEQ)
    parser.add_argument("--comp-len", type=int, default=COMP_LEN)
    parser.add_argument("--num-gen", type=int, default=NUM_GEN)
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    args = parser.parse_args()

    logger.info("=== Unsloth GRPO Training ===")
    logger.info("Model: %s", args.model)
    logger.info("Data: %s", args.data)
    logger.info("Reward: %s", args.reward)

    # Check model exists
    if not Path(args.model).exists():
        logger.error("Model not found: %s. Run SFT first.", args.model)
        sys.exit(1)

    # Load data
    data_path = Path(args.data)
    if not data_path.exists():
        logger.error("Data not found: %s", args.data)
        sys.exit(1)

    records = []
    with open(data_path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    logger.info("Loaded %d records", len(records))

    # Import Unsloth
    from unsloth import FastLanguageModel

    # Load model with fast inference
    logger.info("Loading model with fast_inference=True...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.seq,
        load_in_4bit=False,
        load_in_16bit=True,
        full_finetuning=False,
        dtype=None,
        fast_inference=True,
    )

    # Fix tokenizer (Qwen3.5 may return processor)
    tok = tokenizer.tokenizer if hasattr(tokenizer, "tokenizer") else tokenizer

    # Prepare prompts
    prompts = []
    ground_truths = []
    for r in records:
        msgs = r.get("messages", [])
        prompt_msgs = [m for m in msgs if m.get("role") in ("system", "user")]
        if not prompt_msgs:
            continue

        converted = convert_messages(prompt_msgs)
        try:
            text = tok.apply_chat_template(
                converted,
                tokenize=False,
                add_generation_prompt=True,
            )
            prompts.append(text)
            ground_truths.append(r.get("ground_truth_flag", ""))
        except Exception as e:
            logger.warning("Skipped: %s", e)

    logger.info("Prepared %d prompts", len(prompts))
    if not prompts:
        logger.error("No valid prompts!")
        sys.exit(1)

    # Apply LoRA
    logger.info("Applying LoRA (r=%d, alpha=%d)", LORA_R, LORA_ALPHA)
    model = FastLanguageModel.get_peft_model(
        model,
        r=LORA_R,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha=LORA_ALPHA,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=3407,
        max_seq_length=args.seq,
    )

    # Create dataset
    from datasets import Dataset

    ds = Dataset.from_dict({
        "prompt": prompts,
        "ground_truth": ground_truths,
    })

    # Select reward
    if args.reward == "binary":
        reward_funcs = [binary_reward_fn]
    elif args.reward == "both":
        reward_funcs = [binary_reward_fn, progressive_reward_fn]
    else:
        reward_funcs = [progressive_reward_fn]

    logger.info("Reward functions: %s", [f.__name__ for f in reward_funcs])

    # Train
    from trl import GRPOTrainer, GRPOConfig

    logger.info("Starting GRPO training...")
    trainer = GRPOTrainer(
        model=model,
        processing_class=tok,
        reward_funcs=reward_funcs,
        args=GRPOConfig(
            output_dir=args.output,
            num_generations=args.num_gen,
            max_completion_length=args.comp_len,
            per_device_train_batch_size=BATCH,
            gradient_accumulation_steps=GRAD_ACCUM,
            num_train_epochs=args.epochs,
            warmup_steps=10,
            learning_rate=LR,
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            logging_steps=1,
            save_steps=25,
            save_total_limit=2,
            seed=3407,
            bf16=True,
            report_to="none",
            beta=BETA,
            temperature=TEMP,
        ),
        train_dataset=ds,
    )

    stats = trainer.train()
    logger.info("GRPO complete! Loss: %.4f", stats.training_loss)

    # Save
    final_dir = str(Path(args.output) / "final")
    logger.info("Saving LoRA to %s", final_dir)
    model.save_pretrained(final_dir)
    tok.save_pretrained(final_dir)

    # Merge
    merge_dir = str(Path(args.output) / "merged")
    logger.info("Merging to %s", merge_dir)
    model.save_pretrained_merged(merge_dir, tok, save_method="merged_16bit")

    logger.info("=== GRPO Training Complete ===")
    logger.info("  Loss: %.4f", stats.training_loss)
    logger.info("  LoRA: %s", final_dir)
    logger.info("  Merged: %s", merge_dir)


if __name__ == "__main__":
    main()
