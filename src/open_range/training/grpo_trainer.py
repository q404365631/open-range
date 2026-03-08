"""Unsloth GRPO trainer for OpenRange CTF trajectories.

Provides binary and progressive reward functions for training models
to solve CTF challenges via tool-calling in qwen3_coder XML format.

Binary reward: flag captured = 1.0, else 0.0
Progressive reward: multi-signal (flag, format, efficiency, progression, hallucination)

Usage::

    from open_range.training.grpo_trainer import run_grpo, GRPOConfig
    run_grpo(GRPOConfig(
        model_name="outputs/sft-merged",
        data_paths=["data/online_rl.jsonl"],
        output_dir="outputs/grpo",
    ))

Or via CLI::

    openrange grpo --model outputs/sft-merged --data data/online_rl.jsonl
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool call parsing (qwen3_coder XML format)
# ---------------------------------------------------------------------------

_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*<function=(\w+)>(.*?)</function>\s*</tool_call>",
    re.DOTALL,
)
_PARAM_RE = re.compile(r"<parameter=(\w+)>(.*?)</parameter>", re.DOTALL)
_FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)


def parse_tool_calls(text: str) -> list[dict[str, Any]]:
    """Parse qwen3_coder XML tool calls from model output.

    Returns list of {"name": str, "arguments": dict}.
    """
    # Strip thinking tags before parsing
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    calls = []
    for match in _TOOL_CALL_RE.finditer(text):
        name = match.group(1)
        body = match.group(2)
        args = {}
        for pm in _PARAM_RE.finditer(body):
            args[pm.group(1)] = pm.group(2).strip()
        calls.append({"name": name, "arguments": args})
    return calls


def extract_flags_from_text(text: str) -> list[str]:
    """Extract flag{...} patterns from text."""
    return _FLAG_RE.findall(text)


# ---------------------------------------------------------------------------
# Reward functions (TRL GRPOTrainer compatible)
# ---------------------------------------------------------------------------
# TRL GRPOTrainer reward_funcs signature:
#   def reward_fn(completions, **kwargs) -> list[float]
# completions: list of list of dicts (messages) or list of strings
# kwargs may include: prompts, ground_truth, ground_truth_flag, etc.


def binary_reward(completions: list, **kwargs) -> list[float]:
    """Binary flag-capture reward: 1.0 if correct flag found, else 0.0.

    Checks completions for:
    1. submit_flag tool calls with matching value
    2. flag{...} patterns matching ground truth

    Expects kwargs["ground_truth"] or kwargs["ground_truth_flag"]
    to contain the correct flag per sample.
    """
    ground_truths = kwargs.get("ground_truth") or kwargs.get("ground_truth_flag", [])
    if not ground_truths:
        return [0.0] * len(completions)

    rewards = []
    for i, completion in enumerate(completions):
        gt = ground_truths[i] if i < len(ground_truths) else ""
        if not gt:
            rewards.append(0.0)
            continue

        # Extract text from completion
        text = _completion_to_text(completion)

        # Check submit_flag tool calls
        tool_calls = parse_tool_calls(text)
        for tc in tool_calls:
            if tc["name"] in ("submit_flag", "flag_found"):
                submitted = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                if submitted.strip() == gt.strip():
                    rewards.append(1.0)
                    break
        else:
            # Check for flag pattern in raw text
            flags = extract_flags_from_text(text)
            if any(f.strip() == gt.strip() for f in flags):
                rewards.append(1.0)
            else:
                rewards.append(0.0)

    return rewards


def progressive_reward(completions: list, **kwargs) -> list[float]:
    """Multi-signal progressive reward for CTF trajectories.

    Signals (weights sum to 1.0):
    - flag_capture (0.40): correct flag found
    - tool_format  (0.15): well-formed qwen3_coder tool calls
    - efficiency   (0.10): fewer tool calls = better (gamma^n)
    - progression  (0.15): recon → exploit → flag sequence
    - reasoning    (0.10): has <think> reasoning blocks
    - hallucination(-0.20): penalty per incorrect flag submission
    """
    ground_truths = kwargs.get("ground_truth") or kwargs.get("ground_truth_flag", [])
    rewards = []

    for i, completion in enumerate(completions):
        gt = ground_truths[i] if i < len(ground_truths) else ""
        text = _completion_to_text(completion)
        tool_calls = parse_tool_calls(text)

        score = 0.0

        # 1. Flag capture (0.40)
        flag_found = False
        for tc in tool_calls:
            if tc["name"] in ("submit_flag", "flag_found"):
                submitted = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                if gt and submitted.strip() == gt.strip():
                    flag_found = True
                    break
        if not flag_found:
            flags = extract_flags_from_text(text)
            flag_found = any(f.strip() == gt.strip() for f in flags) if gt else False
        if flag_found:
            score += 0.40

        # 2. Tool format (0.15) - well-formed tool calls present
        if tool_calls:
            score += 0.15
        elif "<tool_call>" in text:
            # Attempted but malformed
            score += 0.05

        # 3. Efficiency (0.10) - gamma^n_calls, fewer = better
        n_calls = max(len(tool_calls), 1)
        gamma = 0.92
        score += 0.10 * (gamma ** (n_calls - 1))

        # 4. Progression (0.15) - recon → exploit → flag sequence
        progression_score = _score_progression(tool_calls)
        score += 0.15 * progression_score

        # 5. Reasoning (0.10) - has thinking blocks
        if "<think>" in text and "</think>" in text:
            score += 0.10
        elif "<think>" in text:
            score += 0.05

        # 6. Hallucination penalty (-0.20 per bad flag)
        if gt:
            bad_flags = 0
            for tc in tool_calls:
                if tc["name"] in ("submit_flag", "flag_found"):
                    submitted = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                    if submitted.strip() and submitted.strip() != gt.strip():
                        bad_flags += 1
            score -= 0.20 * bad_flags

        rewards.append(max(score, -1.0))  # Floor at -1.0

    return rewards


def _score_progression(tool_calls: list[dict]) -> float:
    """Score the recon → exploit → flag progression pattern.

    Returns 0.0-1.0 based on how well tool calls follow the
    expected CTF attack sequence.
    """
    if not tool_calls:
        return 0.0

    names = [tc["name"] for tc in tool_calls]

    # Define stages
    recon_tools = {"shell_command", "exec_command", "web_search", "file_search", "grep", "read_file", "list_sessions"}
    exploit_tools = {"shell_command", "exec_command", "python_code", "write_stdin", "apply_patch"}
    flag_tools = {"submit_flag", "flag_found"}

    phases_hit = 0.0

    # Check for recon phase (early tool calls)
    early = names[:max(len(names) // 3, 1)]
    if any(n in recon_tools for n in early):
        phases_hit += 0.33

    # Check for exploitation (middle tool calls)
    if len(names) > 1:
        mid = names[len(names) // 3: 2 * len(names) // 3] or names[1:]
        if any(n in exploit_tools for n in mid):
            phases_hit += 0.33

    # Check for flag submission (late tool calls)
    late = names[-max(len(names) // 3, 1):]
    if any(n in flag_tools for n in late):
        phases_hit += 0.34

    return min(phases_hit, 1.0)


def _completion_to_text(completion: Any) -> str:
    """Extract text from a TRL completion (string or message list)."""
    if isinstance(completion, str):
        return completion
    if isinstance(completion, list):
        parts = []
        for msg in completion:
            if isinstance(msg, dict):
                parts.append(msg.get("content", ""))
            elif isinstance(msg, str):
                parts.append(msg)
        return "\n".join(parts)
    return str(completion)


# ---------------------------------------------------------------------------
# Online reward (executes against OpenEnv environment)
# ---------------------------------------------------------------------------


def make_online_reward(env_url: str, timeout: float = 30.0):
    """Create a reward function that executes tool calls against an OpenEnv server.

    Args:
        env_url: Base URL of the OpenRange server (e.g. http://localhost:8000).
        timeout: HTTP request timeout in seconds.

    Returns:
        A reward function compatible with TRL GRPOTrainer.
    """
    import httpx

    def online_reward(completions: list, **kwargs) -> list[float]:
        ground_truths = kwargs.get("ground_truth") or kwargs.get("ground_truth_flag", [])
        rewards = []

        for i, completion in enumerate(completions):
            gt = ground_truths[i] if i < len(ground_truths) else ""
            text = _completion_to_text(completion)
            tool_calls = parse_tool_calls(text)

            episode_reward = 0.0
            try:
                # Reset environment for this episode
                with httpx.Client(base_url=env_url, timeout=timeout) as client:
                    client.post("/reset")

                    for tc in tool_calls:
                        name = tc["name"]
                        args = tc["arguments"]

                        # Map tool calls to RangeAction commands
                        if name in ("shell_command", "exec_command"):
                            command = args.get("command", "")
                        elif name in ("submit_flag", "flag_found"):
                            command = f"submit_flag {args.get('flag', args.get('value', ''))}"
                        elif name == "python_code":
                            command = f"python3 -c {json.dumps(args.get('code', ''))}"
                        elif name == "read_file":
                            command = f"cat {args.get('path', args.get('file', ''))}"
                        elif name == "grep":
                            pattern = args.get("pattern", "")
                            path = args.get("path", ".")
                            command = f"grep -r {json.dumps(pattern)} {path}"
                        else:
                            command = f"{name} {' '.join(str(v) for v in args.values())}"

                        resp = client.post("/step", json={
                            "command": command,
                            "mode": "red",
                        })
                        data = resp.json()
                        obs = data.get("observation", data)

                        reward = obs.get("reward", 0.0) or 0.0
                        episode_reward += reward

                        if obs.get("done", False):
                            break

                        # Check for flag capture
                        flags = obs.get("flags_captured", [])
                        if flags and gt and gt in flags:
                            episode_reward += 1.0
                            break

            except Exception as e:
                logger.warning("Online reward failed for sample %d: %s", i, e)
                # Fall back to text-based binary check
                episode_reward = binary_reward([completion], ground_truth=[gt])[0] * 0.5

            rewards.append(episode_reward)

        return rewards

    return online_reward


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_grpo_data(
    data_paths: list[str | Path],
    tokenizer: Any,
) -> list[dict[str, Any]]:
    """Load online RL JSONL data for GRPO training.

    Each record should have:
    - messages: list of system/user messages (prompts only, no assistant)
    - ground_truth_flag: the correct flag for reward computation
    - metadata: optional challenge metadata

    Returns list of dicts with "prompt" (tokenized text) and "ground_truth".
    """
    from open_range.training.dataset import load_jsonl_records
    from open_range.training.sft_trainer import convert_messages_for_qwen35

    records = load_jsonl_records(data_paths)
    dataset = []
    skipped = 0

    for record in records:
        messages = record.get("messages", [])
        gt_flag = record.get("ground_truth_flag", "")

        if not messages:
            skipped += 1
            continue

        # Keep only system and user messages (prompts, no completions)
        prompt_messages = [m for m in messages if m.get("role") in ("system", "user")]
        if not prompt_messages:
            skipped += 1
            continue

        # Convert to qwen3_coder format
        converted = convert_messages_for_qwen35(prompt_messages)

        try:
            prompt_text = tokenizer.apply_chat_template(
                converted,
                tokenize=False,
                add_generation_prompt=True,
            )
            dataset.append({
                "prompt": prompt_text,
                "ground_truth": gt_flag,
            })
        except Exception as e:
            logger.warning("Skipped GRPO sample: %s", e)
            skipped += 1

    logger.info("Loaded %d GRPO prompts (%d skipped)", len(dataset), skipped)
    return dataset


# ---------------------------------------------------------------------------
# GRPO config
# ---------------------------------------------------------------------------


@dataclass
class GRPOConfig:
    """Configuration for Unsloth GRPO training."""

    model_name: str = "outputs/sft-merged"  # Start from SFT checkpoint
    max_seq_length: int = 4096
    load_in_4bit: bool = False
    load_in_16bit: bool = True

    # LoRA
    lora_r: int = 16
    lora_alpha: int = 16
    lora_dropout: float = 0
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])

    # GRPO specific
    num_generations: int = 4  # Completions per prompt for group scoring
    max_completion_length: int = 2048
    temperature: float = 0.7
    beta: float = 0.04  # KL penalty coefficient

    # Training
    epochs: int = 1
    batch_size: int = 1
    gradient_accumulation_steps: int = 4
    learning_rate: float = 5e-6  # Lower than SFT
    warmup_steps: int = 10
    weight_decay: float = 0.01
    lr_scheduler_type: str = "cosine"
    logging_steps: int = 1
    save_steps: int = 25
    save_total_limit: int = 2
    seed: int = 3407

    # Reward
    reward_mode: str = "progressive"  # "binary", "progressive", or "online"
    env_url: str | None = None  # Required for "online" mode

    # Data
    data_paths: list[str] = field(default_factory=list)

    # Output
    output_dir: str = "outputs/grpo"
    merge_output_dir: str | None = None


# ---------------------------------------------------------------------------
# Main GRPO training function
# ---------------------------------------------------------------------------


def run_grpo(config: GRPOConfig) -> dict[str, Any]:
    """Run Unsloth GRPO training.

    Returns dict with training stats.
    """
    import os
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

    from unsloth import FastLanguageModel
    from trl import GRPOTrainer, GRPOConfig as TRLGRPOConfig
    from datasets import Dataset

    # --- 1. Load model with fast inference for GRPO ---
    logger.info("Loading model: %s", config.model_name)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=config.model_name,
        max_seq_length=config.max_seq_length,
        load_in_4bit=config.load_in_4bit,
        load_in_16bit=config.load_in_16bit,
        full_finetuning=False,
        dtype=None,
        fast_inference=True,  # Required for Unsloth GRPO (uses vLLM internally)
    )

    # --- 2. Apply LoRA ---
    logger.info("Applying LoRA (r=%d, alpha=%d)", config.lora_r, config.lora_alpha)
    model = FastLanguageModel.get_peft_model(
        model,
        r=config.lora_r,
        target_modules=config.target_modules,
        lora_alpha=config.lora_alpha,
        lora_dropout=config.lora_dropout,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=config.seed,
        max_seq_length=config.max_seq_length,
    )

    # --- 3. Load data ---
    logger.info("Loading GRPO data from %d files", len(config.data_paths))
    raw_data = load_grpo_data(config.data_paths, tokenizer)

    if not raw_data:
        raise ValueError("No GRPO training samples loaded!")

    dataset = Dataset.from_dict({
        "prompt": [d["prompt"] for d in raw_data],
        "ground_truth": [d["ground_truth"] for d in raw_data],
    })
    logger.info("Dataset: %d prompts", len(dataset))

    # --- 4. Select reward function(s) ---
    if config.reward_mode == "binary":
        reward_funcs = [binary_reward]
        logger.info("Using binary reward (flag capture only)")
    elif config.reward_mode == "online":
        if not config.env_url:
            raise ValueError("env_url required for online reward mode")
        reward_funcs = [make_online_reward(config.env_url)]
        logger.info("Using online reward (env=%s)", config.env_url)
    else:  # progressive (default)
        reward_funcs = [progressive_reward]
        logger.info("Using progressive reward (6 signals)")

    # --- 5. Train ---
    logger.info("Starting GRPO training...")
    trainer = GRPOTrainer(
        model=model,
        processing_class=tokenizer,
        reward_funcs=reward_funcs,
        args=TRLGRPOConfig(
            output_dir=config.output_dir,
            num_generations=config.num_generations,
            max_completion_length=config.max_completion_length,
            per_device_train_batch_size=config.batch_size,
            gradient_accumulation_steps=config.gradient_accumulation_steps,
            num_train_epochs=config.epochs,
            warmup_steps=config.warmup_steps,
            learning_rate=config.learning_rate,
            weight_decay=config.weight_decay,
            lr_scheduler_type=config.lr_scheduler_type,
            logging_steps=config.logging_steps,
            save_steps=config.save_steps,
            save_total_limit=config.save_total_limit,
            seed=config.seed,
            bf16=True,
            report_to="none",
            beta=config.beta,
            temperature=config.temperature,
        ),
        train_dataset=dataset,
    )

    stats = trainer.train()
    logger.info("GRPO training complete! Loss: %.4f", stats.training_loss)

    # --- 6. Save LoRA adapter ---
    final_dir = str(Path(config.output_dir) / "final")
    logger.info("Saving LoRA adapter to %s", final_dir)
    model.save_pretrained(final_dir)
    tokenizer.save_pretrained(final_dir)

    # --- 7. Optionally merge ---
    if config.merge_output_dir:
        logger.info("Merging LoRA -> %s", config.merge_output_dir)
        model.save_pretrained_merged(
            config.merge_output_dir,
            tokenizer,
            save_method="merged_16bit",
        )
        logger.info("Merged model saved to %s", config.merge_output_dir)

    return {
        "training_loss": stats.training_loss,
        "num_prompts": len(raw_data),
        "max_seq_length": config.max_seq_length,
        "reward_mode": config.reward_mode,
        "lora_adapter": final_dir,
        "merged_model": config.merge_output_dir,
    }
