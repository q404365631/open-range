"""Helpers for rendering observations for text-oriented agents."""

from __future__ import annotations

from typing import Any


def format_observation(observation: Any) -> str:
    """Convert structured observations into compact text."""
    if isinstance(observation, str):
        return observation

    parts: list[str] = []

    stdout = getattr(observation, "stdout", "")
    if stdout:
        parts.append(str(stdout))

    stderr = getattr(observation, "stderr", "")
    if stderr:
        parts.append(f"STDERR:\n{stderr}")

    alerts = getattr(observation, "alerts", None)
    if alerts:
        alert_lines = "\n".join(f"- {alert}" for alert in alerts)
        parts.append(f"ALERTS:\n{alert_lines}")

    flags = getattr(observation, "flags_captured", None)
    if flags:
        flag_lines = "\n".join(f"- {flag}" for flag in flags)
        parts.append(f"FLAGS CAPTURED:\n{flag_lines}")

    reward = getattr(observation, "reward", None)
    if reward is not None:
        parts.append(f"REWARD: {reward}")

    done = getattr(observation, "done", None)
    if done:
        parts.append("DONE: true")

    if parts:
        return "\n\n".join(parts)

    return str(observation)
