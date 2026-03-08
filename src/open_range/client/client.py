"""OpenEnv client for OpenRange.

Provides OpenRangeEnv which wraps the typed EnvClient with
OpenRange-specific action/observation/state parsing.
"""

from __future__ import annotations

from typing import Any

from open_range.server.models import RangeAction, RangeObservation, RangeState

try:
    from openenv.core.env_client import EnvClient
    from openenv.core.client_types import StepResult

    class OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState]):
        """Typed OpenEnv client for OpenRange."""

        def _step_payload(self, action: RangeAction) -> dict:
            return {"command": action.command, "mode": action.mode}

        def _parse_result(self, payload: dict) -> StepResult[RangeObservation]:
            obs = RangeObservation(**payload.get("observation", {}))
            return StepResult(
                observation=obs,
                reward=payload.get("reward"),
                done=bool(payload.get("done", False)),
            )

        def _parse_state(self, payload: dict) -> RangeState:
            return RangeState(**payload)

except ImportError:
    # Stub for development without openenv installed
    from dataclasses import dataclass

    @dataclass
    class StepResult:  # type: ignore[no-redef]
        """Minimal StepResult stub matching openenv.core.client_types."""

        observation: RangeObservation
        reward: float | None = None
        done: bool = False

    class OpenRangeEnv:  # type: ignore[no-redef]
        """Stub client for development without openenv."""

        def __init__(self, base_url: str = "http://localhost:8000"):
            self.base_url = base_url

        def _step_payload(self, action: RangeAction) -> dict:
            return {"command": action.command, "mode": action.mode}

        def _parse_result(self, payload: dict) -> StepResult:
            obs = RangeObservation(**payload.get("observation", {}))
            return StepResult(
                observation=obs,
                reward=payload.get("reward"),
                done=bool(payload.get("done", False)),
            )

        def _parse_state(self, payload: dict) -> RangeState:
            return RangeState(**payload)
