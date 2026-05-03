"""Environment actor turn contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ActorTurn:
    task_id: str
    actor_id: str
    actor_kind: str
    target: str
    action: Mapping[str, object]
    observation: Mapping[str, object] | None = None
    state: Mapping[str, object] | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "actor_id": self.actor_id,
            "actor_kind": self.actor_kind,
            "target": self.target,
            "action": dict(self.action),
            "observation": (
                None if self.observation is None else dict(self.observation)
            ),
            "state": None if self.state is None else dict(self.state),
            "metadata": dict(self.metadata),
        }
