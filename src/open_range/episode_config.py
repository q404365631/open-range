"""Episode-time controls for runtime behavior."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


TrainingMode = Literal["red_only", "blue_only_live", "blue_only_from_prefix", "joint_pool"]
SchedulerMode = Literal["async", "strict_turn"]
GreenProfile = Literal["quiet", "balanced", "busy"]
GreenBranchBackend = Literal["scripted", "disabled"]
OpponentController = Literal["scripted", "sleep"]
StartState = Literal[
    "clean",
    "post_delivery",
    "post_click",
    "post_credential_theft",
    "post_foothold",
    "during_lateral_movement",
]
RewardProfile = Literal["terminal_first"]


class EpisodeConfig(BaseModel):
    """Empirical controls for one admitted episode runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: TrainingMode = "joint_pool"
    scheduler_mode: SchedulerMode = "async"
    green_enabled: bool = True
    green_routine_enabled: bool = True
    green_branch_enabled: bool = True
    green_profile: GreenProfile = "balanced"
    green_branch_backend: GreenBranchBackend = "scripted"
    telemetry_delay_enabled: bool = True
    continuity_enforced: bool = True
    reward_profile: RewardProfile = "terminal_first"
    red_shaping_enabled: bool = True
    blue_shaping_enabled: bool = True
    opponent_red: OpponentController = "scripted"
    opponent_blue: OpponentController = "scripted"
    start_state: StartState = "clean"
    episode_horizon: float = Field(default=25.0, gt=0.0)
    continuity_threshold: float = Field(default=0.9, ge=0.0, le=1.0)

    @property
    def controls_red(self) -> bool:
        return self.mode in {"red_only", "joint_pool"}

    @property
    def controls_blue(self) -> bool:
        return self.mode in {"blue_only_live", "blue_only_from_prefix", "joint_pool"}


DEFAULT_EPISODE_CONFIG = EpisodeConfig()
