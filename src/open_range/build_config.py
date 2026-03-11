"""Build-time feature controls for world construction and admission."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from open_range.manifest import WeaknessFamily


class BuildConfig(BaseModel):
    """Empirical controls for world construction and admission strength."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    services_enabled: tuple[str, ...] = Field(default_factory=tuple)
    workflows_enabled: tuple[str, ...] = Field(default_factory=tuple)
    weakness_families_enabled: tuple[WeaknessFamily, ...] = Field(default_factory=tuple)
    observability_surfaces_enabled: tuple[str, ...] = Field(default_factory=tuple)
    phishing_surface_enabled: bool = True
    green_artifacts_enabled: bool = True
    topology_scale: Literal["small", "standard"] = "standard"
    validation_profile: Literal["full", "smoke"] = "full"
    red_witness_count: int = Field(default=1, ge=1)
    blue_witness_count: int = Field(default=1, ge=1)


DEFAULT_BUILD_CONFIG = BuildConfig()
