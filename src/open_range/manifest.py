"""Strict public manifest types.

The manifest defines the legal family of business worlds. It is intentionally
public and must not encode a golden path, literal exploit steps, or flag paths.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PositiveInt


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


WeaknessFamily = Literal[
    "auth_misconfig",
    "workflow_abuse",
    "secret_exposure",
    "input_validation",
    "telemetry_blindspot",
]

NoiseDensity = Literal["low", "medium", "high"]
AssetClass = Literal["crown_jewel", "sensitive", "operational"]


class BusinessSpec(_StrictModel):
    archetype: str = Field(min_length=1)
    workflows: tuple[str, ...] = Field(default_factory=tuple, min_length=1)


class TopologySpec(_StrictModel):
    zones: tuple[str, ...] = Field(default_factory=tuple, min_length=1)
    services: tuple[str, ...] = Field(default_factory=tuple, min_length=1)


class UserRoleSpec(_StrictModel):
    roles: dict[str, PositiveInt] = Field(default_factory=dict, min_length=1)


class ManifestAsset(_StrictModel):
    id: str = Field(min_length=1)
    asset_class: AssetClass = Field(alias="class")


class ObjectivePredicate(_StrictModel):
    predicate: str = Field(min_length=1)


class ObjectiveSet(_StrictModel):
    red: tuple[ObjectivePredicate, ...] = Field(default_factory=tuple, min_length=1)
    blue: tuple[ObjectivePredicate, ...] = Field(default_factory=tuple, min_length=1)


class ObservabilityRequirements(_StrictModel):
    require_web_logs: bool = False
    require_idp_logs: bool = False
    require_email_logs: bool = False
    require_siem_ingest: bool = False


class SecuritySpec(_StrictModel):
    allowed_weakness_families: tuple[WeaknessFamily, ...] = Field(
        default_factory=tuple,
        min_length=1,
    )
    observability: ObservabilityRequirements


class DifficultySpec(_StrictModel):
    target_red_path_depth: PositiveInt
    target_blue_signal_points: PositiveInt
    target_noise_density: NoiseDensity


class MutationBounds(_StrictModel):
    max_new_hosts: int = Field(ge=0, default=0)
    max_new_services: int = Field(ge=0, default=0)
    max_new_users: int = Field(ge=0, default=0)
    max_new_weaknesses: int = Field(ge=0, default=0)


class EnterpriseSaaSManifest(_StrictModel):
    version: Literal[1] = 1
    world_family: Literal["enterprise_saas_v1"] = "enterprise_saas_v1"
    seed: int
    business: BusinessSpec
    topology: TopologySpec
    users: UserRoleSpec
    assets: tuple[ManifestAsset, ...] = Field(default_factory=tuple, min_length=1)
    objectives: ObjectiveSet
    security: SecuritySpec
    difficulty: DifficultySpec
    mutation_bounds: MutationBounds


def validate_manifest(payload: dict) -> EnterpriseSaaSManifest:
    """Validate raw public manifest payload into the strict model."""
    return EnterpriseSaaSManifest.model_validate(payload)


def manifest_schema() -> dict:
    """Return the JSON schema for the strict public manifest."""
    return EnterpriseSaaSManifest.model_json_schema()
