"""Deterministic weakness seeding."""

from __future__ import annotations

import random
from typing import Protocol

from open_range.manifest import WeaknessFamily
from open_range.world_ir import WeaknessSpec, WorldIR


class WeaknessSeeder(Protocol):
    def apply(self, world: WorldIR, seed: int | None = None) -> WorldIR: ...


class CatalogWeaknessSeeder:
    """Apply a bounded deterministic weakness catalog to a compiled world."""

    def apply(self, world: WorldIR, seed: int | None = None) -> WorldIR:
        rng = random.Random(world.seed if seed is None else seed)
        available = sorted(self._available_families(world))
        if not available:
            return world

        selected = tuple(sorted(rng.sample(available, k=min(2, len(available)))))
        weaknesses = tuple(self._seed_one(world, family) for family in selected)
        lineage = world.lineage.model_copy(
            update={
                "mutation_ops": tuple(world.lineage.mutation_ops) + tuple(
                    f"seed:{weak.family}:{weak.target}" for weak in weaknesses
                )
            }
        )
        return world.model_copy(update={"weaknesses": weaknesses, "lineage": lineage})

    @staticmethod
    def _available_families(world: WorldIR) -> set[WeaknessFamily]:
        service_kinds = {service.kind for service in world.services}
        available: set[WeaknessFamily] = set()
        if "web_app" in service_kinds:
            available.update({"input_validation", "workflow_abuse"})
        if {"fileshare", "db", "idp"} & service_kinds:
            available.add("secret_exposure")
        if "idp" in service_kinds:
            available.add("auth_misconfig")
        if {"email", "siem"} & service_kinds:
            available.add("telemetry_blindspot")
        if world.allowed_weakness_families:
            available &= set(world.allowed_weakness_families)
        return available

    @staticmethod
    def _seed_one(world: WorldIR, family: WeaknessFamily) -> WeaknessSpec:
        if family == "input_validation":
            return WeaknessSpec(
                id="wk-input-validation-web",
                family=family,
                target="svc-web",
                preconditions=("public_reachability", "user_input_surface"),
                expected_event_signatures=("InitialAccess", "SensitiveAssetRead"),
                blue_observability_surfaces=("web_access", "ingest"),
                remediation="shell:touch /tmp/openrange-contained",
            )
        if family == "workflow_abuse":
            workflow = world.workflows[0].id if world.workflows else "wf-generic"
            return WeaknessSpec(
                id="wk-workflow-abuse",
                family=family,
                target="svc-web",
                preconditions=(workflow, "approval_path_exists"),
                expected_event_signatures=("InitialAccess", "UnauthorizedCredentialUse"),
                blue_observability_surfaces=("web_access", "audit"),
                remediation="shell:touch /tmp/openrange-contained",
            )
        if family == "secret_exposure":
            target = "svc-fileshare" if any(service.id == "svc-fileshare" for service in world.services) else "svc-idp"
            return WeaknessSpec(
                id="wk-secret-exposure",
                family=family,
                target=target,
                preconditions=("sensitive_material_present",),
                expected_event_signatures=("CredentialObtained", "SensitiveAssetRead"),
                blue_observability_surfaces=("share_access", "audit", "ingest"),
                remediation="shell:touch /tmp/openrange-contained",
            )
        if family == "auth_misconfig":
            return WeaknessSpec(
                id="wk-auth-misconfig-idp",
                family=family,
                target="svc-idp",
                preconditions=("interactive_login",),
                expected_event_signatures=("CredentialObtained", "UnauthorizedCredentialUse"),
                blue_observability_surfaces=("auth", "audit"),
                remediation="shell:touch /tmp/openrange-contained",
            )
        return WeaknessSpec(
            id="wk-telemetry-blindspot",
            family=family,
            target="svc-email" if any(service.id == "svc-email" for service in world.services) else "svc-web",
            preconditions=("critical_action_exists",),
            expected_event_signatures=("InitialAccess", "DetectionAlertRaised"),
            blue_observability_surfaces=("smtp", "ingest"),
            remediation="shell:touch /tmp/openrange-contained",
        )
