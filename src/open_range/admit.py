"""Deterministic admission controller."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from open_range.admission import (
    ProbeSpec,
    ValidatorCheckReport,
    ValidatorReport,
    ValidatorStageReport,
    WitnessAction,
    WitnessBundle,
    WitnessTrace,
)
from open_range.build_config import BuildConfig, DEFAULT_BUILD_CONFIG
from open_range.cluster import LiveBackend
from open_range.episode_config import EpisodeConfig
from open_range.execution import PodActionBackend
from open_range.runtime import WitnessDrivenRuntime
from open_range.runtime_types import Action
from open_range.snapshot import KindArtifacts, Snapshot, world_hash
from open_range.world_ir import AssetSpec, ServiceSpec, WorldIR


class AdmissionController(Protocol):
    def admit(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> tuple[WitnessBundle, ValidatorReport]: ...


CheckFunc = Callable[[WorldIR, KindArtifacts, WitnessBundle | None], ValidatorCheckReport]


@dataclass(frozen=True)
class _Stage:
    name: str
    checks: tuple[CheckFunc, ...]


class LocalAdmissionController:
    """Run deterministic admission in fail-fast or analysis mode."""

    def __init__(self, mode: str = "fail_fast", *, live_backend: LiveBackend | None = None) -> None:
        if mode not in {"fail_fast", "analysis"}:
            raise ValueError("mode must be 'fail_fast' or 'analysis'")
        self.mode = mode
        self.live_backend = live_backend

    def admit(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> tuple[WitnessBundle, ValidatorReport]:
        witness_bundle: WitnessBundle | None = None
        stages: list[ValidatorStageReport] = []
        continue_running = True
        health_info: dict[str, object] = {"render_dir": artifacts.render_dir}

        for stage in self._stages(build_config):
            checks: list[ValidatorCheckReport] = []
            for check in stage.checks:
                if not continue_running:
                    break
                if witness_bundle is None and stage.name in {"red_witness", "blue_witness", "necessity", "shortcut", "determinism"}:
                    witness_bundle = _build_witness_bundle(world, build_config)
                result = check(world, artifacts, witness_bundle)
                checks.append(result)
                if self.mode == "fail_fast" and not result.passed and not result.advisory:
                    continue_running = False
            stage_passed = all(result.passed or result.advisory for result in checks)
            stages.append(
                ValidatorStageReport(
                    name=stage.name,
                    passed=stage_passed,
                    checks=tuple(checks),
                )
            )
            if self.mode == "fail_fast" and not stage_passed:
                break

        final_bundle = witness_bundle or _build_witness_bundle(world, build_config)

        if continue_running and self.live_backend is not None:
            live_stage, live_info = self._run_live_backend_checks(world, artifacts, final_bundle)
            stages.append(live_stage)
            health_info.update(live_info)
            if self.mode == "fail_fast" and not live_stage.passed:
                continue_running = False

        admitted = all(stage.passed for stage in stages)
        report = ValidatorReport(
            admitted=admitted,
            mode=self.mode,
            world_id=world.world_id,
            world_hash=world_hash(world),
            summary="admitted" if admitted else "rejected",
            build_logs=tuple(artifacts.rendered_files),
            health_info=health_info,
            stages=tuple(stages),
        )
        return final_bundle, report

    @staticmethod
    def _stages(build_config: BuildConfig) -> tuple[_Stage, ...]:
        base = (
            _Stage(
                "static",
                (
                    _check_manifest_compliance,
                    _check_graph_consistency,
                    _check_path_solvability,
                    _check_objective_grounding,
                    _check_workflow_consistency,
                ),
            ),
            _Stage(
                "live",
                (
                    _check_render_outputs,
                    _check_service_health_contract,
                    _check_siem_ingest,
                    _check_isolation,
                    _check_difficulty_envelope,
                ),
            ),
            _Stage("red_witness", (_check_red_witness,)),
            _Stage("blue_witness", (_check_blue_witness,)),
        )
        if build_config.validation_profile == "smoke":
            return base
        return base + (
            _Stage("necessity", (_check_necessity,)),
            _Stage("shortcut", (_check_shortcut_probes,)),
            _Stage("determinism", (_check_determinism,)),
        )

    def _run_live_backend_checks(
        self,
        world: WorldIR,
        artifacts: KindArtifacts,
        witness_bundle: WitnessBundle,
    ) -> tuple[ValidatorStageReport, dict[str, object]]:
        assert self.live_backend is not None
        checks: list[ValidatorCheckReport] = []
        expected_services = {service.id for service in world.services}
        live_info: dict[str, object] = {}
        try:
            release = self.live_backend.boot(
                snapshot_id=world.world_id,
                artifacts_dir=Path(artifacts.render_dir),
            )
            discovered = set(release.pods.pod_ids)
            checks.append(
                ValidatorCheckReport(
                    name="kind_boot",
                    passed=expected_services <= discovered,
                    details={
                        "release_name": release.release_name,
                        "expected_services": sorted(expected_services),
                        "discovered_services": sorted(discovered),
                    },
                    error="" if expected_services <= discovered else "live release missing expected services",
                )
            )

            unhealthy = [
                service_id
                for service_id in sorted(expected_services & discovered)
                if not asyncio.run(release.pods.is_healthy(service_id))
            ]
            checks.append(
                ValidatorCheckReport(
                    name="kind_health",
                    passed=not unhealthy,
                    details={
                        "release_name": release.release_name,
                        "unhealthy_services": unhealthy,
                    },
                    error="" if not unhealthy else "one or more live services failed readiness",
                )
            )
            snapshot = _ephemeral_snapshot(world, artifacts, witness_bundle)
            backend = PodActionBackend()
            backend.bind(snapshot, release)
            checks.append(_live_service_smoke_check(world, release))
            checks.append(_live_red_witness_check(snapshot, backend))
            checks.append(_live_siem_ingest_check(release))
            checks.append(_live_blue_witness_check(snapshot, backend))
            checks.append(_live_determinism_check(snapshot, backend))
            checks.append(_live_necessity_check(snapshot, release, backend))
            checks.append(_live_shortcut_probe_check(snapshot, release))
            live_info = {
                "live_release": release.release_name,
                "live_service_count": len(discovered),
            }
        except Exception as exc:  # noqa: BLE001
            checks.append(
                ValidatorCheckReport(
                    name="kind_boot",
                    passed=False,
                    details={"artifacts_dir": artifacts.render_dir},
                    error=str(exc),
                )
            )
        finally:
            if "release" in locals():
                try:
                    self.live_backend.teardown(release)
                except Exception:
                    pass

        stage = ValidatorStageReport(
            name="kind_live",
            passed=all(check.passed or check.advisory for check in checks),
            checks=tuple(checks),
        )
        return stage, live_info


def _check_manifest_compliance(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    allowed = {"web_app", "email", "idp", "fileshare", "db", "siem"}
    invalid = sorted(service.kind for service in world.services if service.kind not in allowed)
    passed = world.world_family == "enterprise_saas_v1" and not invalid
    return ValidatorCheckReport(
        name="manifest_compliance",
        passed=passed,
        details={"invalid_service_kinds": invalid},
        error="" if passed else "world violates the fixed service palette",
    )


def _check_graph_consistency(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    host_ids = {host.id for host in world.hosts}
    service_ids = {service.id for service in world.services}
    asset_ids = {asset.id for asset in world.assets}
    issues = []

    if len(host_ids) != len(world.hosts):
        issues.append("duplicate host ids")
    if len(service_ids) != len(world.services):
        issues.append("duplicate service ids")

    for service in world.services:
        if service.host not in host_ids:
            issues.append(f"service {service.id} references missing host {service.host}")
        for dep in service.dependencies:
            if dep not in service_ids:
                issues.append(f"service {service.id} references missing dependency {dep}")

    for asset in world.assets:
        if asset.owner_service not in service_ids:
            issues.append(f"asset {asset.id} references missing owner service {asset.owner_service}")

    valid_nodes = host_ids | service_ids | asset_ids | {group.id for group in world.groups} | {user.id for user in world.users}
    for edge in world.network_edges + world.trust_edges + world.data_edges + world.telemetry_edges:
        if edge.source not in valid_nodes:
            issues.append(f"edge {edge.id} missing source {edge.source}")
        if edge.target not in valid_nodes:
            issues.append(f"edge {edge.id} missing target {edge.target}")

    return ValidatorCheckReport(
        name="graph_consistency",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


def _check_path_solvability(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    starts = {service.id for service in world.services if _is_public_service(service)}
    adjacency = _service_graph(world)
    unreachable = []
    for objective in world.red_objectives:
        target_service = _objective_target_service(world, objective.predicate)
        if target_service and not _reachable_from_any(starts, target_service, adjacency):
            unreachable.append(target_service)
    return ValidatorCheckReport(
        name="path_solvability",
        passed=not unreachable,
        details={"starts": sorted(starts), "unreachable_targets": unreachable},
        error="" if not unreachable else f"unreachable objective targets: {sorted(set(unreachable))}",
    )


def _check_objective_grounding(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    issues = []
    for objective in world.red_objectives + world.blue_objectives:
        if _objective_target_service(world, objective.predicate) is None and _objective_target_asset(world, objective.predicate) is None:
            if "service_health_above" not in objective.predicate and "intrusion_detected" not in objective.predicate and "intrusion_contained" not in objective.predicate:
                issues.append(objective.predicate)
    if not world.weaknesses:
        issues.append("no weaknesses seeded")
    return ValidatorCheckReport(
        name="objective_grounding",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


def _check_workflow_consistency(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    service_ids = {service.id for service in world.services}
    asset_ids = {asset.id for asset in world.assets}
    issues = []
    for workflow in world.workflows:
        for step in workflow.steps:
            if step.service and step.service not in service_ids:
                issues.append(f"workflow {workflow.id} references missing service {step.service}")
            if step.asset and step.asset not in asset_ids:
                issues.append(f"workflow {workflow.id} references missing asset {step.asset}")
    return ValidatorCheckReport(
        name="topology_workflow_consistency",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


def _check_render_outputs(_world: WorldIR, artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    missing = [path for path in artifacts.rendered_files if not Path(path).exists()]
    return ValidatorCheckReport(
        name="render_outputs",
        passed=not missing,
        details={"missing": missing},
        error="" if not missing else f"missing rendered files: {missing}",
    )


def _check_service_health_contract(world: WorldIR, artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    rendered = artifacts.chart_values.get("services", {})
    missing = [service.id for service in world.services if service.id not in rendered]
    passed = not missing and len(rendered) == len(world.services)
    return ValidatorCheckReport(
        name="service_health",
        passed=passed,
        details={"missing_services": missing, "rendered_service_count": len(rendered)},
        error="" if passed else f"services missing from rendered chart values: {missing}",
    )


def _check_siem_ingest(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    telemetry_targets = {edge.target for edge in world.telemetry_edges}
    actual_sources = {edge.source for edge in world.telemetry_edges}
    expected_sources = {service.id for service in world.services if service.id != "svc-siem"}
    passed = "svc-siem" in telemetry_targets and expected_sources <= actual_sources
    return ValidatorCheckReport(
        name="siem_ingest",
        passed=passed,
        details={"expected_sources": sorted(expected_sources), "actual_sources": sorted(actual_sources)},
        error="" if passed else "not all services ship telemetry to svc-siem",
    )


def _check_isolation(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    issues = []
    host_by_id = {host.id: host for host in world.hosts}
    for service in world.services:
        host = host_by_id[service.host]
        if host.zone in {"data", "management"} and host.exposure == "public":
            issues.append(f"{service.id} is public in restricted zone {host.zone}")
    return ValidatorCheckReport(
        name="isolation",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


def _check_difficulty_envelope(world: WorldIR, _artifacts: KindArtifacts, _wb: WitnessBundle | None) -> ValidatorCheckReport:
    red_depth = _red_path_depth(world)
    lower = max(1, world.target_red_path_depth - 2)
    upper = world.target_red_path_depth + 2
    blue_signal_points = len({edge.source for edge in world.telemetry_edges})
    passed = lower <= red_depth <= upper and blue_signal_points >= min(world.target_blue_signal_points, len(world.services))
    return ValidatorCheckReport(
        name="difficulty_envelope",
        passed=passed,
        details={
            "computed_red_path_depth": red_depth,
            "target_red_path_depth": world.target_red_path_depth,
            "blue_signal_points": blue_signal_points,
            "target_blue_signal_points": world.target_blue_signal_points,
        },
        error="" if passed else "world falls outside the configured difficulty envelope",
    )


def _check_red_witness(_world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    trace = wb.red_witnesses[0] if wb and wb.red_witnesses else None
    passed = trace is not None and bool(trace.steps)
    return ValidatorCheckReport(
        name="red_witness",
        passed=passed,
        details={"trace_id": trace.id if trace else "", "step_count": len(trace.steps) if trace else 0},
        error="" if passed else "no valid red witness",
    )


def _check_blue_witness(world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    trace = wb.blue_witnesses[0] if wb and wb.blue_witnesses else None
    passed = trace is not None and bool(trace.steps) and len(trace.objective_ids) <= len(world.blue_objectives)
    return ValidatorCheckReport(
        name="blue_witness",
        passed=passed,
        details={"trace_id": trace.id if trace else "", "step_count": len(trace.steps) if trace else 0},
        error="" if passed else "no valid blue witness",
    )


def _check_necessity(world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    red_trace = wb.red_witnesses[0] if wb and wb.red_witnesses else None
    weakness_targets = {weak.target for weak in world.weaknesses}
    red_targets = {step.target for step in red_trace.steps} if red_trace else set()
    observability_sources = {edge.source for edge in world.telemetry_edges}
    issues = []
    if not weakness_targets:
        issues.append("no weakness targets")
    if not (weakness_targets & red_targets):
        issues.append("red witness does not traverse a seeded weakness target")
    if not observability_sources:
        issues.append("blue witness lacks observability substrate")
    if not all(weak.remediation for weak in world.weaknesses):
        issues.append("one or more weaknesses lack remediation metadata")
    return ValidatorCheckReport(
        name="necessity",
        passed=not issues,
        details={"issues": issues},
        error="; ".join(issues),
    )


def _check_shortcut_probes(world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    probes = wb.shortcut_probes if wb else ()
    public_services = {service.id for service in world.services if _is_public_service(service)}
    critical_assets = {asset.owner_service for asset in world.assets if asset.confidentiality == "critical"}
    issues = []
    if public_services & critical_assets:
        issues.append("critical asset exposed directly via public service")
    if not probes:
        issues.append("no shortcut probes generated")
    return ValidatorCheckReport(
        name="shortcut_probes",
        passed=not issues,
        details={"issues": issues, "probe_count": len(probes)},
        error="; ".join(issues),
    )


def _check_determinism(world: WorldIR, _artifacts: KindArtifacts, wb: WitnessBundle | None) -> ValidatorCheckReport:
    regenerated = _build_witness_bundle(
        world,
        BuildConfig(
            red_witness_count=len(wb.red_witnesses) if wb else 1,
            blue_witness_count=len(wb.blue_witnesses) if wb else 1,
        ),
    )
    passed = wb is not None and regenerated.model_dump(mode="json") == wb.model_dump(mode="json")
    return ValidatorCheckReport(
        name="determinism",
        passed=passed,
        details={"world_hash": world_hash(world)},
        error="" if passed else "witness bundle is not deterministic",
    )


def _ephemeral_snapshot(world: WorldIR, artifacts: KindArtifacts, witness_bundle: WitnessBundle) -> Snapshot:
    report = ValidatorReport(
        admitted=True,
        world_id=world.world_id,
        world_hash=world_hash(world),
        summary="admission-live-check",
    )
    return Snapshot(
        snapshot_id=f"{world.world_id}-admission",
        world=world,
        artifacts=artifacts,
        validator_report=report,
        witness_bundle=witness_bundle,
        world_hash=world_hash(world),
    )


def _live_service_smoke_check(world: WorldIR, release) -> ValidatorCheckReport:
    commands = {
        "svc-web": ("sandbox-red", "wget -qO- http://svc-web:80/ | grep -q OpenRange"),
        "svc-email": ("sandbox-red", "nc -z -w 3 svc-email 25"),
        "svc-idp": ("sandbox-blue", "nc -z -w 3 svc-idp 389"),
        "svc-fileshare": ("sandbox-blue", "nc -z -w 3 svc-fileshare 445"),
        "svc-db": ("sandbox-blue", "nc -z -w 3 svc-db 3306"),
        "svc-siem": ("sandbox-blue", "wget -qO- http://svc-siem:9200/all.log >/dev/null"),
    }
    failures: list[str] = []
    for service in world.services:
        runner, cmd = commands.get(service.id, ("sandbox-blue", "true"))
        result = asyncio.run(release.pods.exec(runner, cmd, timeout=10.0))
        if not result.ok:
            failures.append(f"{service.id}:{result.stderr or result.stdout or 'smoke failed'}")
    return ValidatorCheckReport(
        name="live_service_smoke",
        passed=not failures,
        details={"failures": failures},
        error="; ".join(failures),
    )


def _live_red_witness_check(snapshot: Snapshot, backend: PodActionBackend) -> ValidatorCheckReport:
    score, _events, _health, outputs = _run_red_witness(snapshot, backend, episode_seed=snapshot.world.seed)
    passed = score.winner == "red" and score.done
    return ValidatorCheckReport(
        name="live_red_witness",
        passed=passed,
        details={"winner": score.winner, "terminal_reason": score.terminal_reason, "outputs": outputs},
        error="" if passed else "live red witness did not satisfy terminal objectives",
    )


def _live_blue_witness_check(snapshot: Snapshot, backend: PodActionBackend) -> ValidatorCheckReport:
    runtime = WitnessDrivenRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="blue_only_live",
            episode_horizon=max(6, len(snapshot.witness_bundle.blue_witnesses[0].steps) + 3),
        ),
    )
    outputs: list[str] = []
    blue_steps = list(snapshot.witness_bundle.blue_witnesses[0].steps)
    step_idx = 0
    while not runtime.state().done:
        decision = runtime.next_decision()
        step = blue_steps[step_idx] if step_idx < len(blue_steps) else None
        action = _runtime_action("blue", step) if step is not None else Action(actor_id="blue", role="blue", kind="sleep", payload={})
        result = runtime.act("blue", action)
        outputs.append(result.stdout or result.stderr)
        if decision.actor != "blue":
            break
        if step is not None:
            step_idx += 1
    score = runtime.score()
    passed = score.winner == "blue" and score.done
    return ValidatorCheckReport(
        name="live_blue_witness",
        passed=passed,
        details={"winner": score.winner, "terminal_reason": score.terminal_reason, "outputs": outputs},
        error="" if passed else "live blue witness did not validate detect-and-contain path",
    )


def _live_siem_ingest_check(release) -> ValidatorCheckReport:
    result = asyncio.run(
        release.pods.exec("svc-siem", "grep -q 'InitialAccess' /srv/http/siem/all.log", timeout=10.0)
    )
    return ValidatorCheckReport(
        name="live_siem_ingest",
        passed=result.ok,
        details={"stdout": result.stdout.strip(), "stderr": result.stderr.strip()},
        error="" if result.ok else "siem log sink did not record witness events",
    )


def _live_determinism_check(snapshot: Snapshot, backend: PodActionBackend) -> ValidatorCheckReport:
    first_score, first_events, first_health, _first_outputs = _run_red_witness(
        snapshot,
        backend,
        episode_seed=snapshot.world.seed,
    )
    second_score, second_events, second_health, _second_outputs = _run_red_witness(
        snapshot,
        backend,
        episode_seed=snapshot.world.seed,
    )
    passed = (
        first_events == second_events
        and first_health == second_health
        and first_score.winner == second_score.winner
        and first_score.terminal_reason == second_score.terminal_reason
    )
    return ValidatorCheckReport(
        name="live_determinism",
        passed=passed,
        details={
            "first_event_count": len(first_events),
            "second_event_count": len(second_events),
            "winner": first_score.winner,
        },
        error="" if passed else "live witness replay is not deterministic",
    )


def _live_necessity_check(snapshot: Snapshot, release, backend: PodActionBackend) -> ValidatorCheckReport:
    red_targets = {step.target for step in snapshot.witness_bundle.red_witnesses[0].steps}
    target_weakness = next((weak for weak in snapshot.world.weaknesses if weak.target in red_targets), None)
    if target_weakness is None:
        return ValidatorCheckReport(
            name="live_necessity",
            passed=False,
            details={"reason": "no witness-relevant weakness"},
            error="no witness-relevant weakness available for live necessity check",
        )
    command = _remediation_command(target_weakness.remediation)
    if not command:
        return ValidatorCheckReport(
            name="live_necessity",
            passed=False,
            details={"weakness_id": target_weakness.id, "remediation": target_weakness.remediation},
            error="weakness remediation is not executable",
        )
    apply_result = asyncio.run(release.pods.exec(target_weakness.target, command, timeout=10.0))
    score, _events, _health, outputs = _run_red_witness(
        snapshot,
        backend,
        episode_seed=snapshot.world.seed,
    )
    asyncio.run(release.pods.exec(target_weakness.target, "rm -f /tmp/openrange-contained", timeout=10.0))
    passed = apply_result.ok and score.winner != "red"
    return ValidatorCheckReport(
        name="live_necessity",
        passed=passed,
        details={
            "weakness_id": target_weakness.id,
            "target": target_weakness.target,
            "winner_after_remediation": score.winner,
            "outputs": outputs,
        },
        error="" if passed else "live remediation did not break the witness path",
    )


def _live_shortcut_probe_check(snapshot: Snapshot, release) -> ValidatorCheckReport:
    host_by_id = {host.id: host for host in snapshot.world.hosts}
    service_by_id = {service.id: service for service in snapshot.world.services}
    protected_targets = sorted(
        {
            asset.owner_service
            for asset in snapshot.world.assets
            if asset.confidentiality == "critical"
            and asset.owner_service in service_by_id
            and host_by_id[service_by_id[asset.owner_service].host].exposure != "public"
        }
    )
    unexpected: list[str] = []
    for service_id in protected_targets:
        service = service_by_id[service_id]
        result = asyncio.run(release.pods.exec("sandbox-red", _service_probe_command(service), timeout=10.0))
        if result.ok:
            unexpected.append(f"direct_external_access:{service_id}")
    if "svc-idp" in service_by_id:
        admin_probe = asyncio.run(release.pods.exec("sandbox-red", _service_probe_command(service_by_id["svc-idp"]), timeout=10.0))
        if admin_probe.ok:
            unexpected.append("direct_admin_access:svc-idp")
    return ValidatorCheckReport(
        name="live_shortcuts",
        passed=not unexpected,
        details={"unexpected_reachability": unexpected},
        error="; ".join(unexpected),
    )
def _runtime_action(actor: str, step: WitnessAction) -> Action:
    payload = dict(step.payload)
    if step.target:
        payload.setdefault("target", step.target)
    if actor == "blue" and step.kind == "submit_finding":
        event_type = str(payload.get("event", payload.get("event_type", "InitialAccess")))
        payload["event_type"] = event_type
    return Action(actor_id=actor, role=actor, kind=step.kind, payload=payload)


def _run_red_witness(
    snapshot: Snapshot,
    backend: PodActionBackend,
    *,
    episode_seed: int,
):
    del episode_seed
    runtime = WitnessDrivenRuntime(action_backend=backend)
    runtime.reset(
        snapshot,
        EpisodeConfig(
            mode="red_only",
            opponent_blue="sleep",
            episode_horizon=max(5, len(snapshot.witness_bundle.red_witnesses[0].steps) + 2),
        ),
    )
    outputs: list[str] = []
    red_steps = list(snapshot.witness_bundle.red_witnesses[0].steps)
    step_idx = 0
    while not runtime.state().done and step_idx < len(red_steps):
        decision = runtime.next_decision()
        if decision.actor != "red":
            break
        step = red_steps[step_idx]
        result = runtime.act("red", _runtime_action("red", step))
        outputs.append(result.stdout or result.stderr)
        step_idx += 1
    score = runtime.score()
    events = tuple(event.model_dump(mode="json") for event in runtime.export_events())
    health = tuple(sorted(runtime.state().service_health.items()))
    return score, events, health, outputs


def _remediation_command(remediation: str) -> str:
    if remediation.startswith("shell:"):
        return remediation.split("shell:", 1)[1].strip()
    return ""


def _service_probe_command(service: ServiceSpec) -> str:
    port = service.ports[0] if service.ports else 80
    if service.kind == "web_app":
        return f"wget -qO- http://{service.id}:{port}/ >/dev/null"
    return f"nc -z -w 3 {service.id} {port}"


def _build_witness_bundle(world: WorldIR, build_config: BuildConfig = DEFAULT_BUILD_CONFIG) -> WitnessBundle:
    red_trace = _build_red_witness(world)
    blue_trace = _build_blue_witness(world, red_trace)
    smoke_tests = tuple(
        ProbeSpec(
            id=f"smoke-{service.id}",
            kind="smoke",
            description=f"boot and basic health for {service.id}",
            command=f"check {service.id}",
        )
        for service in world.services
    )
    shortcut_probes = (
        ProbeSpec(id="shortcut-direct-asset", kind="shortcut", description="direct external crown-jewel access"),
        ProbeSpec(id="shortcut-admin", kind="shortcut", description="direct admin access"),
        ProbeSpec(id="shortcut-cross-zone", kind="shortcut", description="unintended cross-zone reachability"),
        ProbeSpec(id="shortcut-secret", kind="shortcut", description="leaked secrets"),
        ProbeSpec(id="shortcut-unlogged", kind="shortcut", description="unlogged critical actions"),
    )
    determinism_probes = (
        ProbeSpec(id="determinism-red", kind="determinism", description="replay red witness"),
    )
    necessity_probes = tuple(
        ProbeSpec(
            id=f"necessity-{weak.id}",
            kind="necessity",
            description=f"remove or remediate {weak.id} and require witness degradation",
        )
        for weak in world.weaknesses
    )
    red_witnesses = tuple(
        red_trace.model_copy(update={"id": f"{red_trace.id}-{idx}"})
        for idx in range(1, build_config.red_witness_count + 1)
    )
    blue_witnesses = tuple(
        blue_trace.model_copy(update={"id": f"{blue_trace.id}-{idx}"})
        for idx in range(1, build_config.blue_witness_count + 1)
    )
    return WitnessBundle(
        red_witnesses=red_witnesses,
        blue_witnesses=blue_witnesses,
        smoke_tests=smoke_tests,
        shortcut_probes=shortcut_probes,
        determinism_probes=determinism_probes,
        necessity_probes=necessity_probes,
    )


def _build_red_witness(world: WorldIR) -> WitnessTrace:
    start = next((service.id for service in world.services if _is_public_service(service)), world.services[0].id)
    graph = _service_graph(world)
    weakness_by_target = {weak.target: weak for weak in world.weaknesses}
    first_weakness = weakness_by_target.get(start) or next(iter(world.weaknesses), None)

    steps = [
        WitnessAction(
            actor="red",
            kind="api",
            target=start,
            payload={"action": "initial_access", "weakness": first_weakness.id if first_weakness else ""},
        )
    ]

    current = start
    for objective in world.red_objectives:
        target = _objective_target_service(world, objective.predicate) or current
        path = _shortest_path(current, target, graph)
        for service_id in path[1:]:
            steps.append(
                WitnessAction(
                    actor="red",
                    kind="api",
                    target=service_id,
                    payload={"action": "traverse"},
                )
            )
        asset = _objective_target_asset(world, objective.predicate)
        steps.append(
            WitnessAction(
                actor="red",
                kind="api",
                target=target,
                payload={"action": "satisfy_objective", "asset": asset.id if asset else ""},
            )
        )
        current = target
    events = []
    for weak in world.weaknesses:
        events.extend(weak.expected_event_signatures)
    return WitnessTrace(
        id=f"red-{world.world_id}",
        role="red",
        objective_ids=tuple(objective.id for objective in world.red_objectives),
        expected_events=tuple(dict.fromkeys(events + ["SensitiveAssetRead"])),
        steps=tuple(steps),
    )


def _build_blue_witness(world: WorldIR, red_trace: WitnessTrace) -> WitnessTrace:
    detect_target = red_trace.steps[0].target if red_trace.steps else "svc-web"
    contain_target = red_trace.steps[-1].target if red_trace.steps else "svc-siem"
    return WitnessTrace(
        id=f"blue-{world.world_id}",
        role="blue",
        objective_ids=tuple(objective.id for objective in world.blue_objectives),
        expected_events=("DetectionAlertRaised", "ContainmentApplied"),
        steps=(
            WitnessAction(actor="blue", kind="shell", target="svc-siem", payload={"action": "observe_events"}),
            WitnessAction(actor="blue", kind="submit_finding", target=detect_target, payload={"event": "InitialAccess"}),
            WitnessAction(actor="blue", kind="control", target=contain_target, payload={"action": "contain"}),
        ),
    )


def _service_graph(world: WorldIR) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = {service.id: set() for service in world.services}
    for service in world.services:
        for dep in service.dependencies:
            adjacency.setdefault(service.id, set()).add(dep)
            adjacency.setdefault(dep, set()).add(service.id)
    for edge in world.network_edges + world.trust_edges + world.data_edges:
        if edge.source in adjacency and edge.target in adjacency:
            adjacency[edge.source].add(edge.target)
            adjacency[edge.target].add(edge.source)
    return adjacency


def _shortest_path(start: str, target: str, adjacency: dict[str, set[str]]) -> tuple[str, ...]:
    if start == target:
        return (start,)
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(start, (start,))])
    seen = {start}
    while queue:
        current, path = queue.popleft()
        for neighbor in sorted(adjacency.get(current, set())):
            if neighbor == target:
                return path + (neighbor,)
            if neighbor in seen:
                continue
            seen.add(neighbor)
            queue.append((neighbor, path + (neighbor,)))
    return (start, target)


def _reachable_from_any(starts: set[str], target: str, adjacency: dict[str, set[str]]) -> bool:
    if not starts:
        return False
    for start in starts:
        if target in _shortest_path(start, target, adjacency):
            return True
    return False


def _objective_target_service(world: WorldIR, predicate: str) -> str | None:
    asset = _objective_target_asset(world, predicate)
    if asset is not None:
        return asset.owner_service
    if any(token in predicate for token in ("service_health_above", "intrusion_detected", "intrusion_contained")):
        return "svc-siem"
    return None


def _objective_target_asset(world: WorldIR, predicate: str) -> AssetSpec | None:
    if "(" not in predicate or ")" not in predicate:
        return None
    inner = predicate.split("(", 1)[1].rsplit(")", 1)[0].strip()
    if not inner:
        return None
    for asset in world.assets:
        if asset.id == inner:
            return asset
    return None


def _is_public_service(service: ServiceSpec) -> bool:
    return service.kind in {"web_app", "email"}


def _red_path_depth(world: WorldIR) -> int:
    start = next((service.id for service in world.services if _is_public_service(service)), world.services[0].id)
    target = _objective_target_service(world, world.red_objectives[0].predicate) or world.services[-1].id
    return len(_shortest_path(start, target, _service_graph(world)))
