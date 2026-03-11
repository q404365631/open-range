from __future__ import annotations

from pathlib import Path

from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.curriculum import FrontierMutationPolicy, PopulationStats, propose_mutations
from open_range.pipeline import BuildPipeline
from open_range.store import FileSnapshotStore
from open_range.weaknesses import CatalogWeaknessSeeder


def _manifest_payload() -> dict:
    return {
        "version": 1,
        "world_family": "enterprise_saas_v1",
        "seed": 1337,
        "business": {
            "archetype": "healthcare_saas",
            "workflows": [
                "helpdesk_ticketing",
                "payroll_approval",
                "document_sharing",
                "internal_email",
            ],
        },
        "topology": {
            "zones": ["external", "dmz", "corp", "data", "management"],
            "services": ["web_app", "email", "idp", "fileshare", "db", "siem"],
        },
        "users": {
            "roles": {"sales": 2, "engineer": 1, "finance": 1, "it_admin": 1},
        },
        "assets": [
            {"id": "finance_docs", "class": "crown_jewel"},
            {"id": "payroll_db", "class": "crown_jewel"},
            {"id": "idp_admin_cred", "class": "sensitive"},
        ],
        "objectives": {
            "red": [
                {"predicate": "asset_read(finance_docs)"},
                {"predicate": "credential_obtained(idp_admin_cred)"},
            ],
            "blue": [
                {"predicate": "intrusion_detected(initial_access)"},
                {"predicate": "intrusion_contained(before_asset_read)"},
                {"predicate": "service_health_above(0.9)"},
            ],
        },
        "security": {
            "allowed_weakness_families": [
                "auth_misconfig",
                "workflow_abuse",
                "secret_exposure",
                "input_validation",
                "telemetry_blindspot",
            ],
            "observability": {
                "require_web_logs": True,
                "require_idp_logs": True,
                "require_email_logs": True,
                "require_siem_ingest": True,
            },
        },
        "difficulty": {
            "target_red_path_depth": 4,
            "target_blue_signal_points": 4,
            "target_noise_density": "medium",
        },
        "mutation_bounds": {
            "max_new_hosts": 2,
            "max_new_services": 1,
            "max_new_users": 5,
            "max_new_weaknesses": 2,
        },
    }


def _seeded_world():
    world = EnterpriseSaaSManifestCompiler().compile(_manifest_payload())
    return CatalogWeaknessSeeder().apply(world)


def test_policy_choose_parent_prefers_frontier_train_world():
    policy = FrontierMutationPolicy()
    population = [
        PopulationStats(
            snapshot_id="snap-hard",
            world_id="world-hard",
            split="train",
            episodes=12,
            red_win_rate=0.05,
            blue_win_rate=0.9,
            flake_rate=0.02,
            novelty=0.8,
            blue_signal_points=5,
        ),
        PopulationStats(
            snapshot_id="snap-frontier",
            world_id="world-frontier",
            split="train",
            episodes=8,
            red_win_rate=0.52,
            blue_win_rate=0.48,
            flake_rate=0.01,
            novelty=0.6,
            blue_signal_points=4,
        ),
        PopulationStats(
            snapshot_id="snap-eval",
            world_id="world-eval",
            split="eval",
            episodes=50,
            red_win_rate=0.5,
            blue_win_rate=0.5,
            flake_rate=0.0,
            novelty=1.0,
            blue_signal_points=6,
        ),
    ]

    assert policy.choose_parent(population) == "snap-frontier"


def test_policy_mutate_is_deterministic_and_tracks_lineage():
    world = _seeded_world()
    policy = FrontierMutationPolicy()
    stats = PopulationStats(
        snapshot_id="snap-parent",
        world_id=world.world_id,
        split="train",
        episodes=10,
        red_win_rate=0.7,
        blue_win_rate=0.3,
        flake_rate=0.02,
        novelty=0.4,
        blue_signal_points=4,
    )

    child_a = policy.mutate(world, parent_stats=stats, child_seed=2026)
    child_b = policy.mutate(world, parent_stats=stats, child_seed=2026)

    assert child_a == child_b
    assert child_a.lineage.generation == world.lineage.generation + 1
    assert child_a.lineage.parent_world_id == world.world_id
    assert child_a.seed == 2026
    assert len(child_a.hosts) <= len(world.hosts) + world.mutation_bounds.max_new_hosts
    assert len(child_a.services) <= len(world.services) + world.mutation_bounds.max_new_services
    assert len(child_a.users) <= len(world.users) + world.mutation_bounds.max_new_users
    assert len(child_a.weaknesses) <= len(world.weaknesses) + world.mutation_bounds.max_new_weaknesses
    assert child_a.lineage.mutation_ops != world.lineage.mutation_ops


def test_mutated_child_is_admitted_and_can_live_in_eval_pool(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    parent_candidate = pipeline.build(_manifest_payload(), tmp_path / "parent-render")
    parent_snapshot = pipeline.admit(parent_candidate, split="train")

    policy = FrontierMutationPolicy()
    child_world = policy.mutate(
        parent_snapshot.world,
        parent_stats=PopulationStats(
            snapshot_id=parent_snapshot.snapshot_id,
            world_id=parent_snapshot.world.world_id,
            split="train",
            episodes=6,
            red_win_rate=0.55,
            blue_win_rate=0.45,
            flake_rate=0.01,
            novelty=0.7,
            blue_signal_points=4,
        ),
        child_seed=3030,
    )
    child_snapshot = pipeline.admit_child(child_world, tmp_path / "child-render", split="eval")

    assert child_snapshot.parent_world_id == parent_snapshot.world.world_id
    assert child_snapshot.validator_report.admitted is True
    assert len(store.list(split="train")) == 1
    assert len(store.list(split="eval")) == 1
    assert store.sample(split="eval", strategy="latest").snapshot_id == child_snapshot.snapshot_id


def test_propose_mutations_loads_best_parent_from_store(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    pipeline = BuildPipeline(store=store)
    parent_snapshot = pipeline.admit(pipeline.build(_manifest_payload(), tmp_path / "render"), split="train")

    children = propose_mutations(
        [
            PopulationStats(
                snapshot_id=parent_snapshot.snapshot_id,
                world_id=parent_snapshot.world.world_id,
                split="train",
                episodes=5,
                red_win_rate=0.5,
                blue_win_rate=0.5,
                flake_rate=0.0,
                novelty=0.5,
                blue_signal_points=4,
            )
        ],
        store=store,
    )

    assert len(children) == 1
    assert children[0].lineage.parent_world_id == parent_snapshot.world.world_id
