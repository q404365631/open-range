"""Tests for population-guided mutation selection policy."""

import random

from open_range.builder.mutation_policy import PopulationMutationPolicy
from open_range.protocols import BuildContext, MutationOp


def test_policy_selects_structural_and_security_when_both_available(sample_snapshot_spec):
    policy = PopulationMutationPolicy()
    structural = [
        MutationOp(
            mutation_id="add_service_web",
            op_type="add_service",
            target_selector={"host": "web"},
            params={"service": "redis"},
        )
    ]
    security = [
        MutationOp(
            mutation_id="seed_sqli",
            op_type="seed_vuln",
            target_selector={"host": "web"},
            params={"vuln_type": "sqli"},
        ),
        MutationOp(
            mutation_id="noise1",
            op_type="add_benign_noise",
            target_selector={"location": "siem:noise.log"},
            params={"location": "siem:noise.log"},
        ),
    ]

    ops, _score, _breakdown = policy.choose_mutations(
        structural_candidates=structural,
        security_candidates=security,
        snapshot=sample_snapshot_spec,
        context=BuildContext(seed=1, tier=1),
        rng=random.Random(7),
    )

    op_types = {op.op_type for op in ops}
    assert "add_service" in op_types
    assert op_types.intersection({"seed_vuln", "add_benign_noise"})


def test_policy_best_effort_when_only_security_available(sample_snapshot_spec):
    policy = PopulationMutationPolicy()
    security = [
        MutationOp(
            mutation_id="seed_sqli",
            op_type="seed_vuln",
            target_selector={"host": "web"},
            params={"vuln_type": "sqli"},
        ),
        MutationOp(
            mutation_id="noise1",
            op_type="add_benign_noise",
            target_selector={"location": "siem:noise.log"},
            params={"location": "siem:noise.log"},
        ),
    ]

    ops, _score, _breakdown = policy.choose_mutations(
        structural_candidates=[],
        security_candidates=security,
        snapshot=sample_snapshot_spec,
        context=BuildContext(seed=1, tier=1),
        rng=random.Random(11),
    )

    assert len(ops) == 1
    assert ops[0].op_type in {"seed_vuln", "add_benign_noise"}


def test_policy_best_effort_when_only_structural_available(sample_snapshot_spec):
    policy = PopulationMutationPolicy()
    structural = [
        MutationOp(
            mutation_id="add_trust_edge_1",
            op_type="add_trust_edge",
            target_selector={"source": "alice", "target": "bob"},
            params={"type": "delegation"},
        ),
        MutationOp(
            mutation_id="add_dep_1",
            op_type="add_dependency_edge",
            target_selector={"source": "web", "target": "db"},
            params={},
        ),
    ]

    ops, _score, _breakdown = policy.choose_mutations(
        structural_candidates=structural,
        security_candidates=[],
        snapshot=sample_snapshot_spec,
        context=BuildContext(seed=1, tier=1),
        rng=random.Random(21),
    )

    assert len(ops) == 1
    assert ops[0].op_type in {"add_trust_edge", "add_dependency_edge"}
