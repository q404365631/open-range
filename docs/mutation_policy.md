# Mutation Policy Weights

`PopulationMutationPolicy` is a hand-authored heuristic policy, but its
weights and shaping constants are now explicit in
`src/open_range/builder/mutation_policy.py` under `MutationPolicySettings`.

The policy has three jobs:

1. Choose which stored snapshot is the best parent to mutate next.
2. Choose which structural mutation op to apply.
3. Choose which security/noise mutation op to apply.

## Parent Selection Terms

These fields live in `MutationPolicySettings.parent`.

| Field | Default | Why it exists |
| --- | ---: | --- |
| `frontier_weight` | `0.28` | Prefer snapshots near the current learning frontier instead of trivially solved or impossible ones. |
| `replay_weight` | `0.18` | Revisit under-played snapshots so the curriculum does not collapse to a tiny subset. |
| `novelty_weight` | `0.16` | Favor rarer vulnerability mixes across the population. |
| `weak_overlap_weight` | `0.18` | Bias parent choice toward snapshots that exercise known weak areas. |
| `lineage_balance_weight` | `0.08` | Prevent one root lineage from dominating the pool. |
| `depth_balance_weight` | `0.04` | Avoid over-sampling very deep descendant chains. |
| `recency_weight` | `0.04` | Cool down parents that were used repeatedly in the recent window. |
| `complexity_weight` | `0.04` | Slightly prefer richer parents with more structure to mutate from. |

Shaping constants in the same model explain how those raw signals are formed:

| Field | Default | Meaning |
| --- | ---: | --- |
| `minimum_total` | `0.05` | Sampling floor for low-scoring parents. |
| `unplayed_frontier_score` | `0.40` | Frontier score used before any play stats exist. |
| `empty_vuln_novelty_score` | `0.25` | Novelty fallback for snapshots with no typed vulnerabilities. |
| `preferred_generation_depth` | `3.0` | Depth after which descendant chains start being penalized. |
| `complexity_vuln_factor` | `0.25` | Complexity contribution per vulnerability. |
| `complexity_golden_path_factor` | `0.03` | Complexity contribution per golden-path step. |
| `complexity_dependency_edge_factor` | `0.02` | Complexity contribution per dependency edge. |
| `complexity_trust_edge_factor` | `0.02` | Complexity contribution per trust edge. |
| `complexity_cap` | `1.0` | Cap for the normalized complexity score. |

## Mutation Selection Terms

These fields live in `MutationPolicySettings.mutation`.

| Field | Default | Why it exists |
| --- | ---: | --- |
| `curriculum_weight` | `0.38` | Prefer ops that target the agent's current weakness. |
| `novelty_weight` | `0.24` | Prefer ops that open new surfaces or vary episode shape. |
| `structural_gain_weight` | `0.28` | Prefer ops that materially expand the scenario graph. |
| `lineage_weight` | `0.10` | Slight bias toward shallower lineage when all else is equal. |
| `minimum_total` | `0.05` | Sampling floor for low-scoring mutation ops. |

Raw novelty bonuses in `MutationPolicySettings.novelty`:

| Field | Default | Meaning |
| --- | ---: | --- |
| `base_bonus` | `0.40` | Baseline novelty for every op. |
| `new_vuln_class_bonus` | `1.0` | Extra novelty for a vulnerability class not seen recently. |
| `new_noise_surface_bonus` | `0.50` | Extra novelty for noise on a new attack surface. |
| `structural_op_bonus` | `0.40` | Extra novelty for non-security ops that change the graph. |

Raw curriculum bonuses in `MutationPolicySettings.curriculum`:

| Field | Default | Meaning |
| --- | ---: | --- |
| `base_bonus` | `0.35` | Baseline curriculum value for every op. |
| `weak_area_bonus` | `1.50` | Reward seeding a vulnerability in a known weak area. |
| `new_vuln_bonus` | `0.40` | Reward introducing a vulnerability class not present in the parent. |
| `chain_length_bonus` | `0.60` | Reward edges that help satisfy multi-hop chain requirements. |
| `focus_identity_bonus` | `0.50` | Reward identity-layer ops when curriculum focus is identity. |
| `focus_infra_bonus` | `0.50` | Reward infra-layer ops when curriculum focus is infra. |
| `focus_process_bonus` | `0.40` | Reward benign noise when focus is process realism. |

## Structural Gain Table

These fields live in `MutationPolicySettings.structural_gains`.

| Op Type | Default |
| --- | ---: |
| `add_service` | `1.00` |
| `add_dependency_edge` | `0.90` |
| `add_trust_edge` | `0.85` |
| `add_user` | `0.80` |
| `seed_vuln` | `0.70` |
| `add_benign_noise` | `0.30` |
| `default_gain` | `0.20` |

## Tuning Path

You can swap weights without touching policy code:

1. Write a JSON or YAML file matching `MutationPolicySettings`.
2. Load it with `load_mutation_policy_settings(path)` or pass it into `PopulationMutationPolicy(settings=...)`.
3. Compare it against the default policy with:

```bash
PYTHONPATH=src .venv/bin/python scripts/calibrate_mutation_policy.py \
  --store-dir snapshots \
  --stats path/to/snapshot_stats.json \
  --context path/to/build_context.json \
  --settings tuned=path/to/policy_settings.yaml
```

The calibration output is JSON so it can be diffed, archived, or fed into
notebooks. Parent-selection logs and `MutationPlan.score_breakdown` now expose
weighted contributions instead of only raw feature values.
