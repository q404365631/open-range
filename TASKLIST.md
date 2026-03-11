# OpenRange Tasklist

This file tracks the branch-local rewrite against `spec_new.md`.

Rules:
- Do not edit `spec.md` or `spec_new.md`.
- Prefer deletion over compatibility shims when an older API conflicts with the current spec.
- Keep the branch runnable at the end of each completed phase.
- Check off only work that is implemented and verified.

## Phase 0 - Audit and freeze

- [x] Create standalone branch
- [x] Add tracked rewrite tasklist
- [x] Audit the inherited code against the earlier spec
- [x] Read and diff the new spec
- [x] Identify modules whose public contract now conflicts with `spec_new.md`

## Phase 1 - Freeze schemas

- [x] Keep strict manifest schema
- [x] Keep `WorldIR` as the canonical business graph
- [x] Keep `ValidatorReport` schema/model
- [x] Keep `WitnessBundle` schema/model
- [x] Add `BuildConfig`
- [x] Add `EpisodeConfig`
- [x] Add tests for config serialization and defaults

## Phase 2 - Fixed world family

- [x] Implement bounded `enterprise_saas_v1`
- [x] Keep manifest-first compilation into `WorldIR`
- [x] Keep deterministic weakness seeding
- [x] Thread `BuildConfig` through compiler decisions
- [x] Make enabled services/workflows/weakness families build-configurable

## Phase 3 - Live rendering and admission

- [x] Render live Kind artifacts from `WorldIR`
- [x] Generate private witness bundles
- [x] Keep deterministic static and live admission checks
- [x] Keep snapshot immutability
- [x] Change build/admission signatures to `build(manifest, build_config)` and `admit(candidate)`
- [x] Thread `BuildConfig` into admission strength and witness counts
- [x] Re-verify determinism under the new config surface

## Phase 4 - Runtime rewrite

- [x] Replace `tick + phase + observe()` with `sim_time + next_decision()`
- [x] Make green fully internal at runtime
- [x] Keep actor-specific observations
- [x] Enforce hard `done`
- [x] Preserve real blue terminal condition
- [x] Add `Decision`, `EpisodeHandle`, and updated `EpisodeState`
- [x] Support async scheduler mode
- [x] Keep strict-turn as an ablation via `EpisodeConfig`

## Phase 5 - Green rewrite

- [x] Change green scheduler contract to `reset(snapshot, episode_config)` and `advance_until(sim_time)`
- [x] Keep persona/workload snapshot state
- [x] Keep scripted routine traffic
- [x] Keep reactive branch hooks
- [x] Make green enablement/routine/branch/profile configurable from `EpisodeConfig`
- [x] Keep correct-origin traffic and typed events

## Phase 6 - Reward cleanup

- [x] Keep terminal-first, objective/event-grounded reward logic
- [x] Keep hallucination and false-positive penalties
- [x] Drop evidence and command-name patch rewards
- [x] Gate shaping through `EpisodeConfig`
- [x] Re-verify score and termination behavior under the new runtime API

## Phase 7 - Training/runtime modes

- [x] Support `red_only`
- [x] Support `blue_only_live`
- [x] Support `blue_only_from_prefix`
- [x] Support `joint_pool`
- [x] Add internal opponent controllers for non-external roles
- [x] Add prefix-start handling through `EpisodeConfig.start_state`

## Phase 8 - Package and surface cleanup

- [x] Delete remaining public APIs that expose `tick`, `phase`, `observe()`, or trainer-stepped green
- [x] Rewrite CLI, demo, driver, sim plane, and docs to the new contract
- [x] Rewrite runtime/service/integration tests to the new contract
- [x] Re-run the full suite

## Audit notes

Current status against `spec_new.md`:
- public runtime now exposes `reset(..., episode_config)`, `next_decision()`, `act(...)`, `state()`, and `score()`
- green is runtime-owned and no longer trainer-stepped
- `BuildConfig` and `EpisodeConfig` are part of the public package surface
- build/admission signatures now carry `BuildConfig`
- training modes and prefix-start semantics are represented explicitly in `EpisodeConfig`

Current keep list:
- manifest-first `enterprise_saas_v1`
- deterministic weakness seeding
- private witness-driven admission
- immutable snapshots
- live Kind backend
- objective/event-grounded rewards

Current drop list:
- explicit public `tick + phase` semantics
- trainer-stepped green actions
- stale API/documentation compatibility around the earlier runtime contract
