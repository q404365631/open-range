# Architecture

OpenRange is organized as a Python control plane with bundled assets.

## Layers

```text
strict manifest
  -> WorldIR compiler
  -> deterministic synth + weakness seeding
  -> Kind renderer
  -> deterministic admission + private witnesses
  -> immutable snapshot store
  -> explicit green/red/blue runtime
```

## Repo boundaries

- `src/open_range/`: supported importable code
- `manifests/`: checked-in example manifests for the strict public schema
- `schemas/`: generated JSON schemas
- `examples/`: runnable examples against the current package API
- `data/`, `scripts/`: repo-only operational or experimental material

## Runtime model

- one snapshot defines one admitted world
- `reset(snapshot_id, episode_config)` selects or loads a stored snapshot and binds runtime mode
- the env advances internal green activity until the next external decision point
- `next_decision()` exposes only externally controlled red/blue actors
- red and blue have separate observations and separate session state
- admission uses private witness traces rather than a public golden path

## Non-goals

- no compatibility layer for the deleted legacy builder/server/client stack
- no repo-level OpenEnv HTTP server wrapper
- no public answer-key semantics in manifests
