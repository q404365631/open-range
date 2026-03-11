# OpenRange

OpenRange is a manifest-first red/blue/green cyber range packaged as an installable Python control plane.

The supported surface is:

- strict public manifests for the bounded `enterprise_saas_v1` family
- a Python build/admit/store/runtime API under [`src/open_range`](/home/talian/priv/open-range/src/open_range)
- a small CLI exposed as `openrange`
- packaged chart assets, schemas, docs, and manifest examples

The legacy OpenEnv server/client stack and public golden-path model are not part of the current package surface.

## Package shape

```text
src/open_range/      importable runtime, compiler, renderer, admission, store
manifests/           checked-in strict manifest examples
schemas/             generated JSON schemas
examples/            small runnable demos against the current API
data/                repo-only training artifacts
docs/                current package documentation
```

## Installation

```bash
pip install .
openrange --help
openrange-demo
```

## Current pipeline

```text
manifest
  -> validate_manifest
  -> ManifestCompiler
  -> WorldSynthesizer
  -> WeaknessSeeder
  -> KindRenderer
  -> AdmissionController
  -> SnapshotStore
  -> OpenRange runtime
```

## What is implemented

- strict manifest, `WorldIR`, `WitnessBundle`, and `ValidatorReport` models
- deterministic `enterprise_saas_v1` compiler
- deterministic bounded synthesis for seeded business artifacts
- deterministic weakness seeding from an allowed-family catalog
- Kind renderer with service payloads, firewall rules, and red/blue/green sandboxes
- deterministic admission with optional live Kind checks
- immutable snapshot store with train/eval splits
- simulated-time runtime with `EpisodeConfig`, actor-specific observations, and `next_decision()`
- live pod execution bridge and typed event flow
- deterministic curriculum and tandem episode driver
- checked-in manifest examples that validate and compile against the rewritten package

## Current gaps

- there is no production OpenEnv HTTP/WebSocket layer on this branch
- live remediation is still bounded marker-based, not richer service-native patching
- live shortcut probes are bounded and port-oriented
- green reactive behavior is deterministic and bounded, not policy-rich

## CLI

```bash
openrange build  -m manifests/tier1_basic.yaml -o /tmp/openrange-build
openrange admit  -m manifests/tier1_basic.yaml -o /tmp/openrange-build --store-dir snapshots
openrange reset  --store-dir snapshots --sample-seed 7 --mode joint_pool
```

## Python usage

```python
from open_range import BuildPipeline, EpisodeConfig, OpenRange, load_bundled_manifest

pipeline = BuildPipeline()
candidate = pipeline.build(load_bundled_manifest("tier1_basic.yaml"), "/tmp/openrange-build")
snapshot = pipeline.admit(candidate)

service = OpenRange()
state = service.reset(snapshot.snapshot_id, EpisodeConfig(mode="joint_pool"))
decision = service.next_decision()
```

## Demo

```bash
PYTHONPATH=src .venv/bin/python examples/demo.py --manifest manifests/tier1_basic.yaml
PYTHONPATH=src .venv/bin/python -m open_range.examples.demo
openrange-demo
```

## Container image

The root [Dockerfile](/home/talian/priv/open-range/Dockerfile) now builds a CLI image for the standalone package:

```bash
docker build -t openrange .
docker run --rm openrange --help
```

## Verification

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests -q
```
