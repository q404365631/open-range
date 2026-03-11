# Data

Files under `data/` are repo-local training artifacts and references.

They are not part of the supported runtime package surface.

Current usage:

- `sft.jsonl`: seed supervised trajectories
- `synthetic*.jsonl`: generated or experimental datasets
- `tool_info.md`: prompt-side tool catalog material

The standalone branch currently ships the runtime, admission, and curriculum core first. Training data generation is experimental repo material, not a stable CLI/API contract.
