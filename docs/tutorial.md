# Tutorial: From `uv sync` to a Working v1 Cyber Eval

This tutorial walks you from a fresh clone to a running cyber evaluation
in about 15 minutes. By the end, you'll have:

1. Built a world with the v1 cyber pack
2. Run an agent against it
3. Walked through a curriculum

## Prerequisites

- Python 3.11+
- `uv` package manager
- Docker (for running cyber ranges)

## Milestone 1: Build a World

```bash
# Clone and install
git clone https://github.com/vecna-labs/open-range.git
cd open-range
uv sync

# Build a world with the v1 cyber pack
python -c "
from openrange import OR
result = OR.build('cyber_webapp_offense_v1')
print(f'World built: {result.world_id}')
print(f'Nodes: {result.graph.node_count}')
print(f'Edges: {result.graph.edge_count}')
print(f'Services: {result.graph.count_nodes("service")}')
print(f'Vulns: {result.graph.count_nodes("vulnerability")}')
"
```

Expected output:
```
World built: world-abc123
Nodes: 15
Edges: 22
Services: 3
Vulns: 5
```

## Milestone 2: Run an Agent

### Option A: With Codex (requires API key)

```bash
export OPENAI_API_KEY=sk-...
python examples/codex_eval.py --world-id world-abc123
```

### Option B: Scripted Agent (no API key needed)

```bash
python -c "
from openrange import OR

# Load the world
world = OR.load('world-abc123')

# Get the entrypoint
entrypoint = world.runtime.entrypoint
print(f'Entrypoint: {entrypoint}')

# Simple scripted agent: hit the public route
import requests
response = requests.get(f'http://localhost:8080/')
print(f'Status: {response.status_code}')
print(f'Body: {response.text[:200]}')

# Submit the flag
flag = 'FLAG{example_flag}'
result = world.submit(flag)
print(f'Submission result: {result}')
"
```

### Option C: With Strands

```bash
export ANTHROPIC_API_KEY=sk-...
python examples/strands_eval.py --world-id world-abc123
```

## Milestone 3: Walk the Curriculum

A curriculum defines a sequence of worlds that increase in difficulty.

```python
from openrange import OR

curriculum = {
    "patch": ["sql_injection", "xss", "command_injection"],
}

# Evolve a snapshot through the curriculum
snapshot = OR.build("cyber_webapp_offense_v1")
for vuln_type in curriculum["patch"]:
    print(f"\n=== Patching: {vuln_type} ===")
    evolved = OR.evolve(snapshot, curriculum={"patch": [vuln_type]})
    print(f"Remaining vulns: {evolved.graph.count_nodes('vulnerability')}")
    snapshot = evolved

print("\nAll vulnerabilities patched!")
```

## Next Steps

- Read the [Pack Author Guide](docs/pack-author-guide.md) to create your own packs
- Explore the [API docs](docs/api.md) for advanced usage
- Check the [Dashboard docs](docs/dashboard.md) for visualization
