# Pack Author Guide: Build a Pack from Scratch

This guide walks you through creating an OpenRange pack from scratch.
We'll use a simple "Hello World" style example to illustrate each concept.

## What is a Pack?

A pack ships four components:

1. **Ontology** (`WorldSchema`): Node types, edge types, and constraints
2. **Realizer** (`Pack.realize(graph, manifest) -> RuntimeBundle`): Turns a graph into runnable artifacts
3. **Default Builder** (`Pack.default_builder(context) -> Builder`): Creates the world graph
4. **Optional**: Verifier helpers and runtime backings

## Step 1: Define the Ontology

The ontology describes the types of entities in your world and how they relate.

```python
from openrange import WorldSchema, NodeType, EdgeType, Constraint

schema = WorldSchema(
    node_types=[
        NodeType("service", properties={"port": int, "protocol": str}),
        NodeType("host", properties={"hostname": str, "os": str}),
        NodeType("vulnerability", properties={"severity": str, "cve": str}),
    ],
    edge_types=[
        EdgeType("runs_on", "service", "host"),
        EdgeType("has_vuln", "host", "vulnerability"),
        EdgeType("depends_on", "service", "service"),
    ],
    constraints=[
        Constraint("unique_port", "No two services on the same host share a port"),
    ],
)
```

**When do you need a constraint?**
Use constraints when you need to validate that a generated graph makes sense.
For example: "each host must have at least one service" or "no circular dependencies".

## Step 2: Write the Realizer

The realizer takes a validated graph and produces runtime artifacts (files, containers, etc.).

```python
from openrange import Pack, RuntimeBundle

class MyPack(Pack):
    def realize(self, graph, manifest):
        artifacts = {}
        
        for node in graph.nodes:
            if node.type == "service":
                # Generate Dockerfile for each service
                artifacts[f"services/{node.id}/Dockerfile"] = self._gen_dockerfile(node)
            elif node.type == "host":
                # Generate docker-compose entry
                artifacts[f"hosts/{node.id}/config.yml"] = self._gen_host_config(node)
        
        return RuntimeBundle(
            artifacts=artifacts,
            entrypoint="docker-compose up -d",
        )
```

**Choosing between codegen, file-copy, and container-image:**
- **Codegen**: Generate files dynamically based on graph properties
- **File-copy**: Ship static template files with your pack
- **Container-image**: Pre-build Docker images for complex services

## Step 3: Write the Default Builder

The builder creates a default world graph from a manifest.

```python
from openrange import Builder

class MyPack(Pack):
    def default_builder(self, context):
        builder = Builder()
        
        # Add a default host
        host = builder.add_node("host", hostname="target-01", os="ubuntu:22.04")
        
        # Add a web service
        web = builder.add_node("service", port=80, protocol="http")
        builder.add_edge("runs_on", web.id, host.id)
        
        # Add a vulnerability
        vuln = builder.add_node("vulnerability", severity="high", cve="CVE-2024-0001")
        builder.add_edge("has_vuln", host.id, vuln.id)
        
        return builder
```

## Step 4: Register Your Pack

Create a `pack.py` file in your pack directory:

```python
# src/openrange/packs/my_pack/pack.py
from openrange import Pack, WorldSchema, Builder, RuntimeBundle

class MyPack(Pack):
    name = "my_pack"
    version = "1.0.0"
    
    @property
    def schema(self):
        return WorldSchema(...)
    
    def realize(self, graph, manifest):
        ...
    
    def default_builder(self, context):
        ...
```

Then register it in your pack's `__init__.py`:

```python
from .pack import MyPack

__all__ = ["MyPack"]
```

## Directory Structure

```
src/openrange/packs/my_pack/
├── __init__.py
├── pack.py          # Main pack class
├── templates/       # Static templates (optional)
│   ├── Dockerfile.j2
│   └── service.conf.j2
└── README.md        # Pack documentation
```

## Testing Your Pack

1. Build a world: `OR.build("my_pack")`
2. Check the graph: Verify node/edge counts
3. Realize the world: Check generated artifacts
4. Run an agent: Verify the world is interactable

## Reference

See the cyber v1 pack at `src/openrange/packs/cyber_webapp_offense_v1/` for a complete real-world example.
