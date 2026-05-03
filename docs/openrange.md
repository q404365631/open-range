# OpenRange

> [!WARNING]
> This document describes the direction OpenRange is working toward. It does not necessarily reflect the current implementation.

OpenRange is a domain-agnostic environment platform for training and evaluating agents.

The core idea is simple: bring your own agent harness, and run it against generated worlds with a stable episode lifecycle. OpenRange owns world construction, task admission, runtime coordination, episode checking, and observability. It does not own the model, agent framework, tool harness, training loop, or reward policy.

This document is a high-level overview. Specific contracts should live in separate docs.

## What OpenRange does

OpenRange turns a user request into an admitted world that an agent can act inside.

```text
manifest + pack + builder
        ↓
world graph + runtime artifacts + tasks
        ↓
feasibility checks / admission
        ↓
frozen world snapshot
        ↓
agent episode
        ↓
structured result
```

The goal is not to force every domain into one Gym-style API. The goal is to let different worlds — cyber ranges, trading environments, robotics tasks, enterprise simulations — fit into the same build, admission, runtime, and evaluation flow.

The agent interacts with whatever surface the world exposes: HTTP endpoints, files, shells, MCP tools, simulator APIs, browser sessions, or custom interfaces.

## Core objects

### Manifest

The manifest describes what the user wants built.

It is the request layer: domain, scenario, constraints, task families, scale, target interfaces, and runtime backing. It may also include instructions for how the world should change over time, such as making tasks harder, targeting failure cases, or increasing diversity.

See [manifest.md](manifest.md).

### Pack

A pack is the reusable starting point for a family of worlds.

It can include code, containers, templates, simulator bindings, scripted state machines, seed data, ontology/topology schemas, verifier helpers, and builder hooks. A pack does not describe one final world. It describes what kinds of worlds can be built and how those worlds can be realized.

Examples:

```text
cyber.webapp.offense
cyber.webapp.defense
finance.trading
robotics.pendulum
```

See [pack.md](pack.md).

### Builder

The builder turns a manifest and a pack into a concrete world.

A builder may be handwritten Python, procedural generation, an LLM pipeline, search/sampling, a domain-specific generator, or a hybrid. OpenRange should not require the builder to be an LLM.

The builder outputs:

```text
world graph
runtime artifacts
tasks
feasibility checks
episode checks
admission metadata
```

See [builder.md](builder.md).

### World

A world is the concrete environment the agent interacts with.

It contains the entities, topology, runtime components, entrypoints, hidden state, NPCs, and task-specific success conditions needed for an episode.

See [world.md](world.md).

### Task

A task is what the agent is asked to do inside an admitted world.

A task has three main parts:

```text
instruction   - what the agent sees
entrypoints   - where the agent acts
success check - how OpenRange checks the final episode state
```

The entrypoint is domain-specific. It could be an HTTP endpoint, shell, file path, MCP server, simulator step function, or something else. OpenRange does not standardize the agent’s tool interface.

See [tasks.md](tasks.md).

## World graph

OpenRange represents each generated world as a graph before turning it into runnable artifacts.

The graph answers two questions:

```text
What exists?
How is it connected?
```

For a cyber world, the graph might contain things like:

```text
host.web01
service.api
endpoint.login
db.main
user.admin
cred.admin_token
vuln.sqli_login
```

And connections like:

```text
service.api runs on host.web01
service.api exposes endpoint.login
service.api connects to db.main
endpoint.login has vuln.sqli_login
user.admin owns cred.admin_token
```

The graph is useful because it gives OpenRange a stable intermediate representation of the world. The builder can generate it, admission can check it, the runtime can realize it, and the dashboard can inspect it. Without this layer, every pack would have to invent its own private format for describing what was built.

The world graph is not the runtime. It is the build plan OpenRange uses to produce the runtime.

See [world-ir.md](world-ir.md).

## Build and admission

World generation is a multi-step pipeline.

A typical build flow is:

```text
1. Read manifest
2. Load pack
3. Generate or update world graph
4. Realize runtime artifacts
5. Generate tasks
6. Generate feasibility checks
7. Run admission
8. Repair or regenerate failed pieces
9. Freeze admitted world snapshot
```

A feasibility check verifies that a generated task is actually possible in the generated world. For LLM-backed builders, this may itself be a generated Python script.

If a feasibility check fails, the result feeds back to the builder. The builder may repair the task, the feasibility check, the world graph, or the runtime artifacts.

Admission is complete only when the task is well-formed, possible, and tied to a frozen world snapshot.

See [admission.md](admission.md).

## Runtime backing

A world can be backed by real systems, synthetic systems, or a mix.

A **real backing** runs the actual thing or a close stand-in:

```text
real container
real web service
real binary
real shell
sandboxed broker API
MuJoCo simulator
```

A **synthetic backing** imitates the thing with cheaper code:

```text
Python state machine
scripted fake service
in-memory order book
symbolic network state
mock endpoint backed by generated state
```

A **hybrid backing** combines both. For example, a trading world might expose a broker-like HTTP API, but the API is backed by a Python state machine instead of a real broker. A cyber world might run the vulnerable web app as a real container, but simulate background employees and external systems.

The manifest can request the desired backing. The pack decides what it can support.

See [runtime.md](runtime.md).

## NPCs and multi-actor worlds

A world can include non-player characters: scripted actors, LLM-driven personas, other agents, background users, defenders, attackers, counterparties, or external systems.

NPCs live inside the world runtime. Their actions can affect the state the agent observes and the final state the episode check inspects.

Examples:

```text
a defender rotating credentials
a user responding to phishing email
a trading counterparty placing orders
a human-like persona answering questions
a background process writing logs
```

See [npcs.md](npcs.md).

## Episode checks and rewards

OpenRange checks what happened. It does not define the training reward.

After an episode, an episode check inspects the final world state, agent-written outputs, or declared success events. It returns a structured result.

Examples:

```json
{"success": true}
```

```json
{"success": false, "reason": "admin credential was not recovered"}
```

```json
{"success": true, "subgoals": {"found_login": true, "exploited_sqli": true, "exfiltrated_secret": true}}
```

A training adapter can map this result into scalar rewards, dense rewards, preference data, SFT traces, GRPO/PPO signals, or evaluation metrics.

See [verifiers.md](verifiers.md) and [rewards.md](rewards.md).

## World evolution

OpenRange does not define a curriculum algorithm.

Instead, builders may expose an `evolve` operation. Evolution takes structured feedback from previous episodes and proposes new world edits or tasks.

Example inputs:

```text
task success rates
subgoal completion rates
failure clusters
coverage gaps
requested difficulty change
specific failure mode to target
```

Proposed edits go through the same admission gate as the initial build. A task is never accepted just because the builder generated it.

See [evolution.md](evolution.md).

## Observability and lineage

Every admitted world should be inspectable and reproducible.

OpenRange tracks:

```text
manifest
pack version
builder passes
world graph
runtime artifacts
tasks
feasibility-check results
episode-check results
runtime events
evolution lineage
```

The dashboard should make it possible to inspect what was generated, why a task was admitted or rejected, which world snapshot an episode used, and how the world changed over time.

See [dashboard.md](dashboard.md).

## Design boundaries

OpenRange owns:

```text
world construction
pack contracts
builder interface
admission
runtime coordination
task feasibility checks
episode checks
structured results
world lineage
observability
```

OpenRange does not own:

```text
the agent implementation
the model
the tool harness
the training algorithm
reward shaping policy
rollout infrastructure
```

This boundary is intentional. It lets OpenRange support many domains and training setups without becoming a full agent framework.
