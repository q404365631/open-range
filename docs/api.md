# API
OpenRange does not provide a gymnasium-style `step / reset / observation / reward` loop. The domain is arbitrary, so the API the agent talks to is the world's own surface — HTTP, MCP, a shell, a file path, a simulator's step function. The Builder decides what that surface is, based on the manifest and what the pack provides.

What OpenRange provides is the lifecycle around that surface, inspired by [SkyRL-Agent](https://github.com/NovaSky-AI/SkyRL):

- **build** — the Builder produces an admitted world from manifest + pack. In a run, `OpenRangeRun` owns the dashboard event sink so pack loading, world generation, verification generation, admission, and snapshot creation are visible while the build runs. See [main doc](README.md).
- **snapshot** — the world is brought to a known initial state for an episode from the admitted snapshot artifacts. The pack is source context; the Builder and runtime decide what reset materializes.
- **get tasks** — the harness asks the world for the task instruction and entrypoints. See [What is a task](README.md#what-is-a-task).
- **run** — the agent acts through the entrypoints. OpenRange does not mediate the agent loop, but environment-owned runtimes can record public-interface evidence such as HTTP access logs and emit environment events for the dashboard. Episode termination is either agent stop (harness) or success event (world).
- **verify** — the verifier runs on the world's final state and returns a structured outcome. See [Reward](README.md#reward).
- **report** — outcome, lineage, final state, and environment-owned actor turns are available to the dashboard.

The harness owns the agent loop. OpenRange owns build, reset, success detection, verify, and report. There is no observation API and no reward API; the agent interacts with the task-specific surface materialized by the environment.
