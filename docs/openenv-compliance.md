# OpenEnv Compliance Guide

OpenRange implements the OpenEnv 0.2.x environment contract. This doc maps every requirement.

## Checklist

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| `Environment` subclass | Done | `RangeEnvironment` extends `Environment[RangeAction, RangeObservation, RangeState]` |
| `reset()` returns `ObsT` | Done | Returns `RangeObservation` with episode briefing |
| `step()` returns `ObsT` | Done | Returns `RangeObservation` with stdout/stderr/reward/done |
| `state` property returns `StateT` | Done | Returns `RangeState` (episode_id, step_count, mode, flags_found, services_status, tier) |
| `Action` subclass (Pydantic, extra=forbid) | Done | `RangeAction(Action)` with `command: str`, `mode: Literal["red", "blue"]` |
| `Observation` subclass (Pydantic, extra=forbid) | Done | `RangeObservation(Observation)` — inherits `done`, `reward` from base; adds `stdout`, `stderr`, `flags_captured`, `alerts` |
| `State` subclass (Pydantic, extra=allow) | Done | `RangeState(State)` — inherits `episode_id`, `step_count` from base; adds `mode`, `flags_found`, `services_status`, `tier` |
| `create_app(Class, ActionType, ObsType)` | Done | `open_range.server.app:create_app()` delegates directly to `openenv.core.env_server.create_app(...)` |
| `EnvClient` subclass | Done | `OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState])` |
| `_step_payload()` | Done | Returns `{"command": action.command, "mode": action.mode}` |
| `_parse_result()` | Done | Parses server response to `StepResult[RangeObservation]` |
| `_parse_state()` | Done | Parses server response to `RangeState` |
| `/health` endpoint | Done | Provided by `create_app(...)` |
| `/metadata` endpoint | Done | Provided by `create_app(...)` |
| `/schema` endpoint | Done | Provided by `create_app(...)` |
| `/ws` WebSocket | Done | Provided by `create_app(...)` |
| `/reset`, `/step`, `/state` HTTP | Done | Provided by `create_app(...)` |
| `Rubric` for rewards | Done | `CompositeRedReward`, `CompositeBlueReward` (lazy-loaded in `RangeEnvironment._apply_rewards`) |
| `openenv.yaml` manifest | Done | Root `openenv.yaml` with `spec_version`, `type`, `runtime`, `app`, and `port` |
| `Dockerfile` | Done | Root `Dockerfile` launching `uvicorn open_range.server.app:app` |
| `python -m open_range.server` entry point | Done | `open_range.server.__main__` plus `openrange server` CLI command |

## Server Mode

The server entrypoint is the standard OpenEnv app factory:

- `open_range.server.app:create_app()` returns `create_app(RangeEnvironment, RangeAction, RangeObservation, env_name="open_range")`
- `server.app:app` is the repository-level wrapper referenced by `openenv.yaml`
- The OpenEnv-generated HTTP and WebSocket endpoints are the only public runtime contract

## Deployment

Two execution modes, same API:

- **Docker mode** (local dev): Server and range services in separate Docker Compose containers. Commands route via Docker SDK (`docker exec`).
- **Subprocess mode** (HF Spaces): All services run as background processes in a single container. Commands route via `subprocess.run()`. Set `OPENRANGE_EXECUTION_MODE=subprocess`.

`reset()` selects a pre-validated frozen snapshot from the snapshot store. No LLM calls in the hot path -- snapshot generation is asynchronous.

## Common Mistakes to Avoid

1. **Don't redeclare `done` or `reward` on Observation.** The base class already has them. `RangeObservation` correctly inherits them.
2. **Don't redeclare `episode_id` or `step_count` on State.** The base class already has them. `RangeState` correctly inherits them.
3. **Pass the CLASS or factory to `create_app()`, not an instance.** Each WebSocket session gets its own instance.
4. **Action uses `extra="forbid"` (via openenv base).** Unknown fields cause validation errors. Keep actions minimal.
5. **State uses `extra="allow"`.** You can add any fields you want.
6. **`reset()` returns ObsT (server-side), `StepResult[ObsT]` (client-side).** The server wraps it.
7. **Shared models live outside `server/`.** Clients import `open_range.models`, not `open_range.server.*`.

## API Signatures (Exact)

```python
# Server-side (src/open_range/server/environment.py)
class RangeEnvironment(Environment[RangeAction, RangeObservation, RangeState]):
    SUPPORTS_CONCURRENT_SESSIONS = False

    def __init__(self, runtime: ManagedSnapshotRuntime | None = None,
                 max_steps: int = 100, exec_timeout: float = 30.0,
                 docker_available: bool | None = None,
                 execution_mode: str = "auto") -> None: ...
    def reset(self, seed: int | None = None,
              episode_id: str | None = None, **kwargs) -> RangeObservation: ...
    def step(self, action: RangeAction,
             timeout_s: float | None = None, **kwargs) -> RangeObservation: ...
    @property
    def state(self) -> RangeState: ...

# Client-side (src/open_range/client/client.py)
class OpenRangeEnv(EnvClient[RangeAction, RangeObservation, RangeState]):
    def _step_payload(self, action: RangeAction) -> dict: ...
    def _parse_result(self, payload: dict) -> StepResult[RangeObservation]: ...
    def _parse_state(self, payload: dict) -> RangeState: ...

# App factory (src/open_range/server/app.py)
# Uses an env_factory closure with shared runtime, not the class directly:
def env_factory() -> RangeEnvironment:
    return RangeEnvironment(runtime=runtime)
app = create_openenv_app(env_factory, RangeAction, RangeObservation, env_name="open_range")

# Entry point
# uv run openrange server [--host HOST] [--port PORT]
```

## Reference Implementations

Study these OpenEnv environments as patterns:

- **`envs/coding_env/`** — closest analog (execute code, get stdout/stderr). Uses `Environment` base.
- **`envs/echo_env/`** — simplest possible environment. Uses `MCPEnvironment` base.
- **`envs/finqa_env/`** — MCP tool-based with complex rewards. Uses `MCPEnvironment` base.
