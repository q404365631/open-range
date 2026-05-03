"""Dashboard inspection helpers for admitted snapshots."""

from __future__ import annotations

import asyncio
import json
import queue
import threading
from collections import deque
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import MappingProxyType
from typing import cast
from urllib.parse import urlsplit

from openrange.core import ActorTurn, Snapshot
from openrange.core.snapshot import json_safe


@dataclass(frozen=True, slots=True)
class DashboardEvent:
    id: str
    type: str
    actor: str
    target: str
    time: float
    data: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "actor": self.actor,
            "target": self.target,
            "time": self.time,
            "data": dict(self.data),
        }


class EventBridge:
    def __init__(self, *, max_buffer: int = 200) -> None:
        if max_buffer <= 0:
            raise ValueError("max_buffer must be positive")
        self._events: deque[DashboardEvent] = deque(maxlen=max_buffer)
        self._lock = threading.Lock()
        self._subscribers: list[
            tuple[asyncio.Queue[DashboardEvent | None], asyncio.AbstractEventLoop]
        ] = []
        self._sync_subscribers: list[queue.SimpleQueue[DashboardEvent | None]] = []

    def push(self, event: DashboardEvent) -> None:
        with self._lock:
            self._events.append(event)
            subscribers = tuple(self._subscribers)
            sync_subscribers = tuple(self._sync_subscribers)
        for event_queue, loop in subscribers:
            loop.call_soon_threadsafe(event_queue.put_nowait, event)
        for sync_queue in sync_subscribers:
            sync_queue.put(event)

    def snapshot_buffer(self) -> tuple[DashboardEvent, ...]:
        with self._lock:
            return tuple(self._events)

    async def subscribe(self) -> AsyncIterator[DashboardEvent]:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[DashboardEvent | None] = asyncio.Queue(maxsize=500)
        with self._lock:
            backlog = tuple(self._events)
            self._subscribers.append((queue, loop))
        try:
            for event in backlog:
                yield event
            while True:
                queued = await queue.get()
                if queued is None:
                    return
                yield queued
        finally:
            with self._lock:
                self._subscribers = [
                    (candidate, candidate_loop)
                    for candidate, candidate_loop in self._subscribers
                    if candidate is not queue
                ]

    def subscribe_sync(self) -> Iterator[DashboardEvent]:
        event_queue: queue.SimpleQueue[DashboardEvent | None] = queue.SimpleQueue()
        with self._lock:
            backlog = tuple(self._events)
            self._sync_subscribers.append(event_queue)
        try:
            yield from backlog
            while True:
                event = event_queue.get()
                if event is None:
                    return
                yield event
        finally:
            with self._lock:
                self._sync_subscribers = [
                    candidate
                    for candidate in self._sync_subscribers
                    if candidate is not event_queue
                ]

    def close(self) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers)
            sync_subscribers = tuple(self._sync_subscribers)
        for event_queue, loop in subscribers:
            loop.call_soon_threadsafe(event_queue.put_nowait, None)
        for sync_queue in sync_subscribers:
            sync_queue.put(None)


class DashboardArtifactLog:
    def __init__(
        self,
        event_log_path: str | Path,
        state_path: str | Path,
        *,
        reset: bool = False,
    ) -> None:
        self.event_log_path = Path(event_log_path)
        self.state_path = Path(state_path)
        self.event_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if reset or not self.event_log_path.exists():
            self.event_log_path.write_text("", encoding="utf-8")
        self._lock = threading.Lock()
        self._event_count = len(self.events())
        self.write_state()

    def record_event(
        self,
        event_type: str,
        *,
        actor: str,
        target: str,
        data: Mapping[str, object] | None = None,
    ) -> DashboardEvent:
        with self._lock:
            self._event_count += 1
            event = DashboardEvent(
                f"{self._event_count}:{event_type}",
                event_type,
                actor,
                target,
                float(self._event_count - 1),
                MappingProxyType(dict(data or {})),
            )
            with self.event_log_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(json_safe(event.as_dict()), sort_keys=True) + "\n",
                )
            self.write_state()
            return event

    def record_builder_step(
        self,
        step: str,
        data: Mapping[str, object] | None = None,
    ) -> DashboardEvent:
        return self.record_event(
            "builder_step",
            actor="builder",
            target="snapshot",
            data={**dict(data or {}), "step": step},
        )

    def events(self) -> tuple[DashboardEvent, ...]:
        return tuple(read_dashboard_events(self.event_log_path))

    def write_state(self) -> None:
        write_dashboard_state(self.state_path, self.events(), snapshot=None)


class DashboardView:
    def __init__(
        self,
        snapshot: Snapshot | None = None,
        *,
        bridge: EventBridge | None = None,
        event_log_path: str | Path | None = None,
        state_path: str | Path | None = None,
        reset_artifacts: bool = True,
    ) -> None:
        self.snapshot = snapshot
        self.bridge = bridge or EventBridge()
        self._running = False
        self._lock = threading.Lock()
        self._event_log_path = (
            None if event_log_path is None else Path(event_log_path)
        )
        self._state_path = None if state_path is None else Path(state_path)
        self._stored_dashboard = (
            {}
            if self._state_path is None or reset_artifacts
            else read_dashboard_state(self._state_path)
        )
        if self._event_log_path is not None:
            self._event_log_path.parent.mkdir(parents=True, exist_ok=True)
            if reset_artifacts or not self._event_log_path.exists():
                self._event_log_path.write_text("", encoding="utf-8")
            else:
                for event in read_dashboard_events(self._event_log_path):
                    self.bridge.push(event)
        self._event_count = len(self.bridge.snapshot_buffer())
        if self._state_path is not None:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_state(self._state_path)

    def topology(self) -> Mapping[str, object]:
        if self.snapshot is None:
            stored = self._stored_section("topology")
            if stored:
                return stored
            return {
                "snapshot_id": None,
                "world": {},
                "tasks": [],
                "artifact_paths": [],
                **empty_runtime_topology(),
            }
        runtime_topology = normalized_runtime_topology(self.snapshot)
        return {
            "snapshot_id": self.snapshot.id,
            "world": public_world(self.snapshot.world),
            "tasks": [task.as_dict() for task in self.snapshot.tasks],
            "artifact_paths": sorted(self.snapshot.artifacts),
            **runtime_topology,
        }

    def lineage(self) -> Mapping[str, object]:
        if self.snapshot is None:
            stored = self._stored_section("lineage")
            if stored:
                return stored
            return {
                "snapshot_id": None,
                "admission": None,
                "nodes": [],
            }
        return {
            "snapshot_id": self.snapshot.id,
            "admission": self.snapshot.admission.as_dict(),
            "nodes": [node.as_dict() for node in self.snapshot.lineage],
        }

    def state(self) -> Mapping[str, object]:
        events = [event.as_dict() for event in self.bridge.snapshot_buffer()]
        turn_count = sum(1 for event in events if event["type"] == "env_turn")
        return {
            "running": self._running,
            "status": self._status(),
            "snapshot_id": self._snapshot_id(),
            "event_count": len(events),
            "turn_count": turn_count,
            "latest_event": None if not events else events[-1],
            "activity_summary": activity_summary(events),
            "health": health_summary(events),
            "events": events,
        }

    def _status(self) -> str:
        if self.snapshot is None and self._snapshot_id() is None:
            return "waiting_for_snapshot"
        if self._running:
            return "playing"
        return "paused"

    def reset(self, snapshot: Snapshot | None = None) -> Mapping[str, object]:
        if snapshot is not None:
            self.snapshot = snapshot
        self._running = False
        if self.snapshot is None:
            result = {
                "status": "waiting_for_snapshot",
                "snapshot_id": None,
                "topology": self.topology(),
            }
        else:
            result = {
                "status": "ready",
                "snapshot_id": self.snapshot.id,
                "topology": self.topology(),
            }
        self._write_configured_state()
        return result

    def play(self) -> Mapping[str, object]:
        if self._running:
            return {"status": "already running"}
        self._running = True
        self._write_configured_state()
        return {"status": "playing"}

    def pause(self) -> Mapping[str, object]:
        self._running = False
        self._write_configured_state()
        return {"status": "paused"}

    def record_event(
        self,
        event_type: str,
        *,
        actor: str,
        target: str,
        data: Mapping[str, object] | None = None,
    ) -> DashboardEvent:
        with self._lock:
            self._event_count += 1
            event = DashboardEvent(
                f"{self._event_count}:{event_type}",
                event_type,
                actor,
                target,
                float(self._event_count - 1),
                MappingProxyType(dict(data or {})),
            )
            self.bridge.push(event)
            self._write_event(event)
        return event

    def record_turn(self, turn: ActorTurn) -> DashboardEvent:
        return self.record_event(
            "env_turn",
            actor=turn.actor_id,
            target=turn.target,
            data=turn.as_dict(),
        )

    def turns(self, task_id: str | None = None) -> list[dict[str, object]]:
        turns = [
            dict(event.data)
            for event in self.bridge.snapshot_buffer()
            if event.type == "env_turn"
        ]
        if task_id is None:
            return turns
        return [turn for turn in turns if turn.get("task_id") == task_id]

    def builder_steps(self) -> list[dict[str, object]]:
        return [
            dict(event.data)
            for event in self.bridge.snapshot_buffer()
            if event.type == "builder_step"
        ]

    def inspect(self) -> Mapping[str, object]:
        return {
            "briefing": self.briefing(),
            "topology": self.topology(),
            "lineage": self.lineage(),
            "state": self.state(),
            "actors": self.actors(),
            "turns": self.turns(),
            "builder": {"steps": self.builder_steps()},
            "narration": self.narration(),
        }

    def actors(self) -> list[dict[str, object]]:
        return actor_summaries(
            [event.as_dict() for event in self.bridge.snapshot_buffer()],
        )

    def briefing(self) -> Mapping[str, object]:
        if self.snapshot is None:
            topology = self.topology()
            snapshot_id = topology.get("snapshot_id")
            world = topology.get("world")
            tasks = topology.get("tasks")
            if isinstance(snapshot_id, str) and isinstance(world, Mapping):
                task_rows = tasks if isinstance(tasks, list) else []
                return {
                    "snapshot_id": snapshot_id,
                    "title": str(world.get("title", "")),
                    "goal": str(world.get("goal", "")),
                    "entrypoints": stored_entrypoints(task_rows),
                    "missions": stored_missions(task_rows),
                }
            return {
                "snapshot_id": None,
                "title": "",
                "goal": "",
                "entrypoints": [],
                "missions": [],
            }
        return {
            "snapshot_id": self.snapshot.id,
            "title": str(self.snapshot.world.get("title", "")),
            "goal": str(self.snapshot.world.get("goal", "")),
            "entrypoints": [
                {
                    "task_id": task.id,
                    "kind": entrypoint.kind,
                    "target": entrypoint.target,
                }
                for task in self.snapshot.tasks
                for entrypoint in task.entrypoints
            ],
            "missions": [
                {"task_id": task.id, "instruction": task.instruction}
                for task in self.snapshot.tasks
            ],
        }

    def narration(self) -> Mapping[str, object]:
        return {"narration": fallback_narrate(self.bridge.snapshot_buffer())}

    def _write_event(self, event: DashboardEvent) -> None:
        if self._event_log_path is not None:
            with self._event_log_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(json_safe(event.as_dict()), sort_keys=True) + "\n",
                )
        self._write_configured_state()

    def _write_configured_state(self) -> None:
        if self._state_path is not None:
            self._write_state(self._state_path)

    def _write_state(self, state_path: Path) -> None:
        write_dashboard_state(state_path, self.bridge.snapshot_buffer(), self)

    def _stored_section(self, key: str) -> Mapping[str, object]:
        section = self._stored_dashboard.get(key)
        if isinstance(section, Mapping):
            return section
        return {}

    def _snapshot_id(self) -> str | None:
        if self.snapshot is not None:
            return self.snapshot.id
        topology = self._stored_section("topology")
        snapshot_id = topology.get("snapshot_id")
        return snapshot_id if isinstance(snapshot_id, str) else None


def activity_summary(events: Sequence[Mapping[str, object]]) -> Mapping[str, object]:
    event_types: dict[str, int] = {}
    actors: dict[str, int] = {}
    actor_kinds: dict[str, int] = {}
    for event in events:
        increment(event_types, str(event.get("type", "")))
        increment(actors, str(event.get("actor", "")))
        data = event.get("data")
        actor_kind = "event"
        if isinstance(data, Mapping):
            actor_kind = str(data.get("actor_kind", actor_kind))
        increment(actor_kinds, actor_kind)
    return {
        "event_types": event_types,
        "actors": actors,
        "actor_kinds": actor_kinds,
    }


def actor_summaries(events: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    summaries: dict[str, dict[str, object]] = {}
    counts_by_actor: dict[str, int] = {}
    targets_by_actor: dict[str, set[str]] = {}
    history_by_actor: dict[str, list[dict[str, object]]] = {}
    for event in events:
        actor = str(event.get("actor", ""))
        summary = summaries.setdefault(
            actor,
            {
                "actor_id": actor,
                "actor_kind": "event",
                "event_count": 0,
                "targets": [],
                "latest_event_type": "",
                "latest_action": None,
                "latest_observation": None,
                "history": [],
            },
        )
        counts_by_actor[actor] = counts_by_actor.get(actor, 0) + 1
        summary["event_count"] = counts_by_actor[actor]
        event_type = str(event.get("type", ""))
        target = str(event.get("target", ""))
        targets_by_actor.setdefault(actor, set()).add(target)
        data = event.get("data")
        actor_kind = "event"
        action: object = None
        observation: object = None
        if isinstance(data, Mapping):
            actor_kind = str(data.get("actor_kind", actor_kind))
            action = data.get("action")
            observation = data.get("observation")
        summary["actor_kind"] = actor_kind
        summary["latest_event_type"] = event_type
        summary["latest_action"] = action
        summary["latest_observation"] = observation
        history_by_actor.setdefault(actor, []).append(
            {
                "event_type": event_type,
                "target": target,
                "action": action,
                "observation": observation,
            },
        )
    return [
        actor_summary(
            summaries[actor],
            targets_by_actor[actor],
            history_by_actor[actor],
        )
        for actor in sorted(summaries)
    ]


def actor_summary(
    summary: Mapping[str, object],
    targets: set[str],
    history: list[dict[str, object]],
) -> dict[str, object]:
    return {
        **dict(summary),
        "targets": sorted(targets),
        "history": history[-10:],
    }


def increment(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def empty_runtime_topology() -> dict[str, object]:
    return {
        "services": [],
        "edges": [],
        "zones": [],
        "users": [],
        "green_personas": [],
    }


def normalized_runtime_topology(snapshot: Snapshot) -> dict[str, object]:
    raw = embedded_topology(snapshot)
    services = normalized_rows(raw.get("services"))
    known_services = {str(service.get("id", "")) for service in services}

    world_service = snapshot.world.get("service")
    if isinstance(world_service, str) and world_service not in known_services:
        services.append(
            {
                "id": world_service,
                "kind": "service",
                "zone": "episode",
                "ports": [],
            },
        )
        known_services.add(world_service)

    for task in snapshot.tasks:
        for entrypoint in task.entrypoints:
            if entrypoint.target in known_services:
                continue
            services.append(
                {
                    "id": entrypoint.target,
                    "kind": entrypoint.kind,
                    "zone": "episode",
                    "ports": [],
                },
            )
            known_services.add(entrypoint.target)

    zones = normalized_strings(raw.get("zones"))
    service_zones = sorted(
        {
            str(service["zone"])
            for service in services
            if isinstance(service.get("zone"), str)
        },
    )
    if not zones:
        zones = service_zones
    else:
        zones.extend(zone for zone in service_zones if zone not in zones)

    return {
        "services": services,
        "edges": normalized_rows(raw.get("edges")),
        "zones": zones,
        "users": normalized_rows(raw.get("users")),
        "green_personas": normalized_rows(raw.get("green_personas")),
    }


def embedded_topology(snapshot: Snapshot) -> dict[str, object]:
    raw: dict[str, object] = {}
    for path, content in snapshot.artifacts.items():
        if not path.endswith("topology.json"):
            continue
        try:
            loaded = json.loads(content)
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, Mapping):
            raw.update(loaded)
            break

    world_topology = snapshot.world.get("topology")
    if isinstance(world_topology, Mapping):
        raw.update(world_topology)
    for key in ("services", "edges", "zones", "users", "green_personas"):
        value = snapshot.world.get(key)
        if value is not None:
            raw[key] = value
    return raw


def normalized_rows(value: object) -> list[dict[str, object]]:
    if isinstance(value, Mapping):
        iterable = tuple(value.items())
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        iterable = tuple((None, item) for item in value)
    else:
        return []

    rows: list[dict[str, object]] = []
    for key, item in iterable:
        if isinstance(item, Mapping):
            row = dict(cast(Mapping[str, object], json_safe(item)))
            if "id" not in row:
                row["id"] = "" if key is None else str(key)
            rows.append(row)
        elif isinstance(item, str):
            rows.append({"id": item})
    return rows


def normalized_strings(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return []
    return [item for item in value if isinstance(item, str)]


def health_summary(events: Sequence[Mapping[str, object]]) -> dict[str, float]:
    values = {"uptime": 100.0, "defense": 100.0, "integrity": 100.0}
    found: set[str] = set()
    for event in reversed(events):
        data = event.get("data")
        if not isinstance(data, Mapping):
            continue
        state = data.get("state")
        if not isinstance(state, Mapping):
            continue
        update_health_value(values, found, "uptime", state, "uptime")
        update_health_value(values, found, "uptime", state, "continuity")
        update_health_value(values, found, "defense", state, "defense")
        update_health_reward(values, found, "defense", state, "blue_reward")
        update_health_value(values, found, "integrity", state, "integrity")
        update_health_reward(values, found, "integrity", state, "red_reward")
        if len(found) == len(values):
            break
    return values


def update_health_value(
    values: dict[str, float],
    found: set[str],
    metric: str,
    state: Mapping[str, object],
    key: str,
) -> None:
    if metric in found:
        return
    percent = percent_value(state.get(key))
    if percent is None:
        return
    values[metric] = percent
    found.add(metric)


def update_health_reward(
    values: dict[str, float],
    found: set[str],
    metric: str,
    state: Mapping[str, object],
    key: str,
) -> None:
    if metric in found:
        return
    reward = numeric_value(state.get(key))
    if reward is None:
        return
    values[metric] = clamp_percent(100.0 - abs(reward) * 100.0)
    found.add(metric)


def percent_value(value: object) -> float | None:
    number = numeric_value(value)
    if number is None:
        return None
    if 0.0 <= number <= 1.0:
        return clamp_percent(number * 100.0)
    return clamp_percent(number)


def numeric_value(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def clamp_percent(value: float) -> float:
    return min(100.0, max(0.0, value))


def stored_entrypoints(tasks: Sequence[object]) -> list[dict[str, object]]:
    entrypoints: list[dict[str, object]] = []
    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        task_id = task.get("id")
        for entrypoint in stored_task_entrypoints(task):
            entrypoints.append({"task_id": str(task_id), **entrypoint})
    return entrypoints


def stored_missions(tasks: Sequence[object]) -> list[dict[str, object]]:
    missions: list[dict[str, object]] = []
    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        missions.append(
            {
                "task_id": str(task.get("id", "")),
                "instruction": str(task.get("instruction", "")),
            },
        )
    return missions


def stored_task_entrypoints(task: Mapping[str, object]) -> list[dict[str, object]]:
    rows = task.get("entrypoints")
    if not isinstance(rows, list):
        return []
    entrypoints: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        entrypoints.append(
            {
                "kind": str(row.get("kind", "")),
                "target": str(row.get("target", "")),
            },
        )
    return entrypoints


def public_world(world: Mapping[str, object]) -> dict[str, object]:
    redacted: dict[str, object] = {}
    for key, value in world.items():
        if sensitive_world_key(key):
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def sensitive_world_key(key: str) -> bool:
    normalized = key.lower()
    return normalized == "flag" or any(
        marker in normalized for marker in ("secret", "password", "token")
    )


def fallback_narrate(events: Sequence[DashboardEvent]) -> str:
    if not events:
        return "No episode activity yet."
    return "\n".join(
        f"{event.actor} {event.type} {event.target}" for event in events[-5:]
    )


class DashboardHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        view: DashboardView,
    ) -> None:
        self.view = view
        super().__init__(server_address, DashboardRequestHandler)


class DashboardRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self._write_html()
            return
        if path == "/api/events/stream":
            self._stream_events()
            return
        if path == "/api/narrate/stream":
            self._stream_narration()
            return

        routes = {
            "/api/briefing": self.view.briefing,
            "/api/actors": self.view.actors,
            "/api/topology": self.view.topology,
            "/api/lineage": self.view.lineage,
            "/api/state": self.view.state,
            "/api/inspect": self.view.inspect,
            "/api/narrate": self.view.narration,
        }
        route = routes.get(path)
        if route is None:
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        self._write_json(route())

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        routes = {
            "/api/episode/reset": self.view.reset,
            "/api/episode/play": self.view.play,
            "/api/episode/pause": self.view.pause,
        }
        route = routes.get(path)
        if route is None:
            self._write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        self._write_json(route())

    @property
    def view(self) -> DashboardView:
        return cast(DashboardHTTPServer, self.server).view

    def _write_html(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML)

    def _write_json(
        self,
        payload: object,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _stream_events(self) -> None:
        self._write_sse_headers()
        for event in self.view.bridge.subscribe_sync():
            self._write_sse(event.as_dict(), event=event.type, event_id=event.id)

    def _stream_narration(self) -> None:
        self._write_sse_headers()
        for event in self.view.bridge.subscribe_sync():
            self._write_sse(
                self.view.narration(),
                event="narration",
                event_id=event.id,
            )

    def _write_sse_headers(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()

    def _write_sse(
        self,
        payload: Mapping[str, object],
        *,
        event: str,
        event_id: str,
    ) -> None:
        body = (
            f"id: {event_id}\n"
            f"event: {event}\n"
            f"data: {json.dumps(payload, sort_keys=True)}\n\n"
        ).encode()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except BrokenPipeError:  # pragma: no cover - depends on client timing.
            return

    def log_message(self, format: str, *args: object) -> None:
        return


DASHBOARD_HTML = b"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenRange Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link
  href="https://fonts.googleapis.com/css2?family=Nunito:wght@500;700;800;900&display=swap"
  rel="stylesheet">
<script
  src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script
  src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
<style>
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-soft: #edf1f5;
  --ink: #17202a;
  --muted: #5e6a78;
  --line: #d9dee6;
  --green: #247b4b;
  --blue: #2266a3;
  --red: #a33d33;
  --amber: #966711;
  --teal: #147074;
  --shadow: 0 10px 30px rgba(28, 37, 49, .08);
  --sim-bg: #07111f;
  --sim-panel: #102a56;
  --sim-panel-2: #173b78;
  --sim-line: #8ec5ff;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--sim-bg);
  color: var(--ink);
  font-family: Nunito, Inter, ui-sans-serif, system-ui, -apple-system,
    BlinkMacSystemFont, "Segoe UI", sans-serif;
}
button {
  min-height: 2.25rem;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--surface);
  color: var(--ink);
  font: inherit;
  font-weight: 650;
  padding: .45rem .75rem;
  cursor: pointer;
}
button:hover { border-color: #9aa6b5; }
button.primary { background: var(--ink); border-color: var(--ink); color: #fff; }
main {
  max-width: 1480px;
  margin: 0 auto;
  padding: 1.25rem;
  background: var(--bg);
}
.sim-stage {
  position: relative;
  min-height: 620px;
  height: 100vh;
  overflow: hidden;
  background:
    radial-gradient(circle at 22% 18%, rgba(56, 189, 248, .16), transparent 30%),
    linear-gradient(180deg, #06111f 0%, #0b1830 54%, #081221 100%);
  color: #f8fafc;
  isolation: isolate;
}
#sim-canvas {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  display: block;
}
.sim-overlay {
  position: absolute;
  z-index: 2;
  pointer-events: none;
}
.sim-panel {
  background: var(--sim-panel);
  border: 3px solid var(--sim-line);
  box-shadow: 5px 5px 0 rgba(0, 0, 0, .72);
  color: #f8fafc;
  pointer-events: auto;
}
.sim-title {
  top: 1.2rem;
  left: 1.2rem;
  width: min(32rem, calc(100% - 2.4rem));
  padding: .9rem 1rem;
}
.sim-title h1 {
  margin: 0;
  font-size: clamp(1.15rem, 2.4vw, 2.1rem);
  line-height: 1.05;
  text-transform: uppercase;
  letter-spacing: 0;
}
.sim-title p {
  margin: .4rem 0 0;
  color: #bfdbfe;
  font-size: .92rem;
}
.sim-clock {
  top: 1.2rem;
  right: 1.2rem;
  min-width: 11rem;
  padding: .75rem 1rem;
  text-align: center;
}
.sim-clock strong {
  display: block;
  font-size: 1.55rem;
  line-height: 1;
}
.sim-clock span {
  display: block;
  margin-top: .25rem;
  color: #93c5fd;
  font-size: .78rem;
  font-weight: 900;
  text-transform: uppercase;
}
.sim-event-panel {
  top: 8.4rem;
  left: 1.2rem;
  width: min(23rem, calc(100% - 2.4rem));
  max-height: 17rem;
  padding: .85rem 1rem;
}
.sim-panel-title {
  margin-bottom: .55rem;
  color: #7dd3fc;
  font-size: .76rem;
  font-weight: 900;
  letter-spacing: .08em;
  text-transform: uppercase;
}
.sim-event-list {
  display: grid;
  gap: .4rem;
  max-height: 13.2rem;
  overflow: auto;
  margin: 0;
  padding: 0;
  list-style: none;
}
.sim-event-list li {
  display: grid;
  grid-template-columns: .55rem minmax(0, 1fr);
  gap: .45rem;
  align-items: start;
  color: #dbeafe;
  font-size: .78rem;
  line-height: 1.35;
}
.sim-dot {
  width: .55rem;
  height: .55rem;
  margin-top: .22rem;
  border-radius: 50%;
  background: #94a3b8;
}
.sim-dot.agent { background: #fb7185; }
.sim-dot.npc { background: #4ade80; }
.sim-dot.system { background: #38bdf8; }
.sim-bottom {
  left: 0;
  right: 0;
  bottom: 0;
  display: grid;
  grid-template-columns: minmax(16rem, 24rem) auto minmax(15rem, 20rem);
  gap: 1rem;
  align-items: end;
  padding: 4rem 2rem 1.25rem;
  background: linear-gradient(0deg, rgba(3, 7, 18, .92), transparent);
}
.sim-narrator,
.sim-gauges {
  padding: .85rem 1rem;
  min-height: 8rem;
}
.sim-narrator-text {
  margin: 0;
  max-height: 4.8rem;
  overflow: auto;
  color: #e0f2fe;
  font-size: .85rem;
  line-height: 1.45;
  white-space: pre-wrap;
}
.sim-controls {
  display: flex;
  gap: .55rem;
  align-items: center;
  justify-content: center;
  padding: .55rem;
  background: #0f172a;
  border: 3px solid #64748b;
  box-shadow: 5px 5px 0 rgba(0, 0, 0, .72);
  pointer-events: auto;
}
.sim-controls button {
  width: 3.25rem;
  height: 3.25rem;
  min-height: 0;
  padding: 0;
  border-radius: 0;
  border: 2px solid #94a3b8;
  box-shadow: 3px 3px 0 #000;
  background: #dbeafe;
  color: #0f172a;
  font-size: .9rem;
  font-weight: 900;
}
.sim-controls button:active {
  transform: translate(2px, 2px);
  box-shadow: 1px 1px 0 #000;
}
.sim-controls button.primary {
  background: #22c55e;
  border-color: #86efac;
  color: #052e16;
}
.sim-controls button.danger {
  background: #fb7185;
  border-color: #fecdd3;
  color: #450a0a;
}
.sim-gauge {
  position: relative;
  height: 1.05rem;
  margin-top: .65rem;
  overflow: hidden;
  border: 2px solid #020617;
  background: #020617;
}
.sim-gauge span {
  position: absolute;
  z-index: 1;
  left: .45rem;
  top: 50%;
  transform: translateY(-50%);
  color: #f8fafc;
  font-size: .68rem;
  font-weight: 900;
}
.sim-gauge i {
  display: block;
  height: 100%;
  width: 100%;
  background: #4ade80;
  transition: width .25s ease, background-color .25s ease;
}
.sim-empty {
  top: 45%;
  left: 50%;
  width: min(28rem, calc(100% - 2rem));
  padding: 1rem;
  transform: translate(-50%, -50%);
  text-align: center;
  color: #dbeafe;
}
.sim-empty.hidden { display: none; }
.sim-actor-panel {
  right: 1.2rem;
  top: 8.4rem;
  width: min(23rem, calc(100% - 2.4rem));
  max-height: 24rem;
  padding: .85rem 1rem;
  display: none;
}
.sim-actor-panel.visible { display: block; }
.sim-actor-head {
  display: flex;
  gap: .75rem;
  align-items: start;
  justify-content: space-between;
  padding-bottom: .55rem;
  border-bottom: 1px solid rgba(147, 197, 253, .35);
}
.sim-actor-head h2 {
  margin: 0;
  color: #fef3c7;
  font-size: 1rem;
  overflow-wrap: anywhere;
}
.sim-actor-head p {
  margin: .18rem 0 0;
  color: #bfdbfe;
  font-size: .78rem;
}
.sim-close {
  width: 1.9rem;
  height: 1.9rem;
  min-height: 0;
  padding: 0;
  border: 0;
  background: transparent;
  color: #fff;
  font-size: .95rem;
}
.sim-actor-grid {
  display: grid;
  grid-template-columns: 6rem minmax(0, 1fr);
  gap: .35rem .7rem;
  margin: .75rem 0;
  font-size: .78rem;
}
.sim-actor-grid dt { color: #93c5fd; }
.sim-actor-grid dd {
  margin: 0;
  color: #e0f2fe;
  overflow-wrap: anywhere;
}
.sim-actor-history {
  display: grid;
  gap: .35rem;
  max-height: 9rem;
  overflow: auto;
  margin: 0;
  padding: 0;
  list-style: none;
}
.sim-actor-history li {
  color: #dbeafe;
  font-size: .76rem;
  line-height: 1.35;
}
.shell { display: grid; gap: 1rem; }
.topbar {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 1rem;
  align-items: center;
  padding: 1rem 0 .25rem;
}
.brand h1 { margin: 0; font-size: 1.45rem; letter-spacing: 0; }
.brand p { margin: .25rem 0 0; color: var(--muted); font-size: .92rem; }
.toolbar { display: flex; gap: .5rem; flex-wrap: wrap; justify-content: flex-end; }
.grid {
  display: grid;
  grid-template-columns: minmax(18rem, 1fr) minmax(26rem, 1.5fr) minmax(22rem, 1.1fr);
  gap: 1rem;
  align-items: start;
}
section {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: var(--shadow);
  overflow: hidden;
}
.section-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: .75rem;
  min-height: 3rem;
  padding: .85rem 1rem;
  border-bottom: 1px solid var(--line);
}
.section-head h2 {
  margin: 0;
  font-size: .9rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: #334155;
}
.section-body { padding: 1rem; }
.status-strip {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: .75rem;
}
.metric {
  min-height: 4.5rem;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: .75rem;
}
.metric span {
  display: block;
  color: var(--muted);
  font-size: .75rem;
  text-transform: uppercase;
  letter-spacing: .05em;
}
.metric strong {
  display: block;
  margin-top: .4rem;
  font-size: 1rem;
  overflow-wrap: anywhere;
}
.pill {
  display: inline-flex;
  align-items: center;
  min-height: 1.5rem;
  padding: .15rem .5rem;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--surface-soft);
  color: #334155;
  font-size: .75rem;
  font-weight: 700;
}
.pill.green { color: var(--green); background: #e8f4ed; border-color: #c6e4d2; }
.pill.blue { color: var(--blue); background: #e8f1fb; border-color: #c4dbf1; }
.pill.red { color: var(--red); background: #fbecea; border-color: #f1cac6; }
.pill.amber { color: var(--amber); background: #fbf2dc; border-color: #ead7a7; }
.list { display: grid; gap: .7rem; }
.item {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: .85rem;
  background: #fff;
}
.item h3 { margin: 0 0 .35rem; font-size: .98rem; overflow-wrap: anywhere; }
.item p { margin: .35rem 0; color: var(--muted); line-height: 1.4; }
.kv {
  display: grid;
  grid-template-columns: 8.5rem minmax(0, 1fr);
  gap: .35rem .8rem;
  font-size: .85rem;
}
.kv dt { color: var(--muted); }
.kv dd { margin: 0; overflow-wrap: anywhere; }
.world-table {
  width: 100%;
  border-collapse: collapse;
  font-size: .88rem;
}
.world-table th, .world-table td {
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--line);
  padding: .55rem .35rem;
  overflow-wrap: anywhere;
}
.world-table th { width: 9rem; color: var(--muted); font-weight: 650; }
.event-feed {
  display: grid;
  gap: .6rem;
  max-height: 39rem;
  overflow: auto;
  padding-right: .2rem;
}
.event {
  border-left: 4px solid var(--blue);
  background: #f8fafc;
  border-radius: 6px;
  padding: .7rem .8rem;
}
.event.system { border-left-color: var(--teal); }
.event.agent { border-left-color: var(--green); }
.event.npc { border-left-color: var(--amber); }
.event h3 {
  display: flex;
  justify-content: space-between;
  gap: .75rem;
  margin: 0 0 .25rem;
  font-size: .9rem;
}
.event small { color: var(--muted); font-weight: 600; }
.narration {
  white-space: pre-wrap;
  margin: 0;
  line-height: 1.5;
  color: #263241;
}
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  margin: .65rem 0 0;
  padding: .75rem;
  background: #101820;
  color: #e8eef6;
  border-radius: 6px;
  font-size: .78rem;
  line-height: 1.45;
}
.tabs { display: flex; gap: .35rem; flex-wrap: wrap; }
.tab {
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: .25rem .55rem;
  background: #fff;
  color: var(--muted);
  font-size: .78rem;
  font-weight: 700;
}
.tab.active { color: #fff; background: var(--blue); border-color: var(--blue); }
.empty {
  min-height: 9rem;
  display: grid;
  place-items: center;
  border: 1px dashed #aeb8c5;
  border-radius: 8px;
  color: var(--muted);
  text-align: center;
  padding: 1rem;
}
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.wide { grid-column: 1 / -1; }
@media (max-width: 1180px) {
  .grid { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
  .activity { grid-column: 1 / -1; }
}
@media (max-width: 780px) {
  .sim-stage { min-height: 760px; }
  .sim-title, .sim-clock, .sim-event-panel, .sim-actor-panel {
    position: relative;
    top: auto;
    left: auto;
    right: auto;
    width: auto;
    margin: .75rem;
  }
  .sim-bottom {
    grid-template-columns: 1fr;
    padding: 1rem .75rem;
  }
  .sim-controls { order: -1; justify-self: start; }
  main { padding: .75rem; }
  .topbar { grid-template-columns: 1fr; }
  .toolbar { justify-content: flex-start; }
  .grid, .status-strip, .sim-stage { grid-template-columns: 1fr; }
  .kv { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="sim-stage" id="sim-stage">
  <canvas id="sim-canvas" aria-label="OpenRange episode simulation"></canvas>

  <div class="sim-overlay sim-panel sim-title">
    <h1>OpenRange Episode Dashboard</h1>
    <p id="sim-subtitle">Loading public episode briefing</p>
  </div>

  <div class="sim-overlay sim-panel sim-clock">
    <strong id="sim-clock">00:00</strong>
    <span id="sim-status">Waiting</span>
  </div>

  <div class="sim-overlay sim-panel sim-event-panel">
    <div class="sim-panel-title">Live Event Feed</div>
    <ul class="sim-event-list" id="sim-event-log"></ul>
  </div>

  <div class="sim-overlay sim-panel sim-actor-panel" id="sim-actor-panel">
    <div class="sim-actor-head">
      <div>
        <h2 id="sim-actor-name">Actor</h2>
        <p id="sim-actor-role">No actor selected</p>
      </div>
      <button class="sim-close" id="sim-actor-close" title="Close">X</button>
    </div>
    <dl class="sim-actor-grid">
      <dt>Kind</dt><dd id="sim-actor-kind">event</dd>
      <dt>Events</dt><dd id="sim-actor-events">0</dd>
      <dt>Targets</dt><dd id="sim-actor-targets">none</dd>
      <dt>Latest</dt><dd id="sim-actor-latest">No activity yet.</dd>
    </dl>
    <div class="sim-panel-title">Recent History</div>
    <ul class="sim-actor-history" id="sim-actor-history"></ul>
  </div>

  <div class="sim-overlay sim-panel sim-empty" id="sim-empty">
    No admitted world is loaded yet. Start an eval dashboard through the environment
    or launch against a snapshot store.
  </div>

  <div class="sim-overlay sim-bottom">
    <div class="sim-panel sim-narrator">
      <div class="sim-panel-title">Episode Narrator</div>
      <p class="sim-narrator-text" id="sim-narrator">No episode activity yet.</p>
    </div>

    <div class="sim-controls" aria-label="Episode controls">
      <button class="danger" data-action="reset" title="Reset episode">RST</button>
      <button data-action="pause" title="Pause episode">PAU</button>
      <button class="primary" data-action="play" title="Play episode">PLY</button>
    </div>

    <div class="sim-panel sim-gauges">
      <div class="sim-panel-title">Run Health</div>
      <div class="sim-gauge"><span>Uptime</span><i id="sim-uptime-gauge"></i></div>
      <div class="sim-gauge"><span>Defense</span><i id="sim-defense-gauge"></i></div>
      <div class="sim-gauge">
        <span>Integrity</span><i id="sim-integrity-gauge"></i>
      </div>
    </div>
  </div>
</div>

<main>
<div class="shell">
  <div class="topbar">
    <div class="brand">
      <h1>OpenRange Dashboard</h1>
      <p id="subtitle">Loading snapshot state</p>
    </div>
    <div class="toolbar">
      <button data-action="reset">Reset</button>
      <button data-action="pause">Pause</button>
      <button class="primary" data-action="play">Play</button>
    </div>
  </div>

  <div class="status-strip" id="metrics"></div>

  <div class="grid">
    <section>
      <div class="section-head">
        <h2>Briefing</h2>
        <span class="pill blue">Public surface</span>
      </div>
      <div class="section-body" id="briefing"></div>
    </section>

    <section>
      <div class="section-head">
        <h2>World</h2>
        <span class="pill" id="snapshot-pill">No snapshot</span>
      </div>
      <div class="section-body" id="world"></div>
    </section>

    <section>
      <div class="section-head">
        <h2>Tasks</h2>
        <span class="pill blue" id="task-count">0 tasks</span>
      </div>
      <div class="section-body">
        <div class="list" id="tasks"></div>
      </div>
    </section>

    <section class="activity">
      <div class="section-head">
        <h2>Activity</h2>
        <span class="pill green" id="event-count">0 events</span>
      </div>
      <div class="section-body">
        <div class="event-feed" id="events"></div>
      </div>
    </section>

    <section>
      <div class="section-head">
        <h2>Actors</h2>
        <span class="pill" id="actor-count">0 actors</span>
      </div>
      <div class="section-body">
        <div class="list" id="actors"></div>
      </div>
    </section>

    <section>
      <div class="section-head">
        <h2>Admission</h2>
        <span class="pill" id="admission-pill">Unknown</span>
      </div>
      <div class="section-body" id="admission"></div>
    </section>

    <section>
      <div class="section-head">
        <h2>Lineage</h2>
        <span class="pill" id="lineage-count">0 nodes</span>
      </div>
      <div class="section-body">
        <div class="list" id="lineage"></div>
      </div>
    </section>

    <section>
      <div class="section-head">
        <h2>Narration</h2>
        <span class="pill amber">Recent buffer</span>
      </div>
      <div class="section-body">
        <p class="narration" id="narration">Loading...</p>
      </div>
    </section>

    <section class="wide">
      <div class="section-head">
        <h2>Details</h2>
        <div class="tabs" id="detail-tabs"></div>
      </div>
      <div class="section-body">
        <div id="details"></div>
      </div>
    </section>
  </div>
</div>
</main>
<script>
const model = {
  briefing: {
    snapshot_id: null,
    title: "",
    goal: "",
    entrypoints: [],
    missions: [],
  },
  topology: {
    snapshot_id: null,
    world: {},
    tasks: [],
    artifact_paths: [],
    services: [],
    edges: [],
    zones: [],
    users: [],
    green_personas: [],
  },
  lineage: { snapshot_id: null, admission: null, nodes: [] },
  state: {
    running: false,
    status: "waiting_for_snapshot",
    health: { uptime: 100, defense: 100, integrity: 100 },
    events: [],
  },
  actors: [],
  narration: { narration: "No episode activity yet." },
  detail: "topology",
};

async function json(path, options) {
  const response = await fetch(path, options);
  return response.json();
}

function text(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function escapeHtml(value) {
  return text(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function pretty(value) {
  return escapeHtml(JSON.stringify(value, null, 2));
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function pillClass(value) {
  if (value === true || value === "playing") return "pill green";
  if (value === false) return "pill red";
  if (value === "waiting_for_snapshot") return "pill amber";
  return "pill blue";
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span>` +
    `<strong>${escapeHtml(value)}</strong></div>`;
}

function renderMetrics() {
  const taskCount = model.topology.tasks.length;
  const eventCount = model.state.event_count || model.state.events.length;
  const turnCount = model.state.turn_count || 0;
  const snapshot = model.state.snapshot_id || "none";
  document.getElementById("metrics").innerHTML = [
    metric("Run status", model.state.status || "paused"),
    metric("Snapshot", snapshot),
    metric("Tasks", taskCount),
    metric("Events", eventCount),
    metric("Turns", turnCount),
  ].join("");
  document.getElementById("subtitle").textContent =
    model.topology.snapshot_id
      ? `Snapshot ${model.topology.snapshot_id}`
      : "Waiting for an admitted snapshot";
}

const sim = {
  initialized: false,
  fallback: false,
  fingerprint: "",
  seenEvents: new Set(),
  scene: null,
  camera: null,
  renderer: null,
  controls: null,
  worldGroup: null,
  clock: null,
  servicePositions: {},
  characters: {},
  effects: [],
  selectedActorId: "",
};

function shortText(value, max = 80) {
  const rendered = text(value);
  if (rendered.length <= max) return rendered;
  return `${rendered.slice(0, Math.max(0, max - 3))}...`;
}

function eventData(event) {
  return event.data && typeof event.data === "object" ? event.data : {};
}

function simulationRole(value) {
  const kind = typeof value === "string"
    ? value
    : eventData(value).actor_kind || value.actor || "event";
  if (kind === "agent" || kind === "red") return "agent";
  if (kind === "npc" || kind === "green") return "npc";
  if (kind === "system" || kind === "blue") return "system";
  return "event";
}

function roleColor(role) {
  if (role === "agent") return 0xfb7185;
  if (role === "npc") return 0x4ade80;
  if (role === "system") return 0x38bdf8;
  return 0xfacc15;
}

function roleCss(role) {
  return role === "agent" || role === "npc" || role === "system" ? role : "";
}

function eventLabel(event) {
  const data = eventData(event);
  const action = data.action ? ` ${shortText(data.action, 54)}` : "";
  const observation = data.observation ? ` -> ${shortText(data.observation, 44)}` : "";
  return `${event.actor} -> ${event.target}: ${event.type}${action}${observation}`;
}

function stationDefinitions() {
  const byId = new Map();
  const add = (id, label, kind, zone = "") => {
    if (!id || byId.has(id)) return;
    byId.set(id, {
      id,
      label: shortText(label || id, 18),
      kind: kind || "service",
      zone,
    });
  };

  (model.topology.services || []).forEach((service) => {
    add(
      service.id,
      service.id || service.kind,
      service.kind || service.role || "service",
      service.zone || "",
    );
  });
  (model.briefing.entrypoints || []).forEach((entry) => {
    add(entry.target, entry.target, entry.kind, "episode");
  });
  (model.topology.tasks || []).forEach((task) => {
    const entrypoints = task.entrypoints || [];
    if (!entrypoints.length) add(task.id, task.id, "task", "episode");
    entrypoints.forEach((entry) => (
      add(entry.target, entry.target, entry.kind, "episode")
    ));
  });
  (model.topology.artifact_paths || []).slice(0, 4).forEach((path) => {
    add(`artifact:${path}`, path.split("/").pop() || path, "artifact", "artifact");
  });
  if (!byId.size && model.topology.snapshot_id) {
    add("world", model.briefing.title || "world", "world", "episode");
  }
  return Array.from(byId.values()).slice(0, 12);
}

function actorDefinitions() {
  const byId = new Map();
  const add = (id, role) => {
    if (id && !byId.has(id)) byId.set(id, simulationRole(role));
  };
  (model.actors || []).forEach((actor) => {
    add(actor.actor_id, actor.actor_kind);
  });
  (model.state.events || []).forEach((event) => {
    const data = eventData(event);
    add(data.actor_id || event.actor, event);
  });
  (model.topology.services || []).forEach((service) => {
    if (service.role === "red") add("red", "agent");
    if (service.role === "blue") add("blue", "system");
  });
  const people = (model.topology.green_personas || []).length
    ? model.topology.green_personas
    : model.topology.users || [];
  people.forEach((persona) => {
    add(persona.id || persona.email, "npc");
  });
  if (!byId.size && model.topology.snapshot_id) {
    add("agent", "agent");
    add("system", "system");
  }
  return Array.from(byId.entries()).map(([id, role]) => ({ id, role }));
}

function simulationFingerprint() {
  const stationIds = stationDefinitions().map((station) => station.id).join("|");
  const actorIds = actorDefinitions().map((actor) => (
    `${actor.id}:${actor.role}`
  )).join("|");
  return `${model.topology.snapshot_id || "empty"}:${stationIds}:${actorIds}`;
}

function initSimulation() {
  if (sim.initialized) return;
  sim.initialized = true;
  const canvas = document.getElementById("sim-canvas");
  if (!canvas || !window.THREE) {
    sim.fallback = true;
    drawFallbackSimulation();
    return;
  }

  sim.scene = new THREE.Scene();
  sim.scene.background = new THREE.Color(0x07111f);
  sim.scene.fog = new THREE.FogExp2(0x07111f, 0.018);
  sim.clock = new THREE.Clock();

  sim.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
  sim.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  sim.renderer.shadowMap.enabled = true;
  sim.renderer.shadowMap.type = THREE.PCFSoftShadowMap;

  sim.camera = new THREE.OrthographicCamera(-16, 16, 12, -12, 0.1, 200);
  sim.camera.position.set(26, 24, 26);
  sim.camera.lookAt(0, 0, 0);

  if (THREE.OrbitControls) {
    sim.controls = new THREE.OrbitControls(sim.camera, canvas);
    sim.controls.enableDamping = true;
    sim.controls.dampingFactor = 0.06;
    sim.controls.maxPolarAngle = Math.PI / 2.15;
    sim.controls.minPolarAngle = Math.PI / 6;
  }

  sim.scene.add(new THREE.AmbientLight(0xffffff, 0.56));
  const keyLight = new THREE.DirectionalLight(0xfff5e6, 1.25);
  keyLight.position.set(18, 32, 22);
  keyLight.castShadow = true;
  keyLight.shadow.mapSize.width = 2048;
  keyLight.shadow.mapSize.height = 2048;
  keyLight.shadow.camera.left = -28;
  keyLight.shadow.camera.right = 28;
  keyLight.shadow.camera.top = 28;
  keyLight.shadow.camera.bottom = -28;
  sim.scene.add(keyLight);

  addBaseSimulationScene();
  resizeSimulation();
  window.addEventListener("resize", resizeSimulation);
  installActorSelection(canvas);
  animateSimulation();
}

function addBaseSimulationScene() {
  const gridCanvas = document.createElement("canvas");
  const ctx = gridCanvas.getContext("2d");
  gridCanvas.width = 128;
  gridCanvas.height = 128;
  ctx.fillStyle = "#d8d2ca";
  ctx.fillRect(0, 0, 128, 128);
  ctx.strokeStyle = "#b9aa9b";
  ctx.lineWidth = 2;
  for (let step = 0; step <= 128; step += 16) {
    ctx.beginPath();
    ctx.moveTo(0, step);
    ctx.lineTo(128, step);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(step, 0);
    ctx.lineTo(step, 128);
    ctx.stroke();
  }
  const texture = new THREE.CanvasTexture(gridCanvas);
  texture.wrapS = THREE.RepeatWrapping;
  texture.wrapT = THREE.RepeatWrapping;
  texture.repeat.set(28, 28);
  const floor = new THREE.Mesh(
    new THREE.PlaneGeometry(54, 54),
    new THREE.MeshStandardMaterial({ map: texture, roughness: 0.72 }),
  );
  floor.rotation.x = -Math.PI / 2;
  floor.receiveShadow = true;
  sim.scene.add(floor);

  const wallMaterial = new THREE.MeshStandardMaterial({ color: 0xe2e8f0 });
  [
    { size: [32, 2.8, .45], pos: [0, 1.4, -16] },
    { size: [.45, 2.8, 32], pos: [-16, 1.4, 0] },
  ].forEach((wall) => {
    const mesh = new THREE.Mesh(new THREE.BoxGeometry(...wall.size), wallMaterial);
    mesh.position.set(...wall.pos);
    mesh.castShadow = true;
    sim.scene.add(mesh);
  });

  sim.worldGroup = new THREE.Group();
  sim.scene.add(sim.worldGroup);
}

function clearSimulationWorld() {
  if (!sim.worldGroup) return;
  while (sim.worldGroup.children.length) {
    const child = sim.worldGroup.children[0];
    disposeObject(child);
    sim.worldGroup.remove(child);
  }
  sim.servicePositions = {};
  sim.characters = {};
  sim.effects = [];
}

function disposeObject(object) {
  object.traverse((child) => {
    if (child.geometry) child.geometry.dispose();
    if (child.material) {
      const materials = Array.isArray(child.material)
        ? child.material
        : [child.material];
      materials.forEach((material) => {
        if (material.map) material.map.dispose();
        material.dispose();
      });
    }
  });
}

function rebuildSimulationWorld() {
  if (sim.fallback) return;
  const nextFingerprint = simulationFingerprint();
  if (sim.fingerprint === nextFingerprint) return;
  sim.fingerprint = nextFingerprint;
  clearSimulationWorld();

  const stations = stationDefinitions();
  stations.forEach((station, index) => {
    const pos = stationPosition(station, index, stations);
    addStation(station, pos.x, pos.z, index);
  });

  actorDefinitions().forEach((actor, index) => {
    const profile = actorProfile(actor.id);
    const home = profile ? sim.servicePositions[profile.home_host] : null;
    const side = actor.role === "agent" ? -1 : actor.role === "system" ? 1 : 0;
    const x = home
      ? home.x + (index % 3 - 1) * 1.7
      : side ? side * 18 : -8 + index * 3.2;
    const z = home
      ? home.z + 2 + Math.floor(index / 3) * .7
      : side ? 13 - index * 2.4 : 12;
    addCharacter(actor.id, actor.role, x, z);
  });
}

function stationPosition(station, index, stations) {
  const fixed = {
    "sandbox-red": [-18, -13],
    "red": [-18, -13],
    "svc-web": [-7, -8],
    "svc-email": [6, -8],
    "svc-fileshare": [-10, -2],
    "svc-db": [1, 1],
    "svc-idp": [-6, 7],
    "svc-siem": [8, 6],
    "sandbox-blue": [15, 10],
    "blue": [15, 10],
  };
  if (fixed[station.id]) {
    return { x: fixed[station.id][0], z: fixed[station.id][1] };
  }

  const zoneRows = {
    external: -13,
    dmz: -8,
    corp: -3,
    data: 2,
    management: 7,
    episode: 11,
    artifact: 14,
  };
  if (station.zone && zoneRows[station.zone] !== undefined) {
    const zoneStations = stations.filter((item) => item.zone === station.zone);
    const zoneIndex = zoneStations.findIndex((item) => item.id === station.id);
    const count = Math.max(1, zoneStations.length);
    return {
      x: (zoneIndex - (count - 1) / 2) * 6,
      z: zoneRows[station.zone],
    };
  }

  const total = stations.length;
  const columns = Math.max(2, Math.ceil(Math.sqrt(Math.max(total, 1))));
  const row = Math.floor(index / columns);
  const column = index % columns;
  return {
    x: (column - (columns - 1) / 2) * 7.2,
    z: (row - 1) * 5.4,
  };
}

function addStation(station, x, z, index) {
  const colors = [0x38bdf8, 0xa78bfa, 0xfacc15, 0x4ade80, 0xfb7185, 0x22d3ee];
  const accent = colors[index % colors.length];
  const group = new THREE.Group();
  group.position.set(x, 0, z);

  const deskMaterial = new THREE.MeshStandardMaterial({ color: 0x94a3b8 });
  const screenMaterial = new THREE.MeshStandardMaterial({
    color: 0x08111f,
    emissive: accent,
    emissiveIntensity: .18,
  });
  const top = new THREE.Mesh(new THREE.BoxGeometry(2.4, .12, 1.15), deskMaterial);
  top.position.y = .78;
  top.castShadow = true;
  group.add(top);

  [-.8, .8].forEach((legX) => {
    [-.36, .36].forEach((legZ) => {
      const leg = new THREE.Mesh(new THREE.BoxGeometry(.12, .78, .12), deskMaterial);
      leg.position.set(legX, .38, legZ);
      leg.castShadow = true;
      group.add(leg);
    });
  });

  const monitor = new THREE.Mesh(new THREE.BoxGeometry(.88, .58, .08), screenMaterial);
  monitor.position.set(0, 1.16, -.38);
  monitor.castShadow = true;
  group.add(monitor);

  const ring = new THREE.Mesh(
    new THREE.RingGeometry(1.45, 1.58, 40),
    new THREE.MeshBasicMaterial({
      color: accent,
      transparent: true,
      opacity: .45,
      side: THREE.DoubleSide,
    }),
  );
  ring.rotation.x = -Math.PI / 2;
  ring.position.y = .04;
  group.add(ring);

  const label = makeLabelSprite(
    station.label.toUpperCase(),
    "#dbeafe",
    "rgba(15, 23, 42, .72)",
  );
  label.position.set(0, .08, 1.45);
  group.add(label);

  sim.worldGroup.add(group);
  sim.servicePositions[station.id] = { x, z, ring, accent };
}

function addCharacter(id, role, x, z) {
  const group = new THREE.Group();
  group.position.set(x, 0, z);
  const color = roleColor(role);
  const shirt = new THREE.MeshStandardMaterial({ color });
  const dark = new THREE.MeshStandardMaterial({ color: 0x1e293b });
  const skin = new THREE.MeshStandardMaterial({ color: 0xffd9ad });

  const body = new THREE.Mesh(new THREE.BoxGeometry(.48, .62, .28), shirt);
  body.position.y = .92;
  body.castShadow = true;
  group.add(body);

  const head = new THREE.Mesh(new THREE.BoxGeometry(.32, .32, .32), skin);
  head.position.y = 1.42;
  head.castShadow = true;
  group.add(head);

  const legs = [];
  [-.14, .14].forEach((legX) => {
    const leg = new THREE.Mesh(new THREE.BoxGeometry(.16, .58, .18), dark);
    leg.position.set(legX, .42, 0);
    leg.castShadow = true;
    legs.push(leg);
    group.add(leg);
  });

  const indicator = new THREE.Mesh(
    new THREE.OctahedronGeometry(.2, 0),
    new THREE.MeshStandardMaterial({
      color,
      emissive: color,
      emissiveIntensity: .72,
    }),
  );
  indicator.scale.y = 2.4;
  indicator.position.y = 2.08;
  group.add(indicator);

  const label = makeLabelSprite(shortText(id, 16), "#ffffff", "rgba(15, 23, 42, .78)");
  label.position.y = 2.72;
  group.add(label);

  group.userData.actorId = id;
  group.traverse((child) => { child.userData.actorId = id; });
  sim.worldGroup.add(group);
  sim.characters[id] = {
    group,
    role,
    legs,
    indicator,
    target: null,
    phase: Math.random() * 4,
  };
}

function makeLabelSprite(label, color, background) {
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  canvas.width = 384;
  canvas.height = 82;
  ctx.fillStyle = background;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = "rgba(255,255,255,.18)";
  ctx.lineWidth = 3;
  ctx.strokeRect(1.5, 1.5, canvas.width - 3, canvas.height - 3);
  ctx.font = "800 28px Nunito, system-ui, sans-serif";
  ctx.fillStyle = color;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(label, canvas.width / 2, canvas.height / 2);
  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;
  const material = new THREE.SpriteMaterial({
    map: texture,
    transparent: true,
    depthTest: false,
  });
  const sprite = new THREE.Sprite(material);
  sprite.scale.set(3.8, .82, 1);
  return sprite;
}

function updateSimulationFromEvents() {
  if (sim.fallback) {
    drawFallbackSimulation();
    return;
  }
  (model.state.events || []).forEach((event) => {
    if (sim.seenEvents.has(event.id)) return;
    sim.seenEvents.add(event.id);
    applySimulationEvent(event);
  });
}

function applySimulationEvent(event) {
  const role = simulationRole(event);
  const data = eventData(event);
  const actorId = data.actor_id || event.actor || role;
  if (!sim.characters[actorId]) {
    addCharacter(actorId, role, role === "agent" ? -18 : 18, 10);
  }
  const character = sim.characters[actorId];
  const target = sim.servicePositions[event.target]
    || sim.servicePositions[data.target]
    || Object.values(sim.servicePositions)[0];
  if (!target || !character) return;

  const offset = actorId.split("").reduce((sum, char) => sum + char.charCodeAt(0), 0);
  const angle = (offset % 8) * Math.PI / 4;
  character.target = {
    x: target.x + Math.cos(angle) * 1.75,
    z: target.z + Math.sin(angle) * 1.75,
  };
  spawnPulse(character.group.position, target, role);
  if (target.ring) target.ring.material.color.setHex(roleColor(role));
}

function spawnPulse(from, to, role) {
  const color = roleColor(role);
  const points = [
    new THREE.Vector3(from.x, 1.25, from.z),
    new THREE.Vector3(to.x, 1.25, to.z),
  ];
  const line = new THREE.Line(
    new THREE.BufferGeometry().setFromPoints(points),
    new THREE.LineBasicMaterial({ color, transparent: true, opacity: .88 }),
  );
  sim.worldGroup.add(line);
  sim.effects.push({ object: line, life: 1.2 });

  for (let index = 0; index < 8; index += 1) {
    const particle = new THREE.Mesh(
      new THREE.BoxGeometry(.12, .12, .12),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 1 }),
    );
    particle.position.set(to.x, 1.1, to.z);
    sim.worldGroup.add(particle);
    sim.effects.push({
      object: particle,
      life: .9,
      velocity: new THREE.Vector3(
        (Math.random() - .5) * .18,
        Math.random() * .16 + .06,
        (Math.random() - .5) * .18,
      ),
    });
  }
}

function animateSimulation() {
  if (!sim.renderer || !sim.scene || !sim.camera || !sim.clock) return;
  requestAnimationFrame(animateSimulation);
  const dt = sim.clock.getDelta();
  const elapsed = sim.clock.getElapsedTime();

  Object.values(sim.characters).forEach((character) => {
    character.indicator.rotation.y += dt * 3.2;
    character.indicator.position.y = 2.08 + Math.sin(elapsed * 3) * .05;
    character.phase += dt * 7;
    if (character.target) {
      const pos = character.group.position;
      const dx = character.target.x - pos.x;
      const dz = character.target.z - pos.z;
      const distance = Math.sqrt(dx * dx + dz * dz);
      if (distance > .24) {
        pos.x += (dx / distance) * dt * 4.2;
        pos.z += (dz / distance) * dt * 4.2;
        character.group.rotation.y = Math.atan2(dx, dz);
        character.legs.forEach((leg, index) => {
          leg.rotation.x = Math.sin(character.phase + index * Math.PI) * .5;
        });
      } else {
        character.target = null;
        character.legs.forEach((leg) => { leg.rotation.x = 0; });
      }
    }
  });

  for (let index = sim.effects.length - 1; index >= 0; index -= 1) {
    const effect = sim.effects[index];
    effect.life -= dt;
    if (effect.velocity) {
      effect.object.position.add(effect.velocity);
      effect.velocity.y -= .01;
    }
    if (effect.object.material) {
      effect.object.material.opacity = Math.max(0, effect.life);
    }
    if (effect.life <= 0) {
      sim.worldGroup.remove(effect.object);
      disposeObject(effect.object);
      sim.effects.splice(index, 1);
    }
  }

  if (sim.controls) sim.controls.update();
  sim.renderer.render(sim.scene, sim.camera);
}

function resizeSimulation() {
  const canvas = document.getElementById("sim-canvas");
  if (!canvas) return;
  const width = canvas.clientWidth || window.innerWidth;
  const height = canvas.clientHeight || window.innerHeight;
  if (sim.renderer && sim.camera) {
    const aspect = width / Math.max(1, height);
    const frustum = 16;
    sim.camera.left = -frustum * aspect;
    sim.camera.right = frustum * aspect;
    sim.camera.top = frustum;
    sim.camera.bottom = -frustum;
    sim.camera.updateProjectionMatrix();
    sim.renderer.setSize(width, height, false);
  }
  if (sim.fallback) drawFallbackSimulation();
}

function installActorSelection(canvas) {
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  canvas.addEventListener("click", (event) => {
    if (!sim.camera) return;
    const bounds = canvas.getBoundingClientRect();
    pointer.x = ((event.clientX - bounds.left) / Math.max(1, bounds.width)) * 2 - 1;
    pointer.y = -(((event.clientY - bounds.top) / Math.max(1, bounds.height)) * 2 - 1);
    raycaster.setFromCamera(pointer, sim.camera);
    const roots = Object.values(sim.characters).map((character) => character.group);
    const hits = raycaster.intersectObjects(roots, true);
    for (const hit of hits) {
      const actorId = hit.object.userData.actorId;
      if (actorId) {
        showActorDetails(actorId);
        return;
      }
    }
  });

  document.getElementById("sim-actor-close").addEventListener("click", () => {
    sim.selectedActorId = "";
    renderSelectedActor();
  });
}

function drawFallbackSimulation() {
  const canvas = document.getElementById("sim-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.clientWidth || window.innerWidth;
  const height = canvas.clientHeight || window.innerHeight;
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#07111f";
  ctx.fillRect(0, 0, width, height);
  ctx.strokeStyle = "rgba(147,197,253,.18)";
  for (let x = -height; x < width + height; x += 42) {
    ctx.beginPath();
    ctx.moveTo(x, height * .78);
    ctx.lineTo(x + height, 0);
    ctx.stroke();
  }
  const stations = stationDefinitions();
  const centerX = width / 2;
  const centerY = height / 2 + 30;
  stations.forEach((station, index) => {
    const pos = stationPosition(station, index, stations);
    const x = centerX + pos.x * 22;
    const y = centerY + pos.z * 16;
    ctx.fillStyle = "#102a56";
    ctx.strokeStyle = "#8ec5ff";
    ctx.lineWidth = 3;
    ctx.fillRect(x - 56, y - 28, 112, 56);
    ctx.strokeRect(x - 56, y - 28, 112, 56);
    ctx.fillStyle = "#dbeafe";
    ctx.font = "800 12px Nunito, system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(station.label.toUpperCase(), x, y + 4);
  });
}

function renderSimulationEventLog() {
  const log = document.getElementById("sim-event-log");
  const events = (model.state.events || []).slice(-40).reverse();
  log.innerHTML = "";
  events.forEach((event) => {
    const role = simulationRole(event);
    const item = document.createElement("li");
    const dot = document.createElement("span");
    const label = document.createElement("span");
    dot.className = `sim-dot ${roleCss(role)}`;
    label.textContent = eventLabel(event);
    item.append(dot, label);
    log.appendChild(item);
  });
  if (!events.length) {
    const item = document.createElement("li");
    const dot = document.createElement("span");
    const label = document.createElement("span");
    dot.className = "sim-dot";
    label.textContent = "Waiting for episode events.";
    item.append(dot, label);
    log.appendChild(item);
  }
}

function setGauge(id, value) {
  const gauge = document.getElementById(id);
  const percent = Math.max(0, Math.min(100, value));
  gauge.style.width = `${percent}%`;
  gauge.style.backgroundColor = percent > 66
    ? "#4ade80"
    : percent > 33 ? "#facc15" : "#fb7185";
}

function actorSummary(actorId) {
  return (model.actors || []).find((actor) => actor.actor_id === actorId) || null;
}

function actorProfile(actorId) {
  const people = (model.topology.green_personas || []).length
    ? model.topology.green_personas
    : model.topology.users || [];
  return people.find((person) => person.id === actorId || person.email === actorId)
    || null;
}

function latestActorEvent(actorId) {
  const events = model.state.events || [];
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    const data = eventData(event);
    if (event.actor === actorId || data.actor_id === actorId) return event;
  }
  return null;
}

function showActorDetails(actorId) {
  sim.selectedActorId = actorId;
  renderSelectedActor();
}

function renderSelectedActor() {
  const panel = document.getElementById("sim-actor-panel");
  const actorId = sim.selectedActorId;
  if (!actorId) {
    panel.classList.remove("visible");
    return;
  }

  const summary = actorSummary(actorId);
  const profile = actorProfile(actorId);
  const latest = latestActorEvent(actorId);
  const role = profile
    ? [profile.role, profile.department].filter(Boolean).join(" / ")
    : summary ? summary.actor_kind : sim.characters[actorId]?.role || "event";
  document.getElementById("sim-actor-name").textContent = actorId;
  document.getElementById("sim-actor-role").textContent = role || "event";
  document.getElementById("sim-actor-kind").textContent =
    summary?.actor_kind || sim.characters[actorId]?.role || "event";
  document.getElementById("sim-actor-events").textContent =
    String(summary?.event_count || 0);
  document.getElementById("sim-actor-targets").textContent =
    (summary?.targets || []).join(", ") || profile?.home_host || "none";
  document.getElementById("sim-actor-latest").textContent =
    latest ? eventLabel(latest) : profile?.awareness || "No activity yet.";

  const history = summary?.history || [];
  const list = document.getElementById("sim-actor-history");
  list.innerHTML = "";
  if (!history.length) {
    const item = document.createElement("li");
    item.textContent = "No recent events.";
    list.appendChild(item);
  } else {
    history.slice().reverse().forEach((entry) => {
      const item = document.createElement("li");
      item.textContent = `${entry.event_type} -> ${entry.target}: ${
        shortText(entry.action || entry.observation || "", 80)
      }`;
      list.appendChild(item);
    });
  }
  panel.classList.add("visible");
}

function renderSimulationChrome() {
  const status = model.state.status || "waiting_for_snapshot";
  const eventCount = model.state.event_count || (model.state.events || []).length;
  const taskCount = (model.topology.tasks || []).length;
  const hasSnapshot = Boolean(model.topology.snapshot_id);
  const health = model.state.health || {};
  document.getElementById("sim-subtitle").textContent = hasSnapshot
    ? `${model.briefing.title || "Admitted world"} - ${plural(taskCount, "task")}`
    : "Waiting for an admitted snapshot";
  document.getElementById("sim-status").textContent = status.replaceAll("_", " ");
  document.getElementById("sim-clock").textContent =
    String(eventCount).padStart(2, "0");
  document.getElementById("sim-narrator").textContent =
    model.narration.narration || "No episode activity yet.";
  document.getElementById("sim-empty").classList.toggle("hidden", hasSnapshot);
  setGauge("sim-uptime-gauge", health.uptime ?? (hasSnapshot ? 100 : 12));
  setGauge("sim-defense-gauge", health.defense ?? 100);
  setGauge("sim-integrity-gauge", health.integrity ?? 100);
  renderSimulationEventLog();
  renderSelectedActor();
}

function renderSimulation() {
  initSimulation();
  renderSimulationChrome();
  if (!sim.fallback) {
    rebuildSimulationWorld();
    updateSimulationFromEvents();
  } else {
    drawFallbackSimulation();
  }
}

function renderWorld() {
  const world = model.topology.world || {};
  const rows = Object.entries(world).map(([key, value]) => (
    `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(text(value))}</td></tr>`
  ));
  const artifacts = model.topology.artifact_paths || [];
  document.getElementById("snapshot-pill").className =
    model.topology.snapshot_id ? "pill green" : "pill amber";
  document.getElementById("snapshot-pill").textContent =
    model.topology.snapshot_id ? "Loaded" : "No snapshot";
  const runtimeTopology = {
    zones: model.topology.zones || [],
    services: (model.topology.services || []).map((service) => ({
      id: service.id,
      kind: service.kind,
      zone: service.zone,
      role: service.role,
    })),
    green_personas: (model.topology.green_personas || []).map((persona) => ({
      id: persona.id,
      role: persona.role,
      department: persona.department,
      home_host: persona.home_host,
    })),
  };
  document.getElementById("world").innerHTML = rows.length
    ? `<table class="world-table"><tbody>${rows.join("")}</tbody></table>
       <pre>${pretty({
         artifact_paths: artifacts,
         runtime_topology: runtimeTopology,
       })}</pre>`
    : `<div class="empty">No admitted world is loaded.</div>`;
}

function renderBriefing() {
  const briefing = model.briefing;
  const entrypoints = briefing.entrypoints || [];
  const missions = briefing.missions || [];
  if (!briefing.snapshot_id) {
    document.getElementById("briefing").innerHTML =
      `<div class="empty">No public episode briefing is loaded.</div>`;
    return;
  }
  document.getElementById("briefing").innerHTML = `
    <dl class="kv">
      <dt>Title</dt><dd>${escapeHtml(briefing.title || "Untitled world")}</dd>
      <dt>Goal</dt><dd>${escapeHtml(briefing.goal || "See task mission")}</dd>
      <dt>Entrypoints</dt><dd>${escapeHtml(entrypoints.map((entry) => (
        `${entry.kind}:${entry.target}`
      )).join(", ") || "none")}</dd>
    </dl>
    <div class="list">${missions.map((mission) => (
      `<article class="item">
        <h3>${escapeHtml(mission.task_id)}</h3>
        <p>${escapeHtml(mission.instruction)}</p>
      </article>`
    )).join("")}</div>`;
}

function renderTasks() {
  const tasks = model.topology.tasks || [];
  document.getElementById("task-count").textContent = plural(tasks.length, "task");
  document.getElementById("tasks").innerHTML = tasks.length ? tasks.map((task) => {
    const entrypoints = task.entrypoints || [];
    return `<article class="item">
      <h3>${escapeHtml(task.id)}</h3>
      <p>${escapeHtml(task.instruction)}</p>
      <dl class="kv">
        <dt>Verifier</dt><dd class="mono">${escapeHtml(task.verifier_id)}</dd>
        <dt>Entrypoints</dt>
        <dd>${escapeHtml(entrypoints.map((entry) => (
          `${entry.kind}:${entry.target}`
        )).join(", "))}</dd>
      </dl>
      <pre>${pretty(entrypoints)}</pre>
    </article>`;
  }).join("") : `<div class="empty">No generated tasks are available.</div>`;
}

function renderAdmission() {
  const admission = model.lineage.admission;
  const pill = document.getElementById("admission-pill");
  if (!admission) {
    pill.className = "pill amber";
    pill.textContent = "Waiting";
    document.getElementById("admission").innerHTML =
      `<div class="empty">No admission report is loaded.</div>`;
    return;
  }
  pill.className = pillClass(admission.passed);
  pill.textContent = admission.passed ? "Passed" : "Failed";
  const verifierRows = Object.entries(admission.verifier_results || {}).map(
    ([taskId, result]) => (
    `<article class="item">
      <h3>${escapeHtml(taskId)}</h3>
      <dl class="kv">
        <dt>Passed</dt><dd>${escapeHtml(result.passed)}</dd>
        <dt>Score</dt><dd>${escapeHtml(result.score ?? "")}</dd>
      </dl>
      <pre>${pretty(result)}</pre>
    </article>`
    ),
  );
  document.getElementById("admission").innerHTML = `
    <dl class="kv">
      <dt>Checks</dt><dd>${escapeHtml((admission.checks || []).join(", "))}</dd>
      <dt>Errors</dt><dd>${escapeHtml((admission.errors || []).join(", "))}</dd>
    </dl>
    <div class="list">${verifierRows.join("")}</div>`;
}

function renderLineage() {
  const nodes = model.lineage.nodes || [];
  document.getElementById("lineage-count").textContent = plural(nodes.length, "node");
  document.getElementById("lineage").innerHTML = nodes.length
    ? nodes.map((node, index) => (
    `<article class="item">
      <h3>${index + 1}. ${escapeHtml(node.id)}</h3>
      <dl class="kv">
        <dt>Parent</dt><dd class="mono">${escapeHtml(node.parent_id || "root")}</dd>
        <dt>Prompt</dt><dd>${escapeHtml(node.prompt || "")}</dd>
        <dt>Summary</dt><dd>${escapeHtml(node.builder_summary || "")}</dd>
        <dt>Files</dt><dd>${escapeHtml((node.touched_files || []).join(", "))}</dd>
      </dl>
      <pre>${pretty({
        manifest: node.manifest,
        pack: node.pack,
        curriculum: node.curriculum,
      })}</pre>
    </article>`
    )).join("")
    : `<div class="empty">No lineage nodes are available.</div>`;
}

function eventActorKind(event) {
  if (event.type !== "env_turn" || !event.data) return "";
  return event.data.actor_kind || "";
}

function renderEvents() {
  const events = model.state.events || [];
  const summary = model.state.activity_summary || {};
  document.getElementById("event-count").textContent = plural(events.length, "event");
  document.getElementById("events").innerHTML = events.length
    ? `<pre>${pretty(summary)}</pre>` +
      events.slice().reverse().map((event) => {
    const kind = eventActorKind(event);
    const detail = event.type === "env_turn" ? event.data : event;
    return `<article class="event ${escapeHtml(kind)}">
      <h3>
        <span>${escapeHtml(event.actor)} -> ${escapeHtml(event.target)}</span>
        <small>${escapeHtml(event.type)}</small>
      </h3>
      <dl class="kv">
        <dt>Actor kind</dt><dd>${escapeHtml(kind || "event")}</dd>
        <dt>Action</dt><dd>${escapeHtml(text(detail.action || event.data))}</dd>
        <dt>Observation</dt><dd>${escapeHtml(text(detail.observation || ""))}</dd>
      </dl>
      <pre>${pretty(detail)}</pre>
    </article>`;
    }).join("")
    : `<div class="empty">No episode activity yet.</div>`;
}

function renderActors() {
  const actors = model.actors || [];
  document.getElementById("actor-count").textContent =
    plural(actors.length, "actor");
  document.getElementById("actors").innerHTML = actors.length
    ? actors.map((actor) => (
    `<article class="item">
      <h3>${escapeHtml(actor.actor_id)}</h3>
      <dl class="kv">
        <dt>Kind</dt><dd>${escapeHtml(actor.actor_kind)}</dd>
        <dt>Events</dt><dd>${escapeHtml(actor.event_count)}</dd>
        <dt>Targets</dt><dd>${escapeHtml((actor.targets || []).join(", "))}</dd>
        <dt>Latest</dt><dd>${escapeHtml(actor.latest_event_type || "")}</dd>
      </dl>
      <pre>${pretty({
        latest_action: actor.latest_action,
        latest_observation: actor.latest_observation,
        history: actor.history,
      })}</pre>
    </article>`
    )).join("")
    : `<div class="empty">No actor activity yet.</div>`;
}

function detailPayload() {
  if (model.detail === "briefing") return model.briefing;
  if (model.detail === "actors") return model.actors;
  if (model.detail === "lineage") return model.lineage;
  if (model.detail === "state") return model.state;
  if (model.detail === "events") return model.state.events || [];
  return model.topology;
}

function renderDetails() {
  const tabs = [
    ["briefing", "Briefing"],
    ["actors", "Actors"],
    ["topology", "Topology"],
    ["lineage", "Lineage"],
    ["state", "State"],
    ["events", "Events"],
  ];
  document.getElementById("detail-tabs").innerHTML = tabs.map(([id, label]) => (
    `<button class="tab ${model.detail === id ? "active" : ""}" ` +
      `data-detail="${id}">${label}</button>`
  )).join("");
  document.querySelectorAll("[data-detail]").forEach((tab) => {
    tab.addEventListener("click", () => {
      model.detail = tab.dataset.detail;
      renderDetails();
    });
  });
  document.getElementById("details").innerHTML =
    `<pre>${pretty(detailPayload())}</pre>`;
}

function render() {
  renderMetrics();
  renderSimulation();
  renderBriefing();
  renderWorld();
  renderTasks();
  renderAdmission();
  renderLineage();
  renderEvents();
  renderActors();
  renderDetails();
  document.getElementById("narration").textContent =
    model.narration.narration || "No episode activity yet.";
}

async function refresh() {
  const [briefing, actors, topology, lineage, state, narration] = await Promise.all([
    json("/api/briefing"),
    json("/api/actors"),
    json("/api/topology"),
    json("/api/lineage"),
    json("/api/state"),
    json("/api/narrate"),
  ]);
  model.briefing = briefing;
  model.actors = actors;
  model.topology = topology;
  model.lineage = lineage;
  model.state = state;
  model.narration = narration;
  render();
}

document.querySelectorAll("button[data-action]").forEach((button) => {
  button.addEventListener("click", async () => {
    await json(`/api/episode/${button.dataset.action}`, { method: "POST" });
    await refresh();
  });
});
const events = new EventSource("/api/events/stream");
events.addEventListener("agent_step", refresh);
events.addEventListener("env_turn", refresh);
events.addEventListener("note", refresh);
const narration = new EventSource("/api/narrate/stream");
narration.addEventListener("narration", refresh);
refresh();
</script>
</body>
</html>
"""


def read_dashboard_events(path: Path) -> list[DashboardEvent]:
    if not path.exists():
        return []
    events: list[DashboardEvent] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, Mapping):
            events.append(dashboard_event_from_mapping(data))
    return events


def read_dashboard_state(path: Path) -> Mapping[str, object]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, Mapping) else {}


def dashboard_event_from_mapping(data: Mapping[str, object]) -> DashboardEvent:
    event_id = data.get("id")
    event_type = data.get("type")
    actor = data.get("actor")
    target = data.get("target")
    time = data.get("time")
    event_data = data.get("data", {})
    return DashboardEvent(
        str(event_id),
        str(event_type),
        str(actor),
        str(target),
        float(time) if isinstance(time, int | float) else 0.0,
        MappingProxyType(dict(event_data if isinstance(event_data, Mapping) else {})),
    )


def write_dashboard_state(
    path: Path,
    events: Sequence[DashboardEvent],
    snapshot: DashboardView | None,
) -> None:
    event_rows = [event.as_dict() for event in events]
    turns = [dict(event.data) for event in events if event.type == "env_turn"]
    builder_steps = [
        dict(event.data) for event in events if event.type == "builder_step"
    ]
    state = (
        {
            "running": False,
            "snapshot_id": None,
            "events": event_rows,
        }
        if snapshot is None
        else snapshot.state()
    )
    payload: dict[str, object] = {
        "topology": {} if snapshot is None else snapshot.topology(),
        "lineage": {} if snapshot is None else snapshot.lineage(),
        "state": state,
        "turns": turns,
        "builder": {"steps": builder_steps},
        "narration": {"narration": fallback_narrate(events)},
    }
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(
        json.dumps(json_safe(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
