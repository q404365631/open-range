"""Witness-driven runtime with simulated time and internal green progression."""

from __future__ import annotations

from math import inf
from typing import Literal
from uuid import uuid4

from open_range.episode_config import DEFAULT_EPISODE_CONFIG, EpisodeConfig
from open_range.execution import ActionBackend, ActionExecution
from open_range.green import GreenScheduler, ScriptedGreenScheduler
from open_range.rewards import RewardEngine
from open_range.runtime_types import (
    Action,
    ActionResult,
    ActorSessionState,
    Decision,
    EpisodeScore,
    EpisodeState,
    ExternalRole,
    Observation,
    RuntimeEvent,
    ServiceHealth,
)
from open_range.snapshot import Snapshot


class WitnessDrivenRuntime:
    """Runtime for admitted snapshots with actor-specific decisions."""

    def __init__(
        self,
        *,
        green_scheduler: GreenScheduler | None = None,
        action_backend: ActionBackend | None = None,
    ) -> None:
        self.green_scheduler = green_scheduler or ScriptedGreenScheduler()
        self.action_backend = action_backend
        self.reward_engine = RewardEngine()
        self._snapshot: Snapshot | None = None
        self._episode_config = DEFAULT_EPISODE_CONFIG
        self._state = EpisodeState(snapshot_id="", episode_id="")
        self._events: list[RuntimeEvent] = []
        self._event_visibility: dict[str, dict[str, float]] = {}
        self._observed_event_ids = {"red": set(), "blue": set()}
        self._last_reward_delta = {"red": 0.0, "blue": 0.0}
        self._red_reward_shaping = 0.0
        self._blue_reward_shaping = 0.0
        self._red_progress = 0
        self._blue_detected = False
        self._blue_contained = False
        self._contained_targets: set[str] = set()
        self._red_objectives_satisfied: set[str] = set()
        self._blue_objectives_satisfied: set[str] = set()
        self._detected_event_ids: set[str] = set()
        self._last_red_target = ""
        self._event_seq = 0
        self._decision_seq = 0
        self._pending_actor: ExternalRole | Literal[""] = ""
        self._next_due_time = {"red": 0.0, "blue": 0.0}

    def reset(
        self,
        snapshot: Snapshot,
        episode_config: EpisodeConfig = DEFAULT_EPISODE_CONFIG,
    ) -> EpisodeState:
        self._snapshot = snapshot
        self._episode_config = episode_config
        self.reward_engine.reset()
        self._events = []
        self._event_visibility = {}
        self._observed_event_ids = {"red": set(), "blue": set()}
        self._last_reward_delta = {"red": 0.0, "blue": 0.0}
        self._red_reward_shaping = 0.0
        self._blue_reward_shaping = 0.0
        self._red_progress = 0
        self._blue_detected = False
        self._blue_contained = False
        self._contained_targets = set()
        self._red_objectives_satisfied = set()
        self._blue_objectives_satisfied = set()
        self._detected_event_ids = set()
        self._last_red_target = ""
        self._event_seq = 0
        self._decision_seq = 0
        self._pending_actor = ""
        self._next_due_time = _initial_due_times(episode_config)

        service_health = {service.id: 1.0 for service in snapshot.world.services}
        if self.action_backend is not None:
            live_health = self.action_backend.service_health()
            if live_health:
                service_health.update(live_health)
        continuity = sum(service_health.values()) / len(service_health) if service_health else 1.0
        self._state = EpisodeState(
            snapshot_id=snapshot.snapshot_id,
            episode_id=f"ep-{uuid4()}",
            sim_time=0.0,
            done=False,
            winner="",
            terminal_reason="",
            continuity=continuity,
            service_health=service_health,
            controls_red=episode_config.controls_red,
            controls_blue=episode_config.controls_blue,
            next_actor="",
            decision_count=0,
            red_session=ActorSessionState(session_id=f"red-{uuid4()}", actor_id="red", role="red"),
            blue_session=ActorSessionState(session_id=f"blue-{uuid4()}", actor_id="blue", role="blue"),
        )
        self.green_scheduler.reset(snapshot, episode_config)
        self._apply_prefix_start()
        self._advance_until_external_decision()
        return self.state()

    def set_action_backend(self, action_backend: ActionBackend | None) -> None:
        self.action_backend = action_backend

    def next_decision(self) -> Decision:
        if self._snapshot is None:
            raise RuntimeError("runtime must be reset before next_decision()")
        if self._state.done:
            raise RuntimeError("episode is done; reset() is required before more decisions")
        if not self._pending_actor:
            self._advance_until_external_decision()
        if not self._pending_actor:
            raise RuntimeError("no external decision is available")

        actor = self._pending_actor
        obs = self._build_observation(actor)
        self._decision_seq += 1
        self._state.decision_count += 1
        self._state.next_actor = actor
        return Decision(decision_id=f"dec-{self._decision_seq}", actor=actor, obs=obs)

    def act(self, actor: str, action: Action) -> ActionResult:
        if self._snapshot is None:
            raise RuntimeError("runtime must be reset before act()")
        if self._state.done:
            raise RuntimeError("episode is done; reset() is required before more actions")
        if actor not in {"red", "blue"}:
            raise ValueError("public act() only supports red and blue")
        if self._pending_actor != actor:
            raise RuntimeError(f"cannot act as {actor!r}; next actor is {self._pending_actor!r}")
        if action.role != actor:
            raise ValueError("action.role must match the acting external role")

        result = self._act_red(action) if actor == "red" else self._act_blue(action)
        self._pending_actor = ""
        self._state.next_actor = ""
        self._advance_due_time(actor)
        self._check_terminal_conditions()
        return result.model_copy(update={"done": self._state.done, "sim_time": round(self._state.sim_time, 4)})

    def score(self) -> EpisodeScore:
        red_terminal, blue_terminal = self.reward_engine.terminal_rewards(
            winner=self._state.winner,
            done=self._state.done,
        )
        return EpisodeScore(
            snapshot_id=self._state.snapshot_id,
            episode_id=self._state.episode_id,
            done=self._state.done,
            winner=self._state.winner,
            terminal_reason=self._state.terminal_reason,
            sim_time=round(self._state.sim_time, 4),
            continuity=self._state.continuity,
            red_reward=round(self._red_reward_shaping + red_terminal, 4),
            blue_reward=round(self._blue_reward_shaping + blue_terminal, 4),
            red_objectives_satisfied=tuple(sorted(self._red_objectives_satisfied)),
            blue_objectives_satisfied=tuple(sorted(self._blue_objectives_satisfied)),
            event_count=len(self._events),
        )

    def state(self) -> EpisodeState:
        self._state.red_objectives_satisfied = tuple(sorted(self._red_objectives_satisfied))
        self._state.blue_objectives_satisfied = tuple(sorted(self._blue_objectives_satisfied))
        self._state.next_actor = self._pending_actor
        return self._state.model_copy(deep=True)

    def close(self) -> None:
        self._snapshot = None
        self._pending_actor = ""
        self._state.done = True
        self._state.next_actor = ""

    def export_events(self) -> tuple[RuntimeEvent, ...]:
        return tuple(self._events)

    def _apply_prefix_start(self) -> None:
        if self._snapshot is None:
            return
        if self._episode_config.mode != "blue_only_from_prefix" or self._episode_config.start_state == "clean":
            return
        for _ in range(len(self._snapshot.witness_bundle.red_witnesses[0].steps)):
            step = self._next_red_step()
            if step is None or self._state.done:
                break
            due = max(self._state.sim_time, self._next_due_time["red"])
            self._advance_time(due)
            emitted = self._act_red(_runtime_action("red", step), internal=True).emitted_events
            self._advance_due_time("red")
            self._check_terminal_conditions()
            if self._prefix_satisfied(self._episode_config.start_state, emitted):
                break

    def _prefix_satisfied(self, start_state: str, emitted: tuple[RuntimeEvent, ...]) -> bool:
        event_types = {event.event_type for event in emitted}
        if start_state == "post_delivery":
            return True
        if start_state in {"post_click", "post_foothold"}:
            return "InitialAccess" in event_types
        if start_state == "post_credential_theft":
            return "CredentialObtained" in event_types
        if start_state == "during_lateral_movement":
            return "CrossZoneTraversal" in event_types or self._red_progress >= 2
        return False

    def _advance_until_external_decision(self) -> None:
        while not self._state.done and not self._pending_actor:
            actor, due_time = self._next_scheduled_actor()
            if actor is None:
                self._state.done = True
                self._state.winner = "failure"
                self._state.terminal_reason = "scheduler_exhausted"
                return
            if due_time > self._state.sim_time:
                self._advance_time(due_time)
                continue
            if self._is_controlled(actor):
                self._pending_actor = actor
                self._state.next_actor = actor
                return
            internal_action = self._internal_action(actor)
            if actor == "red":
                self._act_red(internal_action, internal=True)
            else:
                self._act_blue(internal_action, internal=True)
            self._advance_due_time(actor)
            self._check_terminal_conditions()

    def _next_scheduled_actor(self) -> tuple[ExternalRole | None, float]:
        candidates = sorted(
            ((role, due_time) for role, due_time in self._next_due_time.items()),
            key=lambda item: (item[1], 0 if item[0] == "red" else 1),
        )
        if not candidates:
            return None, inf
        return candidates[0]

    def _advance_time(self, target_time: float) -> None:
        if self._state.done:
            return
        self._state.sim_time = round(target_time, 4)
        if self._state.sim_time >= self._episode_config.episode_horizon:
            self._state.done = True
            self._state.winner = "timeout"
            self._state.terminal_reason = "timeout"
            return
        self.green_scheduler.advance_until(self._state.sim_time)
        self._drain_green()

    def _drain_green(self) -> None:
        while not self._state.done:
            ready = self.green_scheduler.pop_ready_actions()
            if not ready:
                break
            for action in ready:
                self._act_green(action)
                if self._state.done:
                    return

    def _build_observation(self, actor: ExternalRole) -> Observation:
        visible = self._visible_events(actor)
        alerts = tuple(
            event
            for event in visible
            if event.malicious or event.event_type in {"DetectionAlertRaised", "ContainmentApplied", "ServiceDegraded"}
        )
        reward_delta = self._last_reward_delta[actor]
        self._last_reward_delta[actor] = 0.0
        self._observed_event_ids[actor].update(event.id for event in visible)
        session = self._state.red_session if actor == "red" else self._state.blue_session
        if session is not None:
            session.observation_count += 1
        return Observation(
            actor_id=actor,
            sim_time=round(self._state.sim_time, 4),
            stdout=f"sim_time={self._state.sim_time:.2f}",
            visible_events=visible,
            alerts_delta=alerts,
            service_health=self._service_health_tuple(),
            reward_delta=reward_delta,
            done=self._state.done,
        )

    def _act_green(self, action: Action) -> ActionResult:
        target = str(action.payload.get("service", action.payload.get("target", "")))
        live = self._execute_live_action(action)
        emitted = self._green_events_for_action(action, live, target) if live.ok else ()
        self._state.sim_time = round(min(self._state.sim_time + 0.01, self._episode_config.episode_horizon), 4)
        return ActionResult(
            action=action,
            sim_time=self._state.sim_time,
            stdout=live.stdout or f"green routine executed on {target}",
            stderr=live.stderr,
            emitted_events=emitted,
            reward_delta=0.0,
            done=self._state.done,
        )

    def _green_events_for_action(
        self,
        action: Action,
        live: ActionExecution,
        target: str,
    ) -> tuple[RuntimeEvent, ...]:
        branch = str(action.payload.get("branch", "")).lower()
        reported_target = str(action.payload.get("reported_target", target)) or target
        if branch == "report_suspicious_activity":
            return (
                self._emit_event(
                    event_type="DetectionAlertRaised",
                    actor="green",
                    source_entity=action.actor_id,
                    target_entity=reported_target,
                    malicious=False,
                    observability_surfaces=("svc-siem",),
                ),
            )
        if branch == "reset_password" and live.recovery_applied:
            return (
                self._emit_event(
                    event_type="RecoveryCompleted",
                    actor="green",
                    source_entity=action.actor_id,
                    target_entity=reported_target,
                    malicious=False,
                    observability_surfaces=self._service_surfaces(target),
                ),
            )
        return (
            self._emit_event(
                event_type="BenignUserAction",
                actor="green",
                source_entity=action.actor_id,
                target_entity=target,
                malicious=False,
                observability_surfaces=self._service_surfaces(target),
            ),
        )

    def _act_red(self, action: Action, *, internal: bool = False) -> ActionResult:
        if self._state.red_session is not None:
            self._state.red_session.action_count += 1

        emitted: list[RuntimeEvent] = []
        target = _action_target(action)
        exec_action = action
        if self.action_backend is not None:
            payload = dict(action.payload)
            payload.setdefault("origin", self._last_red_target or "sandbox-red")
            if target:
                payload.setdefault("target", target)
            exec_action = action.model_copy(update={"payload": payload})
        live = self._execute_live_action(exec_action)
        stdout = live.stdout or "red action had no strategic effect"
        stderr = live.stderr

        expected = self._next_red_step()
        if target in self._contained_targets:
            containment_msg = f"target {target} is contained"
            if containment_msg not in {line.strip() for line in stderr.splitlines() if line.strip()}:
                stderr = "\n".join(filter(None, [stderr, containment_msg])).strip()
        elif expected is not None and live.ok and self._matches_step(action, expected):
            self._red_progress += 1
            stdout = f"red advanced on {target}"
            emitted = self._events_for_red_step(expected, action)
        else:
            stdout = live.stdout or f"red executed on {target or 'unknown target'}"

        reward_delta = self.reward_engine.on_red_action(
            action,
            tuple(emitted),
            shaping_enabled=self._episode_config.red_shaping_enabled,
        )
        self._red_reward_shaping += reward_delta
        if not internal:
            self._last_reward_delta["red"] += reward_delta

        return ActionResult(
            action=action,
            sim_time=round(self._state.sim_time, 4),
            stdout=stdout,
            stderr=stderr,
            emitted_events=tuple(emitted),
            reward_delta=reward_delta,
            done=self._state.done,
        )

    def _act_blue(self, action: Action, *, internal: bool = False) -> ActionResult:
        if self._state.blue_session is not None:
            self._state.blue_session.action_count += 1

        emitted: list[RuntimeEvent] = []
        reward_delta = 0.0
        live = self._execute_live_action(action)
        stdout = live.stdout or "blue action applied"
        stderr = live.stderr

        if action.kind == "submit_finding":
            event_type = str(action.payload.get("event_type", action.payload.get("event", "")))
            target = str(action.payload.get("target", ""))
            matched = self._find_detectable_event(event_type, target, visible_only=True)
            if matched is not None:
                emitted.append(
                    self._emit_event(
                        event_type="DetectionAlertRaised",
                        actor="blue",
                        source_entity="blue",
                        target_entity=matched.target_entity,
                        malicious=False,
                        observability_surfaces=("svc-siem",),
                        linked_objective_predicates=("intrusion_detected(initial_access)",),
                    )
                )
                self._blue_detected = True
                self._blue_objectives_satisfied.add("intrusion_detected(initial_access)")
                self._detected_event_ids.add(matched.id)
                reward_delta += self.reward_engine.on_blue_detection(
                    matched,
                    shaping_enabled=self._episode_config.blue_shaping_enabled,
                )
                stdout = f"validated finding for {matched.event_type}"
            else:
                reward_delta += self.reward_engine.on_blue_detection(
                    None,
                    shaping_enabled=self._episode_config.blue_shaping_enabled,
                )
                stdout = "finding rejected as false positive"
        elif action.kind == "control":
            target = _action_target(action)
            remaining_targets = self._remaining_red_targets()
            continuity_before = self._state.continuity
            if target and target in remaining_targets and live.containment_applied:
                self._contained_targets.add(target)
                emitted.append(
                    self._emit_event(
                        event_type="ContainmentApplied",
                        actor="blue",
                        source_entity="blue",
                        target_entity=target,
                        malicious=False,
                        observability_surfaces=("svc-siem",),
                        linked_objective_predicates=("intrusion_contained(before_asset_read)",),
                    )
                )
                self._blue_contained = True
                self._blue_objectives_satisfied.add("intrusion_contained(before_asset_read)")
                stdout = f"containment applied to {target}"
                self._update_continuity()
                reward_delta += self.reward_engine.on_blue_containment(
                    target=target,
                    path_broken=True,
                    continuity_before=continuity_before,
                    continuity_after=self._state.continuity,
                    shaping_enabled=self._episode_config.blue_shaping_enabled,
                )
            else:
                stdout = live.stdout or f"control action on {target or 'unknown target'} had no path-breaking effect"
                self._update_continuity()
                reward_delta += self.reward_engine.on_blue_containment(
                    target=target,
                    path_broken=False,
                    continuity_before=continuity_before,
                    continuity_after=self._state.continuity,
                    shaping_enabled=self._episode_config.blue_shaping_enabled,
                )
        elif action.kind == "sleep":
            stdout = "blue slept"
        else:
            stdout = live.stdout or f"blue executed {action.kind}"

        self._blue_reward_shaping += reward_delta
        if not internal:
            self._last_reward_delta["blue"] += reward_delta

        return ActionResult(
            action=action,
            sim_time=round(self._state.sim_time, 4),
            stdout=stdout,
            stderr=stderr,
            emitted_events=tuple(emitted),
            reward_delta=reward_delta,
            done=self._state.done,
        )

    def _events_for_red_step(self, expected, action: Action) -> list[RuntimeEvent]:
        emitted: list[RuntimeEvent] = []
        target = expected.target
        step_action = str(expected.payload.get("action", ""))
        asset_id = str(expected.payload.get("asset", ""))

        if step_action == "initial_access":
            emitted.append(
                self._emit_event(
                    event_type="InitialAccess",
                    actor="red",
                    source_entity=action.actor_id,
                    target_entity=target,
                    malicious=True,
                    observability_surfaces=self._service_surfaces(target),
                )
            )
        elif step_action == "traverse":
            emitted.append(
                self._emit_event(
                    event_type="CrossZoneTraversal",
                    actor="red",
                    source_entity=self._last_red_target or action.actor_id,
                    target_entity=target,
                    malicious=True,
                    observability_surfaces=self._service_surfaces(target),
                )
            )
        elif step_action == "satisfy_objective":
            if asset_id and "cred" in asset_id:
                emitted.append(
                    self._emit_event(
                        event_type="CredentialObtained",
                        actor="red",
                        source_entity=target,
                        target_entity=asset_id,
                        malicious=True,
                        observability_surfaces=self._service_surfaces(target),
                        linked_objective_predicates=(f"credential_obtained({asset_id})",),
                    )
                )
                self._red_objectives_satisfied.add(f"credential_obtained({asset_id})")
            elif asset_id:
                emitted.append(
                    self._emit_event(
                        event_type="SensitiveAssetRead",
                        actor="red",
                        source_entity=target,
                        target_entity=asset_id,
                        malicious=True,
                        observability_surfaces=self._service_surfaces(target),
                        linked_objective_predicates=(f"asset_read({asset_id})",),
                    )
                )
                self._red_objectives_satisfied.add(f"asset_read({asset_id})")
        self._last_red_target = target
        return emitted

    def _next_red_step(self):
        if self._snapshot is None:
            return None
        trace = self._snapshot.witness_bundle.red_witnesses[0]
        if self._red_progress >= len(trace.steps):
            return None
        return trace.steps[self._red_progress]

    @staticmethod
    def _matches_step(action: Action, expected) -> bool:
        return action.kind == expected.kind and _action_target(action) == expected.target

    def _find_detectable_event(
        self,
        event_type: str,
        target: str,
        *,
        visible_only: bool,
    ) -> RuntimeEvent | None:
        for event in self._events:
            if not event.malicious:
                continue
            if event.event_type != event_type:
                continue
            if target and event.target_entity != target:
                continue
            if visible_only and not self._is_visible_to("blue", event):
                continue
            return event
        return None

    def _remaining_red_targets(self) -> set[str]:
        if self._snapshot is None:
            return set()
        trace = self._snapshot.witness_bundle.red_witnesses[0]
        return {step.target for step in trace.steps[self._red_progress:]}

    def _check_terminal_conditions(self) -> None:
        red_terminal = self._red_terminal_satisfied()
        blue_terminal = self._blue_terminal_satisfied(red_terminal)
        if red_terminal:
            self._state.done = True
            self._state.winner = "red"
            self._state.terminal_reason = "red_terminal"
            self._pending_actor = ""
            return
        if blue_terminal:
            self._state.done = True
            self._state.winner = "blue"
            self._state.terminal_reason = "blue_terminal"
            self._pending_actor = ""
            return
        if self._state.sim_time >= self._episode_config.episode_horizon:
            self._state.done = True
            self._state.winner = "timeout"
            self._state.terminal_reason = "timeout"
            self._pending_actor = ""

    def _red_terminal_satisfied(self) -> bool:
        if self._snapshot is None:
            return False
        required = {objective.predicate for objective in self._snapshot.world.red_objectives if objective.terminal}
        return bool(required) and required <= self._red_objectives_satisfied

    def _blue_terminal_satisfied(self, red_terminal: bool) -> bool:
        continuity_ok = (
            self._state.continuity >= self._episode_config.continuity_threshold
            if self._episode_config.continuity_enforced
            else True
        )
        return not red_terminal and self._blue_detected and self._blue_contained and continuity_ok

    def _update_continuity(self) -> None:
        if not self._state.service_health:
            self._state.continuity = 1.0
            return
        self._state.continuity = sum(self._state.service_health.values()) / len(self._state.service_health)
        if self._episode_config.continuity_enforced and self._state.continuity < self._episode_config.continuity_threshold:
            self._blue_objectives_satisfied.discard("service_health_above(0.9)")
        elif self._episode_config.continuity_enforced:
            self._blue_objectives_satisfied.add("service_health_above(0.9)")

    def _service_health_tuple(self) -> tuple[ServiceHealth, ...]:
        return tuple(
            ServiceHealth(service_id=service_id, health=health)
            for service_id, health in sorted(self._state.service_health.items())
        )

    def _visible_events(self, actor: ExternalRole) -> tuple[RuntimeEvent, ...]:
        visible: list[RuntimeEvent] = []
        for event in self._events:
            if event.id in self._observed_event_ids[actor]:
                continue
            if not self._is_visible_to(actor, event):
                continue
            if actor == "blue":
                if event.observability_surfaces:
                    visible.append(event)
                continue
            if event.actor in {"green", "red"} or event.event_type in {"ContainmentApplied", "RecoveryCompleted", "ServiceDegraded"}:
                visible.append(event)
        return tuple(visible)

    def _is_visible_to(self, actor: ExternalRole, event: RuntimeEvent) -> bool:
        visible_at = self._event_visibility.get(event.id, {}).get(actor, inf)
        return visible_at <= self._state.sim_time

    def _emit_event(
        self,
        *,
        event_type: str,
        actor: Literal["red", "blue", "green"],
        source_entity: str,
        target_entity: str,
        malicious: bool,
        observability_surfaces: tuple[str, ...],
        linked_objective_predicates: tuple[str, ...] = (),
    ) -> RuntimeEvent:
        self._event_seq += 1
        event = RuntimeEvent(
            id=f"evt-{self._event_seq}",
            event_type=event_type,
            actor=actor,
            time=round(self._state.sim_time, 4),
            source_entity=source_entity,
            target_entity=target_entity,
            malicious=malicious,
            observability_surfaces=observability_surfaces,
            linked_objective_predicates=linked_objective_predicates,
        )
        self._events.append(event)
        blue_delay = 0.5 if self._episode_config.telemetry_delay_enabled else 0.0
        self._event_visibility[event.id] = {
            "red": self._state.sim_time,
            "blue": self._state.sim_time + (blue_delay if observability_surfaces else inf),
        }
        self.green_scheduler.record_event(event)
        if self.action_backend is not None:
            self.action_backend.record_event(event)
        return event

    def _service_surfaces(self, target: str) -> tuple[str, ...]:
        if self._snapshot is None:
            return ()
        for service in self._snapshot.world.services:
            if service.id == target:
                return tuple(service.telemetry_surfaces) + ("svc-siem",)
        return ("svc-siem",)

    def _execute_live_action(self, action: Action) -> ActionExecution:
        if self.action_backend is None:
            directive = str(action.payload.get("action", "contain")).lower()
            return ActionExecution(
                containment_applied=action.kind == "control" and directive not in {"recover", "restore"},
                recovery_applied=action.kind == "control" and directive in {"recover", "restore"},
            )
        result = self.action_backend.execute(action)
        if result.service_health:
            self._state.service_health.update(result.service_health)
            self._update_continuity()
        return result

    def _advance_due_time(self, actor: ExternalRole) -> None:
        cadence = 1.0
        self._next_due_time[actor] = round(max(self._next_due_time[actor], self._state.sim_time) + cadence, 4)

    def _is_controlled(self, actor: ExternalRole) -> bool:
        return self._state.controls_red if actor == "red" else self._state.controls_blue

    def _internal_action(self, actor: ExternalRole) -> Action:
        if actor == "red":
            if self._episode_config.opponent_red == "sleep":
                return Action(actor_id="red", role="red", kind="sleep", payload={})
            step = self._next_red_step()
            if step is None:
                return Action(actor_id="red", role="red", kind="sleep", payload={})
            return _runtime_action("red", step)

        if self._episode_config.opponent_blue == "sleep":
            return Action(actor_id="blue", role="blue", kind="sleep", payload={})
        for event in self._visible_events("blue"):
            if event.malicious and event.id not in self._detected_event_ids:
                return Action(
                    actor_id="blue",
                    role="blue",
                    kind="submit_finding",
                    payload={"event_type": event.event_type, "target": event.target_entity},
                )
        remaining = sorted(self._remaining_red_targets() - self._contained_targets)
        if remaining and self._blue_detected:
            return Action(actor_id="blue", role="blue", kind="control", payload={"target": remaining[0], "action": "contain"})
        return Action(actor_id="blue", role="blue", kind="sleep", payload={})


def _runtime_action(actor: ExternalRole, step) -> Action:
    payload = dict(step.payload)
    if step.target:
        payload.setdefault("target", step.target)
    if actor == "blue" and step.kind == "submit_finding":
        payload["event_type"] = str(payload.get("event", payload.get("event_type", "InitialAccess")))
    return Action(actor_id=actor, role=actor, kind=step.kind, payload=payload)


def _initial_due_times(config: EpisodeConfig) -> dict[str, float]:
    if config.scheduler_mode == "strict_turn":
        return {"red": 0.0, "blue": 0.0}
    return {"red": 0.0, "blue": 0.5 if config.telemetry_delay_enabled else 0.0}


def _action_target(action: Action) -> str:
    target = action.payload.get("target")
    if isinstance(target, str) and target:
        return target
    service = action.payload.get("service")
    if isinstance(service, str) and service:
        return service
    return ""
