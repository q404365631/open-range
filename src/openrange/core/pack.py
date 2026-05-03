"""Pack contracts and generated task artifacts."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import cast

from openrange.core.errors import PackError, StoreError

VerifierResult = Mapping[str, object]
Verifier = Callable[[Mapping[str, object]], VerifierResult]
AdmissionState = Callable[[Mapping[str, object]], Mapping[str, object]]


def verifier_from_source(source: str) -> Verifier:
    namespace: dict[str, object] = {}
    try:
        exec(source, {"__builtins__": {}}, namespace)
    except Exception as exc:
        raise StoreError("stored verifier source is invalid") from exc
    verify = namespace.get("verify")
    if not callable(verify):
        raise StoreError("stored verifier source must define verify()")

    def run(state: Mapping[str, object]) -> VerifierResult:
        result = cast(Verifier, verify)(state)
        if not isinstance(result, Mapping):
            raise StoreError("verifier returned invalid result")
        return MappingProxyType(dict(result))

    return run


def admission_state_from_source(source: str) -> AdmissionState:
    namespace: dict[str, object] = {}
    try:
        exec(source, {"__builtins__": {}}, namespace)
    except Exception as exc:
        raise StoreError("stored admission source is invalid") from exc
    admission_state = namespace.get("admission_state")
    if not callable(admission_state):
        raise StoreError("stored admission source must define admission_state()")

    def run(interface: Mapping[str, object]) -> Mapping[str, object]:
        state = cast(AdmissionState, admission_state)(interface)
        if not isinstance(state, Mapping):
            raise StoreError("admission source returned invalid final state")
        return MappingProxyType(dict(state))

    return run


@dataclass(frozen=True, slots=True)
class Entrypoint:
    kind: str
    target: str
    metadata: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "target": self.target,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> Entrypoint:
        kind = data.get("kind")
        target = data.get("target")
        metadata = data.get("metadata", {})
        if not isinstance(kind, str) or not isinstance(target, str):
            raise StoreError("stored entrypoint is invalid")
        if not isinstance(metadata, Mapping):
            raise StoreError("stored entrypoint metadata is invalid")
        return cls(kind, target, MappingProxyType(dict(metadata)))


@dataclass(frozen=True, slots=True)
class Task:
    id: str
    instruction: str
    entrypoints: tuple[Entrypoint, ...]
    verifier_id: str
    verify: Verifier

    @property
    def interface(self) -> tuple[Entrypoint, ...]:
        return self.entrypoints

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "instruction": self.instruction,
            "entrypoints": [entrypoint.as_dict() for entrypoint in self.entrypoints],
            "verifier_id": self.verifier_id,
        }


@dataclass(frozen=True, slots=True)
class GeneratedWorld:
    world: Mapping[str, object]
    artifacts: Mapping[str, str]
    runtime: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "world": dict(self.world),
            "artifacts": dict(self.artifacts),
            "runtime": dict(self.runtime),
        }


@dataclass(frozen=True, slots=True)
class GeneratedTask:
    id: str
    instruction: str
    entrypoints: tuple[Entrypoint, ...]
    verifier_id: str

    def as_task(self, verifier: Verifier) -> Task:
        return Task(
            self.id,
            self.instruction,
            self.entrypoints,
            self.verifier_id,
            verifier,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "instruction": self.instruction,
            "entrypoints": [entrypoint.as_dict() for entrypoint in self.entrypoints],
            "verifier_id": self.verifier_id,
        }


@dataclass(frozen=True, slots=True)
class GeneratedVerifier:
    id: str
    task_id: str
    source: str

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class GeneratedAdmission:
    task_id: str
    source: str
    final_state: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "source": self.source,
            "final_state": dict(self.final_state),
        }


@dataclass(frozen=True, slots=True)
class GeneratedArtifacts:
    world: GeneratedWorld
    tasks: tuple[GeneratedTask, ...]
    verifiers: tuple[GeneratedVerifier, ...]
    admission: tuple[GeneratedAdmission, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "world": self.world.as_dict(),
            "tasks": [task.as_dict() for task in self.tasks],
            "verifiers": [verifier.as_dict() for verifier in self.verifiers],
            "admission": [admission.as_dict() for admission in self.admission],
        }

    def verifier_sources(self) -> Mapping[str, str]:
        return MappingProxyType(
            {verifier.id: verifier.source for verifier in self.verifiers},
        )


def empty_generated_artifacts() -> GeneratedArtifacts:
    return GeneratedArtifacts(GeneratedWorld({}, {}, {}), (), (), ())


@dataclass(frozen=True, slots=True)
class BuildOutput:
    world: Mapping[str, object]
    tasks: tuple[Task, ...]
    verifier_sources: Mapping[str, str]
    admission_probe: Mapping[str, object]
    generated: GeneratedArtifacts = field(default_factory=empty_generated_artifacts)
    artifacts: Mapping[str, str] = field(default_factory=dict)
    touched_files: tuple[str, ...] = ()
    summary: str = ""


@dataclass(frozen=True, slots=True)
class Pack:
    id: str
    version: str
    dir: Path
    context: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "version": self.version,
            "dir": str(self.dir),
            "context": dict(self.context),
        }


class PackRegistry:
    def __init__(self) -> None:
        self._packs: dict[str, Pack] = {}

    def register(self, pack: Pack) -> None:
        self._packs[pack.id] = pack

    def resolve(self, pack_id: str) -> Pack:
        try:
            return self._packs[pack_id]
        except KeyError as exc:
            raise PackError(f"unknown pack {pack_id!r}") from exc

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._packs))


PACKS = PackRegistry()
