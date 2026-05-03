"""Admitted snapshot and lineage records."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import cast

from openrange.core.admission import AdmissionReport
from openrange.core.errors import StoreError
from openrange.core.manifest import Manifest
from openrange.core.pack import (
    BuildOutput,
    Entrypoint,
    Task,
    Verifier,
    verifier_from_source,
)


@dataclass(frozen=True, slots=True)
class LineageNode:
    id: str
    parent_id: str | None
    manifest: Mapping[str, object]
    pack: Mapping[str, object]
    prompt: str
    builder_summary: str
    touched_files: tuple[str, ...]
    curriculum: Mapping[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "manifest": dict(self.manifest),
            "pack": dict(self.pack),
            "prompt": self.prompt,
            "builder_summary": self.builder_summary,
            "touched_files": list(self.touched_files),
            "curriculum": None if self.curriculum is None else dict(self.curriculum),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> LineageNode:
        node_id = data.get("id")
        parent_id = data.get("parent_id")
        manifest = data.get("manifest")
        pack = data.get("pack")
        prompt = data.get("prompt")
        summary = data.get("builder_summary")
        touched_files = data.get("touched_files")
        curriculum = data.get("curriculum")
        if not isinstance(node_id, str):
            raise StoreError("stored lineage id is invalid")
        if parent_id is not None and not isinstance(parent_id, str):
            raise StoreError("stored lineage parent is invalid")
        if not isinstance(manifest, Mapping) or not isinstance(pack, Mapping):
            raise StoreError("stored lineage inputs are invalid")
        if not isinstance(prompt, str) or not isinstance(summary, str):
            raise StoreError("stored lineage text is invalid")
        if not isinstance(touched_files, list) or not all(
            isinstance(item, str) for item in touched_files
        ):
            raise StoreError("stored lineage touched files are invalid")
        if curriculum is not None and not isinstance(curriculum, Mapping):
            raise StoreError("stored lineage curriculum is invalid")
        return cls(
            node_id,
            parent_id,
            MappingProxyType(dict(manifest)),
            MappingProxyType(dict(pack)),
            prompt,
            summary,
            tuple(touched_files),
            None if curriculum is None else MappingProxyType(dict(curriculum)),
        )


@dataclass(frozen=True, slots=True)
class Snapshot:
    id: str
    manifest: Manifest
    world: Mapping[str, object]
    tasks: tuple[Task, ...]
    verifier_sources: Mapping[str, str]
    generated: Mapping[str, object]
    artifacts: Mapping[str, str]
    admission: AdmissionReport
    lineage: tuple[LineageNode, ...]

    def get_tasks(self) -> tuple[Task, ...]:
        return self.tasks

    def task(self, task_id: str) -> Task:
        for task in self.tasks:
            if task.id == task_id:
                return task
        raise KeyError(f"unknown task {task_id!r}")

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "manifest": self.manifest.as_dict(),
            "world": dict(self.world),
            "tasks": [task.as_dict() for task in self.tasks],
            "verifier_sources": dict(self.verifier_sources),
            "generated": dict(self.generated),
            "artifacts": dict(self.artifacts),
            "admission": self.admission.as_dict(),
            "lineage": [node.as_dict() for node in self.lineage],
        }

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, object],
        verifiers: Mapping[str, Verifier] | None = None,
    ) -> Snapshot:
        snapshot_id = data.get("id")
        manifest = data.get("manifest")
        world = data.get("world")
        tasks = data.get("tasks")
        verifier_sources = data.get("verifier_sources")
        generated = data.get("generated")
        artifacts = data.get("artifacts", {})
        admission = data.get("admission")
        lineage = data.get("lineage")
        if not isinstance(snapshot_id, str):
            raise StoreError("stored snapshot id is invalid")
        if not isinstance(manifest, Mapping) or not isinstance(world, Mapping):
            raise StoreError("stored snapshot manifest/world is invalid")
        if not isinstance(tasks, list):
            raise StoreError("stored tasks are invalid")
        if not isinstance(verifier_sources, Mapping):
            raise StoreError("stored verifier sources are invalid")
        if not isinstance(generated, Mapping):
            raise StoreError("stored generated artifacts are invalid")
        if not isinstance(artifacts, Mapping):
            raise StoreError("stored artifacts are invalid")
        if not isinstance(admission, Mapping) or not isinstance(lineage, list):
            raise StoreError("stored snapshot admission/lineage is invalid")
        if not all(isinstance(row, Mapping) for row in lineage):
            raise StoreError("stored lineage row is invalid")
        parsed_verifier_sources = {
            str(key): str(value) for key, value in verifier_sources.items()
        }
        loaded_verifiers = {
            verifier_id: verifier_from_source(source)
            for verifier_id, source in parsed_verifier_sources.items()
        }
        if verifiers is not None:
            loaded_verifiers.update(verifiers)
        parsed_tasks = tuple(task_from_mapping(row, loaded_verifiers) for row in tasks)
        parsed_artifacts = {str(key): str(value) for key, value in artifacts.items()}
        return cls(
            snapshot_id,
            Manifest.from_mapping(cast(Mapping[str, object], manifest)),
            MappingProxyType(dict(world)),
            parsed_tasks,
            MappingProxyType(parsed_verifier_sources),
            MappingProxyType(cast(Mapping[str, object], json_safe(generated))),
            MappingProxyType(parsed_artifacts),
            AdmissionReport.from_mapping(cast(Mapping[str, object], admission)),
            tuple(
                LineageNode.from_mapping(cast(Mapping[str, object], row))
                for row in lineage
            ),
        )


def task_from_mapping(data: object, verifiers: Mapping[str, Verifier]) -> Task:
    if not isinstance(data, Mapping):
        raise StoreError("stored task is invalid")
    task_id = data.get("id")
    instruction = data.get("instruction")
    entrypoints = data.get("entrypoints")
    verifier_id = data.get("verifier_id")
    if not isinstance(task_id, str) or not isinstance(instruction, str):
        raise StoreError("stored task id/instruction is invalid")
    if not isinstance(entrypoints, list) or not isinstance(verifier_id, str):
        raise StoreError("stored task entrypoints/verifier are invalid")
    if not all(isinstance(item, Mapping) for item in entrypoints):
        raise StoreError("stored entrypoint row is invalid")
    try:
        verifier = verifiers[verifier_id]
    except KeyError as exc:
        raise StoreError(f"unknown stored verifier {verifier_id!r}") from exc
    return Task(
        task_id,
        instruction,
        tuple(
            Entrypoint.from_mapping(cast(Mapping[str, object], item))
            for item in entrypoints
        ),
        verifier_id,
        verifier,
    )


def snapshot_hash(
    manifest: Manifest,
    build: BuildOutput,
    pack_version: str,
    parent_id: str | None,
) -> str:
    payload = {
        "manifest": manifest.as_dict(),
        "world": build.world,
        "tasks": [task.as_dict() for task in build.tasks],
        "verifier_sources": build.verifier_sources,
        "generated": build.generated.as_dict(),
        "artifacts": build.artifacts,
        "pack_version": pack_version,
        "parent_id": parent_id,
    }
    return sha256(stable_json(payload).encode()).hexdigest()[:16]


def stable_json(value: object) -> str:
    return json.dumps(json_safe(value), sort_keys=True, separators=(",", ":"))


def json_safe(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [json_safe(item) for item in value]
    return value
