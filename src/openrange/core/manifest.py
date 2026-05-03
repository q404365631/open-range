"""Manifest parsing for OpenRange builds."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal, cast

import yaml

from openrange.core.errors import ManifestError

PackSourceKind = Literal["builtin", "path", "git", "container"]
WorldMode = Literal["simulation", "emulation"]


@dataclass(frozen=True, slots=True)
class PackSource:
    kind: PackSourceKind = "builtin"
    uri: str | None = None

    @classmethod
    def from_value(cls, value: object) -> PackSource:
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ManifestError("'pack.source' must be a mapping")
        kind = value.get("kind", "builtin")
        uri = value.get("uri")
        if kind not in {"builtin", "path", "git", "container"}:
            raise ManifestError("'pack.source.kind' is invalid")
        if uri is not None and not isinstance(uri, str):
            raise ManifestError("'pack.source.uri' must be a string")
        return cls(cast(PackSourceKind, kind), uri)

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"kind": self.kind}
        if self.uri is not None:
            result["uri"] = self.uri
        return result


@dataclass(frozen=True, slots=True)
class PackRef:
    id: str
    source: PackSource = field(default_factory=PackSource)
    options: Mapping[str, object] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> PackRef:
        pack_id = data.get("id")
        if not isinstance(pack_id, str) or not pack_id:
            raise ManifestError("'pack.id' must be a non-empty string")
        options = data.get("options", {})
        if not isinstance(options, Mapping):
            raise ManifestError("'pack.options' must be a mapping")
        return cls(
            id=pack_id,
            source=PackSource.from_value(data.get("source")),
            options=MappingProxyType(dict(options)),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "source": self.source.as_dict(),
            "options": dict(self.options),
        }


@dataclass(frozen=True, slots=True)
class Manifest:
    world: Mapping[str, object]
    pack: PackRef
    mode: WorldMode = "simulation"
    npc: tuple[Mapping[str, object], ...] = ()

    @classmethod
    def load(cls, manifest: str | Path | Mapping[str, object] | Manifest) -> Manifest:
        if isinstance(manifest, Manifest):
            return manifest
        if isinstance(manifest, str | Path):
            with Path(manifest).open(encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle)
            if not isinstance(loaded, Mapping):
                raise ManifestError("manifest YAML must contain a mapping")
            return cls.from_mapping(cast(Mapping[str, object], loaded))
        return cls.from_mapping(manifest)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> Manifest:
        world = data.get("world")
        pack = data.get("pack")
        if not isinstance(world, Mapping):
            raise ManifestError("'world' must be a mapping")
        if not isinstance(pack, Mapping):
            raise ManifestError("'pack' must be a mapping")
        mode = data.get("mode", "simulation")
        if mode not in {"simulation", "emulation"}:
            raise ManifestError("'mode' must be 'simulation' or 'emulation'")
        npc = data.get("npc", ())
        if not isinstance(npc, list | tuple) or not all(
            isinstance(item, Mapping) for item in npc
        ):
            raise ManifestError("'npc' must be a list of mappings")
        return cls(
            world=MappingProxyType(dict(world)),
            pack=PackRef.from_mapping(cast(Mapping[str, object], pack)),
            mode=cast(WorldMode, mode),
            npc=tuple(MappingProxyType(dict(item)) for item in npc),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "world": dict(self.world),
            "pack": self.pack.as_dict(),
            "mode": self.mode,
            "npc": [dict(item) for item in self.npc],
        }
