"""Bundled pack directory registry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from openrange.core.pack import PACKS, Pack


def register_builtin_pack(pack_dir: Path) -> None:
    descriptor = cast(
        dict[str, object],
        json.loads((pack_dir / "pack.json").read_text(encoding="utf-8")),
    )
    PACKS.register(
        Pack(
            str(descriptor["id"]),
            str(descriptor["version"]),
            pack_dir,
        ),
    )


register_builtin_pack(Path(__file__).parent / "cyber_webapp_offense")
