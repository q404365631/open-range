#!/usr/bin/env python3
"""Offline calibration harness for PopulationMutationPolicy."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

import yaml

from open_range.builder.mutation_policy import (
    PopulationMutationPolicy,
    load_mutation_policy_settings,
)
from open_range.builder.snapshot_store import SnapshotStore
from open_range.protocols import BuildContext


def _load_object(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    payload = Path(path).read_text(encoding="utf-8")
    suffix = Path(path).suffix.lower()
    if suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(payload) or {}
    else:
        data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError(f"expected an object in {path}")
    return data


def _parse_settings_arg(value: str) -> tuple[str, Path]:
    if "=" in value:
        label, raw_path = value.split("=", 1)
        return label.strip(), Path(raw_path).resolve()
    path = Path(value).resolve()
    return path.stem, path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare parent-selection scores across one or more "
            "PopulationMutationPolicy settings files."
        )
    )
    parser.add_argument(
        "--store-dir",
        default="snapshots",
        help="Snapshot store directory containing <snapshot_id>/spec.json entries.",
    )
    parser.add_argument(
        "--stats",
        help=(
            "Optional JSON/YAML file mapping snapshot_id to runtime stats such as "
            "plays, plays_recent, red_solve_rate, and blue_detect_rate."
        ),
    )
    parser.add_argument(
        "--context",
        help="Optional JSON/YAML file describing the BuildContext to score against.",
    )
    parser.add_argument(
        "--settings",
        action="append",
        default=[],
        help=(
            "Optional policy settings file to compare. Repeatable. Accepts "
            "'label=path' or just 'path'."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="How many top-ranked parents to include per policy.",
    )
    args = parser.parse_args(argv)

    entries = asyncio.run(SnapshotStore(args.store_dir).list_entries())
    if not entries:
        raise SystemExit(f"No stored snapshots found under {args.store_dir}")

    context = BuildContext.model_validate(_load_object(args.context))
    snapshot_stats = _load_object(args.stats)

    policies: list[tuple[str, PopulationMutationPolicy]] = [
        ("default", PopulationMutationPolicy()),
    ]
    for item in args.settings:
        label, path = _parse_settings_arg(item)
        policies.append(
            (label, PopulationMutationPolicy(settings=load_mutation_policy_settings(path)))
        )

    report = {
        "store_dir": str(Path(args.store_dir).resolve()),
        "snapshot_count": len(entries),
        "context": context.model_dump(mode="json"),
        "policies": [],
    }

    for label, policy in policies:
        ranked = sorted(
            policy.score_parents(
                entries,
                context=context,
                snapshot_stats=snapshot_stats,
            ),
            key=lambda score: score.total,
            reverse=True,
        )[: max(args.limit, 1)]
        report["policies"].append(
            {
                "label": label,
                "profile_name": policy.name,
                "settings": policy.settings_dict(),
                "top_parents": [score.log_payload() for score in ranked],
            }
        )

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
