"""Trajectory analytics for OpenRange training runs.

Reads JSONL trajectory files (output of ``TrajectoryLogger.export_jsonl``)
and computes summary statistics, per-vuln-class breakdowns, and comparison
reports between runs.

Usage::

    python -m open_range.training.analytics trajectories.jsonl
    python -m open_range.training.analytics run1.jsonl run2.jsonl --compare
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class TrajectoryAnalyzer:
    """Analyze JSONL trajectory files produced by TrajectoryLogger.

    Each line in a JSONL file is expected to have at minimum::

        {
            "episode_id": str,
            "role": "red" | "blue",
            "reward": float,
            "outcome": str,
            "tier": int,
            "messages": [...],
        }

    Additional fields (snapshot_id, vuln_class, etc.) are used when present.
    """

    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []

    @property
    def records(self) -> list[dict[str, Any]]:
        """All loaded JSONL records."""
        return list(self._records)

    def load(self, path: str | Path) -> int:
        """Load one or more JSONL files.

        Can be called multiple times to accumulate records from
        multiple files.

        Args:
            path: Path to a JSONL file.

        Returns:
            Number of records loaded from this file.
        """
        path = Path(path)
        count = 0
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                self._records.append(record)
                count += 1
        return count

    def summary(self) -> dict[str, Any]:
        """Compute summary statistics across all loaded records.

        Returns:
            Dict with:
            - total_episodes: number of unique episode IDs
            - total_records: number of JSONL records loaded
            - outcomes: dict mapping outcome string to count
            - avg_reward: mean reward across all records
            - avg_steps: mean step count (from message pairs)
            - per_role: dict mapping role to {count, avg_reward, outcomes}
        """
        if not self._records:
            return {
                "total_episodes": 0,
                "total_records": 0,
                "outcomes": {},
                "avg_reward": 0.0,
                "avg_steps": 0.0,
                "per_role": {},
            }

        episode_ids = {r.get("episode_id", "") for r in self._records}

        # Outcome counts (deduplicated by episode_id)
        outcomes: dict[str, int] = {}
        seen_episodes: set[str] = set()
        for r in self._records:
            eid = r.get("episode_id", "")
            outcome = r.get("outcome", "unknown")
            if eid not in seen_episodes:
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
                seen_episodes.add(eid)

        # Rewards
        rewards = [r.get("reward", 0.0) for r in self._records]
        avg_reward = sum(rewards) / len(rewards) if rewards else 0.0

        # Steps (count assistant messages as steps)
        steps_list: list[int] = []
        for r in self._records:
            messages = r.get("messages", [])
            n_steps = sum(1 for m in messages if m.get("role") == "assistant")
            steps_list.append(n_steps)
        avg_steps = sum(steps_list) / len(steps_list) if steps_list else 0.0

        # Per-role stats
        per_role: dict[str, dict[str, Any]] = {}
        for r in self._records:
            role = r.get("role", "unknown")
            if role not in per_role:
                per_role[role] = {"count": 0, "total_reward": 0.0, "outcomes": {}}
            per_role[role]["count"] += 1
            per_role[role]["total_reward"] += r.get("reward", 0.0)
            outcome = r.get("outcome", "unknown")
            per_role[role]["outcomes"][outcome] = (
                per_role[role]["outcomes"].get(outcome, 0) + 1
            )

        for role_data in per_role.values():
            count = role_data["count"]
            role_data["avg_reward"] = (
                role_data["total_reward"] / count if count > 0 else 0.0
            )

        return {
            "total_episodes": len(episode_ids),
            "total_records": len(self._records),
            "outcomes": outcomes,
            "avg_reward": round(avg_reward, 4),
            "avg_steps": round(avg_steps, 2),
            "per_role": per_role,
        }

    def by_vuln_class(self) -> dict[str, dict[str, Any]]:
        """Break down solve rates by vulnerability class.

        Looks for ``vuln_class`` or ``vuln_classes`` field in records.
        For records with ``vuln_classes`` (list), each class is counted
        independently.

        Returns:
            Dict mapping vuln class to:
            - attempts: number of episodes
            - solves: number of episodes with outcome containing 'win' or 'captured'
            - solve_rate: solves / attempts
        """
        vuln_stats: dict[str, dict[str, int]] = {}

        for r in self._records:
            # Only count red records for solve rate
            if r.get("role") != "red":
                continue

            classes: list[str] = []
            if "vuln_class" in r:
                classes = [r["vuln_class"]]
            elif "vuln_classes" in r:
                classes = r["vuln_classes"] if isinstance(r["vuln_classes"], list) else [r["vuln_classes"]]
            else:
                continue

            outcome = r.get("outcome", "")
            solved = "win" in outcome or "captured" in outcome

            for vc in classes:
                if vc not in vuln_stats:
                    vuln_stats[vc] = {"attempts": 0, "solves": 0}
                vuln_stats[vc]["attempts"] += 1
                if solved:
                    vuln_stats[vc]["solves"] += 1

        result: dict[str, dict[str, Any]] = {}
        for vc, stats in sorted(vuln_stats.items()):
            result[vc] = {
                "attempts": stats["attempts"],
                "solves": stats["solves"],
                "solve_rate": (
                    round(stats["solves"] / stats["attempts"], 4)
                    if stats["attempts"] > 0
                    else 0.0
                ),
            }
        return result

    def compare(self, other: TrajectoryAnalyzer) -> dict[str, Any]:
        """Compare this analyzer's summary with another's.

        Args:
            other: Another TrajectoryAnalyzer to compare against.

        Returns:
            Dict showing differences:
            - total_episodes_diff
            - avg_reward_diff
            - avg_steps_diff
            - outcome_diffs
            - per_role_diffs
        """
        s1 = self.summary()
        s2 = other.summary()

        outcome_diffs: dict[str, dict[str, int]] = {}
        all_outcomes = set(s1["outcomes"].keys()) | set(s2["outcomes"].keys())
        for outcome in sorted(all_outcomes):
            c1 = s1["outcomes"].get(outcome, 0)
            c2 = s2["outcomes"].get(outcome, 0)
            outcome_diffs[outcome] = {"baseline": c1, "compare": c2, "diff": c2 - c1}

        per_role_diffs: dict[str, dict[str, Any]] = {}
        all_roles = set(s1["per_role"].keys()) | set(s2["per_role"].keys())
        for role in sorted(all_roles):
            r1 = s1["per_role"].get(role, {"count": 0, "avg_reward": 0.0})
            r2 = s2["per_role"].get(role, {"count": 0, "avg_reward": 0.0})
            per_role_diffs[role] = {
                "count_diff": r2["count"] - r1["count"],
                "avg_reward_baseline": r1.get("avg_reward", 0.0),
                "avg_reward_compare": r2.get("avg_reward", 0.0),
                "avg_reward_diff": round(
                    r2.get("avg_reward", 0.0) - r1.get("avg_reward", 0.0), 4
                ),
            }

        return {
            "total_episodes_diff": s2["total_episodes"] - s1["total_episodes"],
            "avg_reward_baseline": s1["avg_reward"],
            "avg_reward_compare": s2["avg_reward"],
            "avg_reward_diff": round(s2["avg_reward"] - s1["avg_reward"], 4),
            "avg_steps_baseline": s1["avg_steps"],
            "avg_steps_compare": s2["avg_steps"],
            "avg_steps_diff": round(s2["avg_steps"] - s1["avg_steps"], 2),
            "outcome_diffs": outcome_diffs,
            "per_role_diffs": per_role_diffs,
        }

    def report(self) -> str:
        """Generate a formatted text report.

        Returns:
            Multi-line string report suitable for terminal output.
        """
        s = self.summary()
        lines: list[str] = []

        lines.append("=" * 60)
        lines.append("OpenRange Trajectory Analysis Report")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Total episodes:  {s['total_episodes']}")
        lines.append(f"Total records:   {s['total_records']}")
        lines.append(f"Average reward:  {s['avg_reward']}")
        lines.append(f"Average steps:   {s['avg_steps']}")
        lines.append("")

        # Outcomes
        lines.append("Outcomes:")
        for outcome, count in sorted(s["outcomes"].items()):
            pct = (count / s["total_episodes"] * 100) if s["total_episodes"] > 0 else 0
            lines.append(f"  {outcome:<20s} {count:>5d}  ({pct:.1f}%)")
        lines.append("")

        # Per-role stats
        lines.append("Per-role statistics:")
        for role, data in sorted(s["per_role"].items()):
            lines.append(f"  {role}:")
            lines.append(f"    Records:     {data['count']}")
            lines.append(f"    Avg reward:  {data['avg_reward']:.4f}")
            role_outcomes = data.get("outcomes", {})
            if role_outcomes:
                lines.append("    Outcomes:")
                for outcome, count in sorted(role_outcomes.items()):
                    lines.append(f"      {outcome}: {count}")
        lines.append("")

        # Vuln class breakdown
        vuln_data = self.by_vuln_class()
        if vuln_data:
            lines.append("Vulnerability class breakdown:")
            for vc, stats in vuln_data.items():
                lines.append(
                    f"  {vc:<25s} "
                    f"attempts={stats['attempts']:>3d}  "
                    f"solves={stats['solves']:>3d}  "
                    f"rate={stats['solve_rate']:.2%}"
                )
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze OpenRange trajectory JSONL files",
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="One or more JSONL trajectory files",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare two files (requires exactly 2 file args)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output summary as JSON instead of formatted report",
    )
    args = parser.parse_args()

    if args.compare:
        if len(args.files) != 2:
            print("--compare requires exactly 2 files", file=sys.stderr)
            sys.exit(1)
        a1 = TrajectoryAnalyzer()
        a1.load(args.files[0])
        a2 = TrajectoryAnalyzer()
        a2.load(args.files[1])
        diff = a1.compare(a2)
        print(json.dumps(diff, indent=2))
        sys.exit(0)

    analyzer = TrajectoryAnalyzer()
    for f in args.files:
        analyzer.load(f)

    if args.json_output:
        print(json.dumps(analyzer.summary(), indent=2, default=str))
    else:
        print(analyzer.report())


if __name__ == "__main__":
    main()
