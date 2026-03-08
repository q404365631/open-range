"""Tests for trajectory analytics (issue #22)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from open_range.training.analytics import TrajectoryAnalyzer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_record(
    episode_id: str = "ep-001",
    role: str = "red",
    reward: float = 0.5,
    outcome: str = "red_win",
    tier: int = 1,
    vuln_class: str | None = None,
    n_steps: int = 3,
) -> dict:
    """Build a single JSONL record matching TrajectoryLogger output format."""
    messages = [
        {"role": "system", "content": "You are a pentester."},
    ]
    for i in range(n_steps):
        messages.append({"role": "user", "content": f"observation {i}"})
        messages.append({"role": "assistant", "content": f"command {i}"})

    record = {
        "episode_id": episode_id,
        "snapshot_id": "snap-001",
        "tier": tier,
        "role": role,
        "messages": messages,
        "reward": reward,
        "outcome": outcome,
    }
    if vuln_class is not None:
        record["vuln_class"] = vuln_class
    return record


@pytest.fixture
def sample_jsonl(tmp_path) -> Path:
    """Create a sample JSONL file with multiple records."""
    records = [
        _make_record("ep-001", "red", 1.0, "red_win", vuln_class="sqli", n_steps=4),
        _make_record("ep-001", "blue", 0.2, "red_win", n_steps=4),
        _make_record("ep-002", "red", 0.0, "timeout", vuln_class="sqli", n_steps=6),
        _make_record("ep-002", "blue", 0.8, "timeout", n_steps=6),
        _make_record("ep-003", "red", 0.5, "red_win", vuln_class="xss", n_steps=3),
        _make_record("ep-003", "blue", 0.3, "red_win", n_steps=3),
    ]
    path = tmp_path / "trajectories.jsonl"
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return path


@pytest.fixture
def compare_jsonl(tmp_path) -> Path:
    """Create a second JSONL file for comparison."""
    records = [
        _make_record("ep-101", "red", 1.0, "red_win", vuln_class="sqli", n_steps=2),
        _make_record("ep-101", "blue", 0.5, "red_win", n_steps=2),
        _make_record("ep-102", "red", 1.0, "red_win", vuln_class="xss", n_steps=3),
        _make_record("ep-102", "blue", 0.7, "red_win", n_steps=3),
    ]
    path = tmp_path / "compare.jsonl"
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return path


# ---------------------------------------------------------------------------
# Tests: loading
# ---------------------------------------------------------------------------


class TestLoading:
    def test_load_returns_count(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        count = analyzer.load(sample_jsonl)
        assert count == 6

    def test_records_accessible(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        assert len(analyzer.records) == 6

    def test_load_accumulates(self, sample_jsonl, compare_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        analyzer.load(compare_jsonl)
        assert len(analyzer.records) == 10

    def test_empty_analyzer(self):
        analyzer = TrajectoryAnalyzer()
        s = analyzer.summary()
        assert s["total_episodes"] == 0
        assert s["total_records"] == 0


# ---------------------------------------------------------------------------
# Tests: summary
# ---------------------------------------------------------------------------


class TestSummary:
    def test_total_episodes(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        s = analyzer.summary()
        assert s["total_episodes"] == 3  # ep-001, ep-002, ep-003

    def test_total_records(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        s = analyzer.summary()
        assert s["total_records"] == 6

    def test_outcomes(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        s = analyzer.summary()
        assert s["outcomes"]["red_win"] == 2
        assert s["outcomes"]["timeout"] == 1

    def test_avg_reward(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        s = analyzer.summary()
        # (1.0 + 0.2 + 0.0 + 0.8 + 0.5 + 0.3) / 6 = 2.8 / 6 = 0.4667
        assert abs(s["avg_reward"] - 0.4667) < 0.01

    def test_avg_steps(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        s = analyzer.summary()
        # Steps are counted as assistant messages: 4, 4, 6, 6, 3, 3
        expected = (4 + 4 + 6 + 6 + 3 + 3) / 6
        assert abs(s["avg_steps"] - expected) < 0.1

    def test_per_role_stats(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        s = analyzer.summary()
        assert "red" in s["per_role"]
        assert "blue" in s["per_role"]
        assert s["per_role"]["red"]["count"] == 3
        assert s["per_role"]["blue"]["count"] == 3


# ---------------------------------------------------------------------------
# Tests: by_vuln_class
# ---------------------------------------------------------------------------


class TestByVulnClass:
    def test_vuln_class_breakdown(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        vc = analyzer.by_vuln_class()
        assert "sqli" in vc
        assert "xss" in vc
        # sqli: ep-001 (red_win), ep-002 (timeout) -> 2 attempts, 1 solve
        assert vc["sqli"]["attempts"] == 2
        assert vc["sqli"]["solves"] == 1
        assert abs(vc["sqli"]["solve_rate"] - 0.5) < 0.01
        # xss: ep-003 (red_win) -> 1 attempt, 1 solve
        assert vc["xss"]["attempts"] == 1
        assert vc["xss"]["solves"] == 1
        assert vc["xss"]["solve_rate"] == 1.0

    def test_no_vuln_class_returns_empty(self, tmp_path):
        """Records without vuln_class produce empty breakdown."""
        path = tmp_path / "no_vuln.jsonl"
        record = _make_record(vuln_class=None)
        with open(path, "w") as f:
            f.write(json.dumps(record) + "\n")
        analyzer = TrajectoryAnalyzer()
        analyzer.load(path)
        assert analyzer.by_vuln_class() == {}


# ---------------------------------------------------------------------------
# Tests: compare
# ---------------------------------------------------------------------------


class TestCompare:
    def test_compare_produces_diffs(self, sample_jsonl, compare_jsonl):
        a1 = TrajectoryAnalyzer()
        a1.load(sample_jsonl)
        a2 = TrajectoryAnalyzer()
        a2.load(compare_jsonl)
        diff = a1.compare(a2)
        assert "avg_reward_diff" in diff
        assert "total_episodes_diff" in diff
        assert diff["total_episodes_diff"] == 2 - 3  # 2 episodes vs 3

    def test_compare_reward_direction(self, sample_jsonl, compare_jsonl):
        a1 = TrajectoryAnalyzer()
        a1.load(sample_jsonl)
        a2 = TrajectoryAnalyzer()
        a2.load(compare_jsonl)
        diff = a1.compare(a2)
        # compare has higher rewards on average
        assert diff["avg_reward_compare"] > diff["avg_reward_baseline"]


# ---------------------------------------------------------------------------
# Tests: report
# ---------------------------------------------------------------------------


class TestReport:
    def test_report_is_string(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        report = analyzer.report()
        assert isinstance(report, str)
        assert "OpenRange Trajectory Analysis Report" in report

    def test_report_contains_stats(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        report = analyzer.report()
        assert "Total episodes:" in report
        assert "Average reward:" in report
        assert "Outcomes:" in report

    def test_report_contains_vuln_breakdown(self, sample_jsonl):
        analyzer = TrajectoryAnalyzer()
        analyzer.load(sample_jsonl)
        report = analyzer.report()
        assert "sqli" in report
        assert "xss" in report

    def test_empty_report(self):
        analyzer = TrajectoryAnalyzer()
        report = analyzer.report()
        assert "Total episodes:  0" in report
