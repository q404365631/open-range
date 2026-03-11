from __future__ import annotations

from open_range.examples.demo import run_demo


def test_demo_runs_against_checked_in_manifest():
    result = run_demo(quiet=True)

    assert result["snapshot_id"]
    assert result["done"] is True
    assert result["winner"] == "blue"
    assert result["turn_count"] >= 2
