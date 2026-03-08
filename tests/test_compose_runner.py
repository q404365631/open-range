from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from open_range.server.compose_runner import ComposeProjectRunner


def test_boot_tears_down_project_when_health_wait_fails(monkeypatch, tmp_path):
    runner = ComposeProjectRunner()
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text("services:\n  attacker:\n    image: alpine\n", encoding="utf-8")

    calls: list[tuple[str, tuple[str, ...]]] = []

    def fake_run(args, *, cwd, timeout):
        calls.append((args[3], tuple(args[5:])))
        if "ps" in args:
            return SimpleNamespace(stdout="cid-attacker\n", returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    def fake_wait(project, services):
        raise RuntimeError("Timed out waiting for healthy services: attacker")

    monkeypatch.setattr(runner, "_run", fake_run)
    monkeypatch.setattr(runner, "_wait_until_healthy", fake_wait)

    with pytest.raises(RuntimeError, match="Timed out waiting for healthy services"):
        runner.boot(
            snapshot_id="spec",
            artifacts_dir=tmp_path,
            compose={"services": {"attacker": {}}},
        )

    down_calls = [args for _project, args in calls if "down" in args]
    assert down_calls, "boot() should tear down the compose project after a health failure"
