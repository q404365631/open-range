import json
from types import SimpleNamespace

from click.testing import CliRunner

from open_range.cli import cli
from open_range.protocols import CheckResult, ContainerSet
from open_range.server.helm_runner import BootedRelease


class _DockerAwareCheck:
    def __init__(self) -> None:
        self.saw_containers = {}

    async def check(self, snapshot, containers: ContainerSet) -> CheckResult:
        self.saw_containers = dict(containers.container_ids)
        return CheckResult(
            name="docker_aware",
            passed=bool(containers.container_ids),
            details={"containers": dict(containers.container_ids)},
            error="" if containers.container_ids else "missing containers",
        )


def test_validate_docker_boots_temporary_project_and_passes_live_containers(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    rendered_dirs: list[str] = []
    teardown_calls: list[str] = []
    check = _DockerAwareCheck()

    class FakeRenderer:
        def render(self, spec, output_dir):
            rendered_dirs.append(str(output_dir))
            chart_dir = output_dir / "openrange"
            chart_dir.mkdir(parents=True, exist_ok=True)
            (chart_dir / "values.yaml").write_text(
                "services:\n  attacker:\n    image: kali\n  web:\n    image: nginx\n",
                encoding="utf-8",
            )
            (output_dir / "kind-config.yaml").write_text("kind: Cluster\n", encoding="utf-8")
            return output_dir

    class FakeHelmRunner:
        def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
            assert compose["services"].keys() == {"attacker", "web"}
            return BootedRelease(
                release_name=project_name or f"or-{snapshot_id}",
                chart_dir=artifacts_dir / "openrange",
                artifacts_dir=artifacts_dir,
                containers=ContainerSet(
                    project_name=project_name or f"openrange-{snapshot_id}",
                    container_ids={"attacker": "cid-attacker", "web": "cid-web"},
                ),
            )

        def teardown(self, project):
            teardown_calls.append(project.project_name)

    monkeypatch.setattr("open_range.builder.renderer.KindRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.helm_runner.HelmRunner", FakeHelmRunner)
    monkeypatch.setattr("open_range.cli._CHECK_REGISTRY", {"build_boot": "fake.DockerAwareCheck"})
    monkeypatch.setattr("open_range.cli._import_check", lambda dotted: lambda: check)

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--snapshot", str(snapshot_path), "--docker"])

    assert result.exit_code == 0, result.output
    assert rendered_dirs
    assert check.saw_containers == {"attacker": "cid-attacker", "web": "cid-web"}
    assert teardown_calls
    assert "Booting temporary Helm release for validation" in result.output
    assert "Validation PASSED" in result.output


def test_validate_docker_uses_rendered_values_for_live_checks(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    class _RenderedSpecCheck:
        def __init__(self) -> None:
            self.compose = {}
            self.saw_containers = {}

        async def check(self, snapshot, containers: ContainerSet) -> CheckResult:
            self.compose = dict(snapshot.compose)
            self.saw_containers = dict(containers.container_ids)
            return CheckResult(name="rendered_spec", passed=bool(self.compose))

    check = _RenderedSpecCheck()

    class FakeRenderer:
        def render(self, spec, output_dir):
            chart_dir = output_dir / "openrange"
            chart_dir.mkdir(parents=True, exist_ok=True)
            (chart_dir / "values.yaml").write_text(
                "services:\n  web:\n    image: nginx\n  db:\n    image: mysql\n",
                encoding="utf-8",
            )
            (output_dir / "kind-config.yaml").write_text("kind: Cluster\n", encoding="utf-8")
            return output_dir

    class FakeHelmRunner:
        def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
            assert compose["services"].keys() == {"web", "db"}
            return BootedRelease(
                release_name=project_name or f"or-{snapshot_id}",
                chart_dir=artifacts_dir / "openrange",
                artifacts_dir=artifacts_dir,
                containers=ContainerSet(
                    project_name=project_name or f"or-{snapshot_id}",
                    container_ids={"web": "pod-web", "db": "pod-db"},
                ),
            )

        def teardown(self, project):
            return None

    monkeypatch.setattr("open_range.builder.renderer.KindRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.helm_runner.HelmRunner", FakeHelmRunner)
    monkeypatch.setattr("open_range.cli._CHECK_REGISTRY", {"build_boot": "fake.DockerAwareCheck"})
    monkeypatch.setattr("open_range.cli._import_check", lambda dotted: lambda: check)

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--snapshot", str(snapshot_path), "--docker"])

    assert result.exit_code == 0, result.output
    assert check.compose["services"]["web"]["image"] == "nginx"
    assert check.saw_containers == {"web": "pod-web", "db": "pod-db"}


def test_validate_rejects_removed_hugging_face_deploy_flag(
    tmp_path,
    sample_snapshot_spec,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "validate",
            "--snapshot",
            str(snapshot_path),
            "--deploy-hf",
            "--hf-space",
            "test/open-range",
            "--hf-token",
            "hf_test",
            "--checks",
            "isolation",
        ],
    )

    assert result.exit_code == 2
    assert "No such option: --deploy-hf" in result.output


def test_validate_without_docker_excludes_live_only_checks(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    invoked: list[str] = []

    class _OfflineCheck:
        def __init__(self, name: str) -> None:
            self.name = name

        async def check(self, snapshot, containers: ContainerSet) -> CheckResult:
            invoked.append(self.name)
            return CheckResult(name=self.name, passed=True)

    monkeypatch.setattr(
        "open_range.cli._CHECK_REGISTRY",
        {
            "build_boot": "fake.BuildBootCheck",
            "reward_grounding": "fake.RewardGroundingCheck",
            "isolation": "fake.IsolationCheck",
            "difficulty": "fake.DifficultyCheck",
            "npc_consistency": "fake.NPCConsistencyCheck",
            "realism_review": "fake.RealismReviewCheck",
        },
    )
    monkeypatch.setattr(
        "open_range.cli._import_check",
        lambda dotted: lambda: _OfflineCheck(dotted.rsplit(".", 1)[-1]),
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--snapshot", str(snapshot_path)])

    assert result.exit_code == 0, result.output
    assert invoked == ["DifficultyCheck"]
    assert "Validation PASSED" in result.output


def test_deploy_installs_rendered_chart_on_kind_cluster(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    compose_dir = tmp_path / "deploy"
    commands: list[list[str]] = []
    prepared: list[str] = []
    boot_calls: list[dict[str, object]] = []

    class FakeRenderer:
        def render(self, spec, output_dir):
            chart_dir = output_dir / "openrange"
            chart_dir.mkdir(parents=True, exist_ok=True)
            (chart_dir / "Chart.yaml").write_text("apiVersion: v2\nname: openrange\n", encoding="utf-8")
            (output_dir / "kind-config.yaml").write_text("kind: Cluster\n", encoding="utf-8")
            return output_dir

    class FakeHelmRunner:
        def prepare_images(self, chart_dir):
            prepared.append(str(chart_dir))

        def boot(self, *, snapshot_id, artifacts_dir, compose=None, project_name=None):
            boot_calls.append(
                {
                    "snapshot_id": snapshot_id,
                    "artifacts_dir": str(artifacts_dir),
                    "project_name": project_name,
                }
            )
            return BootedRelease(
                release_name=project_name or "openrange",
                chart_dir=artifacts_dir / "openrange",
                artifacts_dir=artifacts_dir,
                containers=ContainerSet(project_name=project_name or "openrange"),
            )

    def fake_run(args, capture_output, text, timeout):
        commands.append(list(args))
        if "kubectl" in args and "get" in args:
            return SimpleNamespace(returncode=0, stdout="NAMESPACE NAME\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("open_range.builder.renderer.KindRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.helm_runner.HelmRunner", FakeHelmRunner)
    monkeypatch.setattr(
        "open_range.server.helm_runner.resolve_kubectl_cmd",
        lambda kind_cluster="openrange": ("docker", "exec", f"{kind_cluster}-control-plane", "kubectl"),
    )
    monkeypatch.setattr("subprocess.run", fake_run)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["deploy", "--snapshot", str(snapshot_path), "--chart-dir", str(compose_dir)],
    )

    assert result.exit_code == 0, result.output
    assert commands[0][:3] == ["kind", "create", "cluster"]
    assert "kubectl" in commands[1]
    assert prepared == [str(compose_dir / "openrange")]
    assert boot_calls[0]["project_name"] == "openrange"
    assert "Kind cluster created. Preparing images and installing Helm chart ..." in result.output
    assert "Helm chart installed as release openrange." in result.output
