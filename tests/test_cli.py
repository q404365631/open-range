import json
from types import SimpleNamespace

from click.testing import CliRunner

from open_range.cli import cli
from open_range.protocols import CheckResult, ContainerSet
from open_range.server.compose_runner import BootedSnapshotProject


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


class _FakePayloadContainers:
    def __init__(self) -> None:
        self.container_ids = {"web": "cid-web", "db": "cid-db"}
        self.exec_calls: list[tuple[str, str]] = []
        self.cp_calls: list[tuple[str, str, str]] = []

    async def exec(self, container: str, cmd: str, **kwargs) -> str:
        self.exec_calls.append((container, cmd))
        return "ok"

    async def cp(self, container: str, src: str, dest: str) -> None:
        self.cp_calls.append((container, src, dest))


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
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "docker-compose.yml").write_text(
                "services:\n  attacker:\n    image: alpine\n  web:\n    image: nginx\n",
                encoding="utf-8",
            )
            return output_dir

    class FakeComposeRunner:
        def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
            assert compose["services"].keys() == {"attacker", "web"}
            return BootedSnapshotProject(
                project_name=project_name or f"openrange-{snapshot_id}",
                compose_file=artifacts_dir / "docker-compose.yml",
                artifacts_dir=artifacts_dir,
                containers=ContainerSet(
                    project_name=project_name or f"openrange-{snapshot_id}",
                    container_ids={"attacker": "cid-attacker", "web": "cid-web"},
                ),
            )

        def teardown(self, project):
            teardown_calls.append(project.project_name)

    monkeypatch.setattr("open_range.builder.renderer.SnapshotRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.compose_runner.ComposeProjectRunner", FakeComposeRunner)
    monkeypatch.setattr("open_range.cli._CHECK_REGISTRY", {"build_boot": "fake.DockerAwareCheck"})
    monkeypatch.setattr("open_range.cli._import_check", lambda dotted: lambda: check)

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--snapshot", str(snapshot_path), "--docker"])

    assert result.exit_code == 0, result.output
    assert rendered_dirs
    assert check.saw_containers == {"attacker": "cid-attacker", "web": "cid-web"}
    assert teardown_calls
    assert "Booting temporary Docker project for validation" in result.output
    assert "Validation PASSED" in result.output


def test_validate_docker_applies_rendered_payloads_before_checks(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    check = _DockerAwareCheck()
    containers = _FakePayloadContainers()

    class FakeRenderer:
        def render(self, spec, output_dir):
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "docker-compose.yml").write_text(
                "services:\n  web:\n    image: nginx\n  db:\n    image: mysql\n",
                encoding="utf-8",
            )
            payload_path = output_dir / "rendered_files" / "web" / "var" / "www" / "portal" / "index.php"
            payload_path.parent.mkdir(parents=True, exist_ok=True)
            payload_path.write_text("<?php echo 'ok'; ?>\n", encoding="utf-8")
            (output_dir / "file-payloads.json").write_text(
                json.dumps(
                    {
                        "web:/var/www/portal/index.php": "rendered_files/web/var/www/portal/index.php",
                    }
                ),
                encoding="utf-8",
            )
            return output_dir

    class FakeComposeRunner:
        def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
            return BootedSnapshotProject(
                project_name=project_name or f"openrange-{snapshot_id}",
                compose_file=artifacts_dir / "docker-compose.yml",
                artifacts_dir=artifacts_dir,
                containers=containers,  # type: ignore[arg-type]
            )

        def teardown(self, project):
            return None

    monkeypatch.setattr("open_range.builder.renderer.SnapshotRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.compose_runner.ComposeProjectRunner", FakeComposeRunner)
    monkeypatch.setattr("open_range.cli._CHECK_REGISTRY", {"build_boot": "fake.DockerAwareCheck"})
    monkeypatch.setattr("open_range.cli._import_check", lambda dotted: lambda: check)

    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--snapshot", str(snapshot_path), "--docker"])

    assert result.exit_code == 0, result.output
    assert any(dest == "/var/www/portal/index.php" for _, _, dest in containers.cp_calls)
    assert ("web", "mkdir -p /var/www/portal") in containers.exec_calls


def test_validate_can_deploy_to_hugging_face_after_success(
    tmp_path,
    sample_snapshot_spec,
    monkeypatch,
):
    snapshot_path = tmp_path / "spec.json"
    snapshot_path.write_text(
        json.dumps(sample_snapshot_spec.model_dump(mode="python")),
        encoding="utf-8",
    )

    deployed = {}

    def fake_deploy(snapshot, *, space_id, token, create_repo, private, commit_message):
        deployed.update(
            {
                "snapshot": snapshot,
                "space_id": space_id,
                "token": token,
                "create_repo": create_repo,
                "private": private,
                "commit_message": commit_message,
            }
        )
        return SimpleNamespace(commit_url="https://huggingface.co/spaces/test/open-range/commit/abc123")

    monkeypatch.setattr(
        "open_range.hf_space.deploy_validated_snapshot_to_space",
        fake_deploy,
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

    assert result.exit_code == 0, result.output
    assert deployed["snapshot"] == str(snapshot_path)
    assert deployed["space_id"] == "test/open-range"
    assert deployed["token"] == "hf_test"
    assert deployed["create_repo"] is True
    assert "Hugging Face deployment complete." in result.output


def test_deploy_uses_compose_runner_and_applies_rendered_payloads(
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
    containers = _FakePayloadContainers()
    boot_calls: list[tuple[str, str]] = []

    class FakeRenderer:
        def render(self, spec, output_dir):
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "docker-compose.yml").write_text(
                "services:\n  web:\n    image: nginx\n  db:\n    image: mysql\n",
                encoding="utf-8",
            )
            payload_path = output_dir / "rendered_files" / "web" / "var" / "www" / "portal" / "index.php"
            payload_path.parent.mkdir(parents=True, exist_ok=True)
            payload_path.write_text("<?php echo 'ok'; ?>\n", encoding="utf-8")
            (output_dir / "file-payloads.json").write_text(
                json.dumps(
                    {
                        "web:/var/www/portal/index.php": "rendered_files/web/var/www/portal/index.php",
                    }
                ),
                encoding="utf-8",
            )
            return output_dir

    class FakeComposeRunner:
        def boot(self, *, snapshot_id, artifacts_dir, compose, project_name=None):
            boot_calls.append((snapshot_id, str(artifacts_dir)))
            return BootedSnapshotProject(
                project_name=project_name or f"openrange-{snapshot_id}",
                compose_file=artifacts_dir / "docker-compose.yml",
                artifacts_dir=artifacts_dir,
                containers=containers,  # type: ignore[arg-type]
            )

    monkeypatch.setattr("open_range.builder.renderer.SnapshotRenderer", FakeRenderer)
    monkeypatch.setattr("open_range.server.compose_runner.ComposeProjectRunner", FakeComposeRunner)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["deploy", "--snapshot", str(snapshot_path), "--compose-dir", str(compose_dir)],
    )

    assert result.exit_code == 0, result.output
    assert boot_calls == [("spec", str(compose_dir))]
    assert any(dest == "/var/www/portal/index.php" for _, _, dest in containers.cp_calls)
    assert "Containers started." in result.output
    assert "Project: openrange-spec" in result.output
