"""Edge case tests for SnapshotRenderer.

Tests unusual/boundary specs: no flags, no users, no firewall rules,
db-only flags, file-only flags, multiple vulns, empty golden path.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from open_range.builder.renderer import SnapshotRenderer, _build_context
from open_range.protocols import (
    FlagSpec,
    GoldenPathStep,
    NPCTrafficSpec,
    SnapshotSpec,
    TaskSpec,
    TruthGraph,
    Vulnerability,
)


@pytest.fixture
def renderer():
    return SnapshotRenderer()


def _minimal_topology(**overrides):
    """Build a minimal topology dict, with optional overrides."""
    topo = {
        "hosts": ["web", "db"],
        "zones": {"dmz": ["web"], "internal": ["db"]},
        "users": [],
        "firewall_rules": [],
    }
    topo.update(overrides)
    return topo


# ---------------------------------------------------------------------------
# Spec with no flags
# ---------------------------------------------------------------------------


class TestNoFlags:
    """Spec with zero flags should render without errors."""

    def test_renders_without_error(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(
                vulns=[Vulnerability(id="v1", type="sqli", host="web")]
            ),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "no_flags"
            renderer.render(spec, out)
            for fname in ["docker-compose.yml", "Dockerfile.web", "init.sql"]:
                assert (out / fname).exists()

    def test_dockerfile_has_no_flag_lines(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "no_flags"
            renderer.render(spec, out)
            dockerfile = (out / "Dockerfile.web").read_text()
            assert "FLAG{" not in dockerfile

    def test_context_has_empty_flags(self):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["flags"] == []


# ---------------------------------------------------------------------------
# Spec with no users
# ---------------------------------------------------------------------------


class TestNoUsers:
    """Spec with zero topology users should render cleanly."""

    def test_renders_without_error(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "no_users"
            renderer.render(spec, out)
            assert (out / "Dockerfile.web").exists()

    def test_dockerfile_has_no_useradd(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "no_users"
            renderer.render(spec, out)
            dockerfile = (out / "Dockerfile.web").read_text()
            assert "useradd" not in dockerfile

    def test_context_defaults_db_user(self):
        """With no users, context should synthesize a service DB account."""
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["db_user"] == "svc_db"
        assert ctx["db_pass"]
        assert ctx["db_pass"] != "AppUs3r!2024"


# ---------------------------------------------------------------------------
# Spec with no firewall rules
# ---------------------------------------------------------------------------


class TestNoFirewallRules:
    """Spec with no firewall rules should render iptables with defaults."""

    def test_renders_iptables_without_error(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(firewall_rules=[]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "no_fw"
            renderer.render(spec, out)
            rules = (out / "iptables.rules").read_text()
            assert "*filter" in rules
            assert "COMMIT" in rules

    def test_context_has_empty_firewall_rules(self):
        spec = SnapshotSpec(
            topology=_minimal_topology(firewall_rules=[]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["firewall_rules"] == []


# ---------------------------------------------------------------------------
# Spec with db-only flags
# ---------------------------------------------------------------------------


class TestDBOnlyFlags:
    """Flags on the db host with db: paths should appear in SQL, not Dockerfile."""

    def test_flag_not_in_dockerfile(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(
                vulns=[Vulnerability(id="v1", type="idor", host="web")]
            ),
            flags=[
                FlagSpec(
                    id="flag1",
                    value="FLAG{db_only_flag}",
                    path="db:flags.secrets.flag",
                    host="db",
                ),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "db_only"
            renderer.render(spec, out)
            dockerfile = (out / "Dockerfile.web").read_text()
            assert "FLAG{db_only_flag}" not in dockerfile

    def test_flag_path_with_mysql_prefix_not_in_dockerfile(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[
                FlagSpec(
                    id="flag1",
                    value="FLAG{mysql_flag}",
                    path="mysql:flags.secrets.flag",
                    host="db",
                ),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "mysql_flag"
            renderer.render(spec, out)
            dockerfile = (out / "Dockerfile.web").read_text()
            assert "FLAG{mysql_flag}" not in dockerfile

    def test_db_flag_host_not_web(self, renderer):
        """Flag with host='db' should never appear in Dockerfile.web regardless of path."""
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[
                FlagSpec(
                    id="flag1",
                    value="FLAG{host_db}",
                    path="/some/path/flag.txt",
                    host="db",
                ),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "db_host"
            renderer.render(spec, out)
            dockerfile = (out / "Dockerfile.web").read_text()
            # Template checks flag.host == 'web', so db-hosted flag shouldn't be there
            assert "FLAG{host_db}" not in dockerfile


# ---------------------------------------------------------------------------
# Spec with file-only flags
# ---------------------------------------------------------------------------


class TestFileOnlyFlags:
    """Flags stored as files on web should appear in Dockerfile, not SQL."""

    def test_flag_in_dockerfile(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[
                FlagSpec(
                    id="flag1",
                    value="FLAG{file_only}",
                    path="/var/flags/flag1.txt",
                    host="web",
                ),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "file_only"
            renderer.render(spec, out)
            dockerfile = (out / "Dockerfile.web").read_text()
            assert "FLAG{file_only}" in dockerfile
            assert "/var/flags/flag1.txt" in dockerfile

    def test_flag_not_in_sql(self, renderer):
        """File-based flag should NOT appear in init.sql (it's template-generated, static)."""
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[
                FlagSpec(
                    id="flag1",
                    value="FLAG{file_only_check}",
                    path="/var/flags/flag1.txt",
                    host="web",
                ),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "file_only_sql"
            renderer.render(spec, out)
            sql = (out / "init.sql").read_text()
            assert "FLAG{file_only_check}" not in sql

    def test_multiple_file_flags(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[
                FlagSpec(
                    id="flag1",
                    value="FLAG{first}",
                    path="/var/flags/flag1.txt",
                    host="web",
                ),
                FlagSpec(
                    id="flag2",
                    value="FLAG{second}",
                    path="/var/flags/flag2.txt",
                    host="web",
                ),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "multi_flags"
            renderer.render(spec, out)
            dockerfile = (out / "Dockerfile.web").read_text()
            assert "FLAG{first}" in dockerfile
            assert "FLAG{second}" in dockerfile
            assert "/var/flags/flag1.txt" in dockerfile
            assert "/var/flags/flag2.txt" in dockerfile


# ---------------------------------------------------------------------------
# Spec with multiple vulnerability types
# ---------------------------------------------------------------------------


class TestMultipleVulnTypes:
    """Multiple vuln types should enable correct nginx endpoint blocks."""

    def test_sqli_and_path_traversal_both_enabled(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(
                vulns=[
                    Vulnerability(
                        id="v1", type="sqli", host="web",
                        injection_point="/search?q=",
                    ),
                    Vulnerability(
                        id="v2", type="path_traversal", host="web",
                        injection_point="/download?file=",
                    ),
                ]
            ),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "multi_vuln"
            renderer.render(spec, out)
            nginx = (out / "nginx.conf").read_text()
            assert "/search" in nginx
            assert "/download" in nginx

    def test_context_enables_both_endpoints(self):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(
                vulns=[
                    Vulnerability(id="v1", type="sqli", host="web",
                                  injection_point="/search?q="),
                    Vulnerability(id="v2", type="path_traversal", host="web",
                                  injection_point="/download?file="),
                ]
            ),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx.get("search_endpoint") is True
        assert ctx.get("download_endpoint") is True

    def test_idor_does_not_enable_search_or_download(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(
                vulns=[
                    Vulnerability(
                        id="v1", type="idor", host="web",
                        injection_point="/api/users/{id}",
                    ),
                ]
            ),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert "search_endpoint" not in ctx
        assert "download_endpoint" not in ctx

    def test_three_vulns_render_without_error(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(
                vulns=[
                    Vulnerability(id="v1", type="sqli", host="web",
                                  injection_point="/search?q="),
                    Vulnerability(id="v2", type="path_traversal", host="web",
                                  injection_point="/download?file="),
                    Vulnerability(id="v3", type="xss", host="web",
                                  injection_point="/comment"),
                ]
            ),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "three_vulns"
            renderer.render(spec, out)
            for fname in ["docker-compose.yml", "Dockerfile.attacker", "Dockerfile.web",
                          "Dockerfile.firewall", "Dockerfile.jumpbox", "Dockerfile.siem",
                          "Dockerfile.vpn", "nginx.conf",
                          "init.sql", "iptables.rules"]:
                assert (out / fname).exists()


# ---------------------------------------------------------------------------
# Spec with empty golden path
# ---------------------------------------------------------------------------


class TestEmptyGoldenPath:
    """Spec with no golden path steps should render normally."""

    def test_renders_without_error(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(
                vulns=[Vulnerability(id="v1", type="sqli", host="web")]
            ),
            flags=[
                FlagSpec(id="f1", value="FLAG{x}", path="/var/flags/f.txt", host="web"),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "no_gp"
            renderer.render(spec, out)
            assert (out / "docker-compose.yml").exists()

    def test_compose_still_valid(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "no_gp_compose"
            renderer.render(spec, out)
            compose = (out / "docker-compose.yml").read_text()
            assert "services:" in compose
            assert "web:" in compose


# ---------------------------------------------------------------------------
# Spec with only one host
# ---------------------------------------------------------------------------


class TestSingleHost:
    """Spec with only one host in topology."""

    def test_renders_without_error(self, renderer):
        spec = SnapshotSpec(
            topology={
                "hosts": ["web"],
                "zones": {"dmz": ["web"]},
                "users": [],
                "firewall_rules": [],
            },
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "single_host"
            renderer.render(spec, out)
            assert (out / "docker-compose.yml").exists()

    def test_context_has_one_host(self):
        spec = SnapshotSpec(
            topology={
                "hosts": ["web"],
                "zones": {"dmz": ["web"]},
                "users": [],
                "firewall_rules": [],
            },
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["host_names"] == ["web"]
        assert len(ctx["hosts"]) == 1


# ---------------------------------------------------------------------------
# Spec with dict-format hosts
# ---------------------------------------------------------------------------


class TestDictFormatHosts:
    """Topology with hosts as list of dicts rather than strings."""

    def test_renders_with_dict_hosts(self, renderer):
        spec = SnapshotSpec(
            topology={
                "hosts": [
                    {"name": "web", "zone": "dmz", "networks": ["dmz", "internal"]},
                    {"name": "db", "zone": "internal", "depends_on": ["ldap"]},
                ],
                "zones": {"dmz": ["web"], "internal": ["db"]},
                "users": [],
                "firewall_rules": [],
            },
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "dict_hosts"
            renderer.render(spec, out)
            assert (out / "docker-compose.yml").exists()

    def test_context_preserves_dict_host_info(self):
        spec = SnapshotSpec(
            topology={
                "hosts": [
                    {"name": "web", "zone": "dmz", "networks": ["dmz", "internal"]},
                    {"name": "db", "zone": "internal", "depends_on": ["ldap"]},
                ],
                "zones": {"dmz": ["web"], "internal": ["db"]},
                "users": [],
                "firewall_rules": [],
            },
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        web_host = next(h for h in ctx["hosts"] if h["name"] == "web")
        assert "dmz" in web_host["networks"]
        assert "internal" in web_host["networks"]

        db_host = next(h for h in ctx["hosts"] if h["name"] == "db")
        assert db_host["depends_on"] == ["ldap"]


# ---------------------------------------------------------------------------
# Zone CIDR mapping edge cases
# ---------------------------------------------------------------------------


class TestZoneCIDRMapping:
    """Verify zone-to-CIDR mapping for known and unknown zones."""

    def test_known_zones(self):
        spec = SnapshotSpec(
            topology={
                "hosts": ["web", "db"],
                "zones": {"external": ["web"], "dmz": ["web"], "internal": ["db"],
                          "management": ["db"]},
                "users": [],
                "firewall_rules": [],
            },
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["zone_cidrs"]["external"] == "0.0.0.0/0"
        assert ctx["zone_cidrs"]["dmz"] == "10.0.1.0/24"
        assert ctx["zone_cidrs"]["internal"] == "10.0.2.0/24"
        assert ctx["zone_cidrs"]["management"] == "10.0.3.0/24"

    def test_unknown_zone_gets_default(self):
        spec = SnapshotSpec(
            topology={
                "hosts": ["web"],
                "zones": {"custom_zone": ["web"]},
                "users": [],
                "firewall_rules": [],
            },
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["zone_cidrs"]["custom_zone"] == "0.0.0.0/0"


# ---------------------------------------------------------------------------
# DB user/password resolution edge cases
# ---------------------------------------------------------------------------


class TestDBUserResolution:
    """Verify _find_db_user and _find_db_pass edge cases."""

    def test_admin_user_not_picked_as_db_user(self):
        """Users in 'admins' group should not be picked as db_user."""
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[
                {
                    "username": "root_admin",
                    "password": "AdminPass!",
                    "groups": ["admins"],
                    "hosts": ["db"],
                },
            ]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        # Should use synthesized service account since only admin has db access.
        assert ctx["db_user"] == "svc_db"

    def test_non_admin_db_user_picked(self):
        """Non-admin user with db access should be picked."""
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[
                {
                    "username": "dbworker",
                    "password": "Work3r!Pass",
                    "groups": ["users"],
                    "hosts": ["db", "web"],
                },
            ]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["db_user"] == "dbworker"
        assert ctx["db_pass"] == "Work3r!Pass"

    def test_mysql_root_pass_from_admin_user(self):
        """Admin user with db access provides mysql root password."""
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[
                {
                    "username": "admin",
                    "password": "CustomR00t!",
                    "groups": ["admins"],
                    "hosts": ["db"],
                },
            ]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["mysql_root_password"] == "CustomR00t!"

    def test_mysql_root_pass_default(self):
        """No admin user should fall back to default root password."""
        spec = SnapshotSpec(
            topology=_minimal_topology(users=[]),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["mysql_root_password"] == "r00tP@ss!"


# ---------------------------------------------------------------------------
# Context: app_files from spec.files
# ---------------------------------------------------------------------------


class TestAppFiles:
    """Verify app_files context variable from spec.files."""

    def test_app_files_populated_when_spec_has_files(self):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
            files={"web:/var/www/portal/test.php": "<?php echo 1; ?>"},
        )
        ctx = _build_context(spec)
        assert "web:/var/www/portal/test.php" in ctx["app_files"]

    def test_app_files_empty_when_no_files(self):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[],
            golden_path=[],
        )
        ctx = _build_context(spec)
        assert ctx["app_files"] == {}


# ---------------------------------------------------------------------------
# Mixed flag types: some db, some file
# ---------------------------------------------------------------------------


class TestMixedFlagTypes:
    """Spec with both db-hosted and file-hosted flags."""

    def test_only_file_flags_in_dockerfile(self, renderer):
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[
                FlagSpec(
                    id="flag_file",
                    value="FLAG{in_file}",
                    path="/var/flags/flag1.txt",
                    host="web",
                ),
                FlagSpec(
                    id="flag_db",
                    value="FLAG{in_db}",
                    path="db:flags.secrets.flag",
                    host="db",
                ),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "mixed"
            renderer.render(spec, out)
            dockerfile = (out / "Dockerfile.web").read_text()
            assert "FLAG{in_file}" in dockerfile
            assert "FLAG{in_db}" not in dockerfile

    def test_sql_template_does_not_contain_any_flags(self, renderer):
        """init.sql is static template, flags go in via db:sql at runtime."""
        spec = SnapshotSpec(
            topology=_minimal_topology(),
            truth_graph=TruthGraph(vulns=[]),
            flags=[
                FlagSpec(id="f1", value="FLAG{a}", path="/var/flags/f.txt", host="web"),
                FlagSpec(id="f2", value="FLAG{b}", path="db:flags.secrets.flag", host="db"),
            ],
            golden_path=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "mixed_sql"
            renderer.render(spec, out)
            sql = (out / "init.sql").read_text()
            # Static template shouldn't have dynamic flag values
            assert "FLAG{a}" not in sql
            assert "FLAG{b}" not in sql
