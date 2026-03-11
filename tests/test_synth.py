from __future__ import annotations

from pathlib import Path

from open_range.compiler import EnterpriseSaaSManifestCompiler
from open_range.synth import EnterpriseSaaSWorldSynthesizer
from open_range.weaknesses import CatalogWeaknessSeeder


def _manifest_payload() -> dict:
    return {
        "version": 1,
        "world_family": "enterprise_saas_v1",
        "seed": 1337,
        "business": {
            "archetype": "healthcare_saas",
            "workflows": [
                "helpdesk_ticketing",
                "payroll_approval",
                "document_sharing",
                "internal_email",
            ],
        },
        "topology": {
            "zones": ["external", "dmz", "corp", "data", "management"],
            "services": ["web_app", "email", "idp", "fileshare", "db", "siem"],
        },
        "users": {
            "roles": {"sales": 2, "engineer": 1, "finance": 1, "it_admin": 1},
        },
        "assets": [
            {"id": "finance_docs", "class": "crown_jewel"},
            {"id": "payroll_db", "class": "crown_jewel"},
            {"id": "idp_admin_cred", "class": "sensitive"},
        ],
        "objectives": {
            "red": [
                {"predicate": "credential_obtained(idp_admin_cred)"},
                {"predicate": "asset_read(finance_docs)"},
            ],
            "blue": [
                {"predicate": "intrusion_detected(initial_access)"},
                {"predicate": "intrusion_contained(before_asset_read)"},
                {"predicate": "service_health_above(0.9)"},
            ],
        },
        "security": {
            "allowed_weakness_families": [
                "auth_misconfig",
                "workflow_abuse",
                "secret_exposure",
                "input_validation",
                "telemetry_blindspot",
            ],
            "observability": {
                "require_web_logs": True,
                "require_idp_logs": True,
                "require_email_logs": True,
                "require_siem_ingest": True,
            },
        },
        "difficulty": {
            "target_red_path_depth": 4,
            "target_blue_signal_points": 4,
            "target_noise_density": "medium",
        },
        "mutation_bounds": {
            "max_new_hosts": 2,
            "max_new_services": 1,
            "max_new_users": 5,
            "max_new_weaknesses": 2,
        },
    }


def test_synthesizer_generates_bounded_seed_artifacts(tmp_path: Path):
    world = CatalogWeaknessSeeder().apply(EnterpriseSaaSManifestCompiler().compile(_manifest_payload()))

    synth = EnterpriseSaaSWorldSynthesizer().synthesize(world, tmp_path / "synth")

    assert Path(synth.summary_path).exists()
    assert "svc-web" in synth.service_payloads
    assert any(file.mount_path == "/var/www/html/index.html" for file in synth.service_payloads["svc-web"])
    assert any(file.mount_path == "/docker-entrypoint-initdb.d/01-init.sql" for file in synth.service_payloads["svc-db"])
    assert synth.mailboxes
