"""Manifest-to-topology compilation helpers for root snapshot hydration.

These helpers turn a manifest's declared company world into the canonical
topology fields the mutator, validators, and runtime expect to reason about.
They intentionally keep "real login users" separate from trust-only narrative
principals so the trust graph can be compiled without silently creating extra
accounts in rendered services.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import PurePosixPath
import re
from typing import Any


def build_host_catalog(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the manifest-defined host catalog keyed by host name."""
    catalog: dict[str, dict[str, Any]] = {}
    for raw in manifest.get("topology", {}).get("hosts", []):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "")).strip()
        if not name:
            continue
        catalog[name] = {
            "zone": str(raw.get("zone", "")),
            "services": deepcopy(raw.get("services", [])),
            "connects_to": deepcopy(raw.get("connects_to", [])),
            "purpose": str(raw.get("purpose", "")),
            "hostname": str(raw.get("hostname", "")),
            "os": str(raw.get("os", "")),
            "exposure": deepcopy(raw.get("exposure", {})),
        }
    return catalog


def build_principal_catalog(
    manifest: dict[str, Any],
    existing: dict[str, Any] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Return a canonical principal catalog plus normalized trust-only names."""
    catalog: dict[str, dict[str, Any]] = {}
    trust_only: set[str] = set()

    if isinstance(existing, dict):
        for name, raw in existing.items():
            principal = str(name).strip()
            if not principal or not isinstance(raw, dict):
                continue
            catalog[principal] = deepcopy(raw)

    for raw in manifest.get("users", []):
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username", "")).strip()
        if not username:
            continue
        principal = catalog.setdefault(username, {})
        principal.update(
            {
                "username": username,
                "kind": "user",
                "is_login_account": True,
                "hosts": deepcopy(raw.get("hosts", [])),
                "department": str(raw.get("department", "")),
                "role": str(raw.get("role", "")),
                "email": str(raw.get("email", "")),
                "full_name": str(raw.get("full_name", "")),
            }
        )

    for raw in manifest.get("trust_relationships", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source") or raw.get("from") or "").strip()
        target = str(raw.get("target") or raw.get("to") or "").strip()
        for principal_name in (source, target):
            if not principal_name:
                continue
            principal = catalog.setdefault(principal_name, {})
            if not principal.get("is_login_account", False):
                trust_only.add(principal_name)
            principal.setdefault("username", principal_name)
            principal.setdefault("kind", "trust_principal")
            principal.setdefault("is_login_account", False)
            principal.setdefault("hosts", [])
            principal.setdefault("department", "")
            principal.setdefault("role", "")
            principal.setdefault("email", "")
            principal.setdefault("full_name", "")

    return catalog, sorted(trust_only)


def compile_manifest_topology(
    manifest: dict[str, Any],
    topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile manifest state into graph-friendly topology fields.

    Existing topology fields are preserved where possible so builder-generated
    details such as passwords or payload-specific knobs survive root hydration.
    """
    compiled = deepcopy(topology) if isinstance(topology, dict) else {}
    company = manifest.get("company", {}) if isinstance(manifest.get("company"), dict) else {}

    compiled.setdefault("tier", int(manifest.get("tier", compiled.get("tier", 1)) or 1))
    compiled.setdefault("domain", company.get("domain", "acmecorp.local"))
    compiled.setdefault("org_name", company.get("name", "AcmeCorp"))
    compiled.setdefault("manifest_name", manifest.get("name", ""))
    compiled.setdefault("difficulty", deepcopy(manifest.get("difficulty", {})))
    compiled.setdefault(
        "networks",
        deepcopy(manifest.get("topology", {}).get("networks", [])),
    )
    compiled.setdefault(
        "firewall_rules",
        deepcopy(manifest.get("topology", {}).get("firewall_rules", [])),
    )

    host_catalog = build_host_catalog(manifest)
    compiled["host_catalog"] = host_catalog
    compiled["hosts"] = _merge_hosts(compiled.get("hosts"), host_catalog)
    compiled["zones"] = _merge_zones(compiled.get("zones"), host_catalog)
    compiled["users"] = _merge_users(compiled.get("users"), manifest)
    compiled["host_details"] = _merge_host_details(compiled.get("host_details"), host_catalog)
    compiled["dependency_edges"] = _merge_dependency_edges(
        compiled.get("dependency_edges"),
        host_catalog,
    )

    principal_catalog, trust_only = build_principal_catalog(
        manifest,
        existing=compiled.get("principal_catalog")
        if isinstance(compiled.get("principal_catalog"), dict)
        else None,
    )
    compiled["principal_catalog"] = principal_catalog
    compiled["trust_edges"] = _merge_trust_edges(compiled.get("trust_edges"), manifest)
    compiled["manifest_normalization"] = {
        "trust_only_principals": trust_only,
        "notes": [
            (
                "Normalized trust principals not present in manifest users into "
                "principal_catalog only"
            )
        ]
        if trust_only
        else [],
    }
    runtime_contract = runtime_contract_from_topology(compiled, manifest=manifest)
    compiled["runtime_contract"] = runtime_contract
    compiled.setdefault("web_host", runtime_contract["web_host"])
    compiled.setdefault("db_host", runtime_contract["db_host"])
    compiled.setdefault("ldap_host", runtime_contract["ldap_host"])
    compiled.setdefault("web_doc_root", runtime_contract["web_doc_root"])
    compiled.setdefault("web_config_path", runtime_contract["web_config_path"])
    compiled.setdefault("db_name", runtime_contract["db_name"])
    compiled.setdefault("db_user", runtime_contract["db_user"])
    compiled.setdefault("db_pass", runtime_contract["db_password"])
    compiled.setdefault("db_password", runtime_contract["db_password"])
    compiled.setdefault("ldap_bind_dn", runtime_contract["ldap_bind_dn"])
    compiled.setdefault("ldap_bind_pw", runtime_contract["ldap_bind_pw"])
    compiled.setdefault("ldap_search_base_dn", runtime_contract["ldap_search_base_dn"])
    compiled.setdefault("credential_reuse_user", runtime_contract["credential_reuse_user"])
    compiled.setdefault("credential_reuse_host", runtime_contract["credential_reuse_host"])
    compiled.setdefault(
        "credential_reuse_password",
        runtime_contract["credential_reuse_password"],
    )

    service_accounts = compiled.get("service_accounts")
    if not isinstance(service_accounts, dict):
        service_accounts = {}
    webapp = service_accounts.get("webapp")
    if not isinstance(webapp, dict):
        webapp = {}
    webapp.setdefault("username", runtime_contract["db_user"])
    webapp.setdefault("password", runtime_contract["db_password"])
    webapp.setdefault("ldap_bind_dn", runtime_contract["ldap_bind_dn"])
    webapp.setdefault("ldap_bind_pw", runtime_contract["ldap_bind_pw"])
    service_accounts["webapp"] = webapp
    compiled["service_accounts"] = service_accounts
    return compiled


def runtime_contract_from_topology(
    topology: dict[str, Any] | None,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Derive runtime service/account semantics from compiled topology state."""
    source = topology if isinstance(topology, dict) else {}
    runtime = deepcopy(source.get("runtime_contract", {}))
    if not isinstance(runtime, dict):
        runtime = {}

    domain = _coerce_text(
        runtime.get("domain"),
        source.get("domain"),
        _manifest_company_domain(manifest),
        default="corp.local",
    )
    host_catalog = source.get("host_catalog", {})
    if not isinstance(host_catalog, dict):
        host_catalog = {}
    host_details = source.get("host_details", {})
    if not isinstance(host_details, dict):
        host_details = {}
    hosts = _normalized_hosts(source.get("hosts", []))

    web_host = _select_core_host(
        explicit=_coerce_text(runtime.get("web_host"), source.get("web_host")),
        hosts=hosts,
        host_maps=[host_catalog, host_details],
        preferred_names=("web", "portal", "frontend"),
        service_markers=("nginx", "apache", "http", "php", "gunicorn", "uvicorn"),
        fallback="web",
    )
    db_host = _select_core_host(
        explicit=_coerce_text(runtime.get("db_host"), source.get("db_host")),
        hosts=hosts,
        host_maps=[host_catalog, host_details],
        preferred_names=("db", "database", "mysql"),
        service_markers=("mysql", "mariadb", "postgres", "postgresql", "database"),
        fallback="db",
    )
    ldap_host = _select_core_host(
        explicit=_coerce_text(runtime.get("ldap_host"), source.get("ldap_host")),
        hosts=hosts,
        host_maps=[host_catalog, host_details],
        preferred_names=("ldap", "directory", "idp"),
        service_markers=("ldap", "openldap"),
        fallback="ldap",
    )

    db_name = _coerce_text(
        runtime.get("db_name"),
        source.get("db_name"),
        _infer_manifest_db_name(manifest),
        default="referral_db",
    )

    service_accounts = source.get("service_accounts", {})
    if not isinstance(service_accounts, dict):
        service_accounts = {}
    webapp_account = service_accounts.get("webapp", {})
    if not isinstance(webapp_account, dict):
        webapp_account = {}

    db_user = _coerce_text(
        runtime.get("db_user"),
        source.get("db_user"),
        source.get("db_app_user"),
        webapp_account.get("username"),
    )
    db_password = _coerce_text(
        runtime.get("db_password"),
        runtime.get("db_pass"),
        source.get("db_password"),
        source.get("db_pass"),
        source.get("db_app_password"),
        webapp_account.get("password"),
    )

    users = source.get("users", [])
    selected_user, selected_password = _pick_db_account(users, db_host)
    if not db_user:
        db_user = selected_user
    if not db_password:
        db_password = selected_password
    if not db_user:
        db_user = f"svc_{_slug_token(db_host or 'db')}"
    if not db_password:
        db_password = _predictable_service_password(db_user, domain)

    web_doc_root = _coerce_text(
        runtime.get("web_doc_root"),
        source.get("web_doc_root"),
        default="/var/www/portal",
    )
    if not web_doc_root.startswith("/"):
        web_doc_root = f"/{web_doc_root}"
    web_doc_parent = PurePosixPath(web_doc_root).parent
    default_config_path = (web_doc_parent / "config.php").as_posix()
    if not default_config_path.startswith("/"):
        default_config_path = "/var/www/config.php"
    web_config_path = _coerce_text(
        runtime.get("web_config_path"),
        source.get("web_config_path"),
        default=default_config_path,
    )
    if not web_config_path.startswith("/"):
        web_config_path = f"/{web_config_path}"

    ldap_base_dn = _domain_to_ldap_dn(domain)
    ldap_search_base_dn = _coerce_text(
        runtime.get("ldap_search_base_dn"),
        source.get("ldap_search_base_dn"),
        default=ldap_base_dn,
    )
    ldap_bind_dn = _coerce_text(
        runtime.get("ldap_bind_dn"),
        source.get("ldap_bind_dn"),
        webapp_account.get("ldap_bind_dn"),
        default=f"cn={db_user},{ldap_base_dn}",
    )
    ldap_bind_pw = _coerce_text(
        runtime.get("ldap_bind_pw"),
        source.get("ldap_bind_pw"),
        webapp_account.get("ldap_bind_pw"),
        default=db_password,
    )

    credential_reuse_user = _coerce_text(
        runtime.get("credential_reuse_user"),
        source.get("credential_reuse_user"),
        default=db_user,
    )
    credential_reuse_host = _coerce_text(
        runtime.get("credential_reuse_host"),
        source.get("credential_reuse_host"),
        default=db_host,
    )
    credential_reuse_password = _coerce_text(
        runtime.get("credential_reuse_password"),
        source.get("credential_reuse_password"),
        default=ldap_bind_pw,
    )

    return {
        "domain": domain,
        "web_host": web_host,
        "db_host": db_host,
        "ldap_host": ldap_host,
        "web_doc_root": web_doc_root,
        "web_config_path": web_config_path,
        "db_name": db_name,
        "db_user": db_user,
        "db_password": db_password,
        "ldap_bind_dn": ldap_bind_dn,
        "ldap_bind_pw": ldap_bind_pw,
        "ldap_search_base_dn": ldap_search_base_dn,
        "credential_reuse_user": credential_reuse_user,
        "credential_reuse_host": credential_reuse_host,
        "credential_reuse_password": credential_reuse_password,
    }


def _manifest_company_domain(manifest: dict[str, Any] | None) -> str:
    if not isinstance(manifest, dict):
        return ""
    company = manifest.get("company", {})
    if not isinstance(company, dict):
        return ""
    return str(company.get("domain", "")).strip()


def _normalized_hosts(raw_hosts: object) -> list[str]:
    hosts: list[str] = []
    if not isinstance(raw_hosts, list):
        return hosts
    for raw in raw_hosts:
        if isinstance(raw, dict):
            name = str(raw.get("name", "")).strip()
        else:
            name = str(raw).strip()
        if name and name not in hosts:
            hosts.append(name)
    return hosts


def _select_core_host(
    *,
    explicit: str,
    hosts: list[str],
    host_maps: list[dict[str, Any]],
    preferred_names: tuple[str, ...],
    service_markers: tuple[str, ...],
    fallback: str,
) -> str:
    if explicit and (not hosts or explicit in hosts):
        return explicit
    for name in preferred_names:
        if name in hosts:
            return name
    for host in hosts:
        services = _host_services(host, host_maps)
        if not services:
            continue
        if any(
            marker in service
            for service in services
            for marker in service_markers
        ):
            return host
    for host in hosts:
        lowered = host.lower()
        if any(name in lowered for name in preferred_names):
            return host
    if hosts:
        return hosts[0]
    return fallback


def _host_services(host: str, host_maps: list[dict[str, Any]]) -> list[str]:
    services: list[str] = []
    for host_map in host_maps:
        detail = host_map.get(host, {})
        if not isinstance(detail, dict):
            continue
        raw_services = detail.get("services", [])
        if not isinstance(raw_services, list):
            continue
        for raw_service in raw_services:
            service = str(raw_service).strip().lower()
            if service and service not in services:
                services.append(service)
    return services


def _pick_db_account(raw_users: object, db_host: str) -> tuple[str, str]:
    if not isinstance(raw_users, list):
        return "", ""
    for raw in raw_users:
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username", "")).strip()
        if not username:
            continue
        hosts = raw.get("hosts", [])
        if not isinstance(hosts, list) or db_host not in hosts:
            continue
        password = str(raw.get("password", "")).strip()
        if not _is_privileged_account(raw):
            return username, password
    return "", ""


def _is_privileged_account(user: dict[str, Any]) -> bool:
    groups = user.get("groups", [])
    if isinstance(groups, list):
        lowered = {str(group).strip().lower() for group in groups}
        if {"admin", "admins"} & lowered:
            return True
    role = str(user.get("role", "")).lower()
    return "admin" in role


def _infer_manifest_db_name(manifest: dict[str, Any] | None) -> str:
    if not isinstance(manifest, dict):
        return ""
    for raw in manifest.get("data_inventory", []):
        if not isinstance(raw, dict):
            continue
        location = str(raw.get("location", "")).strip()
        lowered = location.lower()
        for prefix in ("mysql:", "db:"):
            if not lowered.startswith(prefix):
                continue
            raw_name = location[len(prefix):].split(".", 1)[0].strip()
            if raw_name:
                return raw_name
    return ""


def _domain_to_ldap_dn(domain: str) -> str:
    parts = [part for part in domain.split(".") if part]
    if not parts:
        return "dc=corp,dc=local"
    return ",".join(f"dc={part}" for part in parts)


def _predictable_service_password(username: str, domain: str) -> str:
    token = _slug_token(username).replace("_", "")
    if not token:
        token = "service"
    suffix = 200 + (sum(ord(ch) for ch in f"{username}:{domain}") % 700)
    return f"{token.capitalize()}!{suffix}"


def _slug_token(value: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return token or "service"


def _coerce_text(*values: object, default: str = "") -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return default


def _merge_hosts(
    raw_hosts: object,
    host_catalog: dict[str, dict[str, Any]],
) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    if isinstance(raw_hosts, list):
        for raw in raw_hosts:
            if isinstance(raw, dict):
                name = str(raw.get("name", "")).strip()
            else:
                name = str(raw).strip()
            if not name or name in seen:
                continue
            seen.add(name)
            hosts.append(name)
    for host in host_catalog:
        if host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def _merge_zones(
    raw_zones: object,
    host_catalog: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    zones: dict[str, list[str]] = {}
    if isinstance(raw_zones, dict):
        for zone, raw_hosts in raw_zones.items():
            zone_name = str(zone).strip()
            if not zone_name:
                continue
            zone_hosts: list[str] = []
            if isinstance(raw_hosts, list):
                for raw_host in raw_hosts:
                    host = str(raw_host).strip()
                    if host and host not in zone_hosts:
                        zone_hosts.append(host)
            zones[zone_name] = zone_hosts

    for host, raw_catalog in host_catalog.items():
        zone = str(raw_catalog.get("zone", "")).strip() or "default"
        zone_hosts = zones.setdefault(zone, [])
        if host not in zone_hosts:
            zone_hosts.append(host)
    return zones


def _merge_users(raw_users: object, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    existing: dict[str, dict[str, Any]] = {}
    extras: list[dict[str, Any]] = []
    if isinstance(raw_users, list):
        for raw in raw_users:
            if not isinstance(raw, dict):
                continue
            username = str(raw.get("username", "")).strip()
            if not username:
                continue
            existing[username] = deepcopy(raw)

    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in manifest.get("users", []):
        if not isinstance(raw, dict):
            continue
        username = str(raw.get("username", "")).strip()
        if not username:
            continue
        record = existing.pop(username, {})
        record.setdefault("username", username)
        record.setdefault("password", "")
        record.setdefault("groups", [])
        record.setdefault("hosts", deepcopy(raw.get("hosts", [])))
        record.setdefault("email", str(raw.get("email", "")))
        record.setdefault("full_name", str(raw.get("full_name", "")))
        record.setdefault("department", str(raw.get("department", "")))
        record.setdefault("role", str(raw.get("role", "")))
        merged.append(record)
        seen.add(username)

    for username, record in existing.items():
        if username in seen:
            continue
        extras.append(record)
    merged.extend(extras)
    return merged


def _merge_host_details(
    raw_details: object,
    host_catalog: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    host_details: dict[str, dict[str, Any]] = {}
    if isinstance(raw_details, dict):
        for host, raw_detail in raw_details.items():
            host_name = str(host).strip()
            if not host_name or not isinstance(raw_detail, dict):
                continue
            host_details[host_name] = deepcopy(raw_detail)

    for host, raw_catalog in host_catalog.items():
        detail = host_details.setdefault(host, {})
        detail.setdefault("zone", str(raw_catalog.get("zone", "")))
        detail.setdefault("services", deepcopy(raw_catalog.get("services", [])))
        detail.setdefault("connects_to", deepcopy(raw_catalog.get("connects_to", [])))
        detail.setdefault("purpose", str(raw_catalog.get("purpose", "")))
        detail.setdefault("hostname", str(raw_catalog.get("hostname", "")))
        detail.setdefault("os", str(raw_catalog.get("os", "")))
        detail.setdefault("exposure", deepcopy(raw_catalog.get("exposure", {})))
    return host_details


def _merge_dependency_edges(
    raw_edges: object,
    host_catalog: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if isinstance(raw_edges, list):
        for raw in raw_edges:
            if not isinstance(raw, dict):
                continue
            source = str(raw.get("source", "")).strip()
            target = str(raw.get("target", "")).strip()
            if not source or not target or (source, target) in seen:
                continue
            edges.append({"source": source, "target": target})
            seen.add((source, target))

    for source, raw_catalog in host_catalog.items():
        raw_targets = raw_catalog.get("connects_to", [])
        if not isinstance(raw_targets, list):
            continue
        for raw_target in raw_targets:
            target = str(raw_target).strip()
            if not target or (source, target) in seen:
                continue
            edges.append({"source": source, "target": target})
            seen.add((source, target))
    return edges


def _merge_trust_edges(
    raw_edges: object,
    manifest: dict[str, Any],
) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    if isinstance(raw_edges, list):
        for raw in raw_edges:
            if not isinstance(raw, dict):
                continue
            source = str(raw.get("source", "")).strip()
            target = str(raw.get("target", "")).strip()
            edge_type = str(raw.get("type", "")).strip()
            if not source or not target or (source, target, edge_type) in seen:
                continue
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "type": edge_type,
                    "context": str(raw.get("context", "")),
                }
            )
            seen.add((source, target, edge_type))

    for raw in manifest.get("trust_relationships", []):
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("source") or raw.get("from") or "").strip()
        target = str(raw.get("target") or raw.get("to") or "").strip()
        edge_type = str(raw.get("type", "")).strip()
        if not source or not target or (source, target, edge_type) in seen:
            continue
        edges.append(
            {
                "source": source,
                "target": target,
                "type": edge_type,
                "context": str(raw.get("context") or raw.get("description") or ""),
            }
        )
        seen.add((source, target, edge_type))
    return edges
