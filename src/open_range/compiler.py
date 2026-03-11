"""Deterministic manifest compiler for the fixed `enterprise_saas_v1` family."""

from __future__ import annotations

from typing import Protocol

from open_range.build_config import BuildConfig, DEFAULT_BUILD_CONFIG
from open_range.manifest import EnterpriseSaaSManifest, ManifestAsset, validate_manifest
from open_range.world_ir import (
    AssetSpec,
    CredentialSpec,
    EdgeSpec,
    GreenPersona,
    GreenWorkloadSpec,
    GroupSpec,
    HostSpec,
    LineageSpec,
    MutationBoundsSpec,
    ObjectiveSpec,
    ServiceSpec,
    UserSpec,
    WorkflowSpec,
    WorkflowStepSpec,
    WorldIR,
)


class ManifestCompiler(Protocol):
    def compile(
        self,
        manifest: dict | EnterpriseSaaSManifest,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> WorldIR: ...


class EnterpriseSaaSManifestCompiler:
    """Compile the strict manifest into a hand-checkable WorldIR."""

    _SERVICE_LAYOUT = {
        "web_app": {
            "host_id": "web-1",
            "service_id": "svc-web",
            "zone": "dmz",
            "exposure": "public",
            "ports": (80, 443),
            "dependencies": ("svc-db", "svc-idp", "svc-fileshare"),
            "telemetry": ("web_access", "web_error"),
        },
        "email": {
            "host_id": "mail-1",
            "service_id": "svc-email",
            "zone": "dmz",
            "exposure": "public",
            "ports": (25, 587, 993),
            "dependencies": ("svc-idp",),
            "telemetry": ("smtp", "imap"),
        },
        "idp": {
            "host_id": "idp-1",
            "service_id": "svc-idp",
            "zone": "management",
            "exposure": "management",
            "ports": (389,),
            "dependencies": (),
            "telemetry": ("auth", "audit"),
        },
        "fileshare": {
            "host_id": "files-1",
            "service_id": "svc-fileshare",
            "zone": "corp",
            "exposure": "corp",
            "ports": (445,),
            "dependencies": ("svc-idp",),
            "telemetry": ("share_access",),
        },
        "db": {
            "host_id": "db-1",
            "service_id": "svc-db",
            "zone": "data",
            "exposure": "data",
            "ports": (3306,),
            "dependencies": (),
            "telemetry": ("query", "slow_query"),
        },
        "siem": {
            "host_id": "siem-1",
            "service_id": "svc-siem",
            "zone": "management",
            "exposure": "management",
            "ports": (514, 9200),
            "dependencies": (),
            "telemetry": ("ingest", "alert"),
        },
    }

    _ROLE_HOME_SERVICE = {
        "sales": "svc-web",
        "engineer": "svc-web",
        "finance": "svc-fileshare",
        "it_admin": "svc-idp",
    }

    def compile(
        self,
        manifest: dict | EnterpriseSaaSManifest,
        build_config: BuildConfig = DEFAULT_BUILD_CONFIG,
    ) -> WorldIR:
        parsed = manifest if isinstance(manifest, EnterpriseSaaSManifest) else validate_manifest(manifest)
        service_names = self._selected_services(parsed, build_config)
        workflow_names = self._selected_workflows(parsed, build_config)
        allowed_families = self._selected_weakness_families(parsed, build_config)
        allowed_surfaces = set(build_config.observability_surfaces_enabled)

        hosts = []
        services = []
        network_edges = []
        trust_edges = []
        telemetry_edges = []

        for service_name in service_names:
            if service_name not in self._SERVICE_LAYOUT:
                raise ValueError(f"unsupported enterprise_saas_v1 service: {service_name}")
            layout = self._SERVICE_LAYOUT[service_name]
            zone = self._resolve_zone(parsed.topology.zones, layout["zone"])
            telemetry = layout["telemetry"]
            if allowed_surfaces:
                telemetry = tuple(surface for surface in telemetry if surface in allowed_surfaces)
            hosts.append(
                HostSpec(
                    id=layout["host_id"],
                    zone=zone,
                    exposure=layout["exposure"],
                    services=(layout["service_id"],),
                )
            )
            services.append(
                ServiceSpec(
                    id=layout["service_id"],
                    kind=service_name,
                    host=layout["host_id"],
                    ports=layout["ports"],
                    dependencies=layout["dependencies"],
                    telemetry_surfaces=telemetry,
                )
            )
            for dep in layout["dependencies"]:
                network_edges.append(
                    EdgeSpec(
                        id=f"net-{layout['service_id']}-to-{dep}",
                        kind="network",
                        source=layout["service_id"],
                        target=dep,
                        label="service_dependency",
                    )
                )
                trust_edges.append(
                    EdgeSpec(
                        id=f"trust-{layout['service_id']}-to-{dep}",
                        kind="trust",
                        source=layout["service_id"],
                        target=dep,
                        label="service_trust",
                    )
                )
            if service_name != "siem" and (not allowed_surfaces or telemetry):
                telemetry_edges.append(
                    EdgeSpec(
                        id=f"telemetry-{layout['service_id']}-to-siem",
                        kind="telemetry",
                        source=layout["service_id"],
                        target="svc-siem",
                        label="log_ship",
                    )
                )

        users, groups, credentials, personas = self._expand_users(parsed, build_config)
        workflows, data_edges = self._compile_workflows(parsed, workflow_names)
        assets = tuple(self._place_asset(asset) for asset in parsed.assets)

        red_objectives = tuple(
            ObjectiveSpec(id=f"red-{idx}", owner="red", predicate=obj.predicate)
            for idx, obj in enumerate(parsed.objectives.red, start=1)
        )
        blue_objectives = tuple(
            ObjectiveSpec(id=f"blue-{idx}", owner="blue", predicate=obj.predicate)
            for idx, obj in enumerate(parsed.objectives.blue, start=1)
        )

        return WorldIR(
            world_id=f"{parsed.world_family}-{parsed.seed}",
            seed=parsed.seed,
            business_archetype=parsed.business.archetype,
            allowed_service_kinds=service_names,
            allowed_weakness_families=allowed_families,
            target_red_path_depth=parsed.difficulty.target_red_path_depth,
            target_blue_signal_points=parsed.difficulty.target_blue_signal_points,
            zones=parsed.topology.zones,
            hosts=tuple(hosts),
            services=tuple(services),
            users=users,
            groups=groups,
            credentials=credentials,
            assets=assets,
            workflows=workflows,
            network_edges=tuple(network_edges),
            trust_edges=tuple(trust_edges),
            data_edges=data_edges,
            telemetry_edges=tuple(telemetry_edges),
            weaknesses=(),
            red_objectives=red_objectives,
            blue_objectives=blue_objectives,
            green_personas=personas if build_config.green_artifacts_enabled else (),
            green_workload=GreenWorkloadSpec(
                noise_density=parsed.difficulty.target_noise_density,
            ),
            mutation_bounds=MutationBoundsSpec(
                max_new_hosts=parsed.mutation_bounds.max_new_hosts,
                max_new_services=parsed.mutation_bounds.max_new_services,
                max_new_users=parsed.mutation_bounds.max_new_users,
                max_new_weaknesses=parsed.mutation_bounds.max_new_weaknesses,
            ),
            lineage=LineageSpec(seed=parsed.seed),
        )

    @staticmethod
    def _selected_services(
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple[str, ...]:
        services = tuple(manifest.topology.services)
        if build_config.services_enabled:
            enabled = set(build_config.services_enabled)
            services = tuple(service for service in services if service in enabled)
        if not services:
            raise ValueError("build_config removed all services from the world")
        return services

    @staticmethod
    def _selected_workflows(
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple[str, ...]:
        workflows = tuple(manifest.business.workflows)
        if build_config.workflows_enabled:
            enabled = set(build_config.workflows_enabled)
            workflows = tuple(workflow for workflow in workflows if workflow in enabled)
        if not workflows:
            raise ValueError("build_config removed all workflows from the world")
        return workflows

    @staticmethod
    def _selected_weakness_families(
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple:
        families = tuple(manifest.security.allowed_weakness_families)
        if build_config.weakness_families_enabled:
            enabled = set(build_config.weakness_families_enabled)
            families = tuple(family for family in families if family in enabled)
        if not families:
            raise ValueError("build_config removed all enabled weakness families")
        return families

    @staticmethod
    def _resolve_zone(available: tuple[str, ...], preferred: str) -> str:
        if preferred in available:
            return preferred
        if available:
            return available[0]
        raise ValueError("manifest must declare at least one topology zone")

    def _expand_users(
        self,
        manifest: EnterpriseSaaSManifest,
        build_config: BuildConfig,
    ) -> tuple[
        tuple[UserSpec, ...],
        tuple[GroupSpec, ...],
        tuple[CredentialSpec, ...],
        tuple[GreenPersona, ...],
    ]:
        users = []
        groups = []
        credentials = []
        personas = []

        for role, count in manifest.users.roles.items():
            scaled_count = 1 if build_config.topology_scale == "small" else count
            member_ids = []
            home_service = self._ROLE_HOME_SERVICE.get(role, "svc-web")
            home_host = self._host_for_service(home_service)
            for idx in range(1, scaled_count + 1):
                user_id = f"{role}-{idx:02d}"
                member_ids.append(user_id)
                users.append(
                    UserSpec(
                        id=user_id,
                        role=role,
                        department=role,
                        primary_host=home_host,
                        groups=(f"group-{role}",),
                        email=f"{user_id}@corp.local",
                    )
                )
                credentials.append(
                    CredentialSpec(
                        id=f"cred-{user_id}",
                        subject=user_id,
                        secret_ref=f"secret://idp/{user_id}",
                        scope=("svc-idp", home_service),
                    )
                )
                personas.append(
                    GreenPersona(
                        id=user_id,
                        role=role,
                        department=role,
                        home_host=home_host,
                        mailbox=f"{user_id}@corp.local",
                        routine=self._routine_for_role(role),
                    )
                )
            groups.append(
                GroupSpec(
                    id=f"group-{role}",
                    members=tuple(member_ids),
                    privileges=(home_service,),
                )
            )

        return tuple(users), tuple(groups), tuple(credentials), tuple(personas)

    def _compile_workflows(
        self,
        manifest: EnterpriseSaaSManifest,
        workflow_names: tuple[str, ...],
    ) -> tuple[tuple[WorkflowSpec, ...], tuple[EdgeSpec, ...]]:
        workflows = []
        data_edges = []
        for workflow_name in workflow_names:
            steps = self._workflow_steps(workflow_name)
            workflows.append(
                WorkflowSpec(
                    id=f"wf-{workflow_name}",
                    name=workflow_name,
                    steps=steps,
                )
            )
            for idx, step in enumerate(steps, start=1):
                if step.asset:
                    data_edges.append(
                        EdgeSpec(
                            id=f"data-{workflow_name}-{idx}",
                            kind="data",
                            source=step.service or step.actor_role,
                            target=step.asset,
                            label=step.action,
                        )
                    )
        return tuple(workflows), tuple(data_edges)

    @staticmethod
    def _workflow_steps(workflow_name: str) -> tuple[WorkflowStepSpec, ...]:
        if workflow_name == "helpdesk_ticketing":
            return (
                WorkflowStepSpec(id="open-ticket", actor_role="sales", action="open_ticket", service="svc-web"),
                WorkflowStepSpec(id="mail-update", actor_role="sales", action="send_update", service="svc-email"),
            )
        if workflow_name == "payroll_approval":
            return (
                WorkflowStepSpec(id="view-payroll", actor_role="finance", action="view_payroll", service="svc-web", asset="payroll_db"),
                WorkflowStepSpec(id="approve-payroll", actor_role="finance", action="approve_payroll", service="svc-db", asset="payroll_db"),
            )
        if workflow_name == "document_sharing":
            return (
                WorkflowStepSpec(id="share-doc", actor_role="sales", action="share_document", service="svc-fileshare", asset="finance_docs"),
            )
        if workflow_name == "internal_email":
            return (
                WorkflowStepSpec(id="check-mail", actor_role="sales", action="check_mail", service="svc-email"),
            )
        return (
            WorkflowStepSpec(id=f"{workflow_name}-step-1", actor_role="sales", action=workflow_name, service="svc-web"),
        )

    @staticmethod
    def _place_asset(asset: ManifestAsset) -> AssetSpec:
        asset_id = asset.id.lower()
        if "db" in asset_id:
            service = "svc-db"
            location = f"svc-db://main/{asset.id}"
        elif any(token in asset_id for token in ("doc", "file", "share")):
            service = "svc-fileshare"
            location = f"svc-fileshare:/srv/{asset.id}"
        elif any(token in asset_id for token in ("cred", "password", "token", "key")):
            service = "svc-idp"
            location = f"svc-idp://secrets/{asset.id}"
        else:
            service = "svc-web"
            location = f"svc-web://content/{asset.id}"

        confidentiality = {
            "crown_jewel": "critical",
            "sensitive": "high",
            "operational": "medium",
        }[asset.asset_class]
        return AssetSpec(
            id=asset.id,
            asset_class=asset.asset_class,
            location=location,
            owner_service=service,
            confidentiality=confidentiality,
        )

    @staticmethod
    def _host_for_service(service_id: str) -> str:
        for layout in EnterpriseSaaSManifestCompiler._SERVICE_LAYOUT.values():
            if layout["service_id"] == service_id:
                return layout["host_id"]
        return "web-1"

    @staticmethod
    def _routine_for_role(role: str) -> tuple[str, ...]:
        if role == "finance":
            return ("check_mail", "open_payroll_dashboard", "access_fileshare")
        if role == "it_admin":
            return ("review_idp", "triage_alerts", "reset_password")
        return ("check_mail", "browse_app", "access_fileshare")
