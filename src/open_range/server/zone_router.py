"""Zone-based network routing enforcement.

Replaces iptables in the all-in-one container deployment.
All services run on localhost; this module enforces which
zones can reach which other zones on which ports.

The agent experiences identical training signal to a
multi-container setup with real iptables rules.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Default Tier 1 zone routing table
# Maps (from_zone, to_zone) -> set of allowed ports
ZONE_ROUTES: dict[tuple[str, str], set[int]] = {
    ("external", "dmz"): {80, 443, 25},
    ("dmz", "internal"): {3306, 445},
    ("dmz", "management"): {389, 636},
    ("internal", "management"): {389},
    ("management", "dmz"): {514},
    ("management", "internal"): {514},
}

# Host -> zone mapping for Tier 1
HOST_ZONES: dict[str, str] = {
    "attacker": "external",
    "firewall": "external",  # multi-homed but agent sees external
    "web": "dmz",
    "mail": "dmz",
    "db": "internal",
    "files": "internal",
    "ldap": "management",
    "siem": "management",
}

# Host -> localhost port mapping (all services on localhost in subprocess mode)
HOST_PORTS: dict[str, dict[str, int]] = {
    "web": {"http": 80, "https": 443},
    "mail": {"smtp": 25},
    "db": {"mysql": 3306},
    "files": {"smb": 445},
    "ldap": {"ldap": 389, "ldaps": 636},
    "siem": {"syslog": 514},
}


@dataclass
class ZoneRouter:
    """Enforces network zone routing policy."""

    routes: dict[tuple[str, str], set[int]] = field(default_factory=lambda: dict(ZONE_ROUTES))
    host_zones: dict[str, str] = field(default_factory=lambda: dict(HOST_ZONES))

    @classmethod
    def from_snapshot(cls, topology: dict[str, Any]) -> "ZoneRouter":
        """Build router from snapshot topology and firewall rules."""
        router = cls()

        # Override host_zones from topology
        for host in topology.get("hosts", []):
            if isinstance(host, dict):
                name = host.get("name", "")
                zone = host.get("zone", "")
                if name and zone:
                    router.host_zones[name] = zone
            elif isinstance(host, str):
                pass  # keep defaults

        # Override routes from firewall_rules
        rules = topology.get("firewall_rules", [])
        if rules:
            router.routes = {}
            for rule in rules:
                action = rule.get("action", "deny")
                if action != "allow":
                    continue
                from_z = rule.get("from_zone", rule.get("from", ""))
                to_z = rule.get("to_zone", rule.get("to", ""))
                ports = set(rule.get("ports", []))
                if from_z and to_z:
                    key = (from_z, to_z)
                    router.routes[key] = router.routes.get(key, set()) | ports

        return router

    def can_reach(self, from_zone: str, to_zone: str, port: int) -> bool:
        """Check if a connection from one zone to another on a port is allowed."""
        if from_zone == to_zone:
            return True  # same zone always allowed
        allowed_ports = self.routes.get((from_zone, to_zone), set())
        return port in allowed_ports

    def get_zone(self, host: str) -> str:
        """Get the zone for a host."""
        return self.host_zones.get(host, "unknown")

    def check_command_access(self, from_host: str, target_host: str, port: int = 0) -> tuple[bool, str]:
        """Check if from_host can access target_host on port.

        Returns (allowed, reason).
        """
        from_zone = self.get_zone(from_host)
        to_zone = self.get_zone(target_host)

        if from_zone == "unknown" or to_zone == "unknown":
            return True, "unknown zone, allowing"  # permissive for unknown hosts

        if self.can_reach(from_zone, to_zone, port):
            logger.debug("ALLOW %s(%s) -> %s(%s):%d", from_host, from_zone, target_host, to_zone, port)
            return True, "allowed"
        else:
            logger.info("BLOCK %s(%s) -> %s(%s):%d", from_host, from_zone, target_host, to_zone, port)
            return False, f"Zone {from_zone} cannot reach {to_zone} on port {port}"
