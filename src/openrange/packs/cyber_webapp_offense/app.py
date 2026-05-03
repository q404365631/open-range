from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

IDP_SESSION_TOKEN = "or-idp-admin-session"
SUPPORT_RESET_TOKEN = "support-reset-2026"
FLAG_PATH = "/opt/openrange/flag.txt"


def first(query: dict[str, list[str]], name: str) -> str:
    values = query.get(name, [""])
    return values[0] if values else ""


class Handler(BaseHTTPRequestHandler):
    server: WebappServer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/":
            self.index()
            return
        if parsed.path == "/robots.txt":
            self.respond(200, "text/plain", f"Disallow: {self.server.admin_path}\n")
            return
        if parsed.path == "/.well-known/security.txt":
            self.respond(
                200,
                "text/plain",
                "Contact: security@example.test\nScope: this localhost range only\n",
            )
            return
        if parsed.path == "/openapi.json":
            self.respond(
                200,
                "application/json",
                json.dumps(self.server.openapi()),
            )
            return
        if parsed.path == self.server.admin_path:
            self.respond(
                200,
                "application/json",
                json.dumps({"role": "admin", "flag": self.server.flag}),
                event="SensitiveAssetRead",
            )
            return
        if parsed.path == "/api/admin":
            self.api_admin(query)
            return
        if parsed.path == "/search":
            self.search(query)
            return
        if parsed.path == "/records":
            self.records(query)
            return
        if parsed.path == "/download":
            self.download(query)
            return
        if parsed.path == "/fetch":
            self.fetch(query)
            return
        if parsed.path == "/ops":
            self.ops(query)
            return
        if parsed.path == "/idp/token":
            self.idp_token(query)
            return
        if parsed.path == "/vault":
            self.vault(query)
            return
        if parsed.path == "/mailbox/support":
            self.mailbox()
            return
        if parsed.path == "/siem/events":
            self.respond(200, "application/json", json.dumps(self.server.events()))
            return
        self.respond(404, "text/plain", "not found\n")

    def index(self) -> None:
        self.respond(
            200,
            "text/html",
            (
                "<h1>OpenRange Operations Portal</h1>"
                "<p>Public status: online.</p>"
                "<ul>"
                "<li><a href='/robots.txt'>robots</a></li>"
                "<li><a href='/search?q=quarterly'>search</a></li>"
                "<li><a href='/records?record=public'>records</a></li>"
                "<li><a href='/mailbox/support'>support mailbox</a></li>"
                "<li><a href='/openapi.json'>api index</a></li>"
                "</ul>"
            ),
        )

    def api_admin(self, query: dict[str, list[str]]) -> None:
        if first(query, "debug") == "1" and first(query, "as") == "admin":
            self.respond(
                200,
                "application/json",
                json.dumps(
                    {
                        "role": "admin",
                        "flag": self.server.flag,
                        "weakness": "auth_bypass",
                    },
                ),
                event="UnauthorizedCredentialUse",
            )
            return
        self.respond(403, "application/json", json.dumps({"error": "denied"}))

    def search(self, query: dict[str, list[str]]) -> None:
        q = first(query, "q")
        asset = first(query, "asset") or "public"
        lower_q = q.lower()
        if "union select" in lower_q or " or " in lower_q:
            self.respond(
                200,
                "application/json",
                json.dumps(
                    {
                        "rows": [
                            {
                                "asset": asset,
                                "value": self.server.flag,
                                "weakness": "sql_injection",
                            },
                        ],
                    },
                ),
                event="InitialAccess",
            )
            return
        if q.count("'") % 2 == 1:
            self.respond(
                500,
                "text/plain",
                f"sql error near {q!r}\nquery=SELECT * FROM assets WHERE q='{q}'\n",
            )
            return
        self.respond(
            200,
            "application/json",
            json.dumps({"rows": [{"asset": asset, "value": "public status"}]}),
        )

    def records(self, query: dict[str, list[str]]) -> None:
        record = first(query, "record") or "public"
        if record == "admin-console":
            self.respond(
                200,
                "application/json",
                json.dumps(
                    {
                        "record": record,
                        "owner": "admin",
                        "flag": self.server.flag,
                        "weakness": "broken_authorization",
                    },
                ),
                event="SensitiveAssetRead",
            )
            return
        self.respond(
            200,
            "application/json",
            json.dumps({"record": record, "owner": "public"}),
        )

    def download(self, query: dict[str, list[str]]) -> None:
        requested = first(query, "path")
        files = {
            "../../secrets/admin.env": f"ADMIN_FLAG={self.server.flag}\n",
            FLAG_PATH: f"{self.server.flag}\n",
            "reports/public.txt": "public report\n",
        }
        try:
            body = files[requested]
        except KeyError:
            self.respond(404, "text/plain", "missing\n")
            return
        self.respond(200, "text/plain", body, event="SensitiveAssetRead")

    def fetch(self, query: dict[str, list[str]]) -> None:
        url = first(query, "url")
        internal = {
            "http://metadata.local/latest/credentials": {
                "service": "metadata",
                "token": SUPPORT_RESET_TOKEN,
                "flag": self.server.flag,
                "weakness": "ssrf",
            },
            "http://siem.local/canary": {
                "service": "siem",
                "event": "CrossZoneTraversal",
            },
        }
        if url in internal:
            self.respond(
                200,
                "application/json",
                json.dumps(internal[url]),
                event="CrossZoneTraversal",
            )
            return
        status = 400 if not url else 403
        message = "missing url" if not url else "external fetch disabled"
        self.respond(status, "text/plain", f"{message}\n")

    def ops(self, query: dict[str, list[str]]) -> None:
        host = first(query, "host") or "127.0.0.1"
        if ";" in host and f"cat {FLAG_PATH}" in host:
            self.respond(
                200,
                "text/plain",
                f"scan=127.0.0.1\n{self.server.flag}\n",
                event="CommandInjection",
            )
            return
        self.respond(200, "text/plain", f"scan={host}\n")

    def idp_token(self, query: dict[str, list[str]]) -> None:
        if first(query, "username") == "admin" and first(query, "password") == "admin":
            self.respond(
                200,
                "application/json",
                json.dumps(
                    {
                        "access_token": IDP_SESSION_TOKEN,
                        "weakness": "default_credential",
                    },
                ),
                event="CredentialObtained",
            )
            return
        self.respond(401, "application/json", json.dumps({"error": "invalid login"}))

    def vault(self, query: dict[str, list[str]]) -> None:
        if first(query, "token") == IDP_SESSION_TOKEN:
            self.respond(
                200,
                "application/json",
                json.dumps(
                    {
                        "secret": self.server.flag,
                        "weakness": "overbroad_service_account",
                    },
                ),
                event="SensitiveAssetRead",
            )
            return
        self.respond(403, "application/json", json.dumps({"error": "denied"}))

    def mailbox(self) -> None:
        self.respond(
            200,
            "text/plain",
            (
                "Subject: Password reset verification\n\n"
                "Use the emergency service account if the reset workflow blocks you.\n"
                "username=admin\npassword=admin\n"
                f"reset_token={SUPPORT_RESET_TOKEN}\n"
            ),
        )

    def log_message(self, format: str, *args: object) -> None:
        return

    def respond(
        self,
        status: int,
        content_type: str,
        body: str,
        *,
        event: str = "",
    ) -> None:
        self.server.log_access(self.command, self.path, status, event)
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


class WebappServer(ThreadingHTTPServer):
    def __init__(
        self,
        address: tuple[str, int],
        *,
        flag: str,
        admin_path: str,
        log_path: Path,
    ) -> None:
        super().__init__(address, Handler)
        self.flag = flag
        self.admin_path = admin_path
        self.log_path = log_path
        self.security_events: list[dict[str, object]] = []

    def log_access(
        self,
        method: str,
        path: str,
        status: int,
        event: str,
    ) -> None:
        row = {"method": method, "path": path, "status": status}
        if event:
            self.security_events.append({**row, "event": event})
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    def events(self) -> list[dict[str, object]]:
        return list(self.security_events)

    def openapi(self) -> dict[str, object]:
        return {
            "service": "openrange-cyber-webapp-offense",
            "scope": "loopback training target",
            "paths": {
                "/api/admin": "debug auth bypass",
                "/search": "SQL-like query surface",
                "/records": "object access surface",
                "/download": "constrained file retrieval surface",
                "/fetch": "simulated internal URL fetcher",
                "/ops": "simulated command construction surface",
                "/idp/token": "identity provider login",
                "/vault": "privileged secret store",
                "/siem/events": "request and security event log",
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--flag", required=True)
    parser.add_argument("--admin-path", default="/admin/debug")
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()

    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.log.write_text("", encoding="utf-8")
    server = WebappServer(
        (args.host, args.port),
        flag=args.flag,
        admin_path=args.admin_path,
        log_path=args.log,
    )
    host = server.server_address[0]
    port = server.server_address[1]
    print(json.dumps({"host": host, "port": port}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
