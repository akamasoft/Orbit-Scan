"""API REST locale du démon de scan."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.audit import audit_host
from core.cloud import add_asset, list_assets, remove_asset
from core.followup import publish
from core.report import write_report
from core.schedule import ScheduleStore
from core.settings import load_settings, public_settings, save_settings
from core.store import ScanStore


class ApiServer:
    def __init__(self, host: str | None = None, port: int | None = None):
        settings = load_settings()
        self.host = host or settings.get("api_host") or "127.0.0.1"
        self.port = int(port or settings.get("api_port") or 8766)
        self.store = ScanStore()
        self.schedules = ScheduleStore(self.store.path)
        self._scan_lock = threading.Lock()
        self._scanning = False
        self._httpd = None
        self._thread = None

    def start(self) -> None:
        handler = self._handler_class()
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="orbite-api", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()

    def _handler_class(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _authorized(self) -> bool:
                expected = load_settings().get("api_token") or ""
                header = self.headers.get("Authorization", "")
                return header == f"Bearer {expected}"

            def _json(self, code: int, payload) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read(self) -> dict:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    return {}
                raw = self.rfile.read(length)
                try:
                    data = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    return {}
                return data if isinstance(data, dict) else {}

            def do_GET(self):
                if self.path == "/api/health":
                    self._json(200, {"status": "ok", "service": "orbite-scan"})
                    return
                if not self._authorized():
                    self._json(401, {"error": "jeton manquant"})
                    return
                if self.path == "/api/scans":
                    self._json(200, {"scans": server.store.list_scans()})
                elif self.path == "/api/diff":
                    self._json(200, server.store.latest_diff() or {})
                elif self.path.startswith("/api/scans/") and self.path.endswith("/diff"):
                    scan_id = _scan_id(self.path)
                    diff = server.store.get_diff(scan_id) if scan_id else None
                    self._json(200 if diff else 404, diff or {"error": "introuvable"})
                elif self.path.startswith("/api/scans/"):
                    scan_id = _scan_id(self.path)
                    hosts = server.store.hosts_of(scan_id) if scan_id else []
                    self._json(200, {"scan_id": scan_id, "hosts": hosts})
                elif self.path == "/api/schedules":
                    self._json(200, {"schedules": server.schedules.list_schedules()})
                elif self.path == "/api/settings":
                    self._json(200, public_settings())
                elif self.path == "/api/cloud":
                    self._json(200, {"assets": list_assets()})
                elif self.path == "/api/credentials":
                    from core.vault import list_credentials
                    self._json(200, {"credentials": list_credentials()})
                elif self.path == "/api/findings":
                    from core.credentialed import list_findings
                    self._json(200, {"findings": list_findings()})
                elif self.path == "/api/feed":
                    from core.plugins import feed_status
                    self._json(200, feed_status())
                elif self.path == "/api/agents":
                    from core.agents import list_agents
                    self._json(200, {"agents": list_agents()})
                elif self.path == "/api/agent/tasks":
                    from core.agents import tasks
                    self._json(200, tasks())
                else:
                    self._json(404, {"error": "route inconnue"})

            def do_POST(self):
                if not self._authorized():
                    self._json(401, {"error": "jeton manquant"})
                    return
                body = self._read()
                if self.path == "/api/scan":
                    if not server._scan_lock.acquire(blocking=False):
                        self._json(409, {"error": "un scan est déjà en cours"})
                        return
                    server._scanning = True
                    threading.Thread(
                        target=server._run_scan,
                        args=(body.get("subnet") or "",),
                        daemon=True,
                    ).start()
                    self._json(202, {"status": "démarré"})
                elif self.path == "/api/schedules":
                    schedule_id = server.schedules.add(
                        int(body.get("hour") or 2),
                        int(body.get("minute") or 0),
                        body.get("subnet") or "",
                        body.get("label") or "",
                    )
                    self._json(201, {"id": schedule_id})
                elif self.path == "/api/settings":
                    saved = save_settings(body)
                    self._json(200, public_settings(saved))
                elif self.path == "/api/cloud":
                    address = (body.get("address") or "").strip()
                    if not address:
                        self._json(400, {"error": "adresse requise"})
                        return
                    add_asset(body.get("provider") or "cloud", body.get("name") or address, address, body.get("region") or "")
                    self._json(201, {"assets": list_assets()})
                elif self.path == "/api/audit":
                    ip = (body.get("ip") or "").strip()
                    if not ip:
                        self._json(400, {"error": "ip requise"})
                        return
                    self._json(200, audit_host(ip, body.get("ports")))
                elif self.path == "/api/report":
                    try:
                        path = write_report(server.store, body.get("scan_id"))
                    except Exception as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    self._json(200, {"path": str(path)})
                elif self.path == "/api/credentials":
                    from core.vault import add_credential
                    try:
                        created = add_credential(
                            body.get("name") or "",
                            body.get("protocol") or "",
                            body.get("host") or "",
                            body.get("username") or "",
                            body.get("kind") or "password",
                            body.get("secret") or "",
                        )
                    except ValueError as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    self._json(201, {"id": created})
                elif self.path == "/api/auth-scan":
                    from core.credentialed import run_authenticated
                    try:
                        report = run_authenticated(int(body.get("id") or 0))
                    except (TypeError, ValueError) as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    code = 400 if report.get("error") else 200
                    self._json(code, report)
                elif self.path == "/api/feed":
                    from core.plugins import sync_feed
                    try:
                        message = sync_feed(body.get("url"))
                    except Exception as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    self._json(200, {"message": message})
                elif self.path == "/api/agent/report":
                    from core.agents import ingest
                    try:
                        stored = ingest(body)
                    except ValueError as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    self._json(201, stored)
                elif self.path == "/api/integrations/test":
                    from core.integrations import send_test
                    self._json(200, {"notes": send_test()})
                else:
                    self._json(404, {"error": "route inconnue"})

            def do_DELETE(self):
                if not self._authorized():
                    self._json(401, {"error": "jeton manquant"})
                    return
                if self.path.startswith("/api/schedules/"):
                    server.schedules.remove(int(self.path.rsplit("/", 1)[-1]))
                    self._json(200, {"ok": True})
                elif self.path.startswith("/api/cloud/"):
                    remove_asset(self.path.rsplit("/", 1)[-1])
                    self._json(200, {"assets": list_assets()})
                elif self.path.startswith("/api/credentials/"):
                    from core.vault import remove_credential
                    remove_credential(int(self.path.rsplit("/", 1)[-1]))
                    self._json(200, {"ok": True})
                else:
                    self._json(404, {"error": "route inconnue"})

        return Handler

    def _run_scan(self, subnet: str) -> None:
        try:
            from core.scanner import get_default_gateway, get_local_subnet, scan_network

            target = subnet or get_local_subnet()
            hosts = scan_network(target)
            scan_id = self.store.save_scan(
                hosts,
                subnet=target,
                gateway=get_default_gateway(),
                source="api",
            )
            publish(self.store, scan_id)
        finally:
            self._scanning = False
            self._scan_lock.release()


def _scan_id(path: str) -> int | None:
    parts = [part for part in path.split("/") if part]
    if len(parts) < 3 or not parts[2].isdigit():
        return None
    return int(parts[2])
