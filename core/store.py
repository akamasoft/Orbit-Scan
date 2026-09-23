"""Historique local des scans et comparaison différentielle (Network Diff)."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SENSITIVE_PORTS = {
    21, 22, 23, 25, 53, 110, 135, 139, 161, 445,
    512, 513, 514, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 9200, 27017,
}

_SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


def default_db_path() -> Path:
    home = Path.home()
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user not in ("root", os.environ.get("USER")):
        try:
            import pwd

            home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except (KeyError, ImportError):
            pass
    directory = home / ".local" / "share" / "orbite-scan"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        directory.chmod(0o755)
    except OSError:
        pass
    return directory / "history.db"


def data_dir() -> Path:
    return default_db_path().parent


def _norm_mac(mac: str | None) -> str:
    value = (mac or "").strip().lower().replace("-", ":")
    if value in {"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "..."}:
        return ""
    return value


def _ports(host: dict) -> set[int]:
    found = set()
    for port in host.get("open_ports") or []:
        try:
            found.add(int(port))
        except (TypeError, ValueError):
            continue
    return found


def _hostname(host: dict) -> str:
    name = (host.get("hostname") or "").strip()
    ip = host.get("ip") or ""
    if not name or name == ip:
        return ip or "hôte inconnu"
    return name


def _event(kind: str, severity: str, host: dict, detail: str, **extra) -> dict:
    payload = {
        "kind": kind,
        "severity": severity,
        "ip": host.get("ip") or "",
        "mac": _norm_mac(host.get("mac")),
        "hostname": _hostname(host),
        "detail": detail,
    }
    payload.update(extra)
    return payload


def diff_hosts(previous: list[dict], current: list[dict], *, has_baseline: bool) -> dict:
    """Compare deux relevés et décrit les écarts utiles à un administrateur."""
    if not has_baseline:
        return _empty_diff(has_baseline=False)

    prev_by_mac: dict[str, dict] = {}
    prev_by_ip: dict[str, dict] = {}
    for host in previous:
        mac = _norm_mac(host.get("mac"))
        if mac:
            prev_by_mac[mac] = host
        if host.get("ip"):
            prev_by_ip[host["ip"]] = host

    curr_macs = {_norm_mac(h.get("mac")) for h in current if _norm_mac(h.get("mac"))}
    matched_macs: set[str] = set()
    matched_ips: set[str] = set()
    events: list[dict] = []

    for host in current:
        mac = _norm_mac(host.get("mac"))
        ip = host.get("ip") or ""
        ports = _ports(host)
        label = _hostname(host)

        if mac and mac in prev_by_mac:
            old = prev_by_mac[mac]
            matched_macs.add(mac)
            old_ip = old.get("ip") or ""
            if old_ip:
                matched_ips.add(old_ip)
            matched_ips.add(ip)
            if old_ip and old_ip != ip:
                events.append(_event(
                    "ip_changed",
                    "warning",
                    host,
                    f"{label} ({mac}) est passé de {old_ip} à {ip}",
                    previous_ip=old_ip,
                ))
            _append_port_events(events, old, host, ports)
            continue

        old_at_ip = prev_by_ip.get(ip)
        old_mac = _norm_mac(old_at_ip.get("mac")) if old_at_ip else ""
        if old_at_ip and old_mac and mac and mac != old_mac:
            matched_ips.add(ip)
            matched_macs.add(old_mac)
            events.append(_event(
                "mac_changed",
                "critical",
                host,
                f"{ip} a changé de MAC ({old_mac} → {mac}) — suspicion d'usurpation ARP",
                previous_mac=old_mac,
            ))
            _append_port_events(events, old_at_ip, host, ports)
            continue

        if old_at_ip and not mac:
            matched_ips.add(ip)
            _append_port_events(events, old_at_ip, host, ports)
            continue

        events.append(_event(
            "new_asset",
            "warning",
            host,
            f"Nouvel appareil {label}" + (f" ({mac})" if mac else "") + (f" sur {ip}" if ip and label != ip else ""),
        ))

    for host in previous:
        mac = _norm_mac(host.get("mac"))
        ip = host.get("ip") or ""
        if mac and (mac in matched_macs or mac in curr_macs):
            continue
        if ip and ip in matched_ips:
            continue
        events.append(_event(
            "departed",
            "info",
            host,
            f"Appareil disparu {_hostname(host)}" + (f" ({mac})" if mac else ""),
        ))

    events.sort(key=lambda item: (-_SEVERITY_RANK[item["severity"]], item["kind"], item["ip"]))
    return _pack(events, has_baseline=True)


def _append_port_events(events: list[dict], old: dict, host: dict, ports: set[int]) -> None:
    label = _hostname(host)
    ip = host.get("ip") or label
    old_ports = _ports(old)
    for port in sorted(ports - old_ports):
        sensitive = port in SENSITIVE_PORTS
        events.append(_event(
            "port_opened",
            "critical" if sensitive else "warning",
            host,
            f"Port {port} ouvert sur {ip}" + (" — port sensible" if sensitive else ""),
            port=port,
            sensitive=sensitive,
        ))
    for port in sorted(old_ports - ports):
        events.append(_event(
            "port_closed",
            "info",
            host,
            f"Port {port} fermé sur {ip}",
            port=port,
        ))


def _empty_diff(*, has_baseline: bool) -> dict:
    return _pack([], has_baseline=has_baseline)


def _pack(events: list[dict], *, has_baseline: bool) -> dict:
    summary = {
        "new": sum(1 for e in events if e["kind"] == "new_asset"),
        "departed": sum(1 for e in events if e["kind"] == "departed"),
        "ip_changed": sum(1 for e in events if e["kind"] == "ip_changed"),
        "mac_changed": sum(1 for e in events if e["kind"] == "mac_changed"),
        "ports_opened": sum(1 for e in events if e["kind"] == "port_opened"),
        "ports_closed": sum(1 for e in events if e["kind"] == "port_closed"),
        "sensitive": sum(1 for e in events if e.get("sensitive")),
        "critical": sum(1 for e in events if e["severity"] == "critical"),
        "alerts": sum(1 for e in events if e["severity"] in {"warning", "critical"}),
    }
    return {
        "has_baseline": has_baseline,
        "baseline_scan_id": None,
        "current_scan_id": None,
        "summary": summary,
        "events": events,
    }


class ScanStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        subnet TEXT NOT NULL DEFAULT '',
                        gateway TEXT NOT NULL DEFAULT '',
                        source TEXT NOT NULL DEFAULT 'gui',
                        host_count INTEGER NOT NULL DEFAULT 0,
                        alert_count INTEGER NOT NULL DEFAULT 0,
                        critical_count INTEGER NOT NULL DEFAULT 0,
                        diff_json TEXT NOT NULL DEFAULT ''
                    );
                    CREATE TABLE IF NOT EXISTS hosts (
                        id INTEGER PRIMARY KEY,
                        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        ip TEXT NOT NULL,
                        mac TEXT NOT NULL DEFAULT '',
                        hostname TEXT NOT NULL DEFAULT '',
                        vendor TEXT NOT NULL DEFAULT '',
                        role TEXT NOT NULL DEFAULT '',
                        os_hint TEXT NOT NULL DEFAULT '',
                        ttl INTEGER,
                        open_ports TEXT NOT NULL DEFAULT '[]',
                        embedded_device TEXT NOT NULL DEFAULT ''
                    );
                    CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
                    CREATE INDEX IF NOT EXISTS idx_scans_subnet ON scans(subnet, id);
                    """
                )
                conn.commit()
            finally:
                conn.close()
        try:
            self.path.chmod(0o644)
        except OSError:
            pass

    def save_scan(
        self,
        hosts: list[dict],
        *,
        subnet: str = "",
        gateway: str | None = None,
        source: str = "gui",
    ) -> int:
        created = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    INSERT INTO scans (created_at, subnet, gateway, source, host_count)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (created, subnet or "", gateway or "", source, len(hosts)),
                )
                scan_id = int(cur.lastrowid)
                conn.executemany(
                    """
                    INSERT INTO hosts (
                        scan_id, ip, mac, hostname, vendor, role, os_hint, ttl, open_ports, embedded_device
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [_host_row(scan_id, host) for host in hosts],
                )
                previous_id = self._previous_id(conn, scan_id, subnet or "")
                previous = self._load_hosts(conn, previous_id) if previous_id else []
                diff = diff_hosts(previous, [_public_host(h) for h in hosts], has_baseline=previous_id is not None)
                diff["current_scan_id"] = scan_id
                diff["baseline_scan_id"] = previous_id
                summary = diff["summary"]
                conn.execute(
                    """
                    UPDATE scans
                    SET diff_json = ?, alert_count = ?, critical_count = ?
                    WHERE id = ?
                    """,
                    (
                        json.dumps(diff, ensure_ascii=False),
                        summary["alerts"],
                        summary["critical"],
                        scan_id,
                    ),
                )
                conn.commit()
                return scan_id
            finally:
                conn.close()

    def list_scans(self, limit: int = 80) -> list[dict]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT id, created_at, subnet, gateway, source, host_count, alert_count, critical_count
                    FROM scans
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            finally:
                conn.close()
        return [dict(row) for row in rows]

    def hosts_of(self, scan_id: int) -> list[dict]:
        with self._lock:
            conn = self._connect()
            try:
                return self._load_hosts(conn, scan_id)
            finally:
                conn.close()

    def get_diff(self, scan_id: int) -> dict | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT diff_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
            finally:
                conn.close()
        if row is None or not row["diff_json"]:
            return None
        return json.loads(row["diff_json"])

    def latest_diff(self, subnet: str | None = None) -> dict | None:
        with self._lock:
            conn = self._connect()
            try:
                if subnet:
                    row = conn.execute(
                        "SELECT id FROM scans WHERE subnet = ? ORDER BY id DESC LIMIT 1",
                        (subnet,),
                    ).fetchone()
                else:
                    row = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        return self.get_diff(int(row["id"]))

    def _previous_id(self, conn: sqlite3.Connection, scan_id: int, subnet: str) -> int | None:
        row = conn.execute(
            """
            SELECT id FROM scans
            WHERE id < ? AND subnet = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (scan_id, subnet),
        ).fetchone()
        return int(row["id"]) if row else None

    def _load_hosts(self, conn: sqlite3.Connection, scan_id: int) -> list[dict]:
        rows = conn.execute(
            """
            SELECT ip, mac, hostname, vendor, role, os_hint, ttl, open_ports, embedded_device
            FROM hosts WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
        hosts = []
        for row in rows:
            host = dict(row)
            try:
                host["open_ports"] = json.loads(host.get("open_ports") or "[]")
            except json.JSONDecodeError:
                host["open_ports"] = []
            hosts.append(host)
        return hosts


def _host_row(scan_id: int, host: dict) -> tuple:
    ttl = host.get("ttl")
    try:
        ttl = int(ttl) if ttl is not None and ttl != "" else None
    except (TypeError, ValueError):
        ttl = None
    return (
        scan_id,
        host.get("ip") or "",
        _norm_mac(host.get("mac")),
        host.get("hostname") or "",
        host.get("vendor") or "",
        host.get("role") or "",
        host.get("os_hint") or "",
        ttl,
        json.dumps(sorted(_ports(host))),
        host.get("embedded_device") or "",
    )


def _public_host(host: dict) -> dict:
    copied = dict(host)
    copied["mac"] = _norm_mac(host.get("mac"))
    copied["open_ports"] = sorted(_ports(host))
    return copied


def format_when(iso_stamp: str) -> str:
    try:
        moment = datetime.fromisoformat(iso_stamp)
    except ValueError:
        return iso_stamp
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone().strftime("%d/%m/%Y %H:%M")


def summary_text(diff: dict | None) -> str:
    if not diff:
        return "Aucun relevé enregistré."
    if not diff.get("has_baseline"):
        return "Premier relevé enregistré. Le prochain scan montrera les changements."
    summary = diff.get("summary") or {}
    if not summary.get("alerts") and not summary.get("departed") and not summary.get("ports_closed"):
        return "Aucun changement depuis le relevé précédent."
    def _count(count, one, many):
        return f"{count} {one if count == 1 else many}"

    parts = []
    if summary.get("critical"):
        parts.append(_count(summary["critical"], "alerte critique", "alertes critiques"))
    if summary.get("new"):
        parts.append(_count(summary["new"], "nouvel appareil", "nouveaux appareils"))
    if summary.get("mac_changed"):
        parts.append(_count(summary["mac_changed"], "changement de MAC", "changements de MAC"))
    if summary.get("ip_changed"):
        parts.append(_count(summary["ip_changed"], "changement d'IP", "changements d'IP"))
    if summary.get("sensitive"):
        parts.append(_count(summary["sensitive"], "port sensible", "ports sensibles"))
    elif summary.get("ports_opened"):
        parts.append(_count(summary["ports_opened"], "port ouvert", "ports ouverts"))
    if summary.get("departed"):
        parts.append(_count(summary["departed"], "appareil disparu", "appareils disparus"))
    if summary.get("ports_closed") and not summary.get("alerts") and not summary.get("departed"):
        parts.append(_count(summary["ports_closed"], "port fermé", "ports fermés"))
    return "Écarts : " + ", ".join(parts) if parts else "Des changements ont été détectés."
