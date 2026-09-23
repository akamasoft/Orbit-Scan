"""Réception des inventaires d'agents. Aucune commande distante n'est acceptée."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from core.enterprise_db import connect
from core.integrations import dispatch_findings
from core.plugins import match_packages

TASKS = ["inventory"]


def tasks() -> dict:
    return {"tasks": list(TASKS)}


def ingest(report: dict) -> dict:
    hostname = str(report.get("hostname") or "").strip()[:120]
    if not hostname:
        raise ValueError("nom d'hôte requis")
    packages = []
    for item in report.get("packages") or []:
        if isinstance(item, dict) and item.get("name") and item.get("version"):
            packages.append((str(item["name"])[:120], str(item["version"])[:80]))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            packages.append((str(item[0])[:120], str(item[1])[:80]))
    findings = match_packages(packages, hostname)
    stored = {
        "hostname": hostname,
        "os": str(report.get("os") or "")[:160],
        "packages": [{"name": name, "version": version} for name, version in packages],
        "listeners": [str(item)[:80] for item in (report.get("listeners") or [])][:40],
        "hotfixes": [str(item)[:40] for item in (report.get("hotfixes") or [])][:80],
        "findings": findings,
    }
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = connect()
    try:
        conn.execute(
            """
            INSERT INTO agents (hostname, os_name, last_seen, package_count, report_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                os_name = excluded.os_name,
                last_seen = excluded.last_seen,
                package_count = excluded.package_count,
                report_json = excluded.report_json
            """,
            (hostname, stored["os"], now, len(packages), json.dumps(stored, ensure_ascii=False)),
        )
        conn.commit()
    finally:
        conn.close()
    notes = dispatch_findings(findings)
    return {"hostname": hostname, "packages": len(packages), "findings": len(findings), "integrations": notes}


def list_agents() -> list[dict]:
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT hostname, os_name, last_seen, package_count FROM agents ORDER BY last_seen DESC"
        ).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]
