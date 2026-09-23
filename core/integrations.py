"""Envoi des failles prioritaires vers SIEM, journaux CEF et outils de tickets."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from base64 import b64encode

from core.settings import load_settings


def dispatch_findings(findings: list[dict]) -> list[str]:
    urgent = [item for item in findings if item.get("level") == "urgente" and (item.get("kev") or item.get("exploit_known"))]
    if not urgent:
        return []
    settings = load_settings()
    if not settings.get("ticket_on_urgent", True):
        urgent_for_tickets = []
    else:
        urgent_for_tickets = urgent
    notes = []
    for item in urgent:
        if settings.get("splunk_url") and settings.get("splunk_token"):
            notes.append(_post_json(settings["splunk_url"], {"event": item}, {"Authorization": f"Splunk {settings['splunk_token']}"}))
        if settings.get("elastic_url"):
            headers = {}
            if settings.get("elastic_api_key"):
                headers["Authorization"] = f"ApiKey {settings['elastic_api_key']}"
            notes.append(_post_json(settings["elastic_url"], item, headers))
        if settings.get("datadog_api_key"):
            site = settings.get("datadog_site") or "datadoghq.com"
            notes.append(_post_json(
                f"https://http-intake.logs.{site}/api/v2/logs",
                {"ddsource": "orbite-scan", "message": item.get("title"), "cve": item.get("cve"), "host": item.get("host")},
                {"DD-API-KEY": settings["datadog_api_key"]},
            ))
        if settings.get("cef_enabled") and settings.get("syslog_host"):
            notes.append(_cef(settings, item))
    for item in urgent_for_tickets:
        if settings.get("jira_url") and settings.get("jira_project") and settings.get("jira_token"):
            notes.append(_jira(settings, item))
        if settings.get("snow_url") and settings.get("snow_user") and settings.get("snow_password"):
            notes.append(_snow(settings, item))
    return notes


def send_test() -> list[str]:
    sample = {
        "level": "urgente",
        "kev": True,
        "exploit_known": True,
        "cve": "ESSAI",
        "title": "Essai de connecteur Orbite Scan",
        "host": "localhost",
        "score": 10.0,
        "cvss": 7.5,
        "reason": "Message de test, aucune faille réelle.",
    }
    return dispatch_findings([sample]) or ["Aucun connecteur configuré."]


def _post_json(url: str, payload: dict, headers: dict) -> str:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        if value:
            request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return f"{url} : {response.status}"
    except urllib.error.HTTPError as exc:
        return f"{url} : HTTP {exc.code}"
    except Exception as exc:
        return f"{url} : {exc}"


def _cef(settings: dict, item: dict) -> str:
    severity = 10 if item.get("level") == "urgente" else 7
    message = (
        f"CEF:0|Akamasoft|Orbite Scan|1.0|{item.get('cve')}|{item.get('title')}|"
        f"{severity}|src={item.get('host')} msg={item.get('reason')}"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode("utf-8", "replace"), (settings["syslog_host"], int(settings.get("syslog_port") or 514)))
        sock.close()
        return "CEF envoyé"
    except OSError as exc:
        return f"CEF : {exc}"


def _basic(user: str, password: str) -> str:
    token = b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _jira(settings: dict, item: dict) -> str:
    url = settings["jira_url"].rstrip("/") + "/rest/api/3/issue"
    payload = {
        "fields": {
            "project": {"key": settings["jira_project"]},
            "summary": f"[Orbite Scan] {item.get('cve')} sur {item.get('host')}",
            "issuetype": {"name": "Task"},
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": item.get("reason") or item.get("title") or ""}]}],
            },
        }
    }
    return _post_json(url, payload, {"Authorization": _basic(settings.get("jira_user") or "", settings.get("jira_token") or "")})


def _snow(settings: dict, item: dict) -> str:
    url = settings["snow_url"].rstrip("/") + "/api/now/table/incident"
    payload = {
        "short_description": f"[Orbite Scan] {item.get('cve')} sur {item.get('host')}",
        "description": item.get("reason") or item.get("title") or "",
        "urgency": "1",
        "impact": "1",
    }
    return _post_json(url, payload, {"Authorization": _basic(settings.get("snow_user") or "", settings.get("snow_password") or "")})
