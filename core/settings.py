"""Réglages locaux partagés par l'interface, le démon et l'API."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from core.store import data_dir

_DEFAULTS = {
    "webhook_url": "",
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "smtp_to": "",
    "smtp_tls": True,
    "syslog_host": "",
    "syslog_port": 514,
    "api_host": "127.0.0.1",
    "api_port": 8766,
    "api_token": "",
    "feed_url": "",
    "splunk_url": "",
    "splunk_token": "",
    "elastic_url": "",
    "elastic_api_key": "",
    "datadog_api_key": "",
    "datadog_site": "datadoghq.com",
    "jira_url": "",
    "jira_user": "",
    "jira_token": "",
    "jira_project": "",
    "snow_url": "",
    "snow_user": "",
    "snow_password": "",
    "ticket_on_urgent": True,
    "cef_enabled": False,
}


def settings_path() -> Path:
    return data_dir() / "settings.json"


def load_settings() -> dict:
    path = settings_path()
    data = dict(_DEFAULTS)
    if path.exists():
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                data.update(stored)
        except (OSError, json.JSONDecodeError):
            pass
    if not data.get("api_token"):
        data["api_token"] = secrets.token_urlsafe(24)
        try:
            save_settings(data)
        except OSError:
            pass
    return data


def save_settings(values: dict) -> dict:
    current = dict(_DEFAULTS)
    path = settings_path()
    if path.exists():
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                current.update(stored)
        except (OSError, json.JSONDecodeError):
            pass
    for key in _DEFAULTS:
        if key in values and values[key] is not None:
            current[key] = values[key]
    if not current.get("api_token"):
        current["api_token"] = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return current


def public_settings(values: dict | None = None) -> dict:
    data = dict(values or load_settings())
    for key in ("smtp_password", "splunk_token", "elastic_api_key", "datadog_api_key", "jira_token", "snow_password"):
        if data.get(key):
            data[key] = "********"
    return data
