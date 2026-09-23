"""Alertes vers webhook, e-mail et syslog."""

from __future__ import annotations

import json
import smtplib
import socket
import urllib.error
import urllib.request
from email.message import EmailMessage

from core.settings import load_settings
from core.store import summary_text


def send_alerts(diff: dict | None) -> list[str]:
    if not diff or not (diff.get("summary") or {}).get("alerts"):
        return []
    settings = load_settings()
    text = _message(diff)
    notes = []
    if settings.get("webhook_url"):
        notes.append(_webhook(settings["webhook_url"], text, diff))
    if settings.get("smtp_host") and settings.get("smtp_to"):
        notes.append(_email(settings, text))
    if settings.get("syslog_host"):
        notes.append(_syslog(settings, text))
    return notes


def _message(diff: dict) -> str:
    lines = ["Orbite Scan — " + summary_text(diff)]
    for event in diff.get("events") or []:
        if event.get("severity") in {"warning", "critical"}:
            lines.append(f"- [{event['severity']}] {event['detail']}")
    return "\n".join(lines)


def _webhook(url: str, text: str, diff: dict) -> str:
    payload = json.dumps({"text": text, "content": text, "events": diff.get("events") or []}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "OrbiteScan"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return f"webhook {response.status}"
    except urllib.error.URLError as exc:
        return f"webhook en échec : {exc.reason}"


def _email(settings: dict, text: str) -> str:
    message = EmailMessage()
    message["Subject"] = "Orbite Scan — écarts réseau"
    message["From"] = settings.get("smtp_user") or "orbite-scan@localhost"
    message["To"] = settings["smtp_to"]
    message.set_content(text)
    try:
        with smtplib.SMTP(settings["smtp_host"], int(settings.get("smtp_port") or 587), timeout=10) as smtp:
            smtp.ehlo()
            if settings.get("smtp_tls", True):
                smtp.starttls()
                smtp.ehlo()
            if settings.get("smtp_user"):
                smtp.login(settings["smtp_user"], settings.get("smtp_password") or "")
            smtp.send_message(message)
        return "e-mail envoyé"
    except (OSError, smtplib.SMTPException) as exc:
        return f"e-mail en échec : {exc}"


def _syslog(settings: dict, text: str) -> str:
    host = settings["syslog_host"]
    port = int(settings.get("syslog_port") or 514)
    packet = f"<134>1 OrbiteScan - - - - {text.replace(chr(10), ' | ')}\n".encode("utf-8")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(packet, (host, port))
        return "syslog envoyé"
    except OSError as exc:
        return f"syslog en échec : {exc}"
