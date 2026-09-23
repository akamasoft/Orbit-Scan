"""Contrôles de configuration non destructifs.

Aucun essai d'authentification n'est tenté : les services sensibles sont
seulement signalés pour une vérification manuelle.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone

REVIEW_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    161: "SNMP",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP",
}


def audit_host(ip: str, ports: list[int] | None = None, timeout: float = 3.0) -> dict:
    findings = []
    open_ports = set(ports or _open_review_ports(ip, timeout))
    if 443 in open_ports or _port_open(ip, 443, timeout):
        findings.extend(_tls_findings(ip, 443, timeout))
    if 445 in open_ports:
        findings.extend(_smb_findings(ip, timeout))
    for port, name in REVIEW_PORTS.items():
        if port not in open_ports:
            continue
        findings.append({
            "ip": ip,
            "kind": "service_review",
            "severity": "warning" if port in {21, 23, 445, 3389, 5900} else "info",
            "detail": (
                f"{name} ({port}) est exposé sur {ip}. "
                "Les mots de passe d'usine ne sont pas testés : à vérifier manuellement."
            ),
        })
    if not findings:
        findings.append({
            "ip": ip,
            "kind": "clean",
            "severity": "info",
            "detail": f"Aucun défaut de configuration évident sur {ip}.",
        })
    return {"ip": ip, "findings": findings}


def _port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout):
            return True
    except OSError:
        return False


def _open_review_ports(ip: str, timeout: float) -> set[int]:
    found = set()
    for port in list(REVIEW_PORTS) + [443]:
        if _port_open(ip, port, min(timeout, 1.0)):
            found.add(port)
    return found


def _tls_findings(ip: str, port: int, timeout: float) -> list[dict]:
    findings = []
    if _accepts_old_tls(ip, port, timeout):
        findings.append({
            "ip": ip,
            "kind": "tls_old",
            "severity": "critical",
            "detail": f"{ip}:{port} accepte encore TLS 1.0.",
        })
    expiry = _cert_expiry(ip, port, timeout)
    if expiry is not None:
        now = datetime.now(timezone.utc)
        if expiry < now:
            findings.append({
                "ip": ip,
                "kind": "cert_expired",
                "severity": "critical",
                "detail": f"Certificat expiré le {expiry.strftime('%d/%m/%Y')} sur {ip}:{port}.",
            })
        elif (expiry - now).days < 30:
            findings.append({
                "ip": ip,
                "kind": "cert_soon",
                "severity": "warning",
                "detail": f"Certificat de {ip}:{port} expire le {expiry.strftime('%d/%m/%Y')}.",
            })
    return findings


def _accepts_old_tls(ip: str, port: int, timeout: float) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        return False
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip):
                return True
    except (OSError, ssl.SSLError):
        return False


def _cert_expiry(ip: str, port: int, timeout: float):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    if not der or not shutil.which("openssl"):
        return None
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-enddate"],
            input=der,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = result.stdout.decode("utf-8", "replace")
    if "notAfter=" not in text:
        return None
    raw = text.split("notAfter=", 1)[1].strip()
    try:
        parsed = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _smb_findings(ip: str, timeout: float) -> list[dict]:
    if not _port_open(ip, 445, timeout):
        return []
    client = shutil.which("smbclient")
    if not client:
        return [{
            "ip": ip,
            "kind": "smb_open",
            "severity": "warning",
            "detail": f"SMB (445) est ouvert sur {ip}. Le contrôle anonyme demande smbclient, absent de la machine.",
        }]
    try:
        result = subprocess.run(
            [client, "-N", "-L", f"//{ip}"],
            capture_output=True,
            text=True,
            timeout=max(timeout, 5),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [{
            "ip": ip,
            "kind": "smb_open",
            "severity": "warning",
            "detail": f"SMB (445) est ouvert sur {ip}. Le contrôle anonyme n'a pas abouti.",
        }]
    output = (result.stdout or "") + (result.stderr or "")
    if "Sharename" in output or "Disk" in output:
        return [{
            "ip": ip,
            "kind": "smb_anonymous",
            "severity": "critical",
            "detail": f"Des partages SMB de {ip} répondent sans authentification.",
        }]
    return [{
        "ip": ip,
        "kind": "smb_open",
        "severity": "info",
        "detail": f"SMB (445) est ouvert sur {ip}, sans partage anonyme visible.",
    }]
