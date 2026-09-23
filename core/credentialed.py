"""Audit authentifié en lecture seule, avec les identifiants fournis par l'administrateur."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from core.compliance import evaluate
from core.enterprise_db import connect
from core.integrations import dispatch_findings
from core.plugins import match_packages
from core.vault import open_credential

_REMOTE = """
set +e
echo '---OS---'
cat /etc/os-release 2>/dev/null
echo '---PKG---'
if command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME} %{VERSION}\n'
elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f '${Package} ${Version}\n'
elif command -v pacman >/dev/null 2>&1; then pacman -Q
fi
echo '---SSHD---'
sshd -T 2>/dev/null
echo '---POLICY---'
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN) ' /etc/login.defs 2>/dev/null
grep -E '^minlen ' /etc/security/pwquality.conf 2>/dev/null
echo '---FIREWALL---'
systemctl is-active firewalld 2>/dev/null
systemctl is-active ufw 2>/dev/null
echo '---END---'
"""


def run_authenticated(credential_id: int) -> dict:
    record = open_credential(credential_id)
    if record is None:
        return {"error": "identifiant introuvable"}
    try:
        if record["protocol"] == "ssh":
            raw = _ssh(record)
            parsed = _parse_ssh(raw)
        else:
            parsed = _smb(record)
            raw = parsed.pop("raw", "")
    except Exception as exc:
        return {"error": str(exc)}
    host = record["host"]
    findings = match_packages(parsed.get("packages") or [], host)
    compliance = evaluate(
        parsed.get("sshd"),
        parsed.get("policy"),
        parsed.get("firewall") or "",
        parsed.get("smb"),
    )
    report = {
        "credential_id": record["id"],
        "host": host,
        "protocol": record["protocol"],
        "os": parsed.get("os") or "",
        "packages": parsed.get("packages") or [],
        "compliance": compliance,
        "findings": findings,
        "detail": raw[-4000:],
    }
    _save_report(report)
    notes = dispatch_findings(findings)
    report["integrations"] = notes
    report.pop("detail", None)
    return report


def latest_report() -> dict | None:
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM auth_reports ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return _row_report(row)


def list_findings() -> list[dict]:
    conn = connect()
    try:
        rows = conn.execute("SELECT findings_json, host FROM auth_reports ORDER BY id DESC LIMIT 20").fetchall()
    finally:
        conn.close()
    found = []
    for row in rows:
        try:
            items = json.loads(row["findings_json"] or "[]")
        except json.JSONDecodeError:
            continue
        if isinstance(items, list):
            found.extend(items)
    found.sort(key=lambda item: item.get("score") or 0, reverse=True)
    return found


def _save_report(report: dict) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = connect()
    try:
        conn.execute(
            """
            INSERT INTO auth_reports
            (credential_id, host, created_at, packages_json, compliance_json, findings_json, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["credential_id"],
                report["host"],
                now,
                json.dumps(report["packages"], ensure_ascii=False),
                json.dumps(report["compliance"], ensure_ascii=False),
                json.dumps(report["findings"], ensure_ascii=False),
                report.get("detail") or "",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _row_report(row) -> dict:
    def load(field):
        try:
            return json.loads(row[field] or "[]")
        except json.JSONDecodeError:
            return []

    return {
        "id": row["id"],
        "host": row["host"],
        "created_at": row["created_at"],
        "packages": load("packages_json"),
        "compliance": load("compliance_json"),
        "findings": load("findings_json"),
    }


def _ssh(record: dict) -> str:
    target = f"{record['username']}@{record['host']}"
    if record["kind"] == "key":
        return _ssh_key(target, record["secret"])
    return _ssh_password(record["host"], record["username"], record["secret"])


def _ssh_key(target: str, secret: str) -> str:
    path = None
    try:
        material = secret.strip()
        if material.startswith("-----BEGIN"):
            handle = tempfile.NamedTemporaryFile("w", prefix="orbite-key-", delete=False)
            handle.write(material + "\n")
            handle.close()
            path = handle.name
            os.chmod(path, 0o600)
        elif os.path.isfile(material):
            path = material
        else:
            raise RuntimeError("la clé doit être un fichier ou un bloc PEM")
        completed = subprocess.run(
            [
                "ssh", "-i", path, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                "-o", "StrictHostKeyChecking=accept-new", target, _REMOTE,
            ],
            capture_output=True, text=True, timeout=45, check=False,
        )
    finally:
        if path and secret.strip().startswith("-----BEGIN"):
            try:
                os.remove(path)
            except OSError:
                pass
    if completed.returncode != 0 and not completed.stdout:
        raise RuntimeError((completed.stderr or "connexion SSH refusée").strip())
    return completed.stdout


def _ssh_password(host: str, username: str, password: str) -> str:
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("paramiko est requis pour un secret de type mot de passe. Utilisez une clé SSH.") from exc
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, username=username, password=password, timeout=8,
            allow_agent=False, look_for_keys=False, banner_timeout=8,
        )
        _stdin, stdout, stderr = client.exec_command(_REMOTE, timeout=30)
        text = stdout.read().decode("utf-8", "replace")
        error = stderr.read().decode("utf-8", "replace")
    finally:
        client.close()
    if not text and error:
        raise RuntimeError(error.strip() or "connexion SSH refusée")
    return text


def _parse_ssh(raw: str) -> dict:
    sections = _sections(raw)
    packages = []
    for line in (sections.get("PKG") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            packages.append((parts[0], parts[1]))
    sshd = {}
    for line in (sections.get("SSHD") or "").splitlines():
        if " " in line:
            key, value = line.split(" ", 1)
            sshd[key.strip().lower()] = value.strip()
    policy = {}
    for line in (sections.get("POLICY") or "").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.replace("=", " ").split()
        if len(parts) >= 2:
            policy[parts[0]] = parts[1]
    firewall = ""
    for line in (sections.get("FIREWALL") or "").splitlines():
        text = line.strip().lower()
        if text in {"active", "enabled"}:
            firewall = "active"
            break
        if text in {"inactive", "disabled", "failed"}:
            firewall = "inactive"
    os_name = ""
    for line in (sections.get("OS") or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip().strip('"')
    return {"packages": packages, "sshd": sshd, "policy": policy, "firewall": firewall, "os": os_name}


def _sections(raw: str) -> dict:
    current = ""
    buckets: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if line.startswith("---") and line.endswith("---") and len(line) > 6:
            current = line.strip("-")
            buckets.setdefault(current, [])
            continue
        if current:
            buckets.setdefault(current, []).append(line)
    return {key: "\n".join(lines) for key, lines in buckets.items()}


def _smb(record: dict) -> dict:
    binary = shutil.which("smbclient")
    if not binary:
        raise RuntimeError("smbclient n'est pas installé. L'inventaire Windows détaillé se fait avec l'agent local.")
    auth = tempfile.NamedTemporaryFile("w", prefix="orbite-smb-", delete=False)
    try:
        auth.write(f"username = {record['username']}\npassword = {record['secret']}\n")
        auth.close()
        os.chmod(auth.name, 0o600)
        listed = _smbclient(binary, record["host"], auth.name, dialect=None)
        legacy = _smbclient(binary, record["host"], auth.name, dialect="NT1")
    finally:
        try:
            os.remove(auth.name)
        except OSError:
            pass
    smbv1 = legacy.returncode == 0 and "Sharename" in (legacy.stdout or "")
    return {
        "packages": [],
        "sshd": {},
        "policy": {},
        "firewall": "",
        "os": "",
        "smb": {"smbv1": smbv1, "listed": listed.returncode == 0},
        "raw": (listed.stdout or "")[-2000:],
    }


def _smbclient(binary: str, host: str, auth_file: str, dialect: str | None):
    command = [binary, "-L", f"//{host}", "-A", auth_file, "-g", "--option=client min protocol=SMB2"]
    if dialect:
        command = [binary, "-L", f"//{host}", "-A", auth_file, "-m", dialect]
    return subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
