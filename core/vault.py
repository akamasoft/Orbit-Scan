"""Trousseau local. Les secrets sont chiffrés au repos en AES-256-GCM."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.enterprise_db import connect
from core.store import data_dir

_HOST = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_USER = re.compile(r"^[A-Za-z0-9._@\\-]{1,128}$")


def _key() -> bytes:
    path = data_dir() / "vault.key"
    if path.exists():
        raw = path.read_bytes()
        if len(raw) == 32:
            return raw
    raw = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return raw


def _seal(secret: str) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(_key()).encrypt(nonce, secret.encode("utf-8"), None)
    return nonce, cipher


def _open(nonce: bytes, cipher: bytes) -> str:
    return AESGCM(_key()).decrypt(nonce, cipher, None).decode("utf-8")


def add_credential(name: str, protocol: str, host: str, username: str, kind: str, secret: str) -> int:
    protocol = (protocol or "").strip().lower()
    kind = (kind or "").strip().lower()
    host = (host or "").strip()
    username = (username or "").strip()
    if protocol not in {"ssh", "smb"}:
        raise ValueError("protocole attendu : ssh ou smb")
    if kind not in {"password", "key"}:
        raise ValueError("type attendu : password ou key")
    if not _HOST.match(host) or host.startswith("-"):
        raise ValueError("hôte invalide")
    if not _USER.match(username) or username.startswith("-"):
        raise ValueError("utilisateur invalide")
    if not (name or "").strip() or not (secret or "").strip():
        raise ValueError("nom et secret requis")
    nonce, cipher = _seal(secret.strip())
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = connect()
    try:
        cursor = conn.execute(
            """
            INSERT INTO credentials (name, protocol, host, username, kind, nonce, cipher, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name.strip(), protocol, host, username, kind, nonce, cipher, now),
        )
        conn.commit()
        return int(cursor.lastrowid)
    finally:
        conn.close()


def list_credentials() -> list[dict]:
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, name, protocol, host, username, kind, created_at FROM credentials ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def remove_credential(credential_id: int) -> None:
    conn = connect()
    try:
        conn.execute("DELETE FROM credentials WHERE id = ?", (int(credential_id),))
        conn.commit()
    finally:
        conn.close()


def open_credential(credential_id: int) -> dict | None:
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM credentials WHERE id = ?", (int(credential_id),)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    data = dict(row)
    data["secret"] = _open(data.pop("nonce"), data.pop("cipher"))
    return data
