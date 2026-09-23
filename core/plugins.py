"""Catalogue de signatures. Le flux distant ne peut contenir que des métadonnées, jamais du code."""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.priority import prioritize
from core.settings import load_settings
from core.store import data_dir

_ALLOWED = {
    "id", "cve", "title", "cvss", "kev", "exploit_known",
    "package", "aliases", "vulnerable_versions", "vulnerable_below",
}
_BUNDLED = Path(__file__).resolve().parents[1] / "data" / "signatures.json"
_STATE = "feed_state.json"


def _state_path() -> Path:
    return data_dir() / _STATE


def _read_state() -> dict:
    path = _state_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_state(data: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def validate_signatures(payload) -> list[dict]:
    if not isinstance(payload, list):
        raise ValueError("le catalogue doit être une liste")
    clean = []
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("signature invalide")
        extra = set(item) - _ALLOWED
        if extra:
            raise ValueError("champ refusé dans le catalogue : " + ", ".join(sorted(extra)))
        if not item.get("cve") or not item.get("package"):
            raise ValueError("cve et package sont requis")
        clean.append({
            "id": str(item.get("id") or item["cve"]),
            "cve": str(item["cve"]),
            "title": str(item.get("title") or item["cve"]),
            "cvss": float(item.get("cvss") or 0),
            "kev": bool(item.get("kev")),
            "exploit_known": bool(item.get("exploit_known")),
            "package": str(item["package"]).lower(),
            "aliases": [str(name).lower() for name in item.get("aliases") or []],
            "vulnerable_versions": [str(v) for v in item.get("vulnerable_versions") or []],
            "vulnerable_below": str(item.get("vulnerable_below") or ""),
        })
    return clean


def load_signatures() -> list[dict]:
    bundled = []
    if _BUNDLED.exists():
        bundled = validate_signatures(json.loads(_BUNDLED.read_text(encoding="utf-8")))
    overlay = data_dir() / "signatures.json"
    if not overlay.exists():
        return bundled
    try:
        remote = validate_signatures(json.loads(overlay.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValueError):
        return bundled
    by_id = {item["id"]: item for item in bundled}
    for item in remote:
        by_id[item["id"]] = item
    return list(by_id.values())


def sync_feed(url: str | None = None) -> str:
    target = (url if url is not None else load_settings().get("feed_url") or "").strip()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not target:
        _write_state({"synced_at": now, "source": "local", "count": len(load_signatures())})
        return f"Catalogue local, {len(load_signatures())} signature(s). Aucune URL de flux."
    if not target.startswith("https://"):
        raise ValueError("le flux doit être une URL https")
    request = urllib.request.Request(target, headers={"User-Agent": "OrbiteScan-feed"})
    with urllib.request.urlopen(request, timeout=12) as response:
        raw = response.read(2_000_000)
    signatures = validate_signatures(json.loads(raw.decode("utf-8")))
    path = data_dir() / "signatures.json"
    path.write_text(json.dumps(signatures, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_state({"synced_at": now, "source": target, "count": len(signatures)})
    return f"{len(signatures)} signature(s) importée(s)."


def sync_if_due(max_age_hours: int = 24) -> str:
    state = _read_state()
    last = state.get("synced_at") or ""
    if last:
        try:
            when = datetime.fromisoformat(last)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - when < timedelta(hours=max_age_hours):
                return "catalogue à jour"
        except ValueError:
            pass
    return sync_feed()


def feed_status() -> dict:
    state = _read_state()
    return {
        "synced_at": state.get("synced_at") or "",
        "source": state.get("source") or "local",
        "count": len(load_signatures()),
    }


def _version_key(value: str) -> tuple:
    numbers = re.findall(r"\d+", value or "")
    return tuple(int(part) for part in numbers[:8]) or (0,)


def _bare_version(version: str) -> str:
    text = (version or "").strip()
    if ":" in text and text.split(":", 1)[0].isdigit():
        text = text.split(":", 1)[1]
    return text


def _version_hit(installed: str, signature: dict) -> bool:
    version = _bare_version(installed)
    pinned = signature.get("vulnerable_versions") or []
    if pinned:
        return any(version == item or version.startswith(item + "-") or version.startswith(item + ".") for item in pinned)
    ceiling = signature.get("vulnerable_below") or ""
    if not ceiling:
        return False
    return _version_key(version) < _version_key(ceiling)


def _name_hit(name: str, signature: dict) -> bool:
    package = (name or "").lower()
    names = [signature["package"], *signature.get("aliases", [])]
    return package in names or any(package.startswith(item + "-") for item in names)


def match_packages(packages: list[tuple[str, str]], host: str = "") -> list[dict]:
    findings = []
    for signature in load_signatures():
        for name, version in packages:
            if not _name_hit(name, signature) or not _version_hit(version, signature):
                continue
            rank = prioritize(signature["cvss"], signature["kev"], signature["exploit_known"])
            findings.append({
                "host": host,
                "package": name,
                "version": version,
                "cve": signature["cve"],
                "title": signature["title"],
                "cvss": signature["cvss"],
                "kev": signature["kev"],
                "exploit_known": signature["exploit_known"],
                **rank,
            })
            break
    findings.sort(key=lambda item: item["score"], reverse=True)
    return findings
