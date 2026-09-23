"""Inventaire cloud optionnel, fusionné à la carte locale."""

from __future__ import annotations

import json

from core.store import data_dir


def inventory_path():
    return data_dir() / "cloud.json"


def list_assets() -> list[dict]:
    assets = _read_file()
    assets.extend(_aws_instances())
    seen = set()
    unique = []
    for asset in assets:
        address = (asset.get("address") or "").strip()
        if not address or address in seen:
            continue
        seen.add(address)
        unique.append({
            "provider": asset.get("provider") or "cloud",
            "name": asset.get("name") or address,
            "address": address,
            "region": asset.get("region") or "",
            "kind": asset.get("kind") or "instance",
        })
    return unique


def add_asset(provider: str, name: str, address: str, region: str = "", kind: str = "instance") -> None:
    assets = _read_file()
    assets.append({
        "provider": provider or "cloud",
        "name": name or address,
        "address": address.strip(),
        "region": region,
        "kind": kind or "instance",
    })
    _write_file(assets)


def remove_asset(address: str) -> None:
    _write_file([item for item in _read_file() if item.get("address") != address])


def _read_file() -> list[dict]:
    path = inventory_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = data.get("assets") or []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _write_file(assets: list[dict]) -> None:
    path = inventory_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"assets": assets}, indent=2, ensure_ascii=False), encoding="utf-8")


def _aws_instances() -> list[dict]:
    try:
        import boto3
    except ImportError:
        return []
    try:
        client = boto3.client("ec2")
        pages = client.describe_instances()
    except Exception:
        return []
    found = []
    for reservation in pages.get("Reservations") or []:
        for instance in reservation.get("Instances") or []:
            address = instance.get("PrivateIpAddress") or instance.get("PublicIpAddress")
            if not address:
                continue
            name = address
            for tag in instance.get("Tags") or []:
                if tag.get("Key") == "Name" and tag.get("Value"):
                    name = tag["Value"]
            found.append({
                "provider": "aws",
                "name": name,
                "address": address,
                "region": client.meta.region_name or "",
                "kind": "ec2",
            })
    return found
