#!/usr/bin/env python3
"""Agent local Orbite Scan.

Il collecte l'inventaire de la machine (système, paquets, correctifs, ports en écoute)
et l'envoie à l'API. Il n'exécute aucune commande reçue du serveur.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent d'inventaire Orbite Scan")
    parser.add_argument("--server", required=True, help="URL de l'API, ex. http://127.0.0.1:8766")
    parser.add_argument("--token", required=True, help="jeton Bearer de l'API")
    args = parser.parse_args()
    tasks = _get(args.server.rstrip("/") + "/api/agent/tasks", args.token)
    if "inventory" not in (tasks.get("tasks") or []):
        print("aucune tâche d'inventaire")
        return
    report = collect()
    result = _post(args.server.rstrip("/") + "/api/agent/report", args.token, report)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def collect() -> dict:
    return {
        "hostname": platform.node(),
        "os": platform.platform(),
        "packages": _packages(),
        "listeners": _listeners(),
        "hotfixes": _hotfixes(),
    }


def _packages() -> list[dict]:
    if sys.platform == "win32":
        return _powershell_packages()
    if shutil.which("rpm"):
        return _pairs(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\\n"])
    if shutil.which("dpkg-query"):
        return _pairs(["dpkg-query", "-W", "-f", "${Package} ${Version}\\n"])
    if shutil.which("pacman"):
        return _pairs(["pacman", "-Q"])
    return []


def _pairs(command: list[str]) -> list[dict]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    items = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            items.append({"name": parts[0], "version": parts[1]})
    return items


def _powershell_packages() -> list[dict]:
    script = "Get-Package | Select-Object -First 400 Name, Version | ConvertTo-Json -Compress"
    return _powershell_pairs(script)


def _hotfixes() -> list[str]:
    if sys.platform != "win32":
        return []
    script = "Get-HotFix | Select-Object -ExpandProperty HotFixID"
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip().startswith("KB")]


def _powershell_pairs(script: str) -> list[dict]:
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=90, check=False,
        )
        data = json.loads(completed.stdout or "[]")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = [data]
    items = []
    for entry in data:
        if isinstance(entry, dict) and entry.get("Name") and entry.get("Version"):
            items.append({"name": str(entry["Name"]), "version": str(entry["Version"])})
    return items


def _listeners() -> list[str]:
    command = ["ss", "-lnt"] if shutil.which("ss") else ["netstat", "-lnt"]
    if not shutil.which(command[0]):
        return []
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in completed.stdout.splitlines() if "LISTEN" in line][:40]


def _get(url: str, token: str) -> dict:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _post(url: str, token: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    main()
