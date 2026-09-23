"""Démon de scan, d'alertes et d'API, sans interface graphique."""

from __future__ import annotations

import signal
import time
from datetime import datetime

from core.api import ApiServer
from core.followup import publish
from core.scanner import get_default_gateway, get_local_subnet, scan_network
from core.schedule import ScheduleStore
from core.store import ScanStore, summary_text


class ScanDaemon:
    def __init__(self, subnet: str | None, interval: int, once: bool = False, api: bool = True):
        self.subnet = subnet
        self.interval = max(30, int(interval))
        self.once = once
        self.api_enabled = api and not once
        self.store = ScanStore()
        self.schedules = ScheduleStore(self.store.path)
        self._running = True
        self._api = None

    def stop(self, *_args) -> None:
        self._running = False
        if self._api:
            self._api.stop()

    def serve(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        log_path = self.store.path.parent / "daemon.log"
        if self.api_enabled:
            try:
                self._api = ApiServer()
                self._api.start()
                self._log(log_path, f"API sur http://{self._api.host}:{self._api.port}")
                print(f"API sur http://{self._api.host}:{self._api.port}", flush=True)
            except OSError as exc:
                self._api = None
                self._log(log_path, f"API indisponible : {exc}")
                print(f"API indisponible : {exc}", flush=True)
        self._log(log_path, "démon démarré")
        try:
            from core.plugins import sync_if_due

            self._log(log_path, sync_if_due())
        except Exception as exc:
            self._log(log_path, f"flux de signatures non synchronisé : {exc}")
        next_scan = time.time()
        try:
            self._loop(log_path, next_scan)
        finally:
            if self._api:
                self._api.stop()
            self._log(log_path, "démon arrêté")

    def _loop(self, log_path, next_scan: float) -> None:
        while self._running:
            self._run_due(log_path)
            if time.time() >= next_scan:
                self._scan(self.subnet, "daemon", log_path)
                next_scan = time.time() + self.interval
                if self.once:
                    break
            slept = 0
            while self._running and slept < 15 and time.time() < next_scan:
                time.sleep(1)
                slept += 1

    def _run_due(self, log_path) -> None:
        now = datetime.now()
        for item in self.schedules.due(now):
            self._log(log_path, f"planification #{item['id']} {item['hour']:02d}:{item['minute']:02d}")
            self._scan(item.get("subnet") or self.subnet, "schedule", log_path)
            self.schedules.mark_ran(item["id"], now)

    def _scan(self, subnet: str | None, source: str, log_path) -> None:
        try:
            target = subnet or get_local_subnet()
            started = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            self._log(log_path, f"{started} scan de {target} ({source})")
            hosts = scan_network(target)
            scan_id = self.store.save_scan(
                hosts,
                subnet=target,
                gateway=get_default_gateway(),
                source=source,
            )
            diff = self.store.get_diff(scan_id) or {}
            line = f"relevé #{scan_id} — {len(hosts)} hôte(s) — {summary_text(diff)}"
            self._log(log_path, line)
            print(line, flush=True)
            for note in publish(self.store, scan_id):
                self._log(log_path, note)
                print(note, flush=True)
        except Exception as exc:
            self._log(log_path, f"échec du scan : {exc}")
            print(f"échec du scan : {exc}", flush=True)

    @staticmethod
    def _log(path, message: str) -> None:
        try:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(message + "\n")
        except OSError:
            pass
