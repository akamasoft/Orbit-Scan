"""Planification locale des scans."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from core.store import default_db_path


class ScheduleStore:
    def __init__(self, path=None):
        self.path = path or default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schedules (
                    id INTEGER PRIMARY KEY,
                    subnet TEXT NOT NULL DEFAULT '',
                    hour INTEGER NOT NULL,
                    minute INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_run TEXT NOT NULL DEFAULT '',
                    label TEXT NOT NULL DEFAULT ''
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def list_schedules(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, subnet, hour, minute, enabled, last_run, label FROM schedules ORDER BY hour, minute"
            ).fetchall()
        return [dict(row) for row in rows]

    def add(self, hour: int, minute: int, subnet: str = "", label: str = "") -> int:
        hour = max(0, min(23, int(hour)))
        minute = max(0, min(59, int(minute)))
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO schedules (subnet, hour, minute, label) VALUES (?, ?, ?, ?)",
                (subnet or "", hour, minute, label or ""),
            )
            return int(cur.lastrowid)

    def remove(self, schedule_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM schedules WHERE id = ?", (int(schedule_id),))

    def mark_ran(self, schedule_id: int, when: datetime) -> None:
        stamp = when.isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute("UPDATE schedules SET last_run = ? WHERE id = ?", (stamp, int(schedule_id)))

    def due(self, now: datetime | None = None) -> list[dict]:
        moment = now or datetime.now()
        ready = []
        for item in self.list_schedules():
            if not item["enabled"]:
                continue
            if item["hour"] != moment.hour or item["minute"] != moment.minute:
                continue
            last = item.get("last_run") or ""
            if last[:10] == moment.date().isoformat():
                continue
            ready.append(item)
        return ready
