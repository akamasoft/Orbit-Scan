"""Après un relevé : alerter et, s'il y a une anomalie, écrire le PDF."""

from __future__ import annotations

from core.notify import send_alerts
from core.report import write_report


def publish(store, scan_id: int) -> list[str]:
    diff = store.get_diff(scan_id)
    if not diff or not (diff.get("summary") or {}).get("alerts"):
        return []
    notes = send_alerts(diff)
    try:
        path = write_report(store, scan_id)
        notes.append(f"rapport {path}")
    except Exception as exc:
        notes.append(f"rapport en échec : {exc}")
    return notes
