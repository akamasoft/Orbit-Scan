"""Rapport PDF du dernier relevé et de ses écarts."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from core.store import data_dir, format_when, summary_text


def write_report(store, scan_id: int | None = None, destination: Path | None = None) -> Path:
    if scan_id is None:
        scans = store.list_scans(limit=1)
        if not scans:
            raise RuntimeError("aucun relevé à exporter")
        scan_id = scans[0]["id"]
    scans = {item["id"]: item for item in store.list_scans(limit=200)}
    scan = scans.get(scan_id)
    if scan is None:
        raise RuntimeError("relevé introuvable")
    diff = store.get_diff(scan_id) or {}
    hosts = store.hosts_of(scan_id)
    lines = [
        "Orbite Scan — rapport de supervision",
        f"Relevé #{scan_id}  {format_when(scan['created_at'])}",
        f"Cible : {scan['subnet'] or '—'}    Passerelle : {scan['gateway'] or '—'}",
        f"Appareils : {scan['host_count']}",
        "",
        summary_text(diff),
        "",
        "Ecarts",
    ]
    events = diff.get("events") or []
    if not events:
        lines.append("Aucun écart par rapport au relevé précédent.")
    for event in events:
        lines.append(f"- {event.get('severity', '')}  {event.get('detail', '')}")
    lines.extend(["", "Inventaire"])
    for host in hosts:
        ports = " ".join(str(port) for port in host.get("open_ports") or []) or "—"
        lines.append(
            f"{host.get('ip', '')}  {host.get('hostname', '')}  {host.get('vendor', '')}  ports {ports}"
        )
    lines.extend(["", f"Généré le {datetime.now().strftime('%d/%m/%Y %H:%M')}"])
    target = Path(destination) if destination else data_dir() / "reports" / f"releve-{scan_id}.pdf"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_pdf(lines))
    return target


def _pdf(lines: list[str]) -> bytes:
    pages = []
    chunk = []
    y = 800
    for line in lines:
        if y < 56:
            pages.append(chunk)
            chunk = []
            y = 800
        chunk.append((y, _latin(line)[:110]))
        y -= 14
    if chunk:
        pages.append(chunk)
    if not pages:
        pages = [[(800, "Orbite Scan")]]

    objects = []
    page_ids = []
    next_id = 3
    font_id = 3
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for chunk in pages:
        content_id = next_id + 1
        page_id = next_id + 2
        next_id += 2
        stream = "\n".join(
            f"BT /F1 10 Tf 48 {y} Td ({_escape(text)}) Tj ET" for y, text in chunk
        ).encode("latin-1", "replace")
        objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        page_ids.append(page_id)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Contents {content_id} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>"
            ).encode("ascii")
        )
    kids = " ".join(f"{page} 0 R" for page in page_ids)
    catalog = b"<< /Type /Catalog /Pages 2 0 R >>"
    pages_obj = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode("ascii")
    ordered = [catalog, pages_obj, *objects]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, body in enumerate(ordered, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(ordered) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer << /Size {len(ordered) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def _latin(text: str) -> str:
    return text.encode("latin-1", "replace").decode("latin-1")


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
