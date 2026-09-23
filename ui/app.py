import sys
import os
import platform

if platform.system() == "Windows":
    import ctypes
    ctypes.windll.shell32.IsUserAnAdmin()

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit,
    QComboBox, QStackedWidget, QCheckBox, QLineEdit, QScrollArea,
    QFileDialog, QMenu, QProgressBar, QGraphicsOpacityEffect, QDialog, QFrame
)
import ipaddress
from PyQt6.QtWebEngineWidgets import QWebEngineView
import json
import re
import time
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl, QSize, QLocale, QPropertyAnimation, QEasingCurve, QVariantAnimation, QRectF, QUrl as QtUrl
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap, QPainter, QAction, QDesktopServices, QImage, QPen
from PyQt6.QtSvg import QSvgRenderer
import subprocess
import csv
from scapy.all import ARP, Ether, srp, sniff, IP as ScapyIP, TCP,UDP, ICMP
from collections import defaultdict
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.scanner import scan_network, scan_range, is_target_fully_local, get_local_subnet, check_root, get_network_interfaces, capture_traffic, ContinuousMonitor, get_default_gateway
from core.store import ScanStore, format_when, summary_text
from __main__ import __version__


def load_colored_svg(path, color, size=24):
    renderer = QSvgRenderer(path)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(pixmap.rect(), QColor(color))
    painter.end()
    return QIcon(pixmap)


class LogoIniziale(QWidget):
    def __init__(self):
        super().__init__(None)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.SplashScreen
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self.setAutoFillBackground(False)
        self.setStyleSheet("background: transparent;")
        self.setFixedSize(760, 900)

        logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        self._logo = self._cut_logo(logo_path)
        self._dy = 22
        self._angle = 0
        self._anims = []

        self._opacity = QGraphicsOpacityEffect(self)
        self._opacity.setOpacity(0.0)
        self.setGraphicsEffect(self._opacity)

    def showEvent(self, event):
        super().showEvent(event)
        screen = self.screen().availableGeometry()
        self.move(screen.center().x() - self.width() // 2, screen.center().y() - self.height() // 2)

        fade = QPropertyAnimation(self._opacity, b"opacity", self)
        fade.setDuration(480)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        fade.start()

        rise = QVariantAnimation(self)
        rise.setDuration(680)
        rise.setStartValue(18)
        rise.setEndValue(0)
        rise.setEasingCurve(QEasingCurve.Type.OutCubic)
        rise.valueChanged.connect(self._on_rise)
        rise.start()

        spin = QVariantAnimation(self)
        spin.setDuration(2800)
        spin.setStartValue(0)
        spin.setEndValue(360)
        spin.setLoopCount(-1)
        spin.valueChanged.connect(self._on_spin)
        spin.start()
        self._anims.extend([fade, rise, spin])

    def _cut_logo(self, path):
        image = QImage(path).convertToFormat(QImage.Format.Format_ARGB32)
        if image.isNull():
            return QPixmap()
        width, height = image.width(), image.height()
        stride = image.bytesPerLine()
        raw = image.bits()
        raw.setsize(image.sizeInBytes())
        data = bytearray(raw)
        for y in range(height):
            row = y * stride
            for x in range(width):
                i = row + x * 4
                if data[i] < 24 and data[i + 1] < 24 and data[i + 2] < 24:
                    data[i + 3] = 0
        cut = QImage(bytes(data), width, height, stride, QImage.Format.Format_ARGB32)
        return QPixmap.fromImage(cut.copy())

    def _on_spin(self, value):
        self._angle = int(value)
        self.update()

    def _on_rise(self, value):
        self._dy = int(value)
        self.update()

    def reveal(self, window):
        window.setWindowOpacity(0.0)
        window.show()

        fade_out = QPropertyAnimation(self._opacity, b"opacity", self)
        fade_out.setDuration(320)
        fade_out.setStartValue(self._opacity.opacity())
        fade_out.setEndValue(0.0)
        fade_out.setEasingCurve(QEasingCurve.Type.InCubic)
        fade_out.finished.connect(self.close)

        fade_in = QPropertyAnimation(window, b"windowOpacity", window)
        fade_in.setDuration(420)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)

        fade_out.start()
        fade_in.start()
        self._anims.extend([fade_out, fade_in])

    def _text(self, painter, rect, text, color, font, shadow=True):
        painter.setFont(font)
        if shadow:
            painter.setPen(QColor(0, 0, 0, 170))
            for dx, dy in ((0, 1), (1, 0), (0, -1), (-1, 0), (1, 1), (-1, 1)):
                painter.drawText(rect.translated(dx, dy), Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, text)
        painter.setPen(color)
        painter.drawText(rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, text)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        card = self.rect().adjusted(18, 18, -18, -18)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 80))
        painter.drawRoundedRect(card.translated(0, 10), 36, 36)
        painter.setBrush(QColor("#06110c"))
        painter.drawRoundedRect(card, 36, 36)

        accent = QRectF(card.left() + 48, card.top() + 22, card.width() - 96, 4)
        painter.setBrush(QColor("#00ff99"))
        painter.drawRoundedRect(accent, 2, 2)

        plate = QRectF(0, 0, 480, 480)
        plate.moveCenter(QRectF(card).center())
        plate.moveTop(card.top() + 46 + self._dy)
        painter.setBrush(QColor("#04140c"))
        painter.drawEllipse(plate)

        ring = QPen(QColor("#00ff99"))
        ring.setWidth(3)
        painter.setPen(ring)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(plate.adjusted(10, 10, -10, -10))

        arc = QPen(QColor("#7dffc3"))
        arc.setWidth(4)
        arc.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(arc)
        painter.drawArc(plate.adjusted(18, 18, -18, -18), self._angle * 16, 70 * 16)

        if not self._logo.isNull():
            logo = self._logo.scaled(
                408, 408,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            painter.drawPixmap(
                int(plate.center().x() - logo.width() / 2),
                int(plate.center().y() - logo.height() / 2),
                logo,
            )

        text_top = int(plate.bottom()) + 28
        self._text(
            painter,
            self.rect().adjusted(0, text_top, 0, 0),
            "Orbite Scan",
            QColor("#e7fff2"),
            QFont("Liberation Sans", 36, QFont.Weight.Bold),
        )
        self._text(
            painter,
            self.rect().adjusted(0, text_top + 52, 0, 0),
            "Autour de la passerelle.",
            QColor("#9dccb0"),
            QFont("Liberation Sans", 16),
        )
        painter.setPen(QPen(QColor("#00ff99"), 2))
        painter.drawLine(card.center().x() - 28, text_top + 92, card.center().x() + 28, text_top + 92)
        self._text(
            painter,
            self.rect().adjusted(0, text_top + 104, 0, 0),
            f"v{__version__}",
            QColor("#9dccb0"),
            QFont("Liberation Sans", 12),
            shadow=False,
        )
        self._text(
            painter,
            self.rect().adjusted(0, card.bottom() - 46, 0, 0),
            "by Akamasoft",
            QColor("#00ff99"),
            QFont("Liberation Sans", 15, QFont.Weight.DemiBold),
        )
        painter.end()


class ActionWorker(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, cmd: list):
        super().__init__()
        self.cmd = cmd

    def run(self):
        process = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for riga in process.stdout:
            self.output.emit(riga.rstrip())
        process.wait()
        self.finished.emit()


class ScanWorker(QThread):
    finished = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, subnet):
        super().__init__()
        self.subnet = subnet

    def run(self):
        try:
            hosts = scan_network(self.subnet)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(hosts)


class RangeScanWorker(QThread):
    finished = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):
        try:
            hosts = scan_range(self.target)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(hosts)


class TrafficWorker(QThread):
    packet_captured = pyqtSignal(dict)
    finished = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, iface: str):
        super().__init__()
        self.iface = iface
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        def process(pkt):
            if not self._running:
                return
            if ScapyIP not in pkt:
                return

            src = pkt[ScapyIP].src
            dst = pkt[ScapyIP].dst
            size = len(pkt)
            proto = "OTHER"
            port = "-"

            if TCP in pkt:
                proto = "TCP"
                port = str(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "UDP"
                port = str(pkt[UDP].dport)
            elif ICMP in pkt:
                proto = "ICMP"

            self.packet_captured.emit({
                "src": src,
                "dst": dst,
                "proto": proto,
                "port": port,
                "size": size
            })

        try:
            while self._running:
                sniff(
                    iface=self.iface,
                    prn=process,
                    store=False,
                    filter="ip",
                    timeout=1,
                )
        except Exception as exc:
            self.failed.emit(str(exc))
        self.finished.emit()

def is_valid_target(text: str) -> bool:
    text = text.strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        pass
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", text):
        return True
    hostname_re = re.compile(
        r"^(?!-)[a-zA-Z0-9\-]{1,63}(?:\.[a-zA-Z0-9\-]{1,63})*\.?$"
    )
    if hostname_re.match(text):
        if re.match(r"^\d+$", text):
            return False
        return True


CVSS_MIN = 4.0
MAX_CVES_PER_PORT = 5
GENERIC_SERVICES = {"tcpwrapped", "unknown", "filtered", ""}
HIGH_RISK_PORTS  = {21,23,25,110,135,139,445,512,513,514,3389,5900,6379,27017}
MEDIUM_RISK_PORTS = {22,80,8080,3306,5432,1433,2375,2376,4444}

def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    return "LOW"


RISK_FR = {
    "CRITICAL": "CRITIQUE",
    "HIGH": "ÉLEVÉ",
    "MEDIUM": "MOYEN",
    "LOW": "FAIBLE",
    "CLEAN": "SAIN",
}


class AttackSurfaceWorker(QThread):
    finished = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    port_found = pyqtSignal(dict)

    def __init__(self, target: str):
        super().__init__()
        self.target = target

    def run(self):
        import tempfile, xml.etree.ElementTree as ET

        tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
        tmp_path = tmp.name
        tmp.close()

        cmd = [
            "nmap", "-sV", "-O",
            "--script", "vulners",
            "--open", "-Pn", "-T4",
            "-oX", tmp_path,
            self.target
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        seen_ports = set()

        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            if "Scanning" in line or "scan report" in line:
                self.status_update.emit(f"{line.lower()}")
            elif "OS details" in line or "Running:" in line:
                self.status_update.emit(f"{line.lower()}")
            elif "/tcp" in line or "/udp" in line:
                self.status_update.emit(f"Port trouvé : {line}")
                match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
                if match:
                    portid = match.group(1)
                    if portid in seen_ports:
                        continue
                    seen_ports.add(portid)
                    proto = match.group(2)
                    svc = match.group(3)
                    version = match.group(4).strip()
                    portnum = int(portid)
                    if portnum in {21,23,25,110,135,139,445,512,513,514,3389,5900,6379,27017}:
                        risk = "HIGH"
                    elif portnum in {22,80,8080,3306,5432,1433,2375,2376,4444}:
                        risk = "MEDIUM"
                    else:
                        risk = "LOW"
                    self.port_found.emit({
                        "port": portid, "protocol": proto,
                        "service": svc, "version": version or "-", "risk": risk,
                    })

        process.wait()
        self.status_update.emit("Analyse des vulnérabilités…")

        result = self._parse(tmp_path)
        os.unlink(tmp_path)

        self.status_update.emit("Analyse terminée")
        self.finished.emit(result)

    def _parse(self, xml_path: str) -> dict:
        import xml.etree.ElementTree as ET
        from collections import defaultdict

        result = {
            "target": self.target,
            "os": "Inconnu",
            "ports": [],
            "cves": [],
        }

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError):
            return result

        host = root.find("host")
        if host is None:
            return result

        cpe_list = [cpe.text or "" for cpe in host.findall(".//cpe")]
        is_windows = any("windows" in c for c in cpe_list)
        is_linux   = any("linux"   in c for c in cpe_list)
        is_macos   = any("mac_os"  in c or "macos" in c for c in cpe_list)

        osmatch = host.find(".//osmatch")
        if osmatch is not None:
            os_name  = osmatch.get("name", "")
            accuracy = osmatch.get("accuracy", "?")
            result["os"] = f"{os_name} ({accuracy}%)"
            if not any([is_windows, is_linux, is_macos]):
                osL = os_name.lower()
                is_windows = "windows" in osL
                is_linux   = any(k in osL for k in ["linux","ubuntu","debian"])
                is_macos   = any(k in osL for k in ["mac os","macos","darwin"])

        port_cve_count = defaultdict(int)

        for port in host.findall(".//port"): 
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid   = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service  = port.find("service")

            svc_name    = service.get("name",    "-") if service is not None else "-"
            svc_product = service.get("product", "") if service is not None else ""
            svc_version = service.get("version", "") if service is not None else ""
            svc_full    = f"{svc_product} {svc_version}".strip() or "-"
            svc_ostype  = service.get("ostype",  "").lower() if service is not None else ""

            portnum = int(portid)
            if portnum in HIGH_RISK_PORTS:
                risk = "HIGH"
            elif portnum in MEDIUM_RISK_PORTS:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            result["ports"].append({
                "port":     portid,
                "protocol": protocol,
                "service":  svc_name,
                "version":  svc_full,
                "risk":     risk,
            })

            for script in port.findall("script"):
                scriptID = script.get("id", "")
                output   = script.get("output", "")

                if not any(x in scriptID for x in ["vulners", "vuln", "exploit"]):
                    continue

                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    match = re.match(r"(CVE-\d{4}-\d+)\s+(\d+\.\d+)\s+https?://", line)
                    if not match:
                        continue

                    cve_id = match.group(1)
                    cvss   = float(match.group(2))

                    if cvss < CVSS_MIN:
                        continue

                    if svc_name.lower() in GENERIC_SERVICES:
                        continue

                    if not svc_product:
                        continue

                    if any(c["id"] == cve_id for c in result["cves"]):
                        continue

                    if port_cve_count[portid] >= MAX_CVES_PER_PORT:
                        continue

                    windows_only = {"netlogon", "msrpc", "microsoft-ds", "ms-wbt-server"}
                    if svc_name.lower() in windows_only and not is_windows:
                        continue

                    if svc_ostype:
                        if "windows" in svc_ostype and not is_windows:
                            continue
                        if "linux" in svc_ostype and not is_linux:
                            continue

                    port_cve_count[portid] += 1
                    result["cves"].append({
                        "id":      cve_id,
                        "cvss":    cvss,
                        "port":    portid,
                        "service": svc_name,
                        "detail":  f"{svc_name} {svc_full} — {cve_id}",
                    })

        result["cves"].sort(key=lambda c: c["cvss"], reverse=True)

        for port_entry in result["ports"]:
            port_cves = [c for c in result["cves"] if c["port"] == port_entry["port"]]
            if not port_cves:
                continue
            max_cvss = max(c["cvss"] for c in port_cves)
            port_entry["risk"] = cvss_to_severity(max_cvss)

        return result


class ConfigAuditWorker(QThread):
    finished = pyqtSignal(str)

    def __init__(self, ip: str):
        super().__init__()
        self.ip = ip

    def run(self):
        from core.audit import audit_host
        result = audit_host(self.ip)
        text = "\n".join(f"[{item['severity']}] {item['detail']}" for item in result["findings"])
        self.finished.emit(text or "Aucun résultat.")


class AuthAuditWorker(QThread):
    finished = pyqtSignal(dict)

    def __init__(self, credential_id: int):
        super().__init__()
        self.credential_id = credential_id

    def run(self):
        from core.credentialed import run_authenticated
        try:
            self.finished.emit(run_authenticated(self.credential_id))
        except Exception as exc:
            self.finished.emit({"error": str(exc)})


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Orbite Scan")
        self.setMinimumSize(1100, 680)
        screen = QApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            width = min(avail.width() - 48, 1180)
            height = min(avail.height() - 48, 760)
            self.resize(max(width, 960), max(height, 640))
            frame = self.frameGeometry()
            frame.moveCenter(avail.center())
            self.move(frame.topLeft())

        icon_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        self.setWindowIcon(QIcon(icon_path))

        self._apply_theme()
        self.store = ScanStore()
        self._latest_diff = None
        self._build_ui()

        self.live_timer = QTimer()
        self.live_timer.timeout.connect(self._live_scan)

        self.continuous_monitor = None
        self._monitor_active = False
        self._apply_diff_banner(self.store.latest_diff())
        self._reload_journal(select_latest=True)
        self._restore_last_inventory()

    def _apply_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #06110c;
                color: #e7fff2;
                font-family: "Liberation Sans", "Noto Sans", "Segoe UI", sans-serif;
                font-size: 13px;
            }
            QWidget#toolbar {
                background-color: #06110c;
                border-bottom: 1px solid #143828;
            }
            QWidget#navBar {
                background-color: #08160f;
                border-bottom: 1px solid #1c4a34;
            }
            QLabel#title_label {
                color: #e7fff2;
                font-size: 20px;
                font-weight: 700;
                letter-spacing: 0.2px;
                background: transparent;
            }
            QLabel#navGroup {
                color: #00ff99;
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 1.2px;
                padding: 0 8px;
                background: transparent;
            }
            QFrame#card {
                background: #0c1c14;
                border: 1px solid #1c4a34;
                border-radius: 16px;
            }
            QLineEdit, QComboBox, QTextEdit {
                background-color: #07140e;
                color: #e7fff2;
                border: 1px solid #2d8a5e;
                border-radius: 10px;
                padding: 8px 12px;
                selection-background-color: #145c38;
                selection-color: #e7fff2;
                min-height: 18px;
            }
            QLineEdit::placeholder, QTextEdit::placeholder {
                color: #9dccb0;
            }
            QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
                border: 2px solid #00ff99;
                background-color: #07140e;
            }
            QLineEdit#subnet_label {
                min-height: 16px;
            }
            QComboBox::drop-down {
                border: none;
                width: 18px;
            }
            QComboBox QAbstractItemView {
                background-color: #0c1c14;
                color: #e7fff2;
                border: 1px solid #1c4a34;
                border-radius: 10px;
                selection-background-color: #145c38;
                selection-color: #e7fff2;
                outline: 0;
                padding: 4px;
            }
            QPushButton {
                background-color: #0e2218;
                color: #e7fff2;
                border: 1px solid #1c4a34;
                border-radius: 10px;
                padding: 8px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #143828;
                border-color: #00ff99;
                color: #ffffff;
            }
            QPushButton:disabled {
                color: #5d7a6a;
                border-color: #143828;
                background-color: #08140f;
            }
            QPushButton#primary {
                background-color: #00c26e;
                color: #04140c;
                border: none;
                padding: 8px 18px;
            }
            QPushButton#primary:hover {
                background-color: #00ff99;
                color: #04140c;
            }
            QPushButton#primary:disabled {
                background-color: #145c38;
                color: #9dccb0;
                border: none;
            }
            QPushButton#navButton {
                background-color: transparent;
                color: #9dccb0;
                border: none;
                border-bottom: 2px solid transparent;
                border-radius: 0;
                padding: 6px 10px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton#navButton:hover {
                background-color: transparent;
                color: #e7fff2;
                border-bottom: 2px solid #1c4a34;
            }
            QPushButton#navButton[active="true"] {
                background-color: transparent;
                color: #00ff99;
                border-bottom: 2px solid #00ff99;
            }
            QTableWidget {
                background-color: #07140e;
                alternate-background-color: #0c1c14;
                gridline-color: transparent;
                border: none;
                font-family: "Liberation Sans", "Noto Sans", "Segoe UI", sans-serif;
                font-size: 13px;
                outline: 0;
                color: #e7fff2;
            }
            QTableWidget::item {
                padding: 8px 10px;
                border: none;
                color: #e7fff2;
            }
            QTableWidget::item:selected {
                background-color: #145c38;
                color: #e7fff2;
            }
            QHeaderView {
                background-color: #0a2418;
                color: #d8ffe8;
            }
            QHeaderView::section {
                background-color: #0a2418;
                color: #d8ffe8;
                border: none;
                border-bottom: 2px solid #00ff99;
                border-right: 1px solid #143828;
                padding: 10px 10px;
                font-weight: 700;
                font-size: 12px;
                letter-spacing: 0.4px;
            }
            QTextEdit {
                font-family: "JetBrains Mono", "Ubuntu Mono", monospace;
                font-size: 12px;
                background-color: #07140e;
                color: #d8ffe8;
            }
            QCheckBox {
                spacing: 8px;
                color: #d8ffe8;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #2d8a5e;
                border-radius: 5px;
                background: #07140e;
            }
            QCheckBox::indicator:checked {
                background: #00c26e;
                border: 1px solid #00ff99;
            }
            QMenu {
                background-color: #0c1c14;
                color: #e7fff2;
                border: 1px solid #1c4a34;
                border-radius: 10px;
                padding: 6px;
            }
            QMenu::item {
                padding: 8px 16px;
                border-radius: 8px;
            }
            QMenu::item:selected {
                background-color: #145c38;
            }
            QScrollBar:vertical {
                background: transparent;
                width: 10px;
                margin: 4px;
            }
            QScrollBar::handle:vertical {
                background: #1c4a34;
                border-radius: 5px;
                min-height: 28px;
            }
            QScrollBar:horizontal {
                background: transparent;
                height: 10px;
            }
            QScrollBar::handle:horizontal {
                background: #1c4a34;
                border-radius: 5px;
            }
            QScrollBar::add-line, QScrollBar::sub-line {
                width: 0;
                height: 0;
            }
            QStatusBar {
                background: #06110c;
                color: #9dccb0;
                border-top: 1px solid #143828;
                font-size: 12px;
            }
            QToolTip {
                background-color: #0c1c14;
                color: #e7fff2;
                border: 1px solid #00ff99;
                border-radius: 8px;
                padding: 6px 8px;
            }
            QProgressBar {
                background-color: #07140e;
                border: none;
                border-radius: 6px;
                text-align: center;
                color: #e7fff2;
            }
            QProgressBar::chunk {
                background-color: #00c26e;
                border-radius: 6px;
            }
            QLabel#fieldCaption {
                color: #d8ffe8;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.2px;
                background: transparent;
            }
            QLabel#crumb {
                color: #00ff99;
                font-size: 13px;
                font-weight: 500;
                background: transparent;
            }
            QLabel#pageTitle {
                color: #e7fff2;
                font-size: 22px;
                font-weight: 700;
                background: transparent;
            }
            QLabel#sectionLabel {
                color: #9dccb0;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.4px;
                background: transparent;
            }
            QLabel#emptyHint {
                color: #9dccb0;
                font-size: 14px;
                background: transparent;
            }
            QLabel#statusStrip {
                background: transparent;
                color: #9dccb0;
                font-size: 12px;
                padding: 10px 16px;
                border-bottom: 1px solid #143828;
            }
            QWidget#pageHeader {
                background: transparent;
                border: none;
            }
            QWidget#sidePanel, QScrollArea#sidePanel {
                background: #0c1c14;
                border: none;
                border-right: 1px solid #143828;
            }
            QLabel#mono {
                font-family: "JetBrains Mono", "Ubuntu Mono", monospace;
                font-size: 12px;
                color: #d8ffe8;
                background: transparent;
            }
            QLineEdit#mono, QTextEdit#mono {
                font-family: "JetBrains Mono", "Ubuntu Mono", monospace;
                font-size: 12px;
            }
            QLineEdit[state="valid"] {
                border: 1px solid #00ff99;
            }
            QLineEdit[state="invalid"] {
                border: 1px solid #ff6b7a;
                color: #ffd0d6;
            }
            QPushButton:checked {
                background-color: #145c38;
                color: #00ff99;
                border: 1px solid #00ff99;
            }
            QPushButton#danger {
                background: transparent;
                color: #ff8b98;
                border: 1px solid #7a3038;
            }
            QPushButton#danger:hover {
                background: #3a1518;
                border-color: #ff6b7a;
                color: #ffe4e8;
            }
            QPushButton#danger:disabled {
                color: #5d7a6a;
                border-color: #143828;
                background: transparent;
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
            QWidget#filterBar {
                background: transparent;
                border-bottom: 1px solid #1c4a34;
            }
            QSplitter::handle {
                background: #143828;
            }
            QSplitter#quietSplit::handle {
                background: transparent;
            }
            QDialog {
                background: #06110c;
            }
        """)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QVBoxLayout(central)
        root_layout.setSpacing(0)
        root_layout.setContentsMargins(0, 0, 0, 0)

        root_layout.addWidget(self._build_toolbar())
        root_layout.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_home_page())
        self.stack.addWidget(self._build_scan_page())
        self.stack.addWidget(self._build_graph_page())
        self.stack.addWidget(self._build_attackSurface_page())
        self.stack.addWidget(self._build_trafficAnalyzer_page())
        self.stack.addWidget(self._build_journal_page())
        self.stack.addWidget(self._build_platform_page())
        self.stack.addWidget(self._build_enterprise_page())
        root_layout.addWidget(self.stack, stretch=1)

        for btn in self.findChildren(QPushButton):
            btn.setCursor(Qt.CursorShape.PointingHandCursor)

        self.statusBar().showMessage("Prêt.")

    def _build_sidebar(self):
        bar = QWidget()
        bar.setObjectName("navBar")
        bar.setFixedHeight(58)
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 8, 12, 8)
        bar_layout.setSpacing(6)

        assets = os.path.join(os.path.dirname(__file__), "../img", "icons")

        def make_btn(icon_file, label, kind):
            icon_path = os.path.join(assets, icon_file)
            btn = QPushButton(label)
            btn.setObjectName(kind)
            btn.setIcon(load_colored_svg(icon_path, "#9dccb0", size=16))
            btn.setIconSize(QSize(16, 16))
            btn.setToolTip(label)
            btn.setMinimumHeight(36)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            return btn, icon_path

        btn_home, path_home = make_btn("home.svg", "Appareils", "navButton")
        btn_scan, path_scan = make_btn("eye.svg", "Ports", "navButton")
        btn_graph, path_graph = make_btn("network2.svg", "Topologie", "navButton")
        btn_attack, path_attack = make_btn("attack.svg", "Surface", "navButton")
        btn_traffic, path_traffic = make_btn("traffic.svg", "Trafic", "navButton")
        btn_journal, path_journal = make_btn("history.svg", "Journal", "navButton")
        btn_platform, path_platform = make_btn("settings.svg", "Pilotage", "navButton")
        btn_enterprise, path_enterprise = make_btn("shield.svg", "Entreprise", "navButton")

        self.nav_btns = [
            (btn_home, path_home),
            (btn_scan, path_scan),
            (btn_graph, path_graph),
            (btn_attack, path_attack),
            (btn_traffic, path_traffic),
            (btn_journal, path_journal),
            (btn_platform, path_platform),
            (btn_enterprise, path_enterprise),
        ]

        def navigate(index):
            self._go_page(index)

        btn_home.clicked.connect(lambda: navigate(0))
        btn_scan.clicked.connect(lambda: navigate(1))
        btn_graph.clicked.connect(lambda: navigate(2))
        btn_traffic.clicked.connect(lambda: navigate(4))
        btn_attack.clicked.connect(lambda: navigate(3))
        btn_journal.clicked.connect(lambda: navigate(5))
        btn_platform.clicked.connect(lambda: navigate(6))
        btn_enterprise.clicked.connect(lambda: navigate(7))

        for btn, _path in self.nav_btns:
            bar_layout.addWidget(btn)
        bar_layout.addStretch()

        about_btn, _ = make_btn("info.svg", "À propos", "navButton")
        about_btn.clicked.connect(self._show_about)
        bar_layout.addWidget(about_btn)

        self._set_active_nav(0)
        return bar

    def _set_active_nav(self, index):
        for i, (btn, path) in enumerate(self.nav_btns):
            active = i == index
            color = "#00ff99" if active else "#9dccb0"
            btn.setIcon(load_colored_svg(path, color))
            btn.setProperty("active", active)
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        if hasattr(self, "crumb"):
            self.crumb.setText(self._page_titles[index])

    def _show_about(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("À propos d'Orbite Scan")
        dialog.setModal(True)
        dialog.setMinimumWidth(420)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(28, 24, 28, 20)
        layout.setSpacing(8)

        logo = QLabel()
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pixmap = QPixmap(os.path.join(os.path.dirname(__file__), "assets", "logo.png"))
        if not pixmap.isNull():
            logo.setPixmap(pixmap.scaled(88, 88, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        layout.addWidget(logo)

        title = QLabel("Orbite Scan")
        title.setObjectName("pageTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        tagline = QLabel("Autour de la passerelle.")
        tagline.setObjectName("emptyHint")
        tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(tagline)

        version = QLabel(f"Version {__version__}  ·  by Akamasoft")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("color: #9dccb0; background: transparent;")
        layout.addWidget(version)

        layout.addSpacing(8)
        notice = QLabel(
            "Édité par Akamasoft.\n"
            "Licence GNU GPL-3.0 ou ultérieure.\n"
            "Comprend du code de L0p4Map, © HaxL0p4."
        )
        notice.setAlignment(Qt.AlignmentFlag.AlignCenter)
        notice.setWordWrap(True)
        notice.setStyleSheet("color: #9dccb0; background: transparent;")
        layout.addWidget(notice)

        link = QLabel('<a href="https://github.com/akamasoft/Orbit-Scan" style="color:#00ff99; text-decoration:none;">github.com/akamasoft/Orbit-Scan</a>')
        link.setAlignment(Qt.AlignmentFlag.AlignCenter)
        link.setTextFormat(Qt.TextFormat.RichText)
        link.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        link.setOpenExternalLinks(True)
        layout.addWidget(link)

        layout.addSpacing(8)
        close = QPushButton("Fermer")
        close.setObjectName("primary")
        close.clicked.connect(dialog.accept)
        layout.addWidget(close, alignment=Qt.AlignmentFlag.AlignCenter)
        dialog.exec()

    def _go_page(self, index):
        current = self.stack.currentIndex()
        if current == index:
            return
        self._set_active_nav(index)
        if index == 5:
            self._reload_journal(select_latest=False)
        if index == 6 and hasattr(self, "plan_table"):
            self._reload_platform()
        if index == 7 and hasattr(self, "cred_table"):
            self._reload_enterprise()
        if current == 2 or index == 2 or not hasattr(self, "stack"):
            self.stack.setCurrentIndex(index)
            if index == 2:
                self._center_graph()
            return
        self.stack.setGraphicsEffect(None)
        self.stack.setCurrentIndex(index)

    def _center_graph(self):
        if not getattr(self, "graph_ready", False):
            return

        def run():
            if getattr(self, "graph_ready", False):
                self.graph_view.page().runJavaScript("centerGraph()")

        QTimer.singleShot(0, run)
        QTimer.singleShot(300, run)

    def _captioned(self, caption, widget):
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        label = QLabel(caption)
        label.setObjectName("fieldCaption")
        layout.addWidget(label)
        layout.addWidget(widget)
        return box

    def _build_toolbar(self):
        toolbar = QWidget()
        toolbar.setObjectName("toolbar")
        toolbar.setFixedHeight(72)
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(20, 10, 16, 10)
        layout.setSpacing(16)

        brand = QVBoxLayout()
        brand.setSpacing(0)
        title = QLabel("Orbite Scan")
        title.setObjectName("title_label")
        self.crumb = QLabel("Appareils")
        self.crumb.setObjectName("crumb")
        brand.addWidget(title)
        brand.addWidget(self.crumb)
        brand_box = QWidget()
        brand_box.setLayout(brand)

        self.subnet_label = QLineEdit()
        self.subnet_label.setObjectName("subnet_label")
        self.subnet_label.setPlaceholderText("192.168.1.0/24")
        self.subnet_label.setFixedWidth(220)
        self.subnet_label.setToolTip("Sous-réseau, adresse IP ou plage du type 192.168.1.1-50")

        self.iface_selector = QComboBox()
        self.iface_selector.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.iface_selector.setMinimumWidth(200)
        self.iface_selector.setToolTip("Interface utilisée pour découvrir le réseau local")

        self._load_interfaces()
        self.iface_selector.currentIndexChanged.connect(self._on_iface_changed)

        self.scan_button = QPushButton("Scanner")
        self.scan_button.setObjectName("primary")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.scan_button.setToolTip("Découvrir les appareils de la cible")
        self.scan_button.clicked.connect(self._start_scan)

        self._page_titles = [
            "Appareils",
            "Scan de ports",
            "Topologie",
            "Surface d'attaque",
            "Trafic",
            "Journal",
            "Pilotage",
            "Entreprise",
        ]

        layout.addWidget(brand_box)
        layout.addSpacing(28)
        layout.addWidget(self._captioned("Cible", self.subnet_label))
        layout.addSpacing(10)
        layout.addWidget(self._captioned("Interface", self.iface_selector))
        layout.addStretch()
        layout.addWidget(self.scan_button)

        return toolbar

    def _load_interfaces(self):
        interfaces = get_network_interfaces()
        self.interfaces = interfaces

        self.iface_selector.blockSignals(True)
        self.iface_selector.clear()

        for iface in interfaces:
            self.iface_selector.addItem(f"{iface['name']} {iface['ip']}", userData=iface)

        self.iface_selector.blockSignals(False)

    def _on_iface_changed(self,index):
        iface = self.iface_selector.itemData(index)
        if not iface:
            return
        try:
            self.subnet_label.setText(get_local_subnet(iface["name"]))
        except Exception:
            self.subnet_label.clear()

    def _resolve_subnet(self):
        manual = self.subnet_label.text().strip()
        if manual:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", manual):
                return manual
            try:
                return str(ipaddress.ip_network(manual, strict=False))
            except ValueError:
                pass
            try:
                ipaddress.ip_address(manual)
                return manual
            except ValueError:
                pass

        iface = self.iface_selector.currentData()
        if not iface:
            return None
        try:
            return get_local_subnet(iface["name"])
        except Exception:
            return None

    def _build_home_page(self):

        home = QWidget()
        layout = QVBoxLayout(home)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 12, 16, 12)

        layout.addWidget(self._build_diff_banner())

        header = QWidget()
        header.setObjectName("pageHeader")
        header.setFixedHeight(46)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 0, 16, 0)
        home_title = QLabel("Appareils découverts")
        home_title.setObjectName("pageTitle")
        self.home_count = QLabel("En attente d'un scan")
        self.home_count.setObjectName("emptyHint")
        header_layout.addWidget(home_title)
        header_layout.addSpacing(12)
        header_layout.addWidget(self.home_count)
        header_layout.addStretch()
        layout.addWidget(header)

        self.home_empty = QLabel("Aucun appareil pour l'instant.\nChoisissez une cible, puis lancez Scanner.")
        self.home_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.home_empty.setObjectName("emptyHint")
        self.home_empty.setWordWrap(True)

        self.home_stack = QStackedWidget()
        self.home_stack.addWidget(self.home_empty)
        self.home_stack.addWidget(self._build_table())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._as_card(self.home_stack))
        splitter.addWidget(self._as_card(self._build_detail_panel()))
        splitter.setSizes([800, 400])
        splitter.setObjectName("quietSplit")
        layout.addWidget(splitter, stretch=1)

        return home

    def _build_scan_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0,0,0,0)

        layout.addWidget(self._build_scan_options())
        layout.addWidget(self._build_scan_output(), stretch=1)
        return page

    def _build_scan_options(self):
        scroll = QScrollArea()
        scroll.setObjectName("sidePanel")
        scroll.setFixedWidth(300)
        scroll.setWidgetResizable(True)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(6)

        target_label = QLabel("Cible")
        target_label.setObjectName("sectionLabel")
        layout.addWidget(target_label)

        self.scan_target = QLineEdit()
        self.scan_target.setObjectName("mono")
        self.scan_target.setPlaceholderText("192.168.1.1 ou un nom d'hôte")
        layout.addWidget(self.scan_target)
        layout.setSpacing(8)

        self._scan_checks = {}
        sections = {
        "Type de scan": [
            ("-F", "Scan rapide"),
            ("-sS", "Scan SYN"),
            ("-sT", "Connexion TCP"),
            ("-sU", "Scan UDP"),
            ("-sN", "Scan NULL"),
            ("-sX", "Scan Xmas"),
            ("-p-", "Tous les ports"),
            ("-A", "Agressif"),
            ("-Pn", "Sans ping"),
        ],
        "Détection": [
            ("-sV", "Version des services"),
            ("-O", "Détection de l'OS"),
            ("--osscan-guess", "Estimation de l'OS"),
        ],
        "Scripts": [
            ("-sC", "Scripts par défaut"),
            ("--script banner", "Récupération de bannière"),
            ("--script safe", "Scripts sûrs"),
            ("--script vuln", "Scan de vulnérabilités"),
            ("--script vulners", "CVE Vulners"),
            ("--script malware", "Détection de malware"),
            ("--script discovery", "Découverte"),
            ("--script http-enum", "Énumération HTTP"),
            ("--script http-headers", "En-têtes HTTP"),
            ("--script http-methods", "Méthodes HTTP"),
            ("--script ssl-cert", "Certificat SSL"),
            ("--script ssl-enum-ciphers", "Chiffrement SSL"),
            ("--script smb-enum-shares", "Partages SMB"),
            ("--script smb-enum-users", "Utilisateurs SMB"),
            ("--script dns-brute", "Force brute DNS"),
            ("--script ftp-anon", "FTP anonyme"),
            ("--script ssh-auth-methods", "Authentification SSH"),
        ],
        "Sortie": [
            ("--open", "Ports ouverts seulement"),
            ("-v", "Verbeux"),
            ("--reason", "Afficher la raison"),
        ],
        "Rythme": [
            ("-T1", "Furtif (lent)"),
            ("-T2", "Poli"),
            ("-T3", "Normal"),
            ("-T4", "Agressif"),
            ("-T5", "Extrême (rapide)"),
        ],
    }

        for section_name, options in sections.items():
            sep = QWidget()
            sep.setFixedHeight(1)
            sep.setStyleSheet("background-color: #143828;")
            layout.addWidget(sep)
            layout.addSpacing(4)

            sec_label = QLabel(section_name)
            sec_label.setObjectName("sectionLabel")
            layout.addWidget(sec_label)
            layout.addSpacing(2)

            for flag, description in options:
                cb = QCheckBox(f"{description}")
                cb.setFocusPolicy(Qt.FocusPolicy.NoFocus)
                cb.setToolTip(flag)
                self._scan_checks[flag] = cb
                layout.addWidget(cb)
            layout.addSpacing(4)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #143828;")
        layout.addWidget(sep)
        layout.addSpacing(4)

        custom_label = QLabel("Options libres")
        custom_label.setObjectName("sectionLabel")
        layout.addWidget(custom_label)

        self.custom_flags = QLineEdit()
        self.custom_flags.setObjectName("mono")
        self.custom_flags.setPlaceholderText("-p 80,443 --script http-title")
        layout.addWidget(self.custom_flags)
        layout.addSpacing(12)

        self.btn_run_scan = QPushButton("Lancer le scan")
        self.btn_run_scan.setObjectName("primary")
        self.btn_run_scan.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)
        layout.addWidget(self.btn_run_scan)

        self.btn_export_scan = QPushButton("Exporter")
        self.btn_export_scan.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_export_scan.setDisabled(True)
        self.btn_export_scan.clicked.connect(self._export_scan)

        layout.addSpacing(6)
        layout.addWidget(self.btn_export_scan)

        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    def _export_scan(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter le scan Orbite Scan",
            "scan.txt",
            "Fichiers texte (*.txt);;Tous les fichiers (*)"
        )
        if not path:
            return

        with open(path,"w") as f:
            f.write(self.scan_output.toPlainText())

    def _build_scan_output(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        self.scan_cmd_label = QLabel("Aucune commande. Choisissez une cible et des options.")
        self.scan_cmd_label.setObjectName("statusStrip")
        layout.addWidget(self.scan_cmd_label)

        self.scan_output = QTextEdit()
        self.scan_output.setObjectName("mono")
        self.scan_output.setReadOnly(True)
        self.scan_output.setPlaceholderText("Choisissez les options, puis lancez le scan.")
        layout.addWidget(self.scan_output, stretch=1)
        return container

    def _run_nmap_scan(self):
        target = self.scan_target.text().strip()
        if not target:
            self.scan_output.append("Erreur : aucune cible indiquée.")
            return

        cmd = ["nmap"]
        for flag, cb in self._scan_checks.items():
            if cb.isChecked():
                cmd.extend(flag.split())

        custom = self.custom_flags.text().strip()
        if custom:
            cmd.extend(custom.split())

        cmd.append(target)

        self.scan_cmd_label.setText(" ".join(cmd))
        self.scan_output.clear()
        self.scan_output.append(" ".join(cmd) + "\n")

        self.btn_run_scan.setText("Arrêter")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._stop_nmap_scan)

        self.action_worker = ActionWorker(cmd)
        self.action_worker.output.connect(self.scan_output.append)
        self.action_worker.finished.connect(self._on_nmap_finished)
        self.action_worker.start()

    def _stop_nmap_scan(self):
        if hasattr(self, 'action_worker') and self.action_worker.isRunning():
            self.action_worker.finished.disconnect()
            self.action_worker.terminate()
        self.scan_output.append("\nInterrompu.")
        self.btn_export_scan.setDisabled(True)
        self.btn_run_scan.setText("Lancer le scan")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)

    def _on_nmap_finished(self):
        self.scan_output.append("\nTerminé.")
        self.btn_export_scan.setDisabled(False)
        self.btn_run_scan.setText("Lancer le scan")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)

    def _build_graph_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        header = QWidget()
        header.setObjectName("pageHeader")
        header.setFixedHeight(52)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 0, 16, 0)

        header_label = QLabel("Topologie")
        header_label.setObjectName("pageTitle")
        header_layout.addWidget(header_label)
        header_layout.addSpacing(12)

        self.btn_export_graph = QComboBox()
        self.btn_export_graph.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_export_graph.addItem("Exporter")
        self.btn_export_graph.addItem("CSV", userData="csv")
        self.btn_export_graph.addItem("PNG", userData="png")
        self.btn_export_graph.setFixedWidth(120)
        self.btn_export_graph.currentIndexChanged.connect(self._export_graph)
        self.btn_export_graph.setDisabled(True)
        header_layout.addWidget(self.btn_export_graph)
        header_layout.addStretch()

        self.live_interval = QComboBox()
        self.live_interval.addItem("30 s", userData=30)
        self.live_interval.addItem("60 s", userData=60)
        self.live_interval.addItem("120 s", userData=120)
        self.live_interval.setFixedWidth(84)
        self.live_interval.setToolTip("Intervalle du suivi en direct")
        header_layout.addWidget(self.live_interval)
        header_layout.addSpacing(8)

        self.btn_live = QPushButton("En direct")
        self.btn_live.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_live.setCheckable(True)
        self.btn_live.setToolTip("Rafraîchir la carte à intervalle régulier")
        self.btn_live.clicked.connect(self._toggle_live)
        header_layout.addWidget(self.btn_live)

        header_layout.addSpacing(8)

        self.btn_monitor = QPushButton("Surveillance")
        self.btn_monitor.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_monitor.setCheckable(True)
        self.btn_monitor.setToolTip("Rescanner le sous-réseau toutes les 60 secondes")
        self.btn_monitor.clicked.connect(self._toggle_continuous_monitor)
        header_layout.addWidget(self.btn_monitor)

        layout.addWidget(header)

        self.graph_view = QWebEngineView()
        self.graph_view.setStyleSheet("background-color: #06110c;")
        self.graph_ready = False

        html_path = os.path.join(
            os.path.dirname(__file__), "assets", "graph.html"
        )
        self.graph_view.load(QUrl.fromLocalFile(html_path))
        self.graph_view.loadFinished.connect(self._on_graph_loaded)
        layout.addWidget(self.graph_view, stretch=1)

        return page

    def _toggle_continuous_monitor(self):
        if self.btn_monitor.isChecked():
            subnet = self._resolve_subnet()
            if not subnet:
                self.statusBar().showMessage("Aucun sous-réseau disponible pour la surveillance continue.")
                self.btn_monitor.setChecked(False)
                return
            self._monitor_active = True
            iface = self.iface_selector.currentData()
            iface_name = iface["name"] if iface else None
            self.continuous_monitor = ContinuousMonitor()
            self.continuous_monitor.start(
                subnet=subnet,
                iface=iface_name,
                interval=60,
                callback=self._on_continuous_update
            )
            self.statusBar().showMessage("Surveillance continue active — rafraîchissement toutes les 60 s")
        else:
            self._monitor_active = False
            if self.continuous_monitor:
                self.continuous_monitor.stop()
                self.continuous_monitor = None
            self.statusBar().showMessage("Surveillance continue arrêtée.")

    def _on_continuous_update(self, hosts):
        if hasattr(self, 'graph_view') and self.graph_ready:
            self._update_graph(hosts)
            self.last_hosts = hosts
            self.statusBar().showMessage(f"Mise à jour continue — {len(hosts)} appareils")

    def _toggle_live(self):
        if self.btn_live.isChecked():
            interval = int(self.live_interval.currentData() or 30) * 1000
            self.live_timer.start(interval)
            self.statusBar().showMessage(f"Suivi en direct actif — rafraîchissement toutes les {self.live_interval.currentText()}")
        else:
            self.live_timer.stop()
            self.statusBar().showMessage("Suivi en direct arrêté.")

    def _live_scan(self):
        if hasattr(self, 'live_worker') and self.live_worker.isRunning():
            return

        subnet = self._resolve_subnet()
        if not subnet:
            self.statusBar().showMessage("Aucun sous-réseau disponible pour le scan en direct.")
            return

        self.live_worker = ScanWorker(subnet)
        self.live_worker.failed.connect(
            lambda message: self.statusBar().showMessage(f"Suivi interrompu : {message}")
        )
        self.live_worker.finished.connect(self._on_live_scan_finished)
        self.live_worker.start()

    def _on_live_scan_finished(self, hosts):
        self._update_graph(hosts)
        self.last_hosts = hosts
        self.statusBar().showMessage(
        f"Mise à jour en direct — {len(hosts)} appareils — rafraîchissement {self.live_interval.currentText()}")

    def _export_graph(self, index):
        if index == 0:
            return

        fmt = self.btn_export_graph.itemData(index)
        self.btn_export_graph.blockSignals(True)
        self.btn_export_graph.setCurrentIndex(0)
        self.btn_export_graph.blockSignals(False)
        if not hasattr(self, 'last_hosts') or not self.last_hosts:
            self.statusBar().showMessage("Aucune donnée de scan à exporter.")
            return

        if fmt == "csv":
            self._export_graph_csv()
        else:
            self._export_graph_png()

    def _export_graph_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter le graphe en CSV",
            "graph.csv",
            "Fichiers CSV (*.csv);;Tous les fichiers (*)"
        )
        if not path:
            return

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["ip", "mac", "vendor", "hostname"],
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(self.last_hosts)

        self.statusBar().showMessage(f"Graphe (CSV) exporté dans {path}")

    def _export_graph_png(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter le graphe en PNG",
            "graph.png",
            "Images PNG (*.png);;Tous les fichiers (*)"
        )
        if not path:
            return

        pixmap = self.graph_view.grab()
        pixmap.save(path, "PNG")
        self.statusBar().showMessage(f"Graphe (PNG) exporté vers {path}")

    def _on_graph_loaded(self, ok):
        self.graph_ready = True
        if hasattr(self, '_pending_graph_data'):
            self._update_graph(self._pending_graph_data)

    def _ta_send_to_scan(self, item):
        row = item.row()
        ipR = self.ta_table.item(row, 2).text()
        ip = ipR.split(" ")[0]
        self.scan_target.setText(ip)
        self.stack.setCurrentIndex(1)
        self._set_active_nav(1)

    def _export_ta_csv(self):
        if not self._ta_packets:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Exporter le trafic", "trafic.csv", "Fichiers CSV (*.csv);;Tous les fichiers (*)"
        )
        if not path:
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["n","time","src","dst","proto","port","size"])
            writer.writeheader()
            for p in self._ta_packets:
                writer.writerow({k: p[k] for k in ["n","time","src","dst","proto","port","size"]})
        self.statusBar().showMessage(f"Trafic exporté vers {path}")

    def _build_trafficAnalyzer_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        left = QWidget()
        left.setObjectName("sidePanel")
        left.setFixedWidth(230)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(8)

        dev_label = QLabel("Appareils vus")
        dev_label.setObjectName("sectionLabel")
        left_layout.addWidget(dev_label)

        self.ta_device_list = QTableWidget()
        self.ta_device_list.setColumnCount(2)
        self.ta_device_list.setHorizontalHeaderLabels(["IP", "PAQ."])
        self.ta_device_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.ta_device_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.ta_device_list.setColumnWidth(1, 50)
        self.ta_device_list.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ta_device_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ta_device_list.verticalHeader().setVisible(False)
        self.ta_device_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.ta_device_list.itemClicked.connect(self._ta_filter_by_device)
        left_layout.addWidget(self.ta_device_list, stretch=1)

        btn_clear_filter = QPushButton("Tout afficher")
        btn_clear_filter.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_clear_filter.clicked.connect(lambda: self._ta_apply_filter(""))
        left_layout.addWidget(btn_clear_filter)

        layout.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setSpacing(0)
        right_layout.setContentsMargins(0, 0, 0, 0)

        header = QWidget()
        header.setObjectName("pageHeader")
        header.setFixedHeight(52)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 0, 16, 0)

        header_label = QLabel("Trafic")
        header_label.setObjectName("pageTitle")
        header_layout.addWidget(header_label)
        header_layout.addStretch()

        self.btn_start_capture = QPushButton("Démarrer")
        self.btn_start_capture.setObjectName("primary")
        self.btn_start_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_start_capture.clicked.connect(self._ta_start)
        header_layout.addWidget(self.btn_start_capture)
        header_layout.addSpacing(8)

        self.btn_stop_capture = QPushButton("Arrêter")
        self.btn_stop_capture.setObjectName("danger")
        self.btn_stop_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_stop_capture.setEnabled(False)
        self.btn_stop_capture.clicked.connect(self._ta_stop)
        header_layout.addWidget(self.btn_stop_capture)
        header_layout.addSpacing(8)

        self.btn_clear_capture = QPushButton("Effacer")
        self.btn_clear_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_clear_capture.clicked.connect(self._ta_clear)
        header_layout.addWidget(self.btn_clear_capture)
        header_layout.addSpacing(8)

        self.btn_ta_export = QPushButton("Exporter CSV")
        self.btn_ta_export.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_ta_export.setEnabled(False)
        self.btn_ta_export.clicked.connect(self._export_ta_csv)
        header_layout.addWidget(self.btn_ta_export)
        right_layout.addWidget(header)

        filter_bar = QWidget()
        filter_bar.setObjectName("filterBar")
        filter_bar.setFixedHeight(56)
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(16, 0, 16, 0)

        filter_label = QLabel("Filtrer")
        filter_label.setObjectName("sectionLabel")
        filter_layout.addWidget(filter_label)
        filter_layout.addSpacing(8)

        self.ta_filter = QLineEdit()
        self.ta_filter.setPlaceholderText("IP, protocole, port ou nom d'hôte")
        self.ta_filter.textChanged.connect(self._ta_apply_filter)
        filter_layout.addWidget(self.ta_filter)
        right_layout.addWidget(filter_bar)

        self.ta_table = QTableWidget()
        self.ta_table.setColumnCount(7)
        self.ta_table.setHorizontalHeaderLabels([
            "#", "TEMPS", "SRC", "DST", "PROTO", "PORT", "TAILLE"
        ])
        self.ta_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.ta_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for col, w in [(0, 50), (1, 80), (4, 60), (5, 60), (6, 60)]:
            self.ta_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
            self.ta_table.setColumnWidth(col, w)
        self.ta_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ta_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ta_table.verticalHeader().setVisible(False)
        self.ta_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.ta_table.itemDoubleClicked.connect(self._ta_send_to_scan)
        self.ta_table.setAlternatingRowColors(True)
        self.ta_table.verticalHeader().setDefaultSectionSize(38)
        self.ta_table.setShowGrid(False)
        right_layout.addWidget(self.ta_table, stretch=1)

        self.ta_status = QLabel("Prêt. Démarrez une capture pour voir les flux. Un double-clic envoie l'adresse vers le scan de ports.")
        self.ta_status.setObjectName("statusStrip")
        right_layout.addWidget(self.ta_status)
        layout.addWidget(right, stretch=1)

        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}

        return page

    def _ta_start(self):
        iface = self.iface_selector.currentData()
        if not iface:
            return

        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}
        self._ta_data = []
        self.ta_table.setRowCount(0)
        self.ta_device_list.setRowCount(0)

        self.btn_start_capture.setEnabled(False)
        self.btn_stop_capture.setEnabled(True)
        self.ta_status.setText(f"Capture sur {iface['name']}…")
        self.ta_status.setStyleSheet("color: #7dffc3; background: transparent; font-size: 12px; padding: 10px 16px; border-top: 1px solid #143828;")

        self.ta_worker = TrafficWorker(iface["name"])
        self.ta_worker.packet_captured.connect(self._ta_on_packet)
        self.ta_worker.failed.connect(self._ta_on_failed)
        self.ta_worker.finished.connect(self._ta_on_finished)
        self.ta_worker.start()

    def _ta_stop(self):
        if hasattr(self, 'ta_worker') and self.ta_worker.isRunning():
            self.ta_worker.stop()
        self.btn_start_capture.setEnabled(True)
        self.btn_stop_capture.setEnabled(False)
        self.ta_status.setStyleSheet("color: #9dccb0; background: transparent; font-size: 12px; padding: 10px 16px; border-top: 1px solid #143828;")

    def _ta_clear(self):
        if hasattr(self, 'ta_worker') and self.ta_worker.isRunning():
            self.ta_worker.stop()
            self.btn_start_capture.setEnabled(True)
            self.btn_stop_capture.setEnabled(False)
        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}
        self._ta_data = []
        self.ta_table.setRowCount(0)
        self.ta_device_list.setRowCount(0)
        self.btn_ta_export.setEnabled(False)
        self.ta_status.setText("Effacé — appuyez sur Démarrer pour capturer")

    def _ta_on_packet(self, pkt: dict):
        if not hasattr(self, '_ta_packets'):
            return

        if self._ta_start_time is None:
            self._ta_start_time = time.time()

        elapsed = time.time() - self._ta_start_time
        self._ta_packet_count += 1

        src_label = self._resolve_ip_label(pkt["src"])
        dst_label = self._resolve_ip_label(pkt["dst"])

        packet_data = {
            "n": self._ta_packet_count,
            "time": f"{elapsed:.3f}s",
            "src": pkt["src"],
            "dst": pkt["dst"],
            "src_label": src_label,
            "dst_label": dst_label,
            "proto": pkt["proto"],
            "port": pkt["port"],
            "size": pkt["size"],
        }

        self._ta_packets.append(packet_data)

        for ip in [pkt["src"], pkt["dst"]]:
            if ip not in self._ta_device_stats:
                self._ta_device_stats[ip] = 0
            self._ta_device_stats[ip] += 1

        self._ta_add_row(packet_data)

        if self._ta_packet_count % 20 == 0 or self._ta_packet_count <= 5:
            self._ta_update_device_list()
            self.ta_status.setText(
                f"{self._ta_packet_count} paquets capturés — {elapsed:.1f} s"
            )
            if self._ta_packet_count > 0:
                self.btn_ta_export.setEnabled(True)

    def _resolve_ip_label(self, ip: str) -> str:
        if hasattr(self, 'last_hosts'):
            for h in self.last_hosts:
                if h["ip"] == ip:
                    hostname = h.get("hostname", ip)
                    if hostname != ip:
                        return f"{ip} ({hostname.split('.')[0]})"
        return ip

    def _ta_add_row(self, pkt: dict):
        proto_colors = {
            "TCP":  "#102433",
            "UDP":  "#0e2418",
            "ICMP": "#2a1418",
            "OTHER": "#101916",
        }
        bg = QColor(proto_colors.get(pkt["proto"], "#101916"))

        row = self.ta_table.rowCount()
        self.ta_table.insertRow(row)

        items = [
            str(pkt["n"]),
            pkt["time"],
            pkt["src_label"],
            pkt["dst_label"],
            pkt["proto"],
            pkt["port"],
            f"{pkt['size']}B",
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setBackground(bg)
            if col == 4:
                colors = {"TCP": "#4488ff", "UDP": "#44cc88", "ICMP": "#ff8844", "OTHER": "#8b9cb3"}
                item.setForeground(QColor(colors.get(pkt["proto"], "#8b9cb3")))
            self.ta_table.setItem(row, col, item)

        self.ta_table.scrollToBottom()

    def _ta_update_device_list(self):
        self.ta_device_list.setRowCount(0)
        sorted_devs = sorted(self._ta_device_stats.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_devs:
            row = self.ta_device_list.rowCount()
            self.ta_device_list.insertRow(row)
            label = self._resolve_ip_label(ip)
            self.ta_device_list.setItem(row, 0, QTableWidgetItem(label))
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ta_device_list.setItem(row, 1, count_item)

    def _ta_filter_by_device(self, item):
        row = item.row()
        ip_cell = self.ta_device_list.item(row, 0)
        if ip_cell:
            label = ip_cell.text()
            ip = label.split(" ")[0]
            self.ta_filter.setText(ip)

    def _ta_apply_filter(self, text):
        text = text.lower()
        for row in range(self.ta_table.rowCount()):
            visible = not text or any(
                text in (self.ta_table.item(row, col).text().lower() if self.ta_table.item(row, col) else "")
                for col in range(self.ta_table.columnCount())
            )
            self.ta_table.setRowHidden(row, not visible)
        visible_count = sum(
            1 for r in range(self.ta_table.rowCount())
            if not self.ta_table.isRowHidden(r)
        )
        if hasattr(self, '_ta_packet_count'):
            self.ta_status.setText(
                f"{visible_count} paquets affichés sur {self._ta_packet_count}"
                if text else
                f"{self._ta_packet_count} paquets capturés"
            )

    def _ta_on_failed(self, message: str):
        self.ta_status.setText(f"Capture impossible : {message}")

    def _ta_on_finished(self):
        self.btn_start_capture.setEnabled(True)
        self.btn_stop_capture.setEnabled(False)

    def _build_table(self):
        self.table = QTableWidget()
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_menu)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "FABRICANT", "HÔTE"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_device_selected)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.setShowGrid(False)
        return self.table

    def _show_menu(self, pos):
        item = self.table.itemAt(pos)

        if item is None:
            return

        row = item.row()
        ip = self.table.item(row,0).text()

        menu = QMenu()

        portScan_action = QAction("Envoyer vers le scan de ports", self)
        ta_action = QAction("Envoyer vers l'analyseur de trafic", self)
        as_action = QAction("Envoyer vers la surface d'attaque", self)

        portScan_action.triggered.connect(lambda: (self.stack.setCurrentIndex(1), self.scan_target.setText(ip), self._set_active_nav(1)))
        ta_action.triggered.connect(lambda: (self.stack.setCurrentIndex(4), self.ta_filter.setText(ip), self._set_active_nav(4)))
        as_action.triggered.connect(lambda: (self.stack.setCurrentIndex(3), self.as_target.setText(ip), self._set_active_nav(3)))

        menu.addAction(portScan_action)
        menu.addAction(as_action)
        menu.addAction(ta_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _build_detail_panel(self):
        self.detail_panel = QWidget()
        self.detail_panel.setObjectName("sidePanel")
        self.detail_panel.setMinimumWidth(300)
        layout = QVBoxLayout(self.detail_panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        self.detail_name = QLabel("Aucun appareil")
        self.detail_name.setObjectName("pageTitle")
        self.detail_name.setWordWrap(True)
        layout.addWidget(self.detail_name)

        self.detail_hint = QLabel("Sélectionnez une ligne pour voir son identité, puis lancer un ping, un traceroute ou un scan de ports.")
        self.detail_hint.setObjectName("emptyHint")
        self.detail_hint.setWordWrap(True)
        layout.addWidget(self.detail_hint)

        self.detail_ip = QLabel("IP  —")
        self.detail_mac = QLabel("MAC  —")
        self.detail_hostname = QLabel("Hôte  —")
        self.detail_vendor = QLabel("Fabricant  —")
        for label in [self.detail_ip, self.detail_mac, self.detail_hostname, self.detail_vendor]:
            label.setStyleSheet("color: #d8ffe8; font-size: 13px; background: transparent;")
            label.setWordWrap(True)
            label.hide()
            layout.addWidget(label)

        layout.addSpacing(6)
        self.detail_actions = QWidget()
        actions = QHBoxLayout(self.detail_actions)
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(8)
        self.btn_ping = QPushButton("Ping")
        self.btn_portscan = QPushButton("Ports")
        self.btn_traceroute = QPushButton("Traceroute")
        self.btn_ping.clicked.connect(self._run_ping)
        self.btn_traceroute.clicked.connect(self._run_traceroute)
        self.btn_portscan.clicked.connect(self._go_to_scan)
        for btn in [self.btn_ping, self.btn_portscan, self.btn_traceroute]:
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            actions.addWidget(btn)
        self.detail_actions.hide()
        layout.addWidget(self.detail_actions)

        self.output_box = QTextEdit()
        self.output_box.setObjectName("mono")
        self.output_box.setReadOnly(True)
        self.output_box.setPlaceholderText("Le résultat du ping ou du traceroute s'affiche ici.")
        self.output_box.hide()
        layout.addWidget(self.output_box, stretch=1)
        return self.detail_panel

    def _on_device_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            return

        row = self.table.currentRow()
        ip       = self.table.item(row, 0).text()
        mac      = self.table.item(row, 1).text()
        vendor   = self.table.item(row, 2).text()
        hostname = self.table.item(row, 3).text()

        visible_name = hostname if hostname and hostname != ip else ip
        self.detail_name.setText(visible_name)
        self.detail_hint.hide()
        self.detail_ip.setText(f"IP  {ip}")
        self.detail_mac.setText(f"MAC  {mac}")
        self.detail_hostname.setText(f"Hôte  {hostname or '—'}")
        self.detail_vendor.setText(f"Fabricant  {vendor or '—'}")
        for label in [self.detail_ip, self.detail_mac, self.detail_hostname, self.detail_vendor]:
            label.show()
        self.detail_actions.show()
        self.output_box.show()

    def _start_scan(self):
        target = self._resolve_subnet()
        if not target:
            self.statusBar().showMessage("Aucun sous-réseau disponible — choisissez une interface avec une IP ou saisissez-en une.")
            return

        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scan…")
        self._go_page(0)
        self.btn_export_graph.setEnabled(False)
        self.table.setRowCount(0)
        self.home_empty.setText("Scan en cours…")
        self.home_stack.setCurrentIndex(0)
        self.home_count.setText(target)
        self.subnet_label.setText(target)

        if is_target_fully_local(target):
            self.statusBar().showMessage("Scan en cours...")
            self.worker = ScanWorker(target)
        else:
            self.statusBar().showMessage("Scan d'une plage routée (cartographie par traceroute)...")
            self.worker = RangeScanWorker(target)
        self.worker.failed.connect(self._on_scan_failed)
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.start()

    def _as_card(self, widget):
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(widget)
        return frame

    def _populate_table(self, hosts, flags=None):
        flags = flags or {}
        self.table.setRowCount(0)
        for d in hosts:
            row = self.table.rowCount()
            self.table.insertRow(row)
            cells = [
                QTableWidgetItem(str(d.get("ip") or "")),
                QTableWidgetItem(str(d.get("mac") or "")),
                QTableWidgetItem(str(d.get("vendor") or "")),
                QTableWidgetItem(str(d.get("hostname") or "")),
            ]
            level = flags.get(d.get("ip"))
            bg = None
            if level == "critical":
                bg = QColor("#3a1518")
            elif level == "warning":
                bg = QColor("#2a2410")
            for col, cell in enumerate(cells):
                if bg is not None:
                    cell.setBackground(bg)
                self.table.setItem(row, col, cell)

    def _on_scan_failed(self, message: str):
        self.scan_button.setEnabled(True)
        self.scan_button.setText("Scanner")
        self.home_empty.setText("Le scan n'a pas abouti.\nChoisissez une cible, puis lancez Scanner.")
        self.home_stack.setCurrentIndex(0)
        self.statusBar().showMessage(f"Scan interrompu : {message}")

    def _on_scan_finished(self, hosts):
        diff = self._record_scan(hosts, source="gui")
        self._populate_table(hosts, self._row_flags(diff))
        self.last_hosts = hosts
        note = summary_text(diff)
        count = len(hosts)
        label = f"{count} appareil" if count == 1 else f"{count} appareils"
        self.home_count.setText(label)
        if count:
            self.home_stack.setCurrentIndex(1)
        else:
            self.home_empty.setText("Aucun appareil trouvé sur cette cible.")
            self.home_stack.setCurrentIndex(0)
        self.statusBar().showMessage(f"{label}. {note}")
        self.scan_button.setEnabled(True)
        self.scan_button.setText("Scanner")
        self._update_graph(hosts)
        self.btn_export_graph.setDisabled(False)
        self._apply_diff_banner(diff)
        self._reload_journal(select_latest=True)

    def _build_topology(self, hosts: list) -> dict:
        subnet_str = self._resolve_subnet()

        gateway_ip = None
        gateway_candidates = []

        for host in hosts:
            ip = host.get("ip", "")
            hostname = (host.get("hostname") or "").lower()
            vendor = (host.get("vendor") or "").lower()
            if hostname in ("router", "gateway", "_gateway", "default-gateway"):
                gateway_ip = ip
                break
            if ip.endswith(".1") or ip.endswith(".254"):
                gateway_candidates.insert(0, ip) if ip.endswith(".1") else gateway_candidates.append(ip)

        if not gateway_ip and gateway_candidates:
            gateway_ip = gateway_candidates[0]

        subnets_map = {}
        if subnet_str:
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
                subnets_map[subnet_str] = {
                    "network": subnet_str,
                    "prefix": str(net.prefixlen),
                    "broadcast": str(net.broadcast_address),
                    "devices": [],
                }
            except Exception:
                pass

        for host in hosts:
            ip = host.get("ip", "")
            placed = False
            for snet_str, snet_data in subnets_map.items():
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(snet_str, strict=False):
                        snet_data["devices"].append(ip)
                        placed = True
                        break
                except Exception:
                    pass
            if not placed and subnets_map:
                list(subnets_map.values())[0]["devices"].append(ip)

        intermediate_vendors = [
            "cisco", "mikrotik", "ubiquiti", "tp-link", "netgear", "dlink",
            "linksys", "tenda", "zyxel", "aruba", "juniper", "fortinet",
            "ruckus", "meraki", "extreme", "huawei", "h3c", "brocade",
        ]
        intermediate_hostnames = [
            "router", "ap", "wifi", "switch", "hub", "access-point",
            "access_point", "wlan", "gateway", "firewall", "proxy",
        ]

        intermediate_ips = set()
        for host in hosts:
            ip = host.get("ip", "")
            if ip == gateway_ip:
                continue
            vendor = (host.get("vendor") or "").lower()
            hostname = (host.get("hostname") or "").lower()
            if any(k in vendor for k in intermediate_vendors):
                intermediate_ips.add(ip)
                continue
            if any(k in hostname for k in intermediate_hostnames):
                intermediate_ips.add(ip)

        edges = []
        if gateway_ip:
            edges.append({"src": gateway_ip, "dst": "internet", "type": "uplink"})

        for host in hosts:
            ip = host.get("ip", "")
            if ip == gateway_ip:
                continue
            if host.get("router_hop"):
                continue
            if not gateway_ip:
                continue
            if ip in intermediate_ips:
                edges.append({"src": ip, "dst": gateway_ip, "type": "backbone"})
            else:
                parent = gateway_ip
                for inter_ip in intermediate_ips:
                    inter_host = next((h for h in hosts if h.get("ip") == inter_ip), None)
                    if not inter_host:
                        continue
                    inter_vendor = (inter_host.get("vendor") or "").lower()
                    inter_hostname = (inter_host.get("hostname") or "").lower()
                    if any(k in inter_vendor for k in ["tp-link", "netgear", "dlink", "linksys",
                                                        "tenda", "zyxel", "aruba", "ubiquiti",
                                                        "ruckus", "meraki"]) or                        any(k in inter_hostname for k in ["ap", "wifi", "wlan", "access"]):
                        try:
                            host_net = ipaddress.ip_address(ip)
                            inter_net = ipaddress.ip_address(inter_ip)
                            host_parts = str(host_net).split(".")
                            inter_parts = str(inter_net).split(".")
                            if host_parts[:3] == inter_parts[:3]:
                                parent = inter_ip
                                break
                        except Exception:
                            pass
                edges.append({"src": ip, "dst": parent, "type": "client"})

        router_hosts = {}
        seen_router_edges = set()
        existing_ips = {h.get("ip") for h in hosts}

        for host in hosts:
            hop = host.get("router_hop")
            host_ip = host.get("ip")
            if not hop or hop == host_ip:
                continue
            if hop not in existing_ips and hop not in router_hosts:
                router_hosts[hop] = {
                    "ip": hop,
                    "mac": "",
                    "hostname": hop,
                    "vendor": "",
                    "ttl": None,
                    "os_hint": "unknown",
                    "open_ports": [],
                    "role": "router",
                    "snmp_desc": "",
                    "embedded_device": "",
                }
            parent = gateway_ip or "internet"
            if (hop, parent) not in seen_router_edges:
                edges.append({"src": hop, "dst": parent, "type": "backbone"})
                seen_router_edges.add((hop, parent))
            if (host_ip, hop) not in seen_router_edges:
                edges.append({"src": host_ip, "dst": hop, "type": "client"})
                seen_router_edges.add((host_ip, hop))

        devices = list(hosts)
        try:
            from core.cloud import list_assets
            assets = list_assets()
        except Exception:
            assets = []
        if assets:
            cloud_net = {"network": "cloud", "prefix": "", "broadcast": "", "devices": []}
            for asset in assets:
                address = asset.get("address") or ""
                if not address:
                    continue
                devices.append({
                    "ip": address,
                    "mac": "",
                    "hostname": asset.get("name") or address,
                    "vendor": (asset.get("provider") or "cloud").upper(),
                    "ttl": None,
                    "os_hint": "unknown",
                    "open_ports": [],
                    "role": "vm",
                    "snmp_desc": asset.get("region") or "",
                    "embedded_device": "",
                })
                cloud_net["devices"].append(address)
                if gateway_ip:
                    edges.append({"src": address, "dst": gateway_ip, "type": "uplink"})
            subnets_map["cloud"] = cloud_net

        return {
            "devices": devices + list(router_hosts.values()),
            "gateway": gateway_ip,
            "subnet": subnet_str,
            "subnets": list(subnets_map.values()),
            "edges": edges,
            "intermediates": list(intermediate_ips),
        }

    def _update_graph(self, hosts):
        if not hasattr(self, 'graph_view'):
            return
        self._pending_graph_data = hosts
        if not self.graph_ready:
            return
        topology = self._build_topology(hosts)
        self.graph_view.page().runJavaScript("updateGraph(" + json.dumps(topology) + ")")

    def _go_to_scan(self):
        self._set_active_nav(1)
        row = self.table.currentRow()
        if row < 0:
            return
        self.current_target_ip = self.table.item(row, 0).text()
        self.scan_target.setText(self.current_target_ip)
        self.stack.setCurrentIndex(1)

    def _run_ping(self):
        row = self.table.currentRow()
        if row < 0:
            return
        ip = self.table.item(row, 0).text()

        self.output_box.clear()
        self.output_box.append(f"ping {ip}\n")

        if platform.system() == "Windows":
            cmd = ["ping", "-n", "4", ip]
        else:
            cmd = ["ping", "-c", "4", ip]

        self.action_worker = ActionWorker(cmd)
        self.action_worker.output.connect(self.output_box.append)
        self.action_worker.finished.connect(
            lambda: self.output_box.append("\nTerminé.")
        )
        self.action_worker.start()

    def _run_traceroute(self):
        row = self.table.currentRow()
        if row < 0:
            return
        ip = self.table.item(row, 0).text()

        self.output_box.clear()
        self.output_box.append(f"traceroute {ip}\n")

        self.btn_traceroute.setText("Arrêter")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._stop_action)

        if platform.system() == "Windows":
            cmd = ["tracert", ip]
        else:
            cmd = ["traceroute", "-I", ip]

        self.action_worker = ActionWorker(cmd)
        self.action_worker.output.connect(self.output_box.append)
        self.action_worker.finished.connect(self._on_action_finished)
        self.action_worker.start()

    def _stop_action(self):
        if hasattr(self, 'action_worker') and self.action_worker.isRunning():
            self.action_worker.finished.disconnect()
            self.action_worker.terminate()
        self.output_box.append("\nInterrompu.")
        self.btn_traceroute.setText("Traceroute")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._run_traceroute)

    def _on_action_finished(self):
        self.output_box.append("\nTerminé.")
        self.btn_traceroute.setText("Traceroute")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._run_traceroute)

    def _build_attackSurface_page(self):
        self.scanning = False
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        left = QWidget()
        left.setObjectName("sidePanel")
        left.setFixedWidth(260)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(14, 14, 14, 14)
        left_layout.setSpacing(8)

        as_label = QLabel("Cible")
        as_label.setObjectName("sectionLabel")
        left_layout.addWidget(as_label)

        self.as_target = QLineEdit()
        self.as_target.setObjectName("mono")
        self.as_target.setPlaceholderText("IP, réseau ou nom d'hôte")
        left_layout.addWidget(self.as_target)

        self.as_scan_btn = QPushButton("Analyser")
        self.as_scan_btn.setObjectName("primary")
        self.as_scan_btn.setDisabled(True)
        self.as_scan_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_scan_btn.clicked.connect(self._as_start_scan)
        left_layout.addWidget(self.as_scan_btn)

        self.as_audit_btn = QPushButton("Contrôle de configuration")
        self.as_audit_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_audit_btn.setToolTip("TLS, certificat et services exposés. Aucun essai de mot de passe.")
        self.as_audit_btn.clicked.connect(self._run_config_audit)
        left_layout.addWidget(self.as_audit_btn)

        def _on_as_target_changed(text):
            valid = is_valid_target(text)
            self.as_scan_btn.setDisabled(not valid or self.scanning)
            state = "valid" if text and valid else ("invalid" if text else "")
            self.as_target.setProperty("state", state)
            self.as_target.style().unpolish(self.as_target)
            self.as_target.style().polish(self.as_target)

        self.as_target.textChanged.connect(_on_as_target_changed)

        self.as_export_btn = QPushButton("Exporter CSV")
        self.as_export_btn.setDisabled(True)
        self.as_export_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_export_btn.clicked.connect(self._as_export_csv)
        left_layout.addWidget(self.as_export_btn)

        self.as_progress_bar = QProgressBar()
        self.as_progress_bar.setRange(0, 100)
        self.as_progress_bar.setValue(0)
        self.as_progress_bar.setTextVisible(True)
        self.as_progress_bar.setFormat("%p%")
        self.as_progress_bar.setFixedHeight(18)
        self.as_progress_bar.setVisible(False)
        left_layout.addWidget(self.as_progress_bar)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #143828; margin-top: 4px; margin-bottom: 4px;")
        left_layout.addWidget(sep)

        history_label = QLabel("Déjà analysé")
        history_label.setObjectName("sectionLabel")
        left_layout.addWidget(history_label)

        self.as_history = QTableWidget()
        self.as_history.setColumnCount(2)
        self.as_history.setHorizontalHeaderLabels(["CIBLE", "RISQUE"])
        self.as_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.as_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_history.setColumnWidth(1, 90)
        self.as_history.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_history.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_history.verticalHeader().setVisible(False)
        self.as_history.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_history.itemClicked.connect(self._as_load_from_history)
        self.as_history.setShowGrid(False)
        left_layout.addWidget(self.as_history, stretch=1)

        self._as_results = {}
        layout.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self.as_header = QLabel("Surface d'attaque")
        self.as_header.setObjectName("pageTitle")
        self.as_header.setFixedHeight(52)
        self.as_header.setStyleSheet("background: transparent; color: #e7fff2; font-size: 18px; font-weight: 700; padding: 12px 16px;")
        right_layout.addWidget(self.as_header)

        splitter = QSplitter(Qt.Orientation.Vertical)

        ports_container = QWidget()
        ports_layout = QVBoxLayout(ports_container)
        ports_layout.setContentsMargins(0, 0, 0, 0)
        ports_layout.setSpacing(0)

        ports_label = QLabel("Ports ouverts")
        ports_label.setObjectName("sectionLabel")
        ports_label.setFixedHeight(32)
        ports_label.setStyleSheet("color: #9dccb0; background: transparent; padding: 8px 16px;")
        ports_layout.addWidget(ports_label)

        self.as_ports_table = QTableWidget()
        self.as_ports_table.setColumnCount(5)
        self.as_ports_table.setHorizontalHeaderLabels(["PORT", "PROTO", "SERVICE", "VERSION", "RISQUE"])
        self.as_ports_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(0, 70)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(1, 60)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(2, 100)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(4, 100)
        self.as_ports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_ports_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_ports_table.verticalHeader().setVisible(False)
        self.as_ports_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        ports_layout.addWidget(self.as_ports_table)
        splitter.addWidget(ports_container)

        cve_container = QWidget()
        cve_layout = QVBoxLayout(cve_container)
        cve_layout.setContentsMargins(0, 0, 0, 0)
        cve_layout.setSpacing(0)

        cve_label = QLabel("Vulnérabilités")
        cve_label.setObjectName("sectionLabel")
        cve_label.setFixedHeight(32)
        cve_label.setStyleSheet("color: #9dccb0; background: transparent; padding: 8px 16px;")
        cve_layout.addWidget(cve_label)

        self.as_cve_table = QTableWidget()
        self.as_cve_table.setColumnCount(5)
        self.as_cve_table.setHorizontalHeaderLabels(["ID CVE", "CVSS", "PORT", "SERVICE", "DÉTAIL"])
        self.as_cve_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(0, 140)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(1, 60)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(2, 60)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(3, 100)
        self.as_cve_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_cve_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_cve_table.verticalHeader().setVisible(False)
        self.as_cve_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_cve_table.itemDoubleClicked.connect(self._as_open_cve)
        cve_layout.addWidget(self.as_cve_table)
        splitter.addWidget(cve_container)

        splitter.setSizes([300, 200])
        right_layout.addWidget(splitter, stretch=1)

        self.audit_view = QTextEdit()
        self.audit_view.setObjectName("mono")
        self.audit_view.setReadOnly(True)
        self.audit_view.setFixedHeight(96)
        self.audit_view.setPlaceholderText("Le contrôle de configuration s'affiche ici. Aucun mot de passe n'est essayé.")
        right_layout.addWidget(self.audit_view)

        self.as_status = QLabel("Saisissez une cible. Un double-clic sur une CVE ouvre sa fiche.")
        self.as_status.setObjectName("statusStrip")
        right_layout.addWidget(self.as_status)
        layout.addWidget(right, stretch=1)
        return page

    def _as_export_csv(self):
        target = self.as_target.text().strip()
        if not target or target not in self._as_results:
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exporter la surface d'attaque",
            f"attack_surface_{target.replace('.', '_')}.csv",
            "Fichiers CSV (*.csv);;Tous les fichiers (*)"
        )
        if not path:
            return

        result = self._as_results[target]

        with open(path, "w", newline="") as f:
            writer = csv.writer(f)

            writer.writerow(["CIBLE", "OS", "NB_PORTS", "NB_CVE"])
            writer.writerow([
                result["target"],
                result["os"],
                len(result["ports"]),
                len(result["cves"])
            ])
            writer.writerow([])

            writer.writerow(["=== PORTS OUVERTS ==="])
            writer.writerow(["PORT", "PROTOCOLE", "SERVICE", "VERSION", "RISQUE"])
            for p in result["ports"]:
                writer.writerow([p["port"], p["protocol"], p["service"], p["version"], p["risk"]])
            writer.writerow([])

            writer.writerow(["=== VULNÉRABILITÉS / CVE ==="])
            writer.writerow(["ID_CVE", "CVSS", "PORT", "SERVICE", "DETAIL"])
            for c in result["cves"]:
                writer.writerow([c["id"], c["cvss"], c["port"], c["service"], c["detail"]])

        self.statusBar().showMessage(f"Surface d'attaque exportée vers {path}")

    def _as_start_scan(self):
        target = self.as_target.text().strip()
        if not target or not is_valid_target(target):
            self.as_status.setText("Cible invalide — utilisez une IP, un CIDR ou un nom d'hôte.")
            self.as_status.setStyleSheet("color: #ff8b98; background: transparent; font-size: 12px; padding: 10px 16px; border-top: 1px solid #143828;")
            return
        self.scanning = True
        self.as_target.setDisabled(True)
        self.as_scan_btn.setEnabled(False)
        self.as_scan_btn.setText("Analyse…")
        self.as_ports_table.setRowCount(0)
        self.as_cve_table.setRowCount(0)
        self.as_status.setText(f"Analyse de {target}…")
        self.as_status.setStyleSheet("color: #7dffc3; background: transparent; font-size: 12px; padding: 10px 16px; border-top: 1px solid #143828;")
        self.as_progress_bar.setValue(0)
        self.as_progress_bar.setVisible(True)
        def _tick():
            v = self.as_progress_bar.value()
            if v < 94:
                remaining = 94 - v
                step = max(1, remaining // 12)
                self.as_progress_bar.setValue(v + step)
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(2000)
        self._progress_timer.timeout.connect(_tick)
        self._progress_timer.start()
        self.as_worker = AttackSurfaceWorker(target)
        self.as_worker.status_update.connect(self.as_status.setText)
        self.as_worker.port_found.connect(self._as_add_port_realtime)
        self.as_worker.finished.connect(self._as_on_finished)
        self.as_worker.start()

    def _as_add_port_realtime(self, port: dict):
        risk_colors = {"CRITICAL":"#ff0000","HIGH": "#ff4444", "MEDIUM": "#ff9900", "LOW": "#7dffc3"}
        row = self.as_ports_table.rowCount()
        self.as_ports_table.insertRow(row)
        self.as_ports_table.setItem(row, 0, QTableWidgetItem(port["port"]))
        self.as_ports_table.setItem(row, 1, QTableWidgetItem(port["protocol"]))
        self.as_ports_table.setItem(row, 2, QTableWidgetItem(port["service"]))
        self.as_ports_table.setItem(row, 3, QTableWidgetItem(port["version"]))
        risk_item = QTableWidgetItem(RISK_FR.get(port["risk"], port["risk"]))
        risk_item.setForeground(QColor(risk_colors.get(port["risk"], "#9dccb0")))
        self.as_ports_table.setItem(row, 4, risk_item)

    def _as_on_finished(self, result: dict):
        if hasattr(self, '_progress_timer'):
            self._progress_timer.stop()
        self.as_progress_bar.setValue(100)

        self.scanning = False
        self.as_target.setDisabled(False)
        self.as_scan_btn.setEnabled(True)
        self.as_scan_btn.setText("Analyser")

        QTimer.singleShot(700, lambda: self.as_progress_bar.setVisible(False))

        self.as_ports_table.setRowCount(0)
        target = result["target"]
        self._as_results[target] = result
        self._as_display(result)
        self._as_update_history(target, result)
        self.as_export_btn.setEnabled(True)

    def _as_display(self, result: dict):
        target = result["target"]
        os_info = result["os"]
        port_count = len(result["ports"])
        cve_count = len(result["cves"])

        self.as_header.setText(
            f"{target}  —  OS : {os_info}  —  {port_count} ports  —  {cve_count} CVE"
        )
        self.as_header.setStyleSheet("background: transparent; color: #e7fff2; font-size: 15px; font-weight: 700; padding: 12px 16px;")

        risk_colors = {"CRITICAL":"#ff2222","HIGH": "#ff4444", "MEDIUM": "#ff9900", "LOW": "#7dffc3"}
        self.as_ports_table.setRowCount(0)
        for p in result["ports"]:
            row = self.as_ports_table.rowCount()
            self.as_ports_table.insertRow(row)
            self.as_ports_table.setItem(row, 0, QTableWidgetItem(p["port"]))
            self.as_ports_table.setItem(row, 1, QTableWidgetItem(p["protocol"]))
            self.as_ports_table.setItem(row, 2, QTableWidgetItem(p["service"]))
            self.as_ports_table.setItem(row, 3, QTableWidgetItem(p["version"]))
            risk_item = QTableWidgetItem(RISK_FR.get(p["risk"], p["risk"]))
            risk_item.setForeground(QColor(risk_colors.get(p["risk"], "#9dccb0")))
            self.as_ports_table.setItem(row, 4, risk_item)

        self.as_cve_table.setRowCount(0)
        for c in result["cves"]:
            row = self.as_cve_table.rowCount()
            self.as_cve_table.insertRow(row)
            cve_item = QTableWidgetItem(c["id"])
            cve_item.setForeground(QColor("#4488ff"))
            cve_item.setData(Qt.ItemDataRole.UserRole, f"https://nvd.nist.gov/vuln/detail/{c['id']}")
            self.as_cve_table.setItem(row,0,cve_item)
            cvss = c["cvss"]
            cvss_item = QTableWidgetItem(str(cvss))
            if cvss >= 9.0:
                cvss_item.setForeground(QColor("#ff2222"))
            elif cvss >= 7.0:
                cvss_item.setForeground(QColor("#ff6600"))
            elif cvss >= 4.0:
                cvss_item.setForeground(QColor("#ffaa00"))
            else:
                cvss_item.setForeground(QColor("#8b9cb3"))
            self.as_cve_table.setItem(row, 1, cvss_item)
            self.as_cve_table.setItem(row, 2, QTableWidgetItem(c["port"]))
            self.as_cve_table.setItem(row, 3, QTableWidgetItem(c["service"]))
            self.as_cve_table.setItem(row, 4, QTableWidgetItem(c["detail"]))

        if result["cves"]:
            max_cvss = result["cves"][0]["cvss"]
            if max_cvss >= 9.0:
                risk_summary = "CRITICAL"
                color = "#ff2222"
            elif max_cvss >= 7.0:
                risk_summary = "HIGH"
                color = "#ff6600"
            elif max_cvss >= 4.0:
                risk_summary = "MEDIUM"
                color = "#ffaa00"
            else:
                risk_summary = "LOW"
                color = "#7dffc3"
        elif result["ports"]:
            high_ports = [p for p in result["ports"] if p["risk"] == "HIGH"]
            risk_summary = "HIGH" if high_ports else "LOW"
            color = "#ff4444" if high_ports else "#7dffc3"
        else:
            risk_summary = "CLEAN"
            color = "#7dffc3"

        self.as_status.setText(f"Analyse terminée — risque max. : {RISK_FR.get(risk_summary, risk_summary)}")
        self.as_status.setStyleSheet(
            f"color: {color}; background: transparent; font-size: 12px; padding: 10px 16px; border-top: 1px solid #143828;"
        )

    def _as_open_cve(self, item):
        if item.column() != 0:
            return
        url = item.data(Qt.ItemDataRole.UserRole)
        if not url:
            return

        if platform.system() == "Windows":
            os.startfile(url)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            original_user = os.environ.get('SUDO_USER')
            if original_user:
                subprocess.Popen(
                    ["sudo", "-u", original_user, "xdg-open", url],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                QDesktopServices.openUrl(QtUrl(url))

    def _as_update_history(self, target: str, result: dict):
        for row in range(self.as_history.rowCount()):
            if self.as_history.item(row, 0).text() == target:
                self.as_history.removeRow(row)
                break

        row = 0
        self.as_history.insertRow(row)
        self.as_history.setItem(row, 0, QTableWidgetItem(target))

        if result["cves"]:
            max_cvss = result["cves"][0]["cvss"]
            risk = "CRIT." if max_cvss >= 9 else "ÉLEV." if max_cvss >= 7 else "MOY."
            color = "#ff2222" if max_cvss >= 9 else "#ff6600" if max_cvss >= 7 else "#ffaa00"
        elif any(p["risk"] == "HIGH" for p in result["ports"]):
            risk, color = "ÉLEV.", "#ff4444"
        else:
            risk, color = "FAIB.", "#7dffc3"

        risk_item = QTableWidgetItem(risk)
        risk_item.setForeground(QColor(color))
        risk_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.as_history.setItem(row, 1, risk_item)

    def _build_diff_banner(self):
        bar = QWidget()
        bar.setObjectName("diffBanner")
        bar.setFixedHeight(44)
        bar.hide()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 12, 0)
        self.diff_banner_label = QLabel("")
        self.diff_banner_label.setStyleSheet("font-weight: 600;")
        self.diff_banner_btn = QPushButton("Voir le journal")
        self.diff_banner_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.diff_banner_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.diff_banner_btn.clicked.connect(lambda: self._go_page(5))
        layout.addWidget(self.diff_banner_label, stretch=1)
        layout.addWidget(self.diff_banner_btn)
        self.diff_banner = bar
        return bar

    def _apply_diff_banner(self, diff):
        self._latest_diff = diff
        if not diff:
            self.diff_banner.hide()
            return
        summary = diff.get("summary") or {}
        events = diff.get("events") or []
        if summary.get("critical"):
            bg, fg, border = "#3a1518", "#ffb4bc", "#ff6b7a"
        elif summary.get("alerts"):
            bg, fg, border = "#2a2410", "#ffe0a3", "#e6c35c"
        elif events:
            bg, fg, border = "#0c1c14", "#d8ffe8", "#1c4a34"
        elif diff.get("has_baseline"):
            bg, fg, border = "#0e2418", "#7dffc3", "#00c26e"
        else:
            bg, fg, border = "#0c1c14", "#d8ffe8", "#1c4a34"
        self.diff_banner.setStyleSheet(
            f"QWidget#diffBanner {{ background: {bg}; border: 1px solid {border}; border-radius: 12px; }}"
            f"QLabel {{ color: {fg}; background: transparent; }}"
            "QPushButton { background: transparent; color: #e7fff2; border: 1px solid #2d8a5e;"
            " border-radius: 8px; padding: 4px 10px; }"
            "QPushButton:hover { border-color: #00ff99; color: #00ff99; }"
        )
        self.diff_banner_label.setText(summary_text(diff))
        self.diff_banner.show()

    def _restore_last_inventory(self):
        scans = self.store.list_scans(limit=1)
        if not scans:
            return
        scan = scans[0]
        hosts = self.store.hosts_of(scan["id"])
        if scan.get("subnet"):
            self.subnet_label.setText(scan["subnet"])
        if not hosts:
            return
        self._populate_table(hosts, self._row_flags(self.store.get_diff(scan["id"])))
        self.last_hosts = hosts
        self._update_graph(hosts)
        self.home_stack.setCurrentIndex(1)
        count = len(hosts)
        self.home_count.setText(f"{count} appareil" if count == 1 else f"{count} appareils")
        self.btn_export_graph.setEnabled(True)

    def _record_scan(self, hosts, source="gui"):
        try:
            subnet = self._resolve_subnet() or ""
            gateway = None
            try:
                gateway = get_default_gateway()
            except Exception:
                gateway = None
            scan_id = self.store.save_scan(hosts, subnet=subnet, gateway=gateway, source=source)
            import threading
            from core.followup import publish
            threading.Thread(target=publish, args=(self.store, scan_id), daemon=True).start()
            return self.store.get_diff(scan_id)
        except Exception as exc:
            self.statusBar().showMessage(f"Historique non enregistré : {exc}")
            return None

    def _row_flags(self, diff):
        flags = {}
        rank = {"info": 0, "warning": 1, "critical": 2}
        if not diff:
            return flags
        for event in diff.get("events") or []:
            ip = event.get("ip")
            if not ip or event.get("kind") == "departed":
                continue
            current = flags.get(ip)
            if current is None or rank[event["severity"]] > rank[current]:
                flags[ip] = event["severity"]
        return flags

    def _build_journal_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        title = QLabel("Journal des écarts")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Chaque scan est conservé et comparé au relevé précédent du même sous-réseau.")
        subtitle.setObjectName("emptyHint")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        self.journal_summary = QLabel("Aucun relevé pour l'instant.")
        self.journal_summary.setWordWrap(True)
        self.journal_summary.setStyleSheet("color: #d8ffe8; font-size: 14px; background: transparent;")
        layout.addWidget(self.journal_summary)

        body = QSplitter(Qt.Orientation.Horizontal)
        self.journal_scans = QTableWidget()
        self.journal_scans.setColumnCount(4)
        self.journal_scans.setHorizontalHeaderLabels(["DATE", "CIBLE", "HÔTES", "ALERTES"])
        header = self.journal_scans.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.journal_scans.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.journal_scans.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.journal_scans.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.journal_scans.verticalHeader().setVisible(False)
        self.journal_scans.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.journal_scans.setAlternatingRowColors(True)
        self.journal_scans.setShowGrid(False)
        self.journal_scans.verticalHeader().setDefaultSectionSize(40)
        self.journal_scans.itemSelectionChanged.connect(self._on_journal_selected)

        self.journal_events = QTableWidget()
        self.journal_events.setColumnCount(4)
        self.journal_events.setHorizontalHeaderLabels(["GRAVITÉ", "TYPE", "HÔTE", "DÉTAIL"])
        event_header = self.journal_events.horizontalHeader()
        event_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        event_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        event_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        event_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.journal_events.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.journal_events.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.journal_events.verticalHeader().setVisible(False)
        self.journal_events.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.journal_events.setAlternatingRowColors(True)
        self.journal_events.setShowGrid(False)
        self.journal_events.verticalHeader().setDefaultSectionSize(40)

        body.addWidget(self.journal_scans)
        body.addWidget(self.journal_events)
        body.setSizes([420, 760])
        layout.addWidget(body, stretch=1)
        return page

    def _reload_journal(self, select_latest=False):
        if not hasattr(self, "journal_scans"):
            return
        selected = None
        current = self.journal_scans.currentRow()
        if current >= 0:
            item = self.journal_scans.item(current, 0)
            if item is not None:
                selected = item.data(Qt.ItemDataRole.UserRole)
        scans = self.store.list_scans()
        self.journal_scans.blockSignals(True)
        self.journal_scans.setRowCount(0)
        for scan in scans:
            row = self.journal_scans.rowCount()
            self.journal_scans.insertRow(row)
            values = [
                format_when(scan["created_at"]),
                scan["subnet"] or "—",
                str(scan["host_count"]),
                str(scan["alert_count"]),
            ]
            for col, text in enumerate(values):
                cell = QTableWidgetItem(text)
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, scan["id"])
                if scan["critical_count"]:
                    cell.setForeground(QColor("#ff8b98"))
                elif scan["alert_count"]:
                    cell.setForeground(QColor("#ffe0a3"))
                self.journal_scans.setItem(row, col, cell)
        self.journal_scans.blockSignals(False)
        if not scans:
            self.journal_events.setRowCount(0)
            self.journal_summary.setText("Aucun relevé pour l'instant. Lancez un scan depuis l'accueil.")
            return
        target_row = 0 if select_latest or selected is None else 0
        if selected is not None and not select_latest:
            for row in range(self.journal_scans.rowCount()):
                if self.journal_scans.item(row, 0).data(Qt.ItemDataRole.UserRole) == selected:
                    target_row = row
                    break
        self.journal_scans.selectRow(target_row)
        self._show_journal_diff(scans[0]["id"] if target_row == 0 else self.journal_scans.item(target_row, 0).data(Qt.ItemDataRole.UserRole))

    def _on_journal_selected(self):
        row = self.journal_scans.currentRow()
        if row < 0:
            return
        item = self.journal_scans.item(row, 0)
        if item is None:
            return
        self._show_journal_diff(item.data(Qt.ItemDataRole.UserRole))

    def _show_journal_diff(self, scan_id):
        kind_fr = {
            "new_asset": "Nouvel appareil",
            "departed": "Disparu",
            "ip_changed": "Changement d'IP",
            "mac_changed": "Changement de MAC",
            "port_opened": "Port ouvert",
            "port_closed": "Port fermé",
        }
        severity_fr = {"critical": "Critique", "warning": "Attention", "info": "Info"}
        colors = {"critical": "#ff8b98", "warning": "#ffe0a3", "info": "#9dccb0"}
        diff = self.store.get_diff(scan_id) if scan_id else None
        self.journal_summary.setText(summary_text(diff))
        self.journal_events.setRowCount(0)
        for event in (diff or {}).get("events") or []:
            row = self.journal_events.rowCount()
            self.journal_events.insertRow(row)
            host = event.get("hostname") or event.get("ip") or "—"
            values = [
                severity_fr.get(event["severity"], event["severity"]),
                kind_fr.get(event["kind"], event["kind"]),
                host,
                event.get("detail") or "",
            ]
            color = QColor(colors.get(event["severity"], "#d8ffe8"))
            for col, text in enumerate(values):
                cell = QTableWidgetItem(text)
                if col == 0:
                    cell.setForeground(color)
                self.journal_events.setItem(row, col, cell)

    def _run_config_audit(self):
        ip = self.as_target.text().strip()
        if not ip:
            self.as_status.setText("Indiquez une adresse à contrôler.")
            return
        self.as_audit_btn.setEnabled(False)
        self.audit_view.setPlainText("Contrôle en cours…")
        self._audit_worker = ConfigAuditWorker(ip)
        self._audit_worker.finished.connect(self._show_config_audit)
        self._audit_worker.start()

    def _show_config_audit(self, text: str):
        self.audit_view.setPlainText(text)
        self.as_audit_btn.setEnabled(True)
        self.as_status.setText("Contrôle terminé. Aucun mot de passe n'a été essayé.")

    def _build_platform_page(self):
        from core.schedule import ScheduleStore
        from core.settings import load_settings

        page = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(20, 16, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Pilotage")
        title.setObjectName("pageTitle")
        intro = QLabel("Planification, alertes, inventaire cloud, rapport PDF et API du démon. Les essais de mots de passe automatiques ne sont pas faits.")
        intro.setObjectName("emptyHint")
        intro.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(intro)

        layout.addWidget(self._platform_heading("Planification"))
        plan_row = QHBoxLayout()
        self.plan_time = QLineEdit()
        self.plan_time.setPlaceholderText("02:00")
        self.plan_time.setFixedWidth(90)
        self.plan_subnet = QLineEdit()
        self.plan_subnet.setPlaceholderText("sous-réseau, vide = interface courante")
        plan_add = QPushButton("Ajouter")
        plan_add.setObjectName("primary")
        plan_add.clicked.connect(self._add_schedule)
        plan_row.addWidget(self.plan_time)
        plan_row.addWidget(self.plan_subnet, stretch=1)
        plan_row.addWidget(plan_add)
        layout.addLayout(plan_row)
        self.plan_table = QTableWidget()
        self.plan_table.setColumnCount(3)
        self.plan_table.setHorizontalHeaderLabels(["HEURE", "CIBLE", "DERNIER LANCEMENT"])
        self.plan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.plan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.plan_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.plan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.plan_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.plan_table.verticalHeader().setVisible(False)
        self.plan_table.setMaximumHeight(160)
        self.plan_table.setAlternatingRowColors(True)
        self.plan_table.setShowGrid(False)
        self.plan_table.verticalHeader().setDefaultSectionSize(36)
        layout.addWidget(self.plan_table)
        plan_remove = QPushButton("Retirer la planification")
        plan_remove.clicked.connect(self._remove_schedule)
        layout.addWidget(plan_remove, alignment=Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(self._platform_heading("Alertes"))
        settings = load_settings()
        self.alert_webhook = QLineEdit(settings.get("webhook_url") or "")
        self.alert_webhook.setPlaceholderText("URL webhook Slack, Discord ou Teams")
        self.alert_smtp_host = QLineEdit(settings.get("smtp_host") or "")
        self.alert_smtp_host.setPlaceholderText("serveur SMTP")
        self.alert_smtp_port = QLineEdit(str(settings.get("smtp_port") or 587))
        self.alert_smtp_port.setFixedWidth(80)
        self.alert_smtp_user = QLineEdit(settings.get("smtp_user") or "")
        self.alert_smtp_user.setPlaceholderText("utilisateur")
        self.alert_smtp_password = QLineEdit()
        self.alert_smtp_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.alert_smtp_password.setPlaceholderText("mot de passe, vide = inchangé")
        self.alert_smtp_to = QLineEdit(settings.get("smtp_to") or "")
        self.alert_smtp_to.setPlaceholderText("destinataire")
        self.alert_syslog = QLineEdit(settings.get("syslog_host") or "")
        self.alert_syslog.setPlaceholderText("hôte syslog")
        self.alert_syslog_port = QLineEdit(str(settings.get("syslog_port") or 514))
        self.alert_syslog_port.setFixedWidth(80)
        for caption, widget in (
            ("Webhook", self.alert_webhook),
            ("Serveur SMTP", self.alert_smtp_host),
            ("Utilisateur SMTP", self.alert_smtp_user),
            ("Mot de passe SMTP", self.alert_smtp_password),
            ("Destinataire", self.alert_smtp_to),
            ("Hôte syslog", self.alert_syslog),
        ):
            layout.addWidget(self._captioned(caption, widget))
        smtp_row = QHBoxLayout()
        smtp_row.addWidget(QLabel("Port SMTP"))
        smtp_row.addWidget(self.alert_smtp_port)
        smtp_row.addSpacing(12)
        smtp_row.addWidget(QLabel("Port syslog"))
        smtp_row.addWidget(self.alert_syslog_port)
        smtp_row.addStretch()
        layout.addLayout(smtp_row)
        alert_row = QHBoxLayout()
        save_alerts = QPushButton("Enregistrer les alertes")
        save_alerts.setObjectName("primary")
        save_alerts.clicked.connect(self._save_alerts)
        test_alerts = QPushButton("Essai d'alerte")
        test_alerts.clicked.connect(self._test_alerts)
        alert_row.addWidget(save_alerts)
        alert_row.addWidget(test_alerts)
        alert_row.addStretch()
        layout.addLayout(alert_row)

        layout.addWidget(self._platform_heading("Cloud"))
        cloud_row = QHBoxLayout()
        self.cloud_provider = QLineEdit()
        self.cloud_provider.setPlaceholderText("aws, azure, gcp")
        self.cloud_provider.setFixedWidth(120)
        self.cloud_name = QLineEdit()
        self.cloud_name.setPlaceholderText("nom")
        self.cloud_address = QLineEdit()
        self.cloud_address.setPlaceholderText("adresse IP")
        cloud_add = QPushButton("Ajouter")
        cloud_add.clicked.connect(self._add_cloud_asset)
        cloud_row.addWidget(self.cloud_provider)
        cloud_row.addWidget(self.cloud_name)
        cloud_row.addWidget(self.cloud_address, stretch=1)
        cloud_row.addWidget(cloud_add)
        layout.addLayout(cloud_row)
        self.cloud_table = QTableWidget()
        self.cloud_table.setColumnCount(3)
        self.cloud_table.setHorizontalHeaderLabels(["FOURNISSEUR", "NOM", "ADRESSE"])
        self.cloud_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.cloud_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.cloud_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.cloud_table.verticalHeader().setVisible(False)
        self.cloud_table.setMaximumHeight(160)
        self.cloud_table.setAlternatingRowColors(True)
        self.cloud_table.setShowGrid(False)
        self.cloud_table.verticalHeader().setDefaultSectionSize(36)
        layout.addWidget(self.cloud_table)
        cloud_note = QLabel("Si boto3 et des identifiants AWS sont présents, les instances EC2 sont ajoutées à la carte.")
        cloud_note.setObjectName("emptyHint")
        cloud_note.setWordWrap(True)
        layout.addWidget(cloud_note)
        cloud_remove = QPushButton("Retirer l'équipement")
        cloud_remove.clicked.connect(self._remove_cloud_asset)
        layout.addWidget(cloud_remove, alignment=Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(self._platform_heading("Rapport et API"))
        report_btn = QPushButton("Générer le PDF")
        report_btn.setObjectName("primary")
        report_btn.clicked.connect(self._export_pdf)
        layout.addWidget(report_btn, alignment=Qt.AlignmentFlag.AlignLeft)
        token = settings.get("api_token") or ""
        self.api_label = QLabel(
            f"Démon : sudo ./orbite-scan.sh daemon -i 3600\n"
            f"API : http://{settings.get('api_host')}:{settings.get('api_port')}\n"
            f"Jeton : {token}"
        )
        self.api_label.setObjectName("mono")
        self.api_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.api_label.setWordWrap(True)
        layout.addWidget(self.api_label)
        layout.addStretch()
        scroll.setWidget(inner)
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self._schedules = ScheduleStore()
        self._reload_platform()
        return page

    def _platform_heading(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("sectionLabel")
        return label

    def _reload_platform(self):
        from core.cloud import list_assets
        from core.store import format_when

        schedules = self._schedules.list_schedules()
        self.plan_table.setRowCount(0)
        for item in schedules:
            row = self.plan_table.rowCount()
            self.plan_table.insertRow(row)
            hour = QTableWidgetItem(f"{item['hour']:02d}:{item['minute']:02d}")
            hour.setData(Qt.ItemDataRole.UserRole, item["id"])
            self.plan_table.setItem(row, 0, hour)
            self.plan_table.setItem(row, 1, QTableWidgetItem(item["subnet"] or "automatique"))
            last = format_when(item["last_run"]) if item.get("last_run") else "—"
            self.plan_table.setItem(row, 2, QTableWidgetItem(last))
        assets = list_assets()
        self.cloud_table.setRowCount(0)
        for asset in assets:
            row = self.cloud_table.rowCount()
            self.cloud_table.insertRow(row)
            self.cloud_table.setItem(row, 0, QTableWidgetItem(asset["provider"]))
            self.cloud_table.setItem(row, 1, QTableWidgetItem(asset["name"]))
            self.cloud_table.setItem(row, 2, QTableWidgetItem(asset["address"]))

    def _add_schedule(self):
        raw = self.plan_time.text().strip() or "02:00"
        try:
            hour, minute = raw.split(":")
            hour, minute = int(hour), int(minute)
        except ValueError:
            self.statusBar().showMessage("Heure attendue au format HH:MM.")
            return
        self._schedules.add(hour, minute, self.plan_subnet.text().strip())
        self._reload_platform()
        self.statusBar().showMessage("Planification enregistrée. Le démon la lancera à cette heure.")

    def _remove_schedule(self):
        row = self.plan_table.currentRow()
        if row < 0:
            return
        schedule_id = self.plan_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        self._schedules.remove(schedule_id)
        self._reload_platform()

    def _save_alerts(self):
        from core.settings import save_settings
        try:
            smtp_port = int(self.alert_smtp_port.text() or 587)
            syslog_port = int(self.alert_syslog_port.text() or 514)
        except ValueError:
            self.statusBar().showMessage("Les ports doivent être des nombres.")
            return
        payload = {
            "webhook_url": self.alert_webhook.text().strip(),
            "smtp_host": self.alert_smtp_host.text().strip(),
            "smtp_port": smtp_port,
            "smtp_user": self.alert_smtp_user.text().strip(),
            "smtp_to": self.alert_smtp_to.text().strip(),
            "syslog_host": self.alert_syslog.text().strip(),
            "syslog_port": syslog_port,
        }
        password = self.alert_smtp_password.text()
        if password:
            payload["smtp_password"] = password
        save_settings(payload)
        self.alert_smtp_password.clear()
        self.statusBar().showMessage("Alertes enregistrées. Elles partent seulement s'il y a une anomalie.")

    def _test_alerts(self):
        from core.notify import send_alerts
        self._save_alerts()
        notes = send_alerts({
            "summary": {"alerts": 1},
            "events": [{
                "severity": "warning",
                "detail": "Essai d'alerte Orbite Scan.",
                "kind": "new_asset",
            }],
        })
        self.statusBar().showMessage(" · ".join(notes) if notes else "Aucun canal configuré.")

    def _add_cloud_asset(self):
        from core.cloud import add_asset
        address = self.cloud_address.text().strip()
        if not address:
            self.statusBar().showMessage("Indiquez l'adresse de l'équipement cloud.")
            return
        add_asset(self.cloud_provider.text().strip() or "cloud", self.cloud_name.text().strip() or address, address)
        self.cloud_address.clear()
        self.cloud_name.clear()
        self._reload_platform()
        self.statusBar().showMessage("Équipement ajouté. Il apparaîtra sur la carte au prochain scan.")

    def _remove_cloud_asset(self):
        from core.cloud import remove_asset
        row = self.cloud_table.currentRow()
        if row < 0:
            return
        remove_asset(self.cloud_table.item(row, 2).text())
        self._reload_platform()

    def _export_pdf(self):
        from core.report import write_report
        path, _ = QFileDialog.getSaveFileName(self, "Rapport Orbite Scan", "rapport.pdf", "PDF (*.pdf)")
        if not path:
            return
        try:
            written = write_report(self.store, destination=path)
        except Exception as exc:
            self.statusBar().showMessage(f"Rapport non créé : {exc}")
            return
        self.statusBar().showMessage(f"Rapport écrit dans {written}")

    def _build_enterprise_page(self):
        from core.settings import load_settings

        page = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(20, 16, 20, 24)
        layout.setSpacing(12)

        title = QLabel("Entreprise")
        title.setObjectName("pageTitle")
        intro = QLabel(
            "Audit authentifié, conformité, priorisation, agents et connecteurs. "
            "Les identifiants servent uniquement à lire la configuration et les paquets. "
            "Aucun exploit n'est lancé et aucun mot de passe n'est deviné."
        )
        intro.setObjectName("emptyHint")
        intro.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(intro)

        layout.addWidget(self._platform_heading("Trousseau"))
        form = QHBoxLayout()
        self.cred_name = QLineEdit()
        self.cred_name.setPlaceholderText("nom")
        self.cred_protocol = QComboBox()
        self.cred_protocol.addItem("SSH", "ssh")
        self.cred_protocol.addItem("SMB", "smb")
        self.cred_host = QLineEdit()
        self.cred_host.setPlaceholderText("hôte")
        self.cred_user = QLineEdit()
        self.cred_user.setPlaceholderText("utilisateur")
        self.cred_kind = QComboBox()
        self.cred_kind.addItem("Mot de passe", "password")
        self.cred_kind.addItem("Clé", "key")
        form.addWidget(self.cred_name)
        form.addWidget(self.cred_protocol)
        form.addWidget(self.cred_host)
        form.addWidget(self.cred_user)
        form.addWidget(self.cred_kind)
        layout.addLayout(form)
        self.cred_secret = QLineEdit()
        self.cred_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.cred_secret.setPlaceholderText("mot de passe, bloc PEM ou chemin de clé")
        layout.addWidget(self.cred_secret)
        cred_actions = QHBoxLayout()
        cred_add = QPushButton("Enregistrer")
        cred_add.setObjectName("primary")
        cred_add.clicked.connect(self._add_credential)
        cred_scan = QPushButton("Audit authentifié")
        cred_scan.clicked.connect(self._start_auth_audit)
        cred_remove = QPushButton("Retirer")
        cred_remove.clicked.connect(self._remove_credential)
        cred_actions.addWidget(cred_add)
        cred_actions.addWidget(cred_scan)
        cred_actions.addWidget(cred_remove)
        cred_actions.addStretch()
        layout.addLayout(cred_actions)
        self.cred_table = QTableWidget()
        self.cred_table.setColumnCount(4)
        self.cred_table.setHorizontalHeaderLabels(["NOM", "PROTOCOLE", "HÔTE", "UTILISATEUR"])
        self.cred_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.cred_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.cred_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.cred_table.verticalHeader().setVisible(False)
        self.cred_table.setMaximumHeight(140)
        self.cred_table.setShowGrid(False)
        layout.addWidget(self.cred_table)

        layout.addWidget(self._platform_heading("Failles priorisées"))
        self.finding_table = QTableWidget()
        self.finding_table.setColumnCount(5)
        self.finding_table.setHorizontalHeaderLabels(["PRIORITÉ", "SCORE", "CVE", "HÔTE", "DÉTAIL"])
        self.finding_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.finding_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.finding_table.verticalHeader().setVisible(False)
        self.finding_table.setMaximumHeight(180)
        self.finding_table.setShowGrid(False)
        layout.addWidget(self.finding_table)

        layout.addWidget(self._platform_heading("Conformité"))
        self.compliance_table = QTableWidget()
        self.compliance_table.setColumnCount(4)
        self.compliance_table.setHorizontalHeaderLabels(["STATUT", "CONTRÔLE", "RÉFÉRENTIELS", "DÉTAIL"])
        self.compliance_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.compliance_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.compliance_table.verticalHeader().setVisible(False)
        self.compliance_table.setMaximumHeight(180)
        self.compliance_table.setShowGrid(False)
        layout.addWidget(self.compliance_table)

        layout.addWidget(self._platform_heading("Catalogue de signatures"))
        settings = load_settings()
        self.feed_url = QLineEdit(settings.get("feed_url") or "")
        self.feed_url.setPlaceholderText("URL https du flux, vide = catalogue local")
        layout.addWidget(self.feed_url)
        feed_row = QHBoxLayout()
        feed_sync = QPushButton("Synchroniser")
        feed_sync.setObjectName("primary")
        feed_sync.clicked.connect(self._sync_feed)
        self.feed_status = QLabel("")
        self.feed_status.setObjectName("emptyHint")
        feed_row.addWidget(feed_sync)
        feed_row.addWidget(self.feed_status, stretch=1)
        layout.addLayout(feed_row)

        layout.addWidget(self._platform_heading("Agents"))
        agent_help = QLabel("Sur la machine à inventorier : python agent/orbite_agent.py --server http://127.0.0.1:8766 --token <jeton>")
        agent_help.setObjectName("emptyHint")
        agent_help.setWordWrap(True)
        layout.addWidget(agent_help)
        self.agent_table = QTableWidget()
        self.agent_table.setColumnCount(4)
        self.agent_table.setHorizontalHeaderLabels(["HÔTE", "SYSTÈME", "PAQUETS", "VU"])
        self.agent_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.agent_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.agent_table.verticalHeader().setVisible(False)
        self.agent_table.setMaximumHeight(140)
        self.agent_table.setShowGrid(False)
        layout.addWidget(self.agent_table)

        layout.addWidget(self._platform_heading("Connecteurs"))
        self.splunk_url = QLineEdit(settings.get("splunk_url") or "")
        self.splunk_url.setPlaceholderText("URL Splunk HEC")
        self.splunk_token = QLineEdit()
        self.splunk_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.splunk_token.setPlaceholderText("jeton Splunk, vide = inchangé")
        self.elastic_url = QLineEdit(settings.get("elastic_url") or "")
        self.elastic_url.setPlaceholderText("URL Elastic")
        self.elastic_key = QLineEdit()
        self.elastic_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.elastic_key.setPlaceholderText("clé API Elastic, vide = inchangé")
        self.datadog_key = QLineEdit()
        self.datadog_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.datadog_key.setPlaceholderText("clé API Datadog, vide = inchangé")
        self.datadog_site = QLineEdit(settings.get("datadog_site") or "datadoghq.com")
        self.jira_url = QLineEdit(settings.get("jira_url") or "")
        self.jira_url.setPlaceholderText("URL Jira")
        self.jira_user = QLineEdit(settings.get("jira_user") or "")
        self.jira_user.setPlaceholderText("utilisateur Jira")
        self.jira_token = QLineEdit()
        self.jira_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.jira_token.setPlaceholderText("jeton Jira, vide = inchangé")
        self.jira_project = QLineEdit(settings.get("jira_project") or "")
        self.jira_project.setPlaceholderText("clé de projet Jira")
        self.snow_url = QLineEdit(settings.get("snow_url") or "")
        self.snow_url.setPlaceholderText("URL ServiceNow")
        self.snow_user = QLineEdit(settings.get("snow_user") or "")
        self.snow_user.setPlaceholderText("utilisateur ServiceNow")
        self.snow_password = QLineEdit()
        self.snow_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.snow_password.setPlaceholderText("mot de passe ServiceNow, vide = inchangé")
        self.cef_enabled = QCheckBox("Envoyer aussi un événement CEF vers le syslog du pilotage")
        self.cef_enabled.setChecked(bool(settings.get("cef_enabled")))
        self.ticket_on_urgent = QCheckBox("Ouvrir un ticket si la faille est urgente et déjà exploitée")
        self.ticket_on_urgent.setChecked(bool(settings.get("ticket_on_urgent", True)))
        for widget in (
            self.splunk_url, self.splunk_token, self.elastic_url, self.elastic_key,
            self.datadog_key, self.datadog_site, self.jira_url, self.jira_user,
            self.jira_token, self.jira_project, self.snow_url, self.snow_user, self.snow_password,
        ):
            layout.addWidget(widget)
        layout.addWidget(self.cef_enabled)
        layout.addWidget(self.ticket_on_urgent)
        connect_row = QHBoxLayout()
        save_connect = QPushButton("Enregistrer les connecteurs")
        save_connect.setObjectName("primary")
        save_connect.clicked.connect(self._save_connectors)
        test_connect = QPushButton("Essai")
        test_connect.clicked.connect(self._test_connectors)
        connect_row.addWidget(save_connect)
        connect_row.addWidget(test_connect)
        connect_row.addStretch()
        layout.addLayout(connect_row)
        layout.addStretch()
        scroll.setWidget(inner)
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self._reload_enterprise()
        return page

    def _reload_enterprise(self):
        from core.agents import list_agents
        from core.credentialed import latest_report, list_findings
        from core.plugins import feed_status
        from core.vault import list_credentials

        self.cred_table.setRowCount(0)
        for item in list_credentials():
            row = self.cred_table.rowCount()
            self.cred_table.insertRow(row)
            name = QTableWidgetItem(item["name"])
            name.setData(Qt.ItemDataRole.UserRole, item["id"])
            self.cred_table.setItem(row, 0, name)
            self.cred_table.setItem(row, 1, QTableWidgetItem(item["protocol"]))
            self.cred_table.setItem(row, 2, QTableWidgetItem(item["host"]))
            self.cred_table.setItem(row, 3, QTableWidgetItem(item["username"]))
        self._fill_finding_table(list_findings())
        report = latest_report()
        self._fill_compliance_table((report or {}).get("compliance") or [])
        status = feed_status()
        when = status.get("synced_at") or "pas encore"
        self.feed_status.setText(f"{status.get('count', 0)} signature(s) — {when}")
        self.agent_table.setRowCount(0)
        for agent in list_agents():
            row = self.agent_table.rowCount()
            self.agent_table.insertRow(row)
            self.agent_table.setItem(row, 0, QTableWidgetItem(agent["hostname"]))
            self.agent_table.setItem(row, 1, QTableWidgetItem(agent["os_name"]))
            self.agent_table.setItem(row, 2, QTableWidgetItem(str(agent["package_count"])))
            self.agent_table.setItem(row, 3, QTableWidgetItem(agent["last_seen"]))

    def _fill_finding_table(self, findings):
        self.finding_table.setRowCount(0)
        for item in findings:
            row = self.finding_table.rowCount()
            self.finding_table.insertRow(row)
            self.finding_table.setItem(row, 0, QTableWidgetItem(item.get("level") or ""))
            self.finding_table.setItem(row, 1, QTableWidgetItem(str(item.get("score") or "")))
            self.finding_table.setItem(row, 2, QTableWidgetItem(item.get("cve") or ""))
            self.finding_table.setItem(row, 3, QTableWidgetItem(item.get("host") or ""))
            self.finding_table.setItem(row, 4, QTableWidgetItem(item.get("title") or ""))

    def _fill_compliance_table(self, checks):
        self.compliance_table.setRowCount(0)
        labels = {"pass": "conforme", "fail": "écart", "unknown": "inconnu"}
        for item in checks:
            row = self.compliance_table.rowCount()
            self.compliance_table.insertRow(row)
            self.compliance_table.setItem(row, 0, QTableWidgetItem(labels.get(item.get("status"), item.get("status") or "")))
            self.compliance_table.setItem(row, 1, QTableWidgetItem(item.get("title") or ""))
            self.compliance_table.setItem(row, 2, QTableWidgetItem(", ".join(item.get("frameworks") or [])))
            self.compliance_table.setItem(row, 3, QTableWidgetItem(item.get("detail") or ""))

    def _selected_credential_id(self):
        row = self.cred_table.currentRow()
        if row < 0:
            return None
        item = self.cred_table.item(row, 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _add_credential(self):
        from core.vault import add_credential
        try:
            add_credential(
                self.cred_name.text(),
                self.cred_protocol.currentData(),
                self.cred_host.text(),
                self.cred_user.text(),
                self.cred_kind.currentData(),
                self.cred_secret.text(),
            )
        except ValueError as exc:
            self.statusBar().showMessage(str(exc))
            return
        self.cred_secret.clear()
        self._reload_enterprise()
        self.statusBar().showMessage("Identifiant chiffré dans le trousseau.")

    def _remove_credential(self):
        from core.vault import remove_credential
        credential_id = self._selected_credential_id()
        if credential_id is None:
            self.statusBar().showMessage("Sélectionnez un identifiant.")
            return
        remove_credential(credential_id)
        self._reload_enterprise()

    def _start_auth_audit(self):
        credential_id = self._selected_credential_id()
        if credential_id is None:
            self.statusBar().showMessage("Sélectionnez un identifiant.")
            return
        self.statusBar().showMessage("Audit authentifié en cours…")
        self._auth_worker = AuthAuditWorker(credential_id)
        self._auth_worker.finished.connect(self._on_auth_audit)
        self._auth_worker.start()

    def _on_auth_audit(self, report: dict):
        if report.get("error"):
            self.statusBar().showMessage(report["error"])
            return
        self._fill_finding_table(report.get("findings") or [])
        self._fill_compliance_table(report.get("compliance") or [])
        count = len(report.get("findings") or [])
        self.statusBar().showMessage(f"Audit terminé — {count} faille(s) priorisée(s).")

    def _sync_feed(self):
        from core.plugins import sync_feed
        from core.settings import save_settings
        save_settings({"feed_url": self.feed_url.text().strip()})
        try:
            message = sync_feed()
        except Exception as exc:
            self.statusBar().showMessage(f"Flux non importé : {exc}")
            return
        self._reload_enterprise()
        self.statusBar().showMessage(message)

    def _save_connectors(self):
        from core.settings import save_settings
        payload = {
            "feed_url": self.feed_url.text().strip(),
            "splunk_url": self.splunk_url.text().strip(),
            "elastic_url": self.elastic_url.text().strip(),
            "datadog_site": self.datadog_site.text().strip() or "datadoghq.com",
            "jira_url": self.jira_url.text().strip(),
            "jira_user": self.jira_user.text().strip(),
            "jira_project": self.jira_project.text().strip(),
            "snow_url": self.snow_url.text().strip(),
            "snow_user": self.snow_user.text().strip(),
            "cef_enabled": self.cef_enabled.isChecked(),
            "ticket_on_urgent": self.ticket_on_urgent.isChecked(),
        }
        for field, key in (
            (self.splunk_token, "splunk_token"),
            (self.elastic_key, "elastic_api_key"),
            (self.datadog_key, "datadog_api_key"),
            (self.jira_token, "jira_token"),
            (self.snow_password, "snow_password"),
        ):
            if field.text():
                payload[key] = field.text()
                field.clear()
        save_settings(payload)
        self.statusBar().showMessage("Connecteurs enregistrés.")

    def _test_connectors(self):
        from core.integrations import send_test
        self._save_connectors()
        notes = send_test()
        self.statusBar().showMessage(" · ".join(notes))

    def _as_load_from_history(self, item):
        row = item.row()
        target = self.as_history.item(row, 0).text()
        if target in self._as_results:
            self._as_display(self._as_results[target])


if __name__ == "__main__":
    if platform.system() == "Linux":
        check_root()
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu --disable-software-rasterizer"
    os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
    QLocale.setDefault(QLocale(QLocale.Language.French, QLocale.Country.France))
    app = QApplication(sys.argv)
    logo = LogoIniziale()
    logo.show()
    app.processEvents()
    window = MainWindow()
    QTimer.singleShot(2200, lambda: logo.reveal(window))
    sys.exit(app.exec())
