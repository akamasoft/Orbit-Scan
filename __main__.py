import argparse
import csv
import json
import os
import sys

__version__ = "1.0.0"

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))


def _check_root():
    if sys.platform == "win32":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("erreur : privilèges administrateur requis", file=sys.stderr)
            sys.exit(1)
        return
    if hasattr(os, "getuid") and os.getuid() != 0:
        print("erreur : privilèges root requis (lancez avec sudo)", file=sys.stderr)
        sys.exit(1)


def _output_json(hosts: list, outfile=None):
    data = json.dumps(hosts, indent=2)
    if outfile:
        with open(outfile, "w") as f:
            f.write(data)
    else:
        print(data)


def _output_csv(hosts: list, outfile=None):
    fields = ["ip", "mac", "hostname", "vendor", "role", "os_hint", "open_ports", "ttl"]
    rows = []
    for h in hosts:
        rows.append(
            {
                "ip": h.get("ip", ""),
                "mac": h.get("mac", ""),
                "hostname": h.get("hostname", ""),
                "vendor": h.get("vendor", ""),
                "role": h.get("role", ""),
                "os_hint": h.get("os_hint", ""),
                "open_ports": " ".join(str(p) for p in h.get("open_ports", [])),
                "ttl": h.get("ttl", ""),
            }
        )
    if outfile:
        with open(outfile, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _output_table(hosts: list):
    if not hosts:
        print("aucun hôte trouvé.")
        return
    col_ip = max(len(h.get("ip", "")) for h in hosts)
    col_mac = max(len(h.get("mac", "")) for h in hosts)
    col_hn = max(len(h.get("hostname", "")) for h in hosts)
    col_v = max(len(h.get("vendor", "")) for h in hosts)
    col_r = max(len(h.get("role", "")) for h in hosts)

    col_ip = max(col_ip, 15)
    col_mac = max(col_mac, 17)
    col_hn = max(col_hn, 20)
    col_v = max(col_v, 20)
    col_r = max(col_r, 10)

    header = (
        f"{'IP':<{col_ip}}  {'MAC':<{col_mac}}  "
        f"{'HOTE':<{col_hn}}  {'FABRICANT':<{col_v}}  {'RÔLE':<{col_r}}"
    )
    print(header)
    print("-" * len(header))
    for h in hosts:
        print(
            f"{h.get('ip', ''):<{col_ip}}  {h.get('mac', ''):<{col_mac}}  "
            f"{h.get('hostname', ''):<{col_hn}}  {h.get('vendor', ''):<{col_v}}  "
            f"{h.get('role', ''):<{col_r}}"
        )


def cmd_scan(args):
    _check_root()
    from core.scanner import get_local_subnet, scan_network

    subnet = args.target
    if not subnet:
        try:
            subnet = get_local_subnet()
        except RuntimeError as e:
            print(f"erreur : {e}", file=sys.stderr)
            sys.exit(1)

    if not args.quiet:
        print(f"analyse de {subnet}...", file=sys.stderr)

    hosts = scan_network(subnet)
    _remember_scan(hosts, subnet, source="cli")

    fmt = args.output or "table"
    outfile = args.file

    if fmt == "json":
        _output_json(hosts, outfile)
    elif fmt == "csv":
        _output_csv(hosts, outfile)
    else:
        _output_table(hosts)
        if outfile:
            _output_json(hosts, outfile)

    if not args.quiet:
        print(f"\n{len(hosts)} hôte(s) trouvé(s).", file=sys.stderr)


def _remember_scan(hosts, subnet: str, source: str) -> None:
    try:
        from core.scanner import get_default_gateway
        from core.store import ScanStore, summary_text

        store = ScanStore()
        scan_id = store.save_scan(
            hosts,
            subnet=subnet,
            gateway=get_default_gateway(),
            source=source,
        )
        diff = store.get_diff(scan_id)
        print(summary_text(diff), file=sys.stderr)
        from core.followup import publish

        for note in publish(store, scan_id):
            print(note, file=sys.stderr)
    except Exception as exc:
        print(f"historique non enregistré : {exc}", file=sys.stderr)


def cmd_history(_args):
    from core.store import ScanStore, format_when

    scans = ScanStore().list_scans()
    if not scans:
        print("aucun relevé enregistré.")
        return
    print(f"{'ID':<6}{'DATE':<18}{'HÔTES':<8}{'ALERTES':<10}SOURCE    CIBLE")
    for scan in scans:
        print(
            f"{scan['id']:<6}{format_when(scan['created_at']):<18}{scan['host_count']:<8}"
            f"{scan['alert_count']:<10}{scan['source']:<10}{scan['subnet']}"
        )


def cmd_diff(args):
    from core.store import ScanStore, summary_text

    store = ScanStore()
    if args.scan:
        diff = store.get_diff(args.scan)
    else:
        diff = store.latest_diff(args.target)
    if not diff:
        print("aucun relevé à comparer.")
        return
    print(summary_text(diff))
    for event in diff.get("events") or []:
        print(f"[{event['severity']}] {event['detail']}")


def cmd_daemon(args):
    _check_root()
    from core.daemon import ScanDaemon

    ScanDaemon(args.target, args.interval, once=args.once, api=not args.no_api).serve()


def cmd_report(args):
    from core.report import write_report
    from core.store import ScanStore

    path = write_report(ScanStore(), args.scan, args.file)
    print(path)


def cmd_audit(args):
    from core.audit import audit_host

    result = audit_host(args.target)
    for finding in result["findings"]:
        print(f"[{finding['severity']}] {finding['detail']}")


def cmd_vault(args):
    _check_root()
    from core.vault import add_credential, list_credentials, remove_credential

    if args.vault_action == "add":
        created = add_credential(args.name, args.protocol, args.host, args.user, args.kind, args.secret)
        print(f"identifiant #{created} enregistré")
    elif args.vault_action == "remove":
        remove_credential(args.id)
        print(f"identifiant #{args.id} retiré")
    else:
        for item in list_credentials():
            print(f"#{item['id']}  {item['protocol']}  {item['username']}@{item['host']}  {item['name']}")


def cmd_auth_scan(args):
    _check_root()
    from core.credentialed import run_authenticated

    report = run_authenticated(args.id)
    if report.get("error"):
        print(report["error"], file=sys.stderr)
        sys.exit(1)
    print(f"{report.get('host')} — {len(report.get('findings') or [])} faille(s)")
    for item in report.get("findings") or []:
        print(f"[{item['level']}] {item['score']}  {item['cve']}  {item['title']}")
    for item in report.get("compliance") or []:
        print(f"[{item['status']}] {item['title']} — {item['detail']}")


def cmd_feed(_args):
    _check_root()
    from core.plugins import sync_feed

    print(sync_feed())


def cmd_findings(_args):
    _check_root()
    from core.credentialed import list_findings

    findings = list_findings()
    if not findings:
        print("aucune faille priorisée")
        return
    for item in findings:
        print(f"[{item['level']}] {item['score']}  {item.get('host')}  {item['cve']}  {item['title']}")


def cmd_gui(_args):
    _check_root()
    import os

    from PyQt6.QtCore import QLocale, QTimer
    from PyQt6.QtWidgets import QApplication

    from ui.app import LogoIniziale, MainWindow

    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        "--no-sandbox --disable-gpu --disable-software-rasterizer"
    )
    os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"

    QLocale.setDefault(QLocale(QLocale.Language.French, QLocale.Country.France))
    app = QApplication(sys.argv)
    logo = LogoIniziale()
    logo.show()
    app.processEvents()
    window = MainWindow()
    QTimer.singleShot(2200, lambda: logo.reveal(window))
    sys.exit(app.exec())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orbite-scan",
        description="Orbite Scan — supervision et visualisation réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exemples :\n"
            "  sudo orbite-scan                          lancer l'interface\n"
            "  sudo orbite-scan scan                     analyser le sous-réseau local\n"
            "  sudo orbite-scan scan -t 192.168.1.0/24   analyser un sous-réseau\n"
            "  sudo orbite-scan scan -o json             sortie JSON\n"
            "  sudo orbite-scan scan -o csv -f out.csv   enregistrer un CSV\n"
            "  orbite-scan history                       lister les relevés\n"
            "  orbite-scan diff                          écarts du dernier relevé\n"
            "  sudo orbite-scan daemon -i 3600           scan périodique, alertes et API\n"
            "  sudo orbite-scan auth-scan --id 1         audit authentifié en lecture seule\n"
            "  sudo orbite-scan feed                     synchroniser le catalogue de signatures\n"
            "  orbite-scan report -f rapport.pdf         exporter le dernier relevé\n"
            "  sudo orbite-scan audit -t 192.168.1.1     contrôle TLS et services\n"
        ),
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"orbite-scan {__version__}",
    )

    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="analyser le réseau et afficher les résultats")
    scan_p.add_argument(
        "-t",
        "--target",
        metavar="SUBNET",
        default=None,
        help="sous-réseau ou IP cible (défaut : détection automatique)",
    )
    scan_p.add_argument(
        "-o",
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="format de sortie (défaut : table)",
    )
    scan_p.add_argument(
        "-f",
        "--file",
        metavar="PATH",
        default=None,
        help="écrire la sortie dans un fichier plutôt que sur la sortie standard",
    )
    scan_p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="masquer les messages de progression",
    )

    sub.add_parser("gui", help="lancer l'interface graphique (défaut si aucune commande)")

    sub.add_parser("history", help="lister les relevés enregistrés")

    diff_p = sub.add_parser("diff", help="afficher les écarts du dernier relevé")
    diff_p.add_argument("-t", "--target", default=None, help="limiter à un sous-réseau")
    diff_p.add_argument("--scan", type=int, default=None, help="identifiant de relevé")

    daemon_p = sub.add_parser("daemon", help="scanner en arrière-plan et enregistrer les écarts")
    daemon_p.add_argument("-t", "--target", default=None, help="sous-réseau (défaut : détection)")
    daemon_p.add_argument(
        "-i",
        "--interval",
        type=int,
        default=3600,
        help="secondes entre deux scans (minimum 30, défaut 3600)",
    )
    daemon_p.add_argument("--once", action="store_true", help="un seul scan puis arrêt")
    daemon_p.add_argument("--no-api", action="store_true", help="ne pas ouvrir l'API REST")

    report_p = sub.add_parser("report", help="écrire le PDF du dernier relevé")
    report_p.add_argument("--scan", type=int, default=None, help="identifiant de relevé")
    report_p.add_argument("-f", "--file", default=None, help="fichier PDF de destination")

    audit_p = sub.add_parser("audit", help="contrôle de configuration non destructif")
    audit_p.add_argument("-t", "--target", required=True, help="adresse IP à contrôler")

    vault_p = sub.add_parser("vault", help="gérer le trousseau chiffré")
    vault_sub = vault_p.add_subparsers(dest="vault_action")
    vault_add = vault_sub.add_parser("add", help="enregistrer un identifiant")
    vault_add.add_argument("--name", required=True)
    vault_add.add_argument("--protocol", choices=["ssh", "smb"], required=True)
    vault_add.add_argument("--host", required=True)
    vault_add.add_argument("--user", required=True)
    vault_add.add_argument("--kind", choices=["password", "key"], default="password")
    vault_add.add_argument("--secret", required=True, help="mot de passe, bloc PEM ou chemin de clé")
    vault_sub.add_parser("list", help="lister les identifiants sans secret")
    vault_rm = vault_sub.add_parser("remove", help="retirer un identifiant")
    vault_rm.add_argument("--id", type=int, required=True)

    auth_p = sub.add_parser("auth-scan", help="audit authentifié en lecture seule")
    auth_p.add_argument("--id", type=int, required=True, help="identifiant du trousseau")

    sub.add_parser("feed", help="synchroniser le catalogue de signatures")
    sub.add_parser("findings", help="lister les failles priorisées")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "history":
        cmd_history(args)
    elif args.command == "diff":
        cmd_diff(args)
    elif args.command == "daemon":
        cmd_daemon(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "vault":
        cmd_vault(args)
    elif args.command == "auth-scan":
        cmd_auth_scan(args)
    elif args.command == "feed":
        cmd_feed(args)
    elif args.command == "findings":
        cmd_findings(args)
    elif args.command == "gui" or args.command is None:
        cmd_gui(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
