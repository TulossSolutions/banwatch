import argparse
import re
import sys
from pathlib import Path

from .config import load_config, save_config
from .daemon import start_daemon, stop_daemon
from .database import BanwatchDB
from .detector import DetectorEngine
from .firewall import Firewall
from .paths import PID_FILE
from .reporter import Reporter
from .setup_wizard import run_setup
from .signatures import SEVERITY_WEIGHTS, get_service_signatures
from .utils import normalize_allowlist, sudo_check, validate_ip

SYSTEMD_UNIT = """[Unit]
Description=BanWatch - brute-force quarantine daemon
After=network.target

[Service]
Type=forking
PIDFile=/var/run/banwatch.pid
ExecStart=/usr/local/bin/banwatch enable
ExecStop=/usr/local/bin/banwatch disable
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def _print_daemon_state():
    if PID_FILE.exists():
        pid = PID_FILE.read_text().strip()
        if Path(f"/proc/{pid}").exists():
            print(f"   Daemon:     Running (PID {pid})")
        else:
            print("   Daemon:     Stopped (stale PID)")
    else:
        print("   Daemon:     Stopped")


def cmd_status():
    db = BanwatchDB()
    cfg = load_config()
    stats = db.get_stats()

    print("\n" + "=" * 60)
    print("BANWATCH STATUS")
    print("=" * 60)

    _print_daemon_state()
    mode = "DRY RUN (detect only)" if cfg.get("dry_run") else "Live"
    print(f"   Mode:       {mode}")
    print(f"   Services:   {', '.join(cfg.get('services', []))}")
    print(f"   Firewall:   {cfg.get('firewall', 'none')}")
    print(f"   Threshold:  {cfg.get('threshold', 5)} score / {cfg.get('window', 300)}s")
    duration = cfg.get("ban_duration", 0)
    if duration:
        print(f"   Ban length: {duration}s, x{cfg.get('ban_escalation', 2)} per re-offense")
    else:
        print("   Ban length: permanent")
    print()
    print(f"   Total entries:      {stats['total_entries']}")
    print(f"   Currently banned:   {stats['active_quarantined']}")
    print(f"   Attacks (24h):      {stats['attacks_24h']}")
    print()

    if stats["by_service"]:
        print("   Breakdown by service:")
        for svc, count in stats["by_service"].items():
            print(f"      - {svc:<12} {count}")

    print("=" * 60)

    entries = db.get_ban_list(10)
    if entries:
        print("\n   Recent quarantines:")
        print(f"   {'IP':<18} {'Service':<10} {'Attempts':<10} {'Status':<12} {'Last Seen'}")
        print("   " + "-" * 70)
        for e in entries:
            print(
                f"   {e['ip']:<18} {e['service'].upper():<10} {e['attempts']:<10} "
                f"{e['status']:<12} {e['last_seen'][:19]}"
            )
    print()


def cmd_release(ip: str):
    sudo_check()
    try:
        ip = validate_ip(ip)
    except ValueError as e:
        print(e)
        sys.exit(1)

    db = BanwatchDB()
    cfg = load_config()
    fw = Firewall(cfg["firewall"], dry_run=cfg.get("dry_run", False))

    db.release(ip)
    fw.unblock(ip)
    print(f"Released {ip} from quarantine.")


def cmd_report(format: str):
    db = BanwatchDB()
    cfg = load_config()
    reporter = Reporter(db, cfg)
    path = reporter.save_and_maybe_email(format=format)
    print(f"Report generated: {path}")


def cmd_scan():
    sudo_check()
    cfg = load_config()
    if not cfg.get("services"):
        print("Not configured. Run: sudo banwatch setup")
        sys.exit(1)
    db = BanwatchDB()
    fw = Firewall(cfg["firewall"], dry_run=cfg.get("dry_run", False))
    detector = DetectorEngine(cfg, db, fw)
    stats = detector.scan_existing()
    print(f"Scanned {stats['lines']} lines, quarantined {stats['new_bans']} new IP(s).")
    print("New quarantines will be active firewall rules (unless dry-run is enabled).")


def cmd_test_line(service: str, line: str):
    cfg = load_config()
    sigs = get_service_signatures(cfg.get("rules_file"))
    if service not in sigs:
        print(f"Unknown service '{service}'. Known: {', '.join(sorted(sigs))}")
        sys.exit(1)

    threshold = cfg.get("threshold", 5)
    print(f"\nTesting line against '{service}' rules (quarantine threshold score: {threshold}):")
    print(f"  {line}\n")

    matches = []
    for rule in sigs[service]["patterns"]:
        compiled = re.compile(rule["pattern"], re.IGNORECASE)
        m = compiled.search(line)
        if m:
            weight = SEVERITY_WEIGHTS.get(rule["severity"], 1)
            ip = m.group("ip") if "ip" in m.groupdict() else None
            matches.append(weight)
            print(f"  [MATCH]  severity={rule['severity']:<8} weight={weight}  ip={ip}")
            print(f"           {rule['pattern']}")

    if not matches:
        print("  No rules matched this line.")
        return

    total = sum(matches)
    print()
    print(f"  {len(matches)} rule(s) matched, total weight {total} (threshold {threshold}).")
    if total >= threshold:
        print("  This line would contribute to a quarantine.")
    else:
        print("  This line alone would not trigger quarantine.")


def cmd_rules(service: str = None):
    cfg = load_config()
    sigs = get_service_signatures(cfg.get("rules_file"))

    services = [service] if service else (cfg.get("services") or sorted(sigs))
    for svc in services:
        if svc not in sigs:
            print(f"Unknown service '{svc}'. Known: {', '.join(sorted(sigs))}")
            sys.exit(1)

    print("\nACTIVE RULES\n")
    for svc in services:
        print(f"[{svc}]")
        for rule in sigs[svc]["patterns"]:
            weight = SEVERITY_WEIGHTS.get(rule["severity"], 1)
            print(f"    {rule['severity']:<8} (weight {weight})  {rule['pattern']}")
        print()


def cmd_allowlist(action: str, entry: str = None):
    if action == "list":
        cfg = load_config()
        print("\nALLOWLIST")
        for net in cfg.get("allowlist", []):
            print(f"   {net}")
        print()
        return

    sudo_check()
    if not entry:
        print(f"Usage: sudo banwatch allowlist {action} <ip|cidr>")
        sys.exit(1)
    try:
        normalized = normalize_allowlist([entry])[0]
    except ValueError as e:
        print(e)
        sys.exit(1)

    cfg = load_config()
    allowlist = list(cfg.get("allowlist", []))

    if action == "add":
        if normalized in allowlist:
            print(f"{normalized} is already in the allowlist.")
        else:
            allowlist.append(normalized)
            cfg["allowlist"] = allowlist
            save_config(cfg)
            print(f"Added {normalized} to the allowlist.")
    elif action == "remove":
        if normalized in allowlist:
            allowlist.remove(normalized)
            cfg["allowlist"] = allowlist
            save_config(cfg)
            print(f"Removed {normalized} from the allowlist.")
        else:
            print(f"{normalized} is not in the allowlist.")


def cmd_systemd():
    sudo_check()
    unit = Path("/etc/systemd/system/banwatch.service")
    existed = unit.exists()
    unit.write_text(SYSTEMD_UNIT)
    try:
        unit.chmod(0o644)
    except OSError:
        pass

    if existed:
        print("Updated the existing unit file.")
    else:
        print(f"Wrote {unit}")
    print("""
Install and start:
   sudo systemctl daemon-reload
   sudo systemctl enable --now banwatch

Check status:
   sudo systemctl status banwatch
   sudo banwatch status
""")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="banwatch",
        description="BanWatch - As simple as UFW",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    sub.add_parser("setup", help="First-time interactive setup")
    p_enable = sub.add_parser("enable", help="Start the daemon")
    p_enable.add_argument("--dry-run", action="store_true", help="Detect and report only, never block")
    sub.add_parser("disable", help="Stop the daemon")
    sub.add_parser("status", help="Show stats and the ban list")
    p_release = sub.add_parser("release", help="Free an IP from quarantine")
    p_release.add_argument("ip", help="IPv4 address to release")
    p_report = sub.add_parser("report", help="Generate a report")
    p_report.add_argument("--format", choices=["html", "json", "csv"], default="html", help="Report format (default: html)")
    sub.add_parser("scan", help="Scan existing log files from the start for past attacks")
    p_test = sub.add_parser("test-line", help="Test a log line against a service's rules")
    p_test.add_argument("service", help="Service name, e.g. ssh")
    p_test.add_argument("line", help="Log line to test (quote it)")
    p_rules = sub.add_parser("rules", help="Show active patterns")
    p_rules.add_argument("service", nargs="?", help="Show rules for one service only")
    p_allow = sub.add_parser("allowlist", help="Manage the allowlist")
    p_allow.add_argument("action", choices=["add", "remove", "list"], help="Operation to perform")
    p_allow.add_argument("ip", nargs="?", help="IPv4 address or CIDR (add/remove)")
    sub.add_parser("systemd", help="Write a systemd unit file and print install commands")

    return parser


def main():
    args = build_parser().parse_args()

    if args.command == "setup":
        run_setup()
    elif args.command == "enable":
        start_daemon(dry_run=args.dry_run)
    elif args.command == "disable":
        stop_daemon()
    elif args.command == "status":
        cmd_status()
    elif args.command == "release":
        cmd_release(args.ip)
    elif args.command == "report":
        cmd_report(args.format)
    elif args.command == "scan":
        cmd_scan()
    elif args.command == "test-line":
        cmd_test_line(args.service, args.line)
    elif args.command == "rules":
        cmd_rules(args.service)
    elif args.command == "allowlist":
        cmd_allowlist(args.action, args.ip)
    elif args.command == "systemd":
        cmd_systemd()
