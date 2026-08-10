import subprocess

from .config import detect_log_files, load_config, save_config
from .signatures import SERVICE_SIGNATURES
from .ui import ask, ask_yesno, print_banner
from .utils import ensure_dirs, sudo_check

SEP = "=" * 60
TOTAL = 11


def q_header(n: int, title: str):
    print(f"\n{SEP}")
    print(f"  Q{n}/{TOTAL}  {title}")
    print(SEP)


def run_setup():
    sudo_check()
    ensure_dirs()
    print_banner()

    print("First-time setup wizard\n")
    print("BanWatch will watch your services, detect brute-force bots,")
    print("and automatically quarantine them. No external dependencies needed.")

    cfg = load_config()

    q_header(1, "Which services should BanWatch protect?")
    print("   1.  ssh      - SSH brute-force (auth.log, secure)")
    print("   2.  web      - Web attacks (nginx, apache, caddy, traefik, lighttpd, haproxy)")
    print("   3.  database - MySQL, PostgreSQL, MariaDB, MongoDB, Redis, Elasticsearch, Cassandra")
    print("   4.  ftp      - FTP brute-force (vsftpd, proftpd, pure-ftpd)")
    print("   5.  mail     - Mail server attacks (postfix, dovecot)")
    print("   6.  vpn      - VPN intrusion attempts (OpenVPN, WireGuard)")
    print("   7.  all      - Everything above")

    choice = ask("Services to watch", ["ssh", "web", "database", "ftp", "mail", "vpn", "all"], "all")

    if choice.lower() == "all":
        cfg["services"] = ["ssh", "web", "database", "ftp", "mail", "vpn"]
    else:
        cfg["services"] = [choice.lower()]

    print("\nAuto-detecting log files...")
    cfg["log_paths"] = {}
    for svc in cfg["services"]:
        sig = SERVICE_SIGNATURES[svc]
        log_paths = detect_log_files(sig["log_guesses"])
        if log_paths:
            cfg["log_paths"][svc] = log_paths
            for path in log_paths:
                print(f"   {svc:<10} -> {path}")
        else:
            print(f"   {svc:<10} -> log not found, will use port-based detection")

    q_header(2, "Which firewall should BanWatch use to quarantine attackers?")
    has_iptables = subprocess.run(["which", "iptables"], capture_output=True).returncode == 0
    has_ufw = subprocess.run(["which", "ufw"], capture_output=True).returncode == 0

    fw_options = []
    if has_iptables:
        fw_options.append("iptables")
    if has_ufw:
        fw_options.append("ufw")

    if not fw_options:
        print("   No iptables or ufw found. Quarantine will be logged-only.")
        cfg["firewall"] = "none"
    else:
        default_fw = "ufw" if has_ufw else "iptables"
        cfg["firewall"] = ask("Firewall backend", fw_options, default_fw)

    q_header(3, "Attack threshold")
    print("   Rule weights: low=1, medium=2, high=3, critical=4.")
    print("   The sum of rule weights within the window is compared to the threshold.")
    cfg["threshold"] = int(ask("Threshold (score)", [], "5"))

    q_header(4, "Time window for counting attempts")
    cfg["window"] = int(ask("Window (seconds)", [], "300"))

    q_header(5, "Quarantine duration")
    print("   0 = permanent (never auto-released)")
    print("   Repeat offenders get the duration multiplied by 2x each time they come back.")
    cfg["ban_duration"] = int(ask("Ban duration (seconds, 0 = permanent)", [], "0"))
    cfg["ban_escalation"] = 2

    q_header(6, "Private IPs")
    print("   By default BanWatch never bans private IPs (RFC1918, loopback, link-local).")
    cfg["block_private"] = ask_yesno("Allow banning private IPs?", False)

    q_header(7, "Dry-run mode")
    print("   BanWatch can detect and report attacks without touching the firewall.")
    cfg["dry_run"] = ask_yesno("Enable dry-run mode (detect & report only)?", False)

    q_header(8, "Allowlist")
    print("   Trusted IPs/CIDRs that must never be banned (admin workstations, load balancers, VPN gateways).")
    entries = ask("Allowlist (comma-separated)", [], "127.0.0.1")
    cfg["allowlist"] = [e.strip() for e in entries.split(",") if e.strip()]

    q_header(9, "Known bots")
    print("   Known legitimate bots (Google, Bing, Yandex, Baidu, Apple, GPTBot, ClaudeBot, Perplexity, etc.)")
    print("   can be exempted so they are never quarantined for scanning 404 pages.")
    cfg["allow_known_bots"] = ask_yesno("Allow known bots (skip quarantine)?", True)

    q_header(10, "Webhook reports")
    print("   Optional: send periodic report digests to Slack, Discord, or a generic HTTP webhook.")
    if ask_yesno("Configure a webhook for report digests?", False):
        cfg["webhooks"] = []
        while True:
            url = ask("Webhook URL (blank to finish)")
            if not url:
                break
            if "discord.com/api/webhooks" in url:
                wtype = "discord"
            elif "hooks.slack.com" in url:
                wtype = "slack"
            else:
                wtype = "generic"
            cfg["webhooks"].append({"type": wtype, "url": url})
            print(f"   Added {wtype} webhook: {url}")
    else:
        cfg["webhooks"] = []

    q_header(11, "Email reports")
    print("   Optional: receive periodic security reports via email.")
    if ask_yesno("Configure email reports?", False):
        cfg["email"] = ask("Email address")
        cfg["report_frequency"] = ask("Report frequency", ["daily", "weekly", "monthly"], "weekly")
    else:
        cfg["email"] = None
        cfg["report_frequency"] = "weekly"

    save_config(cfg)

    print("\n" + "=" * 60)
    print("Setup complete!")
    print(f"   Services:     {', '.join(cfg['services'])}")
    print(f"   Firewall:     {cfg['firewall']}")
    print(f"   Threshold:    {cfg['threshold']} score in {cfg['window']}s")
    mode = "DRY RUN (detect only)" if cfg["dry_run"] else "Live"
    print(f"   Mode:         {mode}")
    print(f"   Private IPs:  {'may be banned' if cfg['block_private'] else 'never banned'}")
    if cfg["email"]:
        print(f"   Reports:      {cfg['report_frequency']} to {cfg['email']}")
    if cfg["webhooks"]:
        print(f"   Webhooks:     {len(cfg['webhooks'])} configured")
    print("=" * 60)
    print("\nStart protecting now:")
    print("   sudo banwatch enable")
    print("\nView status anytime:")
    print("   sudo banwatch status")
