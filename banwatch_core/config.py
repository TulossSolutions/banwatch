import glob
import json
import re
from email.utils import parseaddr
from pathlib import Path
from typing import List

from .paths import CONFIG_FILE, RULES_FILE
from .signatures import known_services
from .utils import ensure_dirs, normalize_allowlist


DEFAULT_CONFIG = {
    "firewall": "iptables",
    "threshold": 5,
    "window": 300,
    "services": [],
    "log_paths": {},
    "allowlist": ["127.0.0.1"],
    "email": None,
    "email_from": "BanWatch <hello@tuloss.com>",
    "report_hostname": None,
    "report_frequency": "weekly",
    "daemon": False,
    "dry_run": False,
    "block_private": False,
    "allow_known_bots": True,
    "ban_duration": 0,
    "ban_escalation": 2,
    "rules_file": str(RULES_FILE),
    "webhooks": [],
}


def validate_config(cfg: dict) -> dict:
    cfg = {**DEFAULT_CONFIG, **cfg}

    for key in ('email', 'email_from'):
        value = cfg.get(key)
        if key == 'email' and not value:
            continue
        if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(key + ' must be a single email address without control characters')
        name, address = parseaddr(value)
        if not re.fullmatch(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+', address) or address.startswith('-'):
            raise ValueError(key + ' must contain a valid email address')
        if key == 'email' and value != address:
            raise ValueError('email must contain a bare recipient address')
    hostname = cfg.get('report_hostname')
    if hostname is not None and (not isinstance(hostname, str) or not hostname or len(hostname) > 253 or any(ord(c) < 32 for c in hostname)):
        raise ValueError('report_hostname must be a nonempty hostname without control characters')

    if cfg["firewall"] not in {"iptables", "ufw", "nftables", "none"}:
        raise ValueError("firewall must be one of: iptables, ufw, nftables, none")

    if cfg["report_frequency"] not in {"daily", "weekly", "monthly"}:
        raise ValueError("report_frequency must be one of: daily, weekly, monthly")

    for flag in ("dry_run", "block_private", "allow_known_bots"):
        if not isinstance(cfg[flag], bool):
            raise ValueError(f"{flag} must be true or false")

    try:
        cfg["threshold"] = int(cfg["threshold"])
        cfg["window"] = int(cfg["window"])
    except (TypeError, ValueError) as e:
        raise ValueError("threshold and window must be integers") from e

    if cfg["threshold"] < 1:
        raise ValueError("threshold must be at least 1")
    if cfg["window"] < 1:
        raise ValueError("window must be at least 1 second")

    try:
        cfg["ban_duration"] = int(cfg["ban_duration"])
    except (TypeError, ValueError) as e:
        raise ValueError("ban_duration must be an integer (seconds)") from e
    if cfg["ban_duration"] < 0:
        raise ValueError("ban_duration must be 0 (permanent) or a positive number of seconds")

    try:
        cfg["ban_escalation"] = float(cfg["ban_escalation"])
    except (TypeError, ValueError) as e:
        raise ValueError("ban_escalation must be a number") from e
    if cfg["ban_escalation"] < 1:
        raise ValueError("ban_escalation must be at least 1 (1 = no escalation)")

    services = cfg.get("services", [])
    if not isinstance(services, list):
        raise ValueError("services must be a list")
    if "all" in services:
        services = list(known_services(cfg.get("rules_file")))
    unknown = sorted(set(services) - set(known_services(cfg.get("rules_file"))))
    if unknown:
        raise ValueError(f"unknown services: {', '.join(unknown)}")
    cfg["services"] = services

    if not isinstance(cfg.get("log_paths", {}), dict):
        raise ValueError("log_paths must be an object")
    log_paths = {}
    for svc, paths in cfg["log_paths"].items():
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            raise ValueError(f"log_paths['{svc}'] must be a string or a list of strings")
        log_paths[svc] = paths
    cfg["log_paths"] = log_paths

    if not isinstance(cfg.get("rules_file", ""), str):
        raise ValueError("rules_file must be a path string")

    cfg["allowlist"] = normalize_allowlist(cfg.get("allowlist", []))

    webhooks = cfg.get("webhooks", [])
    if not isinstance(webhooks, list):
        raise ValueError("webhooks must be a list")
    cfg["webhooks"] = []
    for hook in webhooks:
        if not isinstance(hook, dict) or not hook.get("url"):
            raise ValueError("each webhook must be an object with a 'url'")
        if hook.get("type", "generic") not in {"slack", "discord", "generic"}:
            raise ValueError("webhook type must be one of: slack, discord, generic")
        cfg["webhooks"].append({"type": str(hook.get("type", "generic")), "url": str(hook["url"])})

    return cfg


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            raw = json.load(f)
            clean = {k: v for k, v in raw.items() if not k.startswith("_")}
            return validate_config(clean)
    return validate_config({})


def save_config(cfg: dict):
    ensure_dirs()
    commented = {
        "_readme": "BanWatch configuration - edit freely and restart with: banwatch disable && banwatch enable",
        "_fields": {
            "services": "List: ssh, web, database, ftp, mail, vpn, or ['all']",
            "log_paths": "Override auto-detected log locations per service (string or list of strings)",
            "allowlist": "List of IPv4/CIDR entries that must never be quarantined",
            "firewall": "Backend: 'iptables', 'ufw', 'nftables', or 'none'",
            "threshold": "Score threshold for quarantine (sum of rule weights within window)",
            "window": "Seconds to count attempts within (integer)",
            "email": "Report recipient (string) or null to disable",
            "email_from": "Report sender, optionally Name <address>; configure an authorized sender domain",
            "report_hostname": "Optional server label in report headers and email subjects",
            "report_frequency": "daily, weekly, or monthly",
            "dry_run": "Detect and report only; never modify the firewall (true/false)",
            "block_private": "Allow quarantining private/loopback IPs (true/false, default false)",
            "allow_known_bots": "Never quarantine known legitimate bots like Google, Bing, LLM crawlers (true/false, default true)",
            "ban_duration": "Seconds a quarantine lasts before auto-release; 0 = permanent (default 0)",
            "ban_escalation": "Multiplier applied to each repeat offense, e.g. 2 = 1h, 2h, 4h... (default 2)",
            "rules_file": "Path to custom rules JSON merged over built-in signatures",
            "webhooks": "List of {'type': 'slack'|'discord'|'generic', 'url': ...} for report digests",
        },
        **validate_config(cfg),
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(commented, f, indent=2)
    try:
        CONFIG_FILE.chmod(0o600)
    except OSError:
        pass


def detect_log_files(guesses: List[str]) -> List[str]:
    """Return every existing log path among the guesses (wildcards expanded, deduped)."""
    found = []
    for guess in guesses:
        matches = glob.glob(guess)
        for match in matches:
            if Path(match).exists() and match not in found:
                found.append(match)
        if Path(guess).exists() and guess not in found:
            found.append(guess)
    return found
