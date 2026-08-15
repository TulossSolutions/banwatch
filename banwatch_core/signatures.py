import json
from pathlib import Path
from typing import Dict, List

from .paths import RULES_FILE

SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SERVICE_SIGNATURES = {
    "ssh": {
        "patterns": [
            {"pattern": r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", "severity": "high"},
            {"pattern": r"Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", "severity": "high"},
            {"pattern": r"Connection closed by (?P<ip>\d+\.\d+\.\d+\.\d+) port", "severity": "low"},
            {"pattern": r"reverse mapping checking getaddrinfo for .*\[(?P<ip>\d+\.\d+\.\d+\.\d+)\] failed", "severity": "low"},
        ],
        "log_guesses": [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/syslog",
        ],
        "ports": [22],
    },
    "ftp": {
        "patterns": [
            {"pattern": r"FAIL LOGIN: Client \"(?P<ip>\d+\.\d+\.\d+\.\d+)\"", "severity": "high"},
            {"pattern": r"Authentication failed for user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", "severity": "high"},
            {"pattern": r"LOGIN FAILED.*ip=\[(?P<ip>\d+\.\d+\.\d+\.\d+)\]", "severity": "high"},
        ],
        "log_guesses": [
            "/var/log/vsftpd.log",
            "/var/log/proftpd/proftpd.log",
            "/var/log/pure-ftpd/transfer.log",
            "/var/log/syslog",
        ],
        "ports": [21],
    },
    "web": {
        "patterns": [
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*\"(GET|POST).*HTTP.*\" (401|403|404|500)", "severity": "low"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*\".*(union(?:\s|%20|\+)+(?:all(?:\s|%20|\+)+)?select\b|('|%27)(?:[^\"&]{0,40}?(?:%20|\+|\s|%09))?(?:or|and|union|select)(?!\w)|\bdrop\s+table\b|\binformation_schema\b|(?:sleep|benchmark|waitfor)\s*[\(%]|\b0x[0-9a-f]{6,}|\bchar\s*[\(%]\s*\d+|(?:select|insert|update|delete)\b[^\"&]{0,40}\b(?:0x|char|concat|substring|version|@@version)\b).*\"", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*\".*(\.\./|\.\.\\|%2e%2e|%c0%ae|/etc/passwd).*\"", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*\".*((?:<|%3c)script|javascript:|(?:onerror|onload|onclick|onfocus)=|(?:alert|prompt|confirm|eval)\s*(?:\(|%28)|document\.cookie|fromCharCode|data:text/html).*\"", "severity": "high"},
            {"pattern": r"user \"[^\"]+\" was not found.*client: (?P<ip>\d+\.\d+\.\d+\.\d+)", "severity": "high"},
            {"pattern": r"no user/password was provided for basic authentication.*client: (?P<ip>\d+\.\d+\.\d+\.\d+)", "severity": "high"},
            {"pattern": r"SSL handshake failed.*client: (?P<ip>\d+\.\d+\.\d+\.\d+)", "severity": "low"},
            {"pattern": r"\[client (?P<ip>\d+\.\d+\.\d+\.\d+):\d+\].*(AH01617|AH01618)", "severity": "high"},
        ],
        "log_guesses": [
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
            "/var/log/apache/access.log",
            "/var/log/apache/error.log",
            "/var/log/lighttpd/access.log",
            "/var/log/lighttpd/error.log",
            "/var/log/caddy/access.log",
            "/var/log/caddy/error.log",
            "/var/log/traefik/access.log",
            "/var/log/traefik/error.log",
            "/var/log/haproxy.log",
        ],
        "ports": [80, 443, 8080, 8443],
    },
    "database": {
        "patterns": [
            {"pattern": r"\[(?P<ip>\d+\.\d+\.\d+\.\d+)\].*authentication failed", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*Access denied for user", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*FATAL:.*password authentication failed", "severity": "high"},
            {"pattern": r"FATAL:.*password authentication failed for user \"(?P<user>\w+)\" from (?P<ip>\d+\.\d+\.\d+\.\d+)", "severity": "high"},
            {"pattern": r"FATAL:.*no pg_hba.conf entry for host \"(?P<ip>\d+\.\d+\.\d+\.\d+)\".*user \"(?P<user>\w+)\"", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*Authentication failed", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*not authorized", "severity": "medium"},
        ],
        "log_guesses": [
            "/var/log/mysql/error.log",
            "/var/log/mysql.log",
            "/var/log/postgresql/postgresql-*.log",
            "/var/log/mariadb/mariadb.log",
            "/var/log/mongodb/mongod.log",
            "/var/log/redis/redis-server.log",
            "/var/log/elasticsearch/*.log",
            "/var/log/cassandra/system.log",
        ],
        "ports": [3306, 5432, 27017, 1433, 6379, 9200, 9042],
    },
    "mail": {
        "patterns": [
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*authentication failed", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*SASL LOGIN authentication failed", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*imap-login:.*Authentication failure", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*pop3-login:.*Authentication failure", "severity": "high"},
        ],
        "log_guesses": [
            "/var/log/mail.log",
            "/var/log/maillog",
            "/var/log/postfix.log",
            "/var/log/dovecot.log",
            "/var/log/syslog",
        ],
        "ports": [25, 465, 587, 993, 995, 110, 143],
    },
    "vpn": {
        "patterns": [
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*TLS Error:.*authentication failed", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*VERIFY ERROR", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*authentication failed for peer", "severity": "high"},
            {"pattern": r"(?P<ip>\d+\.\d+\.\d+\.\d+).*Invalid user.*from.*port", "severity": "high"},
        ],
        "log_guesses": [
            "/var/log/openvpn.log",
            "/var/log/openvpn-status.log",
            "/var/log/wireguard.log",
            "/var/log/syslog",
        ],
        "ports": [1194, 51820, 51821, 443],
    },
}


def normalize_patterns(raw) -> List[dict]:
    """Accept a list of strings or {pattern, severity} dicts and normalize."""
    out = []
    for item in raw:
        if isinstance(item, str):
            out.append({"pattern": item, "severity": "low"})
        elif isinstance(item, dict) and item.get("pattern"):
            out.append(
                {
                    "pattern": str(item["pattern"]),
                    "severity": str(item.get("severity", "low")).lower(),
                }
            )
        else:
            raise ValueError("each rule must be a string or an object with a 'pattern'")
    for rule in out:
        if rule["severity"] not in SEVERITY_WEIGHTS:
            raise ValueError(
                f"unknown severity '{rule['severity']}' (use low, medium, high, critical)"
            )
    return out


def load_rules(rules_file=None) -> dict:
    """Read per-service rule overrides from a JSON file (empty dict if absent)."""
    path = Path(rules_file) if rules_file else RULES_FILE
    if not path.exists():
        return {}

    try:
        with open(path) as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError(f"could not read rules file {path}: {e}")

    if not isinstance(raw, dict):
        raise ValueError("rules file must be a JSON object keyed by service")

    merged = {}
    for service, overrides in raw.items():
        if not isinstance(overrides, dict):
            raise ValueError(f"rules for '{service}' must be an object")
        entry = {}
        if "patterns" in overrides:
            entry["patterns"] = normalize_patterns(overrides["patterns"])
        if "log_guesses" in overrides:
            guesses = overrides["log_guesses"]
            if not isinstance(guesses, list) or not all(isinstance(g, str) for g in guesses):
                raise ValueError(f"log_guesses for '{service}' must be a list of strings")
            entry["log_guesses"] = guesses
        if "ports" in overrides:
            ports = overrides["ports"]
            if not isinstance(ports, list):
                raise ValueError(f"ports for '{service}' must be a list")
            entry["ports"] = [int(p) for p in ports]
        merged[service] = entry
    return merged


def get_service_signatures(rules_file=None) -> Dict[str, dict]:
    """Built-in signatures merged with user rules (per-service patterns are replaced)."""
    merged = {
        service: {
            "patterns": list(sig["patterns"]),
            "log_guesses": list(sig.get("log_guesses", [])),
            "ports": list(sig.get("ports", [])),
        }
        for service, sig in SERVICE_SIGNATURES.items()
    }

    for service, overrides in load_rules(rules_file).items():
        if service in merged:
            merged[service].update(overrides)
        else:
            merged[service] = {
                "patterns": overrides.get("patterns", []),
                "log_guesses": overrides.get("log_guesses", []),
                "ports": overrides.get("ports", []),
            }

    for service, sig in merged.items():
        sig["patterns"] = normalize_patterns(sig.get("patterns", []))
        sig["log_guesses"] = [str(p) for p in sig.get("log_guesses", [])]
        sig["ports"] = [int(p) for p in sig.get("ports", [])]

    return merged


def known_services(rules_file=None) -> List[str]:
    return sorted(get_service_signatures(rules_file).keys())
