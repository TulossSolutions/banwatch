import ipaddress
import os
import sys
from typing import List

from .paths import CONFIG_DIR, REPORT_DIR


def sudo_check():
    if os.geteuid() != 0:
        print("BanWatch requires root privileges for firewall rules.")
        print("   Run with: sudo banwatch <command>")
        sys.exit(1)


def ensure_dirs():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
        REPORT_DIR.chmod(0o750)
    except OSError:
        pass


def validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError as e:
        raise ValueError(f"Invalid IPv4 address: {ip}") from e


def normalize_allowlist(entries: List[str]) -> List[str]:
    if not isinstance(entries, list):
        raise ValueError("allowlist must be a list")

    networks = []
    for entry in entries:
        try:
            networks.append(str(ipaddress.IPv4Network(str(entry), strict=False)))
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid allowlist IPv4/CIDR entry: {entry}") from e
    return networks


def is_allowed_ip(ip: str, cfg: dict) -> bool:
    addr = ipaddress.IPv4Address(validate_ip(ip))
    for network in cfg.get("allowlist", []):
        if addr in ipaddress.IPv4Network(network, strict=False):
            return True
    return False


def is_private_ip(ip: str) -> bool:
    addr = ipaddress.IPv4Address(validate_ip(ip))
    return addr.is_private or addr.is_loopback or addr.is_link_local


KNOWN_BOTS = {
    "Google": ["Googlebot", "Googlebot-Image", "Googlebot-News", "Googlebot-Video",
               "Mediapartners-Google", "AdsBot-Google", "FeedFetcher-Google", "Google-InspectionTool"],
    "Bing": ["bingbot", "BingPreview", "msnbot"],
    "Yandex": ["YandexBot", "YandexImages", "YandexNews", "YandexMetrika"],
    "Baidu": ["Baiduspider"],
    "DuckDuckGo": ["DuckDuckBot"],
    "Apple": ["Applebot"],
    "Sogou": ["Sogou web spider"],
    "PetalBot": ["PetalBot"],
    "Yahoo": ["Slurp"],
    "Common Crawl": ["CCBot"],
    "Amazon": ["Amazonbot"],
    "OpenAI (GPTBot)": ["GPTBot", "ChatGPT-User", "OAI-SearchBot"],
    "Anthropic (ClaudeBot)": ["ClaudeBot", "Claude-Web", "anthropic-ai"],
    "Perplexity": ["PerplexityBot"],
    "Cohere": ["cohere-ai"],
    "Meta": ["Meta-ExternalAgent"],
    "ByteDance": ["Bytespider"],
}


def is_known_bot(line: str) -> bool:
    """True if a log line carries a known legitimate bot user-agent."""
    low = line.lower()
    return any(agent.lower() in low for agents in KNOWN_BOTS.values() for agent in agents)
