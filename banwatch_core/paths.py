from pathlib import Path

APP_NAME = "banwatch"
CONFIG_DIR = Path("/etc/banwatch")
CONFIG_FILE = CONFIG_DIR / "config.json"
RULES_FILE = CONFIG_DIR / "rules.json"
DB_FILE = CONFIG_DIR / "banwatch.db"
PID_FILE = Path("/var/run/banwatch.pid")
REPORT_DIR = Path("/var/log/banwatch")
