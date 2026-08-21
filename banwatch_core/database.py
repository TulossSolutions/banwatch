import sqlite3
import threading
from datetime import datetime, timedelta
from typing import List, Tuple

from .paths import DB_FILE
from .utils import ensure_dirs, validate_ip


class BanwatchDB:
    def __init__(self):
        ensure_dirs()
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(DB_FILE), check_same_thread=False, timeout=30)
        self._init_tables()

    def _init_tables(self):
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS bans (
                    ip TEXT PRIMARY KEY,
                    service TEXT,
                    reason TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    attempts INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'quarantined'
                );
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    service TEXT,
                    pattern TEXT,
                    line TEXT,
                    timestamp TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(ip);
                CREATE INDEX IF NOT EXISTS idx_attacks_time ON attacks(timestamp);
            """
            )
            self.conn.commit()
            try:
                DB_FILE.chmod(0o600)
            except OSError:
                pass
            try:
                self.conn.execute("ALTER TABLE bans ADD COLUMN banned_until TEXT")
                self.conn.commit()
            except sqlite3.OperationalError:
                pass

    def quarantine(self, ip: str, service: str, reason: str, ban_duration: int = 0, ban_escalation: float = 2):
        ip = validate_ip(ip)
        now = datetime.now()
        with self.lock:
            cur = self.conn.execute("SELECT attempts FROM bans WHERE ip=?", (ip,))
            row = cur.fetchone()
            attempts = (row[0] + 1) if row else 1
            banned_until = None
            if ban_duration and ban_duration > 0:
                seconds = int(ban_duration * (ban_escalation ** (attempts - 1)))
                banned_until = (now + timedelta(seconds=seconds)).isoformat()
            if row:
                self.conn.execute(
                    "UPDATE bans SET attempts=?, last_seen=?, status='quarantined', banned_until=? WHERE ip=?",
                    (attempts, now.isoformat(), banned_until, ip),
                )
            else:
                self.conn.execute(
                    "INSERT INTO bans (ip, service, reason, first_seen, last_seen, attempts, status, banned_until) VALUES (?,?,?,?,?,?,'quarantined',?)",
                    (ip, service, reason, now.isoformat(), now.isoformat(), attempts, banned_until),
                )
            self.conn.commit()
            return row is None

    def release(self, ip: str):
        ip = validate_ip(ip)
        with self.lock:
            self.conn.execute("UPDATE bans SET status='released' WHERE ip=?", (ip,))
            self.conn.commit()

    def is_quarantined(self, ip: str) -> bool:
        ip = validate_ip(ip)
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM bans WHERE ip=? AND status='quarantined'", (ip,)
            )
            return cur.fetchone() is not None

    def get_expired(self, now_iso: str = None) -> List[str]:
        """IPs whose quarantine has expired and are still marked quarantined."""
        now_iso = now_iso or datetime.now().isoformat()
        with self.lock:
            cur = self.conn.execute(
                "SELECT ip FROM bans WHERE status='quarantined' AND banned_until IS NOT NULL AND banned_until <= ?",
                (now_iso,),
            )
            return [r[0] for r in cur.fetchall()]

    def mark_expired(self, ip: str):
        ip = validate_ip(ip)
        with self.lock:
            self.conn.execute("UPDATE bans SET status='expired' WHERE ip=?", (ip,))
            self.conn.commit()

    def log_attack(self, ip: str, service: str, pattern: str, line: str):
        ip = validate_ip(ip)
        with self.lock:
            self.conn.execute(
                "INSERT INTO attacks (ip, service, pattern, line, timestamp) VALUES (?,?,?,?,?)",
                (ip, service, pattern, line[:500], datetime.now().isoformat()),
            )
            self.conn.commit()

    def get_stats(self) -> dict:
        with self.lock:
            total = self.conn.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
            active = self.conn.execute(
                "SELECT COUNT(*) FROM bans WHERE status='quarantined'"
            ).fetchone()[0]
            by_service = self.conn.execute(
                "SELECT service, COUNT(*) FROM bans GROUP BY service"
            ).fetchall()
            recent = self.conn.execute(
                "SELECT COUNT(*) FROM attacks WHERE timestamp > datetime('now', '-1 day')"
            ).fetchone()[0]
        return {
            "total_entries": total,
            "active_quarantined": active,
            "by_service": dict(by_service),
            "attacks_24h": recent,
        }

    def get_ban_list(self, limit: int = 50) -> List[dict]:
        with self.lock:
            cur = self.conn.execute(
                "SELECT ip, service, reason, attempts, first_seen, last_seen, status, banned_until FROM bans ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_top_offenders(self, limit: int = 10) -> List[dict]:
        with self.lock:
            cur = self.conn.execute(
                """
                SELECT ip, service, COUNT(*) as events, MAX(timestamp) as last_seen
                FROM attacks GROUP BY ip, service ORDER BY events DESC LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_service_breakdown(self) -> List[Tuple[str, int, int]]:
        with self.lock:
            cur = self.conn.execute(
                """
                SELECT
                    service,
                    COUNT(*) as total,
                    SUM(CASE WHEN status='quarantined' THEN 1 ELSE 0 END) as active
                FROM bans GROUP BY service ORDER BY total DESC
            """
            )
            return cur.fetchall()
