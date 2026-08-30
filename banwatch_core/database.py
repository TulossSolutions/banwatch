import json
import logging
import sqlite3
import threading
import time
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
                CREATE TABLE IF NOT EXISTS report_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generated_at TEXT,
                    total_entries INTEGER,
                    active_quarantined INTEGER,
                    attacks_24h INTEGER,
                    services_protected INTEGER
                );
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
            self._init_reporting()

    def _init_reporting(self):
        self.conn.execute('BEGIN IMMEDIATE')
        columns = {row[1] for row in self.conn.execute('PRAGMA table_info(attacks)')}
        if 'occurred_at' not in columns:
            self.conn.execute('ALTER TABLE attacks ADD COLUMN occurred_at REAL')
        # Also resume interrupted migrations or rows written by an older binary.
        rows = self.conn.execute('SELECT id, timestamp FROM attacks WHERE occurred_at IS NULL').fetchall()
        converted = []
        for row_id, timestamp in rows:
            try:
                converted.append((datetime.fromisoformat(timestamp).timestamp(), row_id))
            except (ValueError, TypeError, OverflowError, OSError):
                logging.warning('Invalid historical attack timestamp at row %s', row_id)
        self.conn.executemany('UPDATE attacks SET occurred_at=? WHERE id=?', converted)
        self.conn.commit()
        self.conn.executescript('''
            CREATE INDEX IF NOT EXISTS idx_attacks_occurred ON attacks(occurred_at);
            CREATE TABLE IF NOT EXISTS ban_events (
                id INTEGER PRIMARY KEY, ip TEXT, service TEXT, action TEXT, occurred_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_ban_events_time ON ban_events(occurred_at);
            CREATE TABLE IF NOT EXISTS report_baselines (
                scope TEXT PRIMARY KEY, generated_at REAL, metrics TEXT
            );
            CREATE TABLE IF NOT EXISTS report_schedule (
                scope TEXT PRIMARY KEY, next_due REAL, attempts INTEGER DEFAULT 0,
                last_success REAL, last_attempt REAL, last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS report_metadata (key TEXT PRIMARY KEY, value TEXT);
        ''')
        self.conn.execute("INSERT OR IGNORE INTO report_metadata VALUES ('tracking_since', ?)", (str(time.time()),))
        self.conn.commit()

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
                    "UPDATE bans SET attempts=?, last_seen=?, status='quarantined', banned_until=?, service=?, reason=? WHERE ip=?",
                    (attempts, now.isoformat(), banned_until, service, reason, ip),
                )
            else:
                self.conn.execute(
                    "INSERT INTO bans (ip, service, reason, first_seen, last_seen, attempts, status, banned_until) VALUES (?,?,?,?,?,?,'quarantined',?)",
                    (ip, service, reason, now.isoformat(), now.isoformat(), attempts, banned_until),
                )
            self.conn.execute(
                'INSERT INTO ban_events (ip, service, action, occurred_at) VALUES (?,?,?,?)',
                (ip, service, 'reban' if row else 'ban', time.time()),
            )
            self.conn.commit()
            return row is None

    def release(self, ip: str):
        ip = validate_ip(ip)
        with self.lock:
            self._record_end(ip, 'release')
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
            self._record_end(ip, 'expire')
            self.conn.execute("UPDATE bans SET status='expired' WHERE ip=?", (ip,))
            self.conn.commit()

    def _record_end(self, ip, action):
        self.conn.execute(
            "INSERT INTO ban_events (ip,service,action,occurred_at) "
            "SELECT ip,service,?,? FROM bans WHERE ip=? AND status='quarantined'",
            (action, time.time(), ip),
        )

    def log_attack(self, ip: str, service: str, pattern: str, line: str):
        ip = validate_ip(ip)
        with self.lock:
            self.conn.execute(
                "INSERT INTO attacks (ip, service, pattern, line, timestamp, occurred_at) VALUES (?,?,?,?,?,?)",
                (ip, service, pattern, line[:500], datetime.now().isoformat(), time.time()),
            )
            self.conn.commit()

    def get_stats(self) -> dict:
        now = time.time()
        with self.lock:
            total = self.conn.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
            active = self.conn.execute(
                "SELECT COUNT(*) FROM bans WHERE status='quarantined'"
            ).fetchone()[0]
            by_service = self.conn.execute(
                "SELECT service, COUNT(*) FROM bans GROUP BY service"
            ).fetchall()
            recent = self.conn.execute(
                'SELECT COUNT(*) FROM attacks WHERE occurred_at >= ? AND occurred_at < ?',
                (now - 86400, now),
            ).fetchone()[0]
        return {
            "total_entries": total,
            "active_quarantined": active,
            "by_service": dict(by_service),
            "attacks_24h": recent,
        }

    def get_latest_report_snapshot(self) -> dict:
        with self.lock:
            cur = self.conn.execute(
                """
                SELECT generated_at, total_entries, active_quarantined, attacks_24h, services_protected
                FROM report_snapshots ORDER BY id DESC LIMIT 1
                """
            )
            row = cur.fetchone()
            if not row:
                return {}
            cols = [c[0] for c in cur.description]
            return dict(zip(cols, row))

    def save_report_snapshot(self, stats: dict, services_protected: int):
        with self.lock:
            self.conn.execute(
                """
                INSERT INTO report_snapshots (
                    generated_at, total_entries, active_quarantined, attacks_24h, services_protected
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().isoformat(),
                    int(stats["total_entries"]),
                    int(stats["active_quarantined"]),
                    int(stats["attacks_24h"]),
                    int(services_protected),
                ),
            )
            self.conn.commit()

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

    def report_data(self, end: float, seconds: int, scope: str) -> dict:
        start = end - seconds
        with self.lock:
            # One SQLite read transaction also excludes interleaved writes by other processes.
            self.conn.execute('BEGIN')
            try:
                stats = self.get_stats()
                events = self.conn.execute(
                    'SELECT COUNT(*) FROM attacks WHERE occurred_at>=? AND occurred_at<?', (start, end)
                ).fetchone()[0]
                previous_events = self.conn.execute(
                    'SELECT COUNT(*) FROM attacks WHERE occurred_at>=? AND occurred_at<?', (start-seconds, start)
                ).fetchone()[0]
                by_service = dict(self.conn.execute(
                    'SELECT service,COUNT(*) FROM attacks WHERE occurred_at>=? AND occurred_at<? GROUP BY service',
                    (start, end),
                ).fetchall())
                cursor = self.conn.execute('''
                    SELECT a.ip,a.service,COUNT(*) AS events,MAX(a.occurred_at) AS last_seen,
                           b.status,b.reason,b.banned_until,b.attempts
                    FROM attacks a LEFT JOIN bans b ON a.ip=b.ip
                    WHERE a.occurred_at>=? AND a.occurred_at<?
                    GROUP BY a.ip,a.service ORDER BY events DESC,a.ip,a.service LIMIT 10
                ''', (start,end))
                offenders = [dict(zip([c[0] for c in cursor.description], r)) for r in cursor.fetchall()]
                actions = dict(self.conn.execute(
                    'SELECT action,COUNT(*) FROM ban_events WHERE occurred_at>=? AND occurred_at<? GROUP BY action',
                    (start,end),
                ).fetchall())
                baseline = self.conn.execute('SELECT generated_at,metrics FROM report_baselines WHERE scope=?', (scope,)).fetchone()
                return {
                    'start': start, 'end': end, 'seconds': seconds, 'stats': stats,
                    'events': events, 'previous_events': previous_events, 'events_by_service': by_service,
                    'breakdown': self.get_service_breakdown(), 'offenders': offenders,
                    'bans': self.get_ban_list(100), 'actions': actions,
                    'active_ips': [r[0] for r in self.conn.execute("SELECT ip FROM bans WHERE status='quarantined'")],
                    'tracking_since': float(self.conn.execute("SELECT value FROM report_metadata WHERE key='tracking_since'").fetchone()[0]),
                    'invalid_timestamps': self.conn.execute('SELECT COUNT(*) FROM attacks WHERE occurred_at IS NULL').fetchone()[0],
                    'baseline': {'generated_at': baseline[0], **json.loads(baseline[1])} if baseline else {},
                }
            finally:
                self.conn.rollback()

    def save_report_baseline(self, scope: str, generated_at: float, metrics: dict):
        with self.lock:
            self.conn.execute('''
                INSERT INTO report_baselines VALUES (?,?,?) ON CONFLICT(scope) DO UPDATE SET
                generated_at=excluded.generated_at,metrics=excluded.metrics
                WHERE excluded.generated_at>report_baselines.generated_at
            ''', (scope,generated_at,json.dumps(metrics)))
            self.conn.commit()

    def next_report_due(self, scope: str, interval: int, now: float) -> float:
        with self.lock:
            self.conn.execute('INSERT OR IGNORE INTO report_schedule (scope,next_due) VALUES (?,?)', (scope,now+interval))
            self.conn.commit()
            return self.conn.execute('SELECT next_due FROM report_schedule WHERE scope=?', (scope,)).fetchone()[0]

    def finish_report_attempt(self, scope: str, interval: int, now: float, success: bool):
        with self.lock:
            row = self.conn.execute('SELECT attempts FROM report_schedule WHERE scope=?', (scope,)).fetchone()
            attempts = 0 if success else (row[0] if row else 0)+1
            delay = interval if success or attempts >= 3 else 900 * attempts
            self.conn.execute('''
                UPDATE report_schedule SET next_due=?,attempts=?,last_attempt=?,
                last_success=CASE WHEN ? THEN ? ELSE last_success END,last_error=? WHERE scope=?
            ''', (now+delay,0 if attempts>=3 else attempts,now,success,now,
                  None if success else 'Report delivery or generation failed',scope))
            self.conn.commit()
