import logging
import os
import re
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from .signatures import SEVERITY_WEIGHTS, get_service_signatures
from .utils import is_allowed_ip, is_known_bot, is_private_ip, validate_ip


class DetectorEngine:
    """Watches log files and quarantines attackers using weighted rule scores."""

    def __init__(self, cfg: dict, db, fw):
        self.cfg = cfg
        self.db = db
        self.fw = fw
        self.tracker: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self.patterns = self._compile_patterns()
        self.running = False
        self.threads: List[threading.Thread] = []
        self.new_bans = 0
        self.health_lock = threading.Lock()
        self.reader_health = {}

    def _compile_patterns(self) -> Dict[str, list]:
        compiled = {}
        sigs = get_service_signatures(self.cfg.get("rules_file"))
        for service in self.cfg["services"]:
            sig = sigs.get(service)
            if sig:
                compiled[service] = [
                    {
                        "re": re.compile(rule["pattern"], re.IGNORECASE),
                        "pattern": rule["pattern"],
                        "severity": rule["severity"],
                        "weight": SEVERITY_WEIGHTS.get(rule["severity"], 1),
                    }
                    for rule in sig["patterns"]
                ]
        return compiled

    def start(self):
        self.running = True
        for svc in self.cfg["services"]:
            paths = self.cfg["log_paths"].get(svc, [])
            watched = list(dict.fromkeys(p for p in paths if p))
            if watched:
                for log_path in watched:
                    t = threading.Thread(target=self._tail, args=(svc, log_path), daemon=True)
                    t.start()
                    self.threads.append(t)
                    logging.info(f"Watching {svc}: {log_path}")
            else:
                logging.warning(f"No log file for {svc}, skipping file watcher")

    def stop(self):
        self.running = False

    def health_snapshot(self):
        with self.health_lock:
            return {key: dict(value) for key, value in self.reader_health.items()}

    def _reader_state(self, service, path, state, read=False, error=False):
        with self.health_lock:
            row = self.reader_health.setdefault(service + ':' + path, {'last_read': 0, 'errors': 0})
            row['state'] = state
            if read:
                row['last_read'] = time.time()
            if error:
                row['errors'] += 1

    def _tail(self, service: str, path: str):
        f = None
        self._reader_state(service, path, 'starting')
        try:
            f = open(path, "r", errors="replace")
            f.seek(0, 2)
            inode = os.fstat(f.fileno()).st_ino
            self._reader_state(service, path, 'reading' if self.patterns.get(service) else 'no rules')
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    try:
                        stat = os.stat(path)
                        if stat.st_ino != inode or stat.st_size < f.tell():
                            f.close()
                            f = open(path, "r", errors="replace")
                            inode = os.fstat(f.fileno()).st_ino
                        self._reader_state(service, path, 'reading' if self.patterns.get(service) else 'no rules')
                    except FileNotFoundError:
                        self._reader_state(service, path, 'missing')
                    continue
                self._reader_state(service, path, 'reading', read=True)
                try:
                    self._analyze(service, line)
                except Exception as e:
                    self._reader_state(service, path, 'error', error=True)
                    logging.error(f"Error analyzing {service} log line: {e}")
        except Exception as e:
            self._reader_state(service, path, 'error', error=True)
            logging.error(f"Error tailing {path}: {e}")
        finally:
            self._reader_state(service, path, 'stopped')
            if f:
                f.close()

    def scan_existing(self) -> dict:
        """Read all configured log files from the start and analyze every line.

        Returns counts of lines read and newly quarantined IPs. Useful for
        catching attacks that happened before the daemon first started.
        """
        total_lines = 0
        self.new_bans = 0
        for svc in self.cfg["services"]:
            paths = self.cfg["log_paths"].get(svc, [])
            for log_path in paths:
                if not log_path or not Path(log_path).exists():
                    continue
                try:
                    with open(log_path, "r", errors="replace") as f:
                        for line in f:
                            total_lines += 1
                            try:
                                self._analyze(svc, line)
                            except Exception as e:
                                logging.error(f"Error analyzing {svc} log line: {e}")
                except Exception as e:
                    logging.error(f"Error scanning {log_path}: {e}")
        return {"lines": total_lines, "new_bans": self.new_bans}

    def _analyze(self, service: str, line: str):
        rules = self.patterns.get(service)
        if not rules:
            return

        if self.cfg.get("allow_known_bots") and is_known_bot(line):
            return

        for rule in rules:
            m = rule["re"].search(line)
            if not m:
                continue
            try:
                ip = validate_ip(m.group("ip"))
            except (IndexError, ValueError):
                return

            if is_allowed_ip(ip, self.cfg):
                logging.info(f"Skipping allowlisted IP: {ip}")
                return

            if not self.cfg.get("block_private") and is_private_ip(ip):
                logging.info(f"Skipping private IP: {ip}")
                return

            if self.db.is_quarantined(ip):
                return

            self.db.log_attack(ip, service, rule["pattern"], line)
            self._track_attempt(ip, service, line, rule["weight"], rule['pattern'])
            break

    def _track_attempt(self, ip: str, service: str, line: str, weight: int, pattern: str = ''):
        now = time.time()
        window = self.cfg["window"]
        threshold = self.cfg["threshold"]

        self.tracker[ip] = [(t, w) for (t, w) in self.tracker[ip] if now - t < window]
        self.tracker[ip].append((now, weight))

        score = sum(w for _, w in self.tracker[ip])
        count = len(self.tracker[ip])
        logging.debug(f"{ip} score {score} ({count} events) on {service}")

        if score >= threshold:
            if self.cfg.get('dry_run') or self.cfg.get('firewall') == 'none':
                logging.info('Detection only: threshold reached for %s on %s', ip, service)
                return
            if not self.fw.block(ip):
                logging.error('Block failed for %s; quarantine not recorded', ip)
                return
            is_new = self.db.quarantine(
                ip,
                service,
                f"{score} score ({count} events) on {service}" + (f"; rule: {pattern[:240]}" if pattern else ''),
                ban_duration=self.cfg.get("ban_duration", 0),
                ban_escalation=self.cfg.get("ban_escalation", 2),
            )
            if is_new:
                self.new_bans += 1
            logging.warning(f"QUARANTINED: {ip} ({service}) - score {score}/{threshold}")
