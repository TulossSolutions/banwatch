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
            watched = [p for p in paths if p and Path(p).exists()]
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

    def _tail(self, service: str, path: str):
        f = None
        try:
            f = open(path, "r")
            f.seek(0, 2)
            inode = os.fstat(f.fileno()).st_ino
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    try:
                        stat = os.stat(path)
                        if stat.st_ino != inode or stat.st_size < f.tell():
                            f.close()
                            f = open(path, "r")
                            inode = os.fstat(f.fileno()).st_ino
                    except FileNotFoundError:
                        pass
                    continue
                self._analyze(service, line)
        except Exception as e:
            logging.error(f"Error tailing {path}: {e}")
        finally:
            if f:
                f.close()

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
            self._track_attempt(ip, service, line, rule["weight"])
            break

    def _track_attempt(self, ip: str, service: str, line: str, weight: int):
        now = time.time()
        window = self.cfg["window"]
        threshold = self.cfg["threshold"]

        self.tracker[ip] = [(t, w) for (t, w) in self.tracker[ip] if now - t < window]
        self.tracker[ip].append((now, weight))

        score = sum(w for _, w in self.tracker[ip])
        count = len(self.tracker[ip])
        logging.debug(f"{ip} score {score} ({count} events) on {service}")

        if score >= threshold:
            is_new = self.db.quarantine(
                ip,
                service,
                f"{score} score ({count} events) on {service}",
                ban_duration=self.cfg.get("ban_duration", 0),
                ban_escalation=self.cfg.get("ban_escalation", 2),
            )
            if is_new:
                self.fw.block(ip)
                logging.warning(f"QUARANTINED: {ip} ({service}) - score {score}/{threshold}")
