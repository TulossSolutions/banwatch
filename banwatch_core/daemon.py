import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from .config import load_config
from .database import BanwatchDB
from .detector import DetectorEngine
from .firewall import Firewall
from .paths import PID_FILE, REPORT_DIR
from .reporter import Reporter
from .utils import sudo_check

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX dev environments
    fcntl = None


class Daemon:
    def __init__(self, cfg=None):
        self.cfg = cfg or load_config()
        self.db = BanwatchDB()
        self.fw = Firewall(
            self.cfg["firewall"], dry_run=self.cfg.get("dry_run", False)
        )
        self.detector = DetectorEngine(self.cfg, self.db, self.fw)
        self.reporter = Reporter(self.db, self.cfg)
        self._shutdown = threading.Event()

    def run(self):
        PID_FILE.write_text(str(os.getpid()))
        try:
            PID_FILE.chmod(0o644)
        except OSError:
            pass

        signal.signal(signal.SIGTERM, lambda signum, frame: self.shutdown())
        signal.signal(signal.SIGINT, lambda signum, frame: self.shutdown())

        log_path = REPORT_DIR / "banwatch.log"
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler(sys.stdout),
            ],
        )

        logging.info("BanWatch daemon starting...")
        logging.info(f"   Services: {', '.join(self.cfg['services'])}")
        logging.info(f"   Firewall: {self.cfg['firewall']}")
        logging.info(f"   Threshold: {self.cfg['threshold']} score in {self.cfg['window']}s")
        if self.cfg.get("dry_run"):
            logging.warning("DRY RUN MODE: detections are logged but no firewall rules are applied")

        self.detector.start()

        freq = self.cfg.get("report_frequency", "weekly")
        interval_hours = {"daily": 24, "weekly": 168, "monthly": 720}.get(freq, 168)
        next_report = time.time() + interval_hours * 3600
        next_expiry_check = time.time() + 30

        try:
            while not self._shutdown.is_set():
                time.sleep(1)
                if time.time() >= next_expiry_check:
                    self._expire_due_bans()
                    next_expiry_check = time.time() + 30
                if time.time() >= next_report:
                    self.reporter.save_and_maybe_email()
                    next_report = time.time() + interval_hours * 3600
        except KeyboardInterrupt:
            pass
        finally:
            self.detector.stop()
            if PID_FILE.exists():
                PID_FILE.unlink()
            logging.info("BanWatch daemon stopped.")

    def shutdown(self):
        self._shutdown.set()

    def _expire_due_bans(self):
        """Unblock quarantined IPs whose ban duration has elapsed (repeat offenders are re-banned with escalation)."""
        for ip in self.db.get_expired():
            if self.fw.unblock(ip):
                self.db.mark_expired(ip)
                logging.info(f"Ban expired, unblocked {ip}")


def _acquire_lock():
    """Atomically claim the daemon via flock on the PID file."""
    try:
        fd = open(PID_FILE, "w")
    except OSError:
        print("Could not open PID file.")
        return None

    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fd.close()
            return None

    #try:
    #    fd.write(str(os.getpid()))
    #    fd.flush()
    #except OSError:
    #    pass
    return fd


def start_daemon(dry_run: bool = False):
    sudo_check()
    cfg = load_config()
    if dry_run:
        cfg["dry_run"] = True
    if not cfg.get("services"):
        print("Not configured. Run: sudo banwatch setup")
        sys.exit(1)

    lock_fd = _acquire_lock()
    if lock_fd is None:
        msg = ""
        try:
            msg = f" (PID {PID_FILE.read_text().strip()})"
        except OSError:
            pass
        print(f"Already running{msg}")
        return

    pid = os.fork()
    if pid > 0:
        # ✅ NEW: Parent waits for grandchild to write a valid PID
        for _ in range(50):  # Wait up to 5 seconds
            time.sleep(0.1)
            if PID_FILE.exists():
                try:
                    child_pid = int(PID_FILE.read_text().strip())
                    os.kill(child_pid, 0)  # Verify process exists
                    print(f"BanWatch enabled (PID {child_pid})")
                    if lock_fd:
                        lock_fd.close()
                    sys.exit(0)
                except (ValueError, ProcessLookupError, PermissionError):
                    continue
        print("Error: BanWatch failed to start (PID not valid)")
        if lock_fd:
            lock_fd.close()
        sys.exit(1)

    # ✅ NEW: Close lock fd in child (no longer needed)
    if lock_fd:
        lock_fd.close()

    os.setsid()
    os.umask(0o077)

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()
    with open("/dev/null", "r") as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open("/dev/null", "a+") as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())
    
    # ✅ PID written HERE (grandchild, after second fork)
    PID_FILE.write_text(str(os.getpid()))
    try:
        PID_FILE.chmod(0o644)
    except OSError:
        pass

    Daemon(cfg=cfg).run()


def stop_daemon():
    sudo_check()
    if not PID_FILE.exists():
        print("Not running.")
        return

    try:
        pid = int(PID_FILE.read_text().strip())
    except ValueError:
        PID_FILE.unlink()
        print("Invalid PID file removed.")
        return

    try:
        os.kill(pid, signal.SIGTERM)
        print("BanWatch disabled.")
    except ProcessLookupError:
        PID_FILE.unlink()
        print("Stale PID file removed.")
