import ipaddress
import json
import shlex
import subprocess
import sys
from typing import List

from .utils import validate_ip

BACKENDS = ("iptables", "ufw", "nftables", "none")


class Firewall:
    def __init__(self, backend: str, dry_run: bool = False):
        self.backend = backend
        self.dry_run = dry_run
        self._nft_base_ready = False

    def block(self, ip: str) -> bool:
        ip = validate_ip(ip)
        if self.dry_run:
            print(f"[banwatch dry-run] would block {ip}", file=sys.stderr)
            return True
        if self.backend == "iptables":
            return self._iptables_block(ip)
        if self.backend == "ufw":
            return self._ufw(["deny", "from", ip])
        if self.backend == "nftables":
            return self._nft_block(ip)
        return False

    def unblock(self, ip: str) -> bool:
        ip = validate_ip(ip)
        if self.dry_run:
            print(f"[banwatch dry-run] would unblock {ip}", file=sys.stderr)
            return True
        if self.backend == "iptables":
            return self._iptables_unblock(ip)
        if self.backend == "ufw":
            return self._ufw(["delete", "deny", "from", ip])
        if self.backend == "nftables":
            return self._nft_unblock(ip)
        return True

    def _run(self, args: List[str], quiet: bool = False) -> int:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0 and not quiet:
                msg = (proc.stderr.strip() or proc.stdout.strip()).replace("\n", " ")
                print(f"[banwatch firewall] {args[0]} failed: {msg}", file=sys.stderr)
            return proc.returncode
        except subprocess.TimeoutExpired:
            if not quiet:
                print(f"[banwatch firewall] timeout running: {' '.join(args)}", file=sys.stderr)
            return 1
        except FileNotFoundError:
            if not quiet:
                print(f"[banwatch firewall] command not found: {args[0]}", file=sys.stderr)
            return 1

    def _iptables_rule(self, ip: str) -> List[str]:
        return ["INPUT", "-s", ip, "-j", "DROP"]

    def _iptables_block(self, ip: str) -> bool:
        if self._run(["iptables", "-C", *self._iptables_rule(ip)]) == 0:
            return True
        return self._run(["iptables", "-A", *self._iptables_rule(ip)]) == 0

    def _iptables_unblock(self, ip: str) -> bool:
        if self._run(["iptables", "-C", *self._iptables_rule(ip)]) != 0:
            return True
        return self._run(["iptables", "-D", *self._iptables_rule(ip)]) == 0

    def _ufw(self, args: List[str]) -> bool:
        return self._run(["ufw", *args]) == 0

    def _nft_base(self):
        if self._nft_base_ready:
            return
        self._run(["nft", "add", "table", "inet", "banwatch"], quiet=True)
        self._run(
            ["nft", "add", "chain", "inet", "banwatch", "drop", "{ type filter hook input priority 0 ; policy accept ; }"],
            quiet=True,
        )
        self._run(
            ["nft", "add", "set", "inet", "banwatch", "banned", "{ type ipv4_addr ; }"],
            quiet=True,
        )
        self._run(
            ["nft", "add", "rule", "inet", "banwatch", "drop", "ip saddr @banned counter drop"],
            quiet=True,
        )
        self._nft_base_ready = True

    def _nft_block(self, ip: str) -> bool:
        self._nft_base()
        rc = self._run(["nft", "add", "element", "inet", "banwatch", "banned", "{", ip, "}"])
        return rc == 0

    def _nft_unblock(self, ip: str) -> bool:
        self._nft_base()
        if not self._nft_contains(ip):
            return True
        return self._run(["nft", "delete", "element", "inet", "banwatch", "banned", "{", ip, "}"]) == 0

    def _nft_contains(self, ip: str) -> bool:
        proc = subprocess.run(
            ["nft", "list", "set", "inet", "banwatch", "banned"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return any(ip in line for line in proc.stdout.splitlines())

    def audit(self, active_ips):
        """Read rule presence only; never repair or assert packet-path effectiveness."""
        if self.dry_run or self.backend == 'none':
            return {'status': 'detection only', 'present': 0, 'expected': len(active_ips)}
        try:
            if self.backend in ('iptables', 'ufw'):
                if self.backend == 'ufw':
                    state = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10, check=True)
                    if not any(line.strip() == 'Status: active' for line in state.stdout.splitlines()):
                        return {'status': 'disabled or unverified', 'expected': len(active_ips)}
                proc = subprocess.run(['iptables-save', '-t', 'filter'], capture_output=True, text=True, timeout=10, check=True)
                chain = 'INPUT' if self.backend == 'iptables' else 'ufw-user-input'
                found = set()
                for line in proc.stdout.splitlines():
                    parts = shlex.split(line)
                    if len(parts) == 6 and parts[:3] == ['-A', chain, '-s'] and parts[4:] == ['-j', 'DROP']:
                        network = ipaddress.ip_network(parts[3], strict=False)
                        if network.version == 4 and network.prefixlen == 32:
                            found.add(str(network.network_address))
            else:
                proc = subprocess.run(['nft', '-j', 'list', 'table', 'inet', 'banwatch'], capture_output=True, text=True, timeout=10, check=True)
                objects = json.loads(proc.stdout)['nftables']
                sets = [o['set'] for o in objects if 'set' in o and o['set'].get('name') == 'banned']
                chains = [o['chain'] for o in objects if 'chain' in o and o['chain'].get('name') == 'drop' and o['chain'].get('hook') == 'input']
                linked = any(o.get('rule', {}).get('chain') == 'drop' and
                             {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '@banned'}} in o['rule'].get('expr', []) and
                             {'drop': None} in o['rule'].get('expr', []) for o in objects if 'rule' in o)
                if not sets or not chains or not linked:
                    return {'status': 'unverified', 'expected': len(active_ips)}
                found = {e for s in sets for e in s.get('elem', []) if isinstance(e, str)}
            missing = set(active_ips) - found
            return {'status': 'rules found' if not missing else 'rules missing',
                    'present': len(set(active_ips) & found), 'expected': len(active_ips), 'missing': len(missing)}
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            return {'status': 'unverified', 'expected': len(active_ips)}
