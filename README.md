# 🔒 BanWatch

**Defensive security as simple as UFW.**

BanWatch scans your services, detects brute-force bots in real-time, and automatically quarantines attackers. No external dependencies. One command to set up, one command to run.

---

## Install

Requires Python 3.8+ (no pip packages needed) and `sudo`. There are two ways to get the files onto your server.

### 1. Get the files

**Option A — copy from your local machine (git clone or scp):**

```bash
git clone https://github.com/TulossSolutions/banwatch.git
cd banwatch
```

or copy the `banwatch` launcher and `banwatch_core/` folder directly via `scp`.

**Option B — download on the server:**

```bash
cd /tmp
curl -L https://github.com/TulossSolutions/banwatch/archive/refs/heads/main.tar.gz | tar xz
cd banwatch-main
```

### 2. Install to `/usr/local/bin`

```bash
sudo install -m 755 banwatch /usr/local/bin/banwatch
sudo cp -r banwatch_core /usr/local/bin/
```

`install -m 755` sets the executable bit even when the file was copied from a system without Unix modes (e.g. Windows over scp). Without it you get `sudo: banwatch: command not found`.

**Windows/scp gotcha:** if you copied files from Windows, the `banwatch` script may have Windows line endings (`\r`), breaking its shebang line. If you see `/usr/bin/env: 'python3\r': No such file or directory`, fix with:

```bash
sudo sed -i 's/\r$//' /usr/local/bin/banwatch
```

### 3. Run the setup wizard

```bash
sudo banwatch setup
```

The interactive wizard asks which services to protect, auto-detects log files, picks your firewall (iptables/ufw/nftables), sets quarantine thresholds, manages the allowlist, and optionally configures email or webhook report digests.

### Alternative: run without the executable

If you'd rather not rely on the installed launcher (or want to run straight from the source tree), use the module directly:

```bash
sudo python3 -m banwatch_core setup    # from inside the banwatch/ folder
```

---

## Commands

| Command | Description |
|---------|-------------|
| `sudo banwatch setup` | Interactive first-time configuration |
| `sudo banwatch systemd` | Write the systemd unit file (then `systemctl enable --now banwatch`) |
| `sudo banwatch enable [--dry-run]` | Start the background daemon manually (optionally detect-only) |
| `sudo banwatch disable` | Stop the daemon |
| `sudo banwatch status` | Show stats, ban list, and service breakdown |
| `sudo banwatch release <IP>` | Free an IP from quarantine |
| `sudo banwatch report [--format html\|json\|csv]` | Generate a report (default: html) |
| `sudo banwatch scan` | Scan existing log files from the start for past attacks |
| `sudo banwatch rules [service]` | Show active patterns with severity/weight |
| `banwatch test-line <service> "<log line>"` | Identify which rule(s) match a line |
| `sudo banwatch allowlist add\|remove <IP/CIDR>` | Manage the allowlist interactively |
| `sudo banwatch allowlist list` | Show the allowlist |

---

## Auto-Detected Services

BanWatch automatically finds log files for the following services. If your logs live elsewhere, edit `/etc/banwatch/config.json`.

### Web Servers (15 paths)
| Service | Default Log Files |
|---------|------------------|
| **Nginx** | `/var/log/nginx/access.log`, `/var/log/nginx/error.log` |
| **Apache2** | `/var/log/apache2/access.log`, `/var/log/apache2/error.log` |
| **Apache (httpd)** | `/var/log/httpd/access_log`, `/var/log/httpd/error_log`, `/var/log/apache/access.log`, `/var/log/apache/error.log` |
| **Lighttpd** | `/var/log/lighttpd/access.log`, `/var/log/lighttpd/error.log` |
| **Caddy** | `/var/log/caddy/access.log`, `/var/log/caddy/error.log` |
| **Traefik** | `/var/log/traefik/access.log`, `/var/log/traefik/error.log` |
| **HAProxy** | `/var/log/haproxy.log` |

### Databases (8 paths)
| Service | Default Log File |
|---------|------------------|
| **MySQL** | `/var/log/mysql/error.log`, `/var/log/mysql.log` |
| **MariaDB** | `/var/log/mariadb/mariadb.log` |
| **PostgreSQL** | `/var/log/postgresql/postgresql-*.log` |
| **MongoDB** | `/var/log/mongodb/mongod.log` |
| **Redis** | `/var/log/redis/redis-server.log` |
| **Elasticsearch** | `/var/log/elasticsearch/*.log` |
| **Cassandra** | `/var/log/cassandra/system.log` |

### Other Services
| Service | Default Log File | What It Detects |
|---------|------------------|-----------------|
| **SSH** | `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog` | Failed passwords, invalid users |
| **FTP** | `/var/log/vsftpd.log`, `/var/log/proftpd/proftpd.log`, `/var/log/pure-ftpd/transfer.log`, `/var/log/syslog` | Failed logins |
| **Mail** | `/var/log/mail.log`, `/var/log/maillog`, `/var/log/postfix.log`, `/var/log/dovecot.log`, `/var/log/syslog` | SASL/auth failures, IMAP/POP3 brute force |
| **VPN** | `/var/log/openvpn.log`, `/var/log/openvpn-status.log`, `/var/log/wireguard.log`, `/var/log/syslog` | TLS/auth errors, invalid peers |

**Total: 6 service categories, 39 log file paths.** All matching paths per service are watched (e.g., both `access.log` and `error.log`). Wildcards (e.g., `postgresql-*.log`, `elasticsearch/*.log`) are expanded automatically.

---

## Configuration Files

All settings are stored in plain JSON. Edit them anytime with any text editor — no need to re-run `setup`.

### Relevant Files

| File | Purpose | Editable? |
|------|---------|-----------|
| `/etc/banwatch/config.json` | Main configuration: services, log paths, thresholds, firewall | ✅ Yes |
| `/etc/banwatch/rules.json` | Optional custom rules overriding built-in signatures | ✅ Yes |
| `/etc/banwatch/banwatch.db` | SQLite database: quarantined IPs, attack history | ⚠️ Use CLI commands |
| `/var/run/banwatch.pid` | Daemon process ID + flock lock | ❌ Managed automatically |
| `/var/log/banwatch/` | HTML/JSON/CSV reports and daemon logs | ❌ Generated automatically |

### Editing `config.json`

```bash
sudo nano /etc/banwatch/config.json
sudo systemctl restart banwatch   # apply changes (or: banwatch disable && banwatch enable)
```

### Example Config

```json
{
  "_readme": "BanWatch configuration — edit freely and restart with: banwatch disable && banwatch enable",
    "_fields": {
    "services": "List: ssh, web, database, ftp, mail, vpn, or ['all']",
    "log_paths": "Override auto-detected log locations per service (string or list of strings)",
    "allowlist": "IPv4/CIDR entries that must never be quarantined",
    "firewall": "Backend: 'iptables', 'ufw', 'nftables', or 'none'",
    "threshold": "Score threshold for quarantine (sum of rule weights within window)",
    "window": "Seconds to count attempts within (integer)",
    "email": "Report recipient (string) or null to disable",
    "report_frequency": "daily, weekly, or monthly",
    "dry_run": "Detect and report only; never modify the firewall (true/false)",
    "block_private": "Allow quarantining private/loopback IPs (true/false, default false)",
    "ban_duration": "Seconds a quarantine lasts before auto-release; 0 = permanent (default 0)",
    "ban_escalation": "Multiplier applied to each repeat offense, e.g. 2 = 1h, 2h, 4h... (default 2)",
    "rules_file": "Path to custom rules JSON merged over built-in signatures",
    "webhooks": "List of {'type': 'slack'|'discord'|'generic', 'url': ...} for report digests"
  },
  "firewall": "ufw",
  "threshold": 5,
  "window": 300,
  "services": ["ssh", "web", "database", "mail"],
  "log_paths": {
    "ssh": "/var/log/auth.log",
    "web": ["/var/log/nginx/access.log", "/var/log/nginx/error.log"],
    "database": "/var/log/mysql/error.log",
    "mail": "/var/log/mail.log"
  },
  "allowlist": ["127.0.0.1", "192.168.1.0/24"],
  "email": "admin@example.com",
  "report_frequency": "weekly",
  "dry_run": false,
  "block_private": false,
  "ban_duration": 0,
  "ban_escalation": 2,
  "rules_file": "/etc/banwatch/rules.json",
  "webhooks": [
    {"type": "slack", "url": "https://hooks.slack.com/services/XXX"}
  ]
}
```

### Config Reference

| Key | Description | Valid Values |
|-----|-------------|--------------|
| `services` | Which services to watch | `["ssh"]`, `["ssh", "web"]`, `["all"]` |
| `log_paths` | Override auto-detected log paths per service (multiple files watched) | `{"web": ["/var/log/nginx/access.log", "/var/log/nginx/error.log"]}` |
| `allowlist` | IPs or CIDR ranges never quarantined | `["127.0.0.1", "192.168.1.0/24"]` |
| `firewall` | Backend for blocking IPs | `"iptables"`, `"ufw"`, `"nftables"`, `"none"` |
| `threshold` | Score threshold for quarantine (see Rules & Severity) | Any integer (default: `5`) |
| `window` | Time window for counting attempts (seconds) | Any integer (default: `300`) |
| `email` | Report recipient (optional, `null` to disable) | `"you@domain.com"` or `null` |
| `report_frequency` | How often to email reports | `"daily"`, `"weekly"`, `"monthly"` |
| `dry_run` | Detect and report only, never block | `true` or `false` (default `false`) |
| `block_private` | Allow quarantining private/loopback IPs | `true` or `false` (default `false`) |
| `ban_duration` | Seconds a quarantine lasts before auto-release | `0` (permanent, default), or e.g. `3600` |
| `ban_escalation` | Duration multiplier per repeat offense (see Ban List) | number ≥ `1` (default `2`) |
| `rules_file` | Custom rules JSON merged over built-ins | path string |
| `webhooks` | Report digest destinations | list of `{"type", "url"}` |

**Tip:** If your logs live in non-standard locations, just edit `log_paths` after setup. Each service can watch multiple files — pass a list to watch them all. If you add a new service later, add it to `services` and add its `log_paths` entry.

**False positives:** Put admin workstations, load balancers, VPN gateways, and trusted private ranges in `allowlist` before enabling automatic firewall blocks.

**Dry run:** Set `"dry_run": true` (or `sudo banwatch enable --dry-run`) to see what BanWatch *would* ban without touching the firewall — great for validating rules before going live.

---

## Rules & Severity

Each rule carries a **severity** that maps to a **weight**. The detector sums the weights of matching events within the time window; when the total reaches `threshold`, the IP is quarantined. Auth brute-force rules are heavy, simple 404s are light.

| Severity | Weight | Example |
|----------|--------|---------|
| `low` | 1 | Web 401/403/404/500, TLS/SSL handshake noise, connection-closed noise |
| `medium` | 2 | Authorization failures |
| `high` | 3 | SSH/FTP/DB/mail/VPN auth failures, web basic-auth failures, SQLi, path traversal, XSS |
| `critical` | 4 | Reserved for custom rules |

With the default `threshold: 5`, two high-severity SSH failures (3 + 3 = 6) trigger quarantine, while a lone 404 (1) needs five hits to matter.

### Custom Rules

Create `/etc/banwatch/rules.json` to override built-in signatures. Patterns are **replaced** per service; `log_guesses` and `ports` can be overridden too. Rules can be plain strings (severity `low`) or objects:

```json
{
  "ssh": {
    "patterns": [
      {"pattern": "Failed password for .* from (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)", "severity": "critical"},
      "Custom suspicious line from (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
    ],
    "log_guesses": ["/var/log/custom-ssh.log"]
  }
}
```

Restart the daemon after editing (`sudo systemctl restart banwatch`). Verify rules anytime:

```bash
sudo banwatch rules ssh              # show active ssh rules
sudo banwatch test-line ssh "Failed password for root from 1.2.3.4 port 22"
```

---

## The Ban List

When an IP's cumulative rule weight reaches the threshold (default: score 5 within 300s), it is:

1. **Logged** in `/etc/banwatch/banwatch.db`
2. **Blocked** via `iptables`, `ufw`, or `nftables`
3. **Tracked** with score, service, and timestamps

By default **private IPs are never banned** (RFC1918, loopback, link-local). Set `"block_private": true` in config to allow it — for example on isolated test networks. Trusted ranges in `allowlist` are always skipped first.

### Ban Duration & Escalation

By default bans are **permanent** until you run `sudo banwatch release`. To avoid locking out legitimate users on a false positive, set `"ban_duration"` to a number of seconds (e.g. `3600`). When it expires, the daemon removes the firewall rule and marks the ban `expired`.

Freed offenders don't get an amnesty — **each time an IP is banned again it gets a longer ban**. The duration is `ban_duration × ban_escalation^(attempts−1)`:

| Offense | Duration (base 1h, escalation 2×) |
|---------|----------------------------------|
| 1st ban | 1h |
| 2nd     | 2h |
| 3rd     | 4h |
| 4th     | 8h |
| ...     | doubles each time |

After a handful of offenses the ban is weeks long — effectively permanent, while a one-off false positive only costs a few hours. `ban_escalation: 1` disables escalation; `ban_duration: 0` keeps permanent bans.

```bash
# View who's banned
sudo banwatch status

# Release a false positive
sudo banwatch release 192.168.1.100

# Manage the allowlist without editing config by hand
sudo banwatch allowlist list
sudo banwatch allowlist add 10.0.0.0/8
sudo banwatch allowlist remove 10.0.0.0/8
```

---

## Reports

Reports include:
- **Total entries** — all-time quarantines
- **Currently quarantined** — active blocks
- **Attacks (24h)** — recent activity
- **Breakdown by service** — SSH / Web / Database / FTP / Mail / VPN with active counts
- **Recent ban entries** — last 100 IPs with status

```bash
sudo banwatch report                 # HTML (default)
sudo banwatch report --format json   # machine-readable stats + ban list
sudo banwatch report --format csv    # ban list as CSV
```

Files are saved to `/var/log/banwatch/`. Reports are optionally emailed via the system `mail` command and/or pushed to **webhooks** as a text digest:

```json
"webhooks": [
  {"type": "slack",   "url": "https://hooks.slack.com/services/XXX"},
  {"type": "discord", "url": "https://discord.com/api/webhooks/XXX"},
  {"type": "generic", "url": "https://example.com/hook"}
]
```

---

## Backfill Scan

The daemon **tails** log files — it only reads new lines written after it starts. Attacks logged *before* the daemon's first start are never seen. To catch up on existing log history, run a one-off backfill scan:

```bash
sudo banwatch scan
```

This reads every configured log file from the beginning, analyzes every line with the same rules the daemon uses, and quarantines matching IPs (respecting the allowlist, private-IP policy, and dry-run mode). Output reports how many lines were read and how many IPs were newly quarantined:

```
Scanned 152340 lines, quarantined 3 new IP(s).
```

Run it once after installing BanWatch on a system that already has log history. Since it reads whole files (including rotations), it can take a while on busy servers; it's safe to stop and re-run, as already-quarantined IPs are skipped.

> **Note:** the scan scores events with the current time, not the log timestamps, so events spread far apart in the log still accumulate within the configured `window`. This is intentional — a historical attacker who hit your postgres once every 90 seconds for an hour should be quarantined, not released because each hit was "too old".

---

## systemd

Run BanWatch as a background service that starts automatically on boot. The daemon must be configured first (see [Install](#install)).

```bash
# 1. Write the unit file (/etc/systemd/system/banwatch.service)
sudo banwatch systemd

# 2. Register and start it
sudo systemctl daemon-reload
sudo systemctl enable --now banwatch

# 3. Verify
sudo systemctl status banwatch
sudo banwatch status
```

The unit runs `banwatch enable` (`Type=forking`, PID file `/var/run/banwatch.pid`) and daemon logs go to `/var/log/banwatch/banwatch.log`.

Common systemctl commands:

| Command | What it does |
|---------|--------------|
| `sudo systemctl enable --now banwatch` | Start now + auto-start on boot |
| `sudo systemctl start banwatch` | Start (once) |
| `sudo systemctl stop banwatch` | Stop |
| `sudo systemctl restart banwatch` | Restart (applies config edits) |
| `sudo systemctl disable --now banwatch` | Stop + remove auto-start |
| `sudo systemctl status banwatch` | Show service state |
| `journalctl -u banwatch -f` | Follow the service's log output |

Prefer `systemctl` over `sudo banwatch enable`/`disable` when the service is installed — the two can disagree about state (the unit's PID file vs. systemd's view). For manual testing, `sudo banwatch enable` / `disable` work fine without systemd.

---

## Uninstall

1. **Stop the daemon** (if running) and disable the systemd service (if installed):

   ```bash
   sudo systemctl disable --now banwatch 2>/dev/null || true
   sudo banwatch disable 2>/dev/null || true
   ```

2. **Remove the systemd unit file** (if generated):

   ```bash
   sudo rm -f /etc/systemd/system/banwatch.service
   sudo systemctl daemon-reload
   ```

3. **Remove the installed files**:

   ```bash
   sudo rm -f /usr/local/bin/banwatch
   sudo rm -rf /usr/local/bin/banwatch_core
   ```

4. **Remove configuration, reports, and logs** (this deletes the ban list and attack history):

   ```bash
   sudo rm -rf /etc/banwatch
   sudo rm -rf /var/log/banwatch
   sudo rm -f /var/run/banwatch.pid
   ```

5. **Release any firewall rules BanWatch added.** Bans applied with `iptables`/`ufw`/`nftables` are not automatically removed on uninstall. Check what was blocked and delete the rules manually:

   ```bash
   # iptables
   sudo iptables -S | grep banwatch

   # ufw
   sudo ufw status numbered

   # nftables
   sudo nft list set inet banwatch banned
   ```

   After uninstalling, the intended cleanup for each backend is:

   ```bash
   # iptables (repeat per banned IP; drop lines mention "banwatch" only if you named them so)
   sudo iptables -D INPUT -s <IP> -j DROP

   # ufw (delete the numbered deny rule for each IP)
   sudo ufw delete deny from <IP>

   # nftables (drop the whole banwatch table)
   sudo nft delete table inet banwatch
   ```

   The simplest manual approach: run `sudo banwatch status` **before** step 4 to list all quarantined IPs, then remove those rules by IP with the commands above.

---

## Architecture

The executable `banwatch` is a small CLI wrapper. Runtime code lives in `banwatch_core/`:

| Module | Purpose |
|--------|---------|
| `config.py` | Load, save, and validate JSON configuration |
| `signatures.py` | Service signatures, severity weights, and `rules.json` merging |
| `database.py` | SQLite ban list and attack history |
| `firewall.py` | `iptables` / `ufw` / `nftables` block and unblock commands |
| `detector.py` | Log tailing, weighted rule matching, score tracking |
| `reporter.py` | HTML/JSON/CSV reports, optional `mail` email, webhook digests |
| `daemon.py` | Background process lifecycle + atomic flock PID lock |
| `cli.py` | Command-line command dispatch |

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Log Tail   │────▶│  Weighted   │────▶│  Ban List   │
│  (threads)  │     │   Matcher   │     │   (SQLite)  │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                                │
                                         ┌──────▼──────┐
                                         │  Firewall   │
                                         │ipt/ufw/nft  │
                                         └─────────────┘
```

---

## License

MIT — Use only on systems you own or have permission to protect.
