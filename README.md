# BanWatch

**A lightweight Fail2ban alternative that feels as simple as UFW.**

BanWatch watches SSH, web, database, mail, FTP, and VPN logs, scores suspicious activity, and automatically quarantines attacking IPs with `ufw`, `iptables`, or `nftables`. It is built for admins who want brute-force protection without managing Fail2ban jails, filters, actions, and regex plumbing.

Use BanWatch when you are searching for:

- a simpler Fail2ban replacement for Linux servers
- automatic IP banning for SSH, Nginx, Apache, PostgreSQL, MySQL, mail, FTP, or VPN logs
- UFW-friendly brute-force protection with an interactive setup wizard
- self-hosted intrusion prevention with no external Python packages
- HTML/email security reports and webhook digests

---

## Quickstart

Fast path for a Linux server with Python 3.8+, `sudo`, and either `ufw`, `iptables`, or `nftables` available:

```bash
curl -fsSL https://raw.githubusercontent.com/TulossSolutions/banwatch/main/install.sh | sudo sh
sudo banwatch setup
sudo banwatch systemd
sudo systemctl daemon-reload
sudo systemctl enable --now banwatch
sudo banwatch status
```

Want to validate first without touching firewall rules?

```bash
sudo banwatch enable --dry-run
sudo banwatch status
```

---

## Features

- **Fail2ban-style protection, simpler workflow:** one setup wizard, plain JSON config, direct CLI commands.
- **Real-time log monitoring:** tails new log lines and handles multiple files per service.
- **Weighted detection rules:** high-confidence auth failures count more than low-signal noise.
- **Automatic quarantine:** blocks attackers with `ufw`, `iptables`, `nftables`, or detect-only mode.
- **Allowlist and private-IP safeguards:** protect admin IPs, load balancers, VPN ranges, and private networks.
- **Ban duration and escalation:** temporary bans can grow longer for repeat offenders.
- **Backfill scanning:** scan existing logs once after installation to catch historical attackers.
- **Custom rules:** override or extend signatures with `/etc/banwatch/rules.json`.
- **Reports:** HTML, JSON, CSV, email reports, and Slack/Discord/generic webhooks.
- **systemd support:** generate a unit file and run BanWatch automatically on boot.
- **No external Python packages:** runs on the Python standard library.

---

## Supported OS

BanWatch is designed for Linux servers because it reads Linux service logs and controls Linux firewalls.

| OS / Platform | Status | Notes |
|---------------|--------|-------|
| Debian 11/12 | Supported | Recommended target; works with `ufw`, `iptables`, or `nftables` |
| Ubuntu 20.04/22.04/24.04 | Supported | Recommended target; common paths auto-detected |
| RHEL / Rocky / AlmaLinux 8/9 | Supported | Uses `/var/log/secure` for SSH; firewall backend depends on installed tools |
| Fedora / CentOS Stream | Expected | Should work when Python 3.8+ and firewall tools are present |
| Arch Linux | Expected | May need custom `log_paths` depending on service configuration |
| Containers | Limited | Needs host log and firewall access; not the recommended deployment model |
| macOS / Windows | Not supported for protection | Useful only for development or copying files to a Linux server |

Minimum runtime: Python 3.8+, root privileges, readable service logs, and one firewall backend (`ufw`, `iptables`, `nftables`) unless using `firewall: none` or `--dry-run`.

---

## Install

Requires Python 3.8+ and `sudo`. BanWatch has no external Python package dependencies.

### Recommended: install script

The simplest installation path downloads the current source release, installs the CLI wrapper, and places the Python package under `/usr/local/lib/banwatch`:

```bash
curl -fsSL https://raw.githubusercontent.com/TulossSolutions/banwatch/main/install.sh | sudo sh
```

Then run the interactive setup:

```bash
sudo banwatch setup
```

Optional one-shot install flows:

```bash
# Install files, then immediately run setup
curl -fsSL https://raw.githubusercontent.com/TulossSolutions/banwatch/main/install.sh | sudo env RUN_SETUP=1 sh

# Install files, write the systemd unit, and start the service
curl -fsSL https://raw.githubusercontent.com/TulossSolutions/banwatch/main/install.sh | sudo env INSTALL_SYSTEMD=1 START_SERVICE=1 sh
```

The script is intentionally small and POSIX `sh` compatible. It installs:

| Path | Purpose |
|------|---------|
| `/usr/local/bin/banwatch` | Executable launcher |
| `/usr/local/lib/banwatch/banwatch_core/` | Python runtime package |

Config, rules, database, and reports are still created at runtime under `/etc/banwatch/` and `/var/log/banwatch/`.

### Install script options

Environment variables let you customize the install without editing the script:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PREFIX` | `/usr/local` | Base install prefix |
| `BIN_DIR` | `$PREFIX/bin` | Where the `banwatch` launcher is written |
| `LIB_ROOT` | `$PREFIX/lib/banwatch` | Where `banwatch_core/` is installed |
| `BANWATCH_REPO` | `https://github.com/TulossSolutions/banwatch` | Repository to download when not run from a checkout |
| `BANWATCH_REF` | `main` | Branch/ref downloaded by the install script |
| `RUN_SETUP` | `0` | Set `1` to run `banwatch setup` after installing |
| `INSTALL_SYSTEMD` | `0` | Set `1` to write the systemd unit after installing |
| `START_SERVICE` | `0` | Set `1` with `INSTALL_SYSTEMD=1` to enable and start the service |

Example pinned branch/ref install:

```bash
curl -fsSL https://raw.githubusercontent.com/TulossSolutions/banwatch/main/install.sh | sudo env BANWATCH_REF=main sh
```

### Alternative: git clone then install locally

```bash
git clone https://github.com/TulossSolutions/banwatch.git
cd banwatch
sudo sh install.sh
sudo banwatch setup
```

When run from a checkout, `install.sh` uses the local files instead of downloading an archive.

### Alternative: manual source install

```bash
sudo install -m 755 banwatch /usr/local/bin/banwatch
sudo mkdir -p /usr/local/lib/banwatch
sudo rm -rf /usr/local/lib/banwatch/banwatch_core
sudo cp -r banwatch_core /usr/local/lib/banwatch/
```

If you use the manual layout above, make sure your launcher can import `/usr/local/lib/banwatch/banwatch_core`. The install script generates that launcher automatically, which is why it is preferred.

### Alternative: run from the source tree

Useful for development or testing before installing globally:

```bash
sudo python3 -m banwatch_core setup
sudo python3 -m banwatch_core enable --dry-run
```

### Installation UX roadmap

The install script is now the easiest path. Longer term, the most user-friendly production install would be a signed `.deb` package and then an APT repository:

| Option | User command | Best for | Notes |
|--------|--------------|----------|-------|
| Install script | `curl -fsSL .../install.sh | sudo sh` | Fast first install | Implemented; simple and auditable |
| `.deb` package | `sudo apt install ./banwatch.deb` | Debian/Ubuntu | Handles files, permissions, man page, systemd unit, uninstall cleanly |
| APT repository | `sudo apt install banwatch` | Production users | Best long-term UX for updates and trust, but requires repo signing/release process |
| PyPI / pipx | `sudo pipx install banwatch` | Python users | Nice Python packaging, but firewall/systemd integration still needs post-install steps |
| Homebrew/Linuxbrew | `brew install banwatch` | Dev/admin laptops | Convenient, less ideal for minimal servers |
| Container image | `docker run ...` | Testing only | Awkward for host logs and firewall control; not recommended as primary install |

### Windows/scp gotcha

If you copied files from Windows, the `banwatch` script may have Windows line endings (`\r`), breaking its shebang line. If you see `/usr/bin/env: 'python3\r': No such file or directory`, fix with:

```bash
sudo sed -i 's/\r$//' /usr/local/bin/banwatch
```

## Update

Pull the latest files and reinstall them over the existing ones:

```bash
curl -fsSL https://raw.githubusercontent.com/TulossSolutions/banwatch/main/install.sh | sudo sh
sudo systemctl restart banwatch   # if running as a systemd service
```

Updates never touch `/etc/banwatch/` (config, rules, database) or `/var/log/banwatch/`. If you copied the files from Windows, re-apply the `\r` fix from step 2 if needed. See [CHANGELOG.md](CHANGELOG.md) for what changed in each release; check the installed version with:

```bash
banwatch --version
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
| **MySQL** | `/var/log/mysql/error.log` |
| **MariaDB** | `/var/log/mariadb/mariadb.log` |
| **PostgreSQL** | `/var/log/postgresql/postgresql-*.log` |
| **MongoDB** | `/var/log/mongodb/mongod.log` |
| **Redis** | `/var/log/redis/redis-server.log` |
| **Elasticsearch** | `/var/log/elasticsearch/*.log` |
| **Cassandra** | `/var/log/cassandra/system.log` |

> **PostgreSQL tip — log the client IP:** BanWatch can only block attackers it can *see*. Postgres only includes the remote IP in its log lines when `log_line_prefix` contains `%h`; without it, lines like `FATAL: unsupported frontend protocol` have no IP and can't be attributed. If you haven't already, add `%h` (and `%q` so the user/db fields stop filling after the first line):

> ```bash
> sudo nano /etc/postgresql/16/main/postgresql.conf
> ```
>
> ```
> log_line_prefix = '%m [%p] [%h] %q%u@%d '
> ```
>
> then reload:
>
> ```bash
> sudo systemctl reload postgresql
> ```
>
> Check it took effect — a line should now read `[...] [213.209.159.66] [unknown]@[unknown] FATAL: ...`:

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
| `email` | One bare recipient address, without a display name (optional, `null` to disable) | `"you@domain.com"` or `null` |
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

1. **Blocked** via `iptables`, `ufw`, or `nftables`
2. **Logged** as quarantined in `/etc/banwatch/banwatch.db` only after the firewall command succeeds
3. **Tracked** with score, service, and timestamps

In `dry_run` or with `firewall: "none"`, detection events are still recorded, but no new active quarantine is created. Existing quarantines and firewall rules are retained: manual release and automatic expiration do not run in these modes. In blocking mode, a release or expiration is recorded only after successful firewall removal. A repeat ban reapplies the firewall rule before updating the record, including its latest service and reason.

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
- **IPs ever banned** and **active bans** recorded in SQLite, compared with the previous successful HTML report.
- **Events in the period**, compared with the preceding equal-duration period: 24 hours, 7 days or 30 days according to `report_frequency`.
- **Monitored services**, verified from a current daemon heartbeat and the state of every configured log reader. An idle readable log is healthy; a missing, stopped or unverified reader is not.
- **Service breakdown** with historical totals, current active counts and percentages, period events, reader availability, last read and errors since daemon start.
- **Top IPs in the period**, with current ban status, reason and expiration; new, repeat, released and expired ban counts.
- **Read-only firewall checks** identifying active database entries without matching rules. Rule presence does not establish packet-path ordering or effective delivery, and discrepancies are never repaired automatically.

The header and email subject identify the server, report frequency and timezone. The original desktop design is retained, including KPI cards, service bars, offender ranks and separate table columns. Base styles are inline; the CSS block contains only mobile rules, including two KPI columns. No repeated containment banner is included.

```bash
sudo banwatch report                 # HTML (default)
sudo banwatch report --format json   # machine-readable stats + ban list
sudo banwatch report --format csv    # ban list as CSV
```

Files are saved to `/var/log/banwatch/`. HTML reports can be emailed as multipart text/HTML via the system `sendmail` interface and/or pushed to **webhooks** as a text digest. GNU `mail` is retained as an HTML-only fallback when `sendmail` is unavailable.

Set `email_from` to an authorized sender (default `BanWatch <hello@tuloss.com>`) and optionally set `report_hostname` to a recognizable server label. These fields are validated to reject header injection. A successful email means the local transport accepted it, not that the recipient received it.

The `email` recipient must be a single bare address, such as `admin@example.com`. Display-name forms such as `Admin <admin@example.com>`, recipient lists, and control characters are rejected. Display names remain supported for the `email_from` sender, such as `BanWatch <hello@tuloss.com>`. Use `null` to disable email reports.

JSON and CSV commands save the requested export and also send the HTML email and/or webhook digest when configured, as before. These exports do not update the HTML/email comparison reference. The first successful HTML-format report establishes that reference. Email failures leave it unchanged; webhook failures do not cause duplicate email retries after an email was accepted. With webhook-only delivery, all configured hooks must accept the report before its reference advances.

The JSON export retains its original top-level fields: `generated_at`, `stats`, `breakdown` (objects containing `service`, `total`, `active`), and `bans`. CSV retains its original seven columns and appends `banned_until`; field values are exported unchanged. Treat exported log-derived text as untrusted when opening CSV files in spreadsheet software.

Automatic report deadlines are persisted in SQLite. Failures retry after 15 minutes, then 30 minutes; after three failed attempts the next normal interval is scheduled. Restarting the daemon no longer postpones an existing deadline.

The 0.6.0 migration preserves legacy timestamps and adds an indexed epoch value using the server's local timezone. Repeated daylight-saving hours in old timezone-free records cannot be reconstructed exactly; new events are unambiguous. Ban lifecycle counts start at migration time because historical release/expiry times were not recorded. The new metric definitions establish a fresh KPI reference. Take a consistent database backup before upgrading.

Webhook configuration:

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
   sudo rm -rf /usr/local/lib/banwatch
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
| `reporter.py` | One data snapshot per report, exports, KPI references and scheduling |
| `report_views.py` | Responsive email HTML and plain-text rendering |
| `report_delivery.py` | Multipart email transport and webhook delivery |
| `monitoring.py` | Read-only reader health and daemon heartbeat |
| `daemon.py` | Background process lifecycle + atomic flock PID lock |
| `cli.py` | Command-line command dispatch |

```
┌─────────────┐      ┌─────────────┐     ┌─────────────┐       ┌────────────┐
│  Log Tail   │ ────>│  Weighted   │────>│  Ban List   │ ────> │  Firewall  │
│  (threads)  │      │   Matcher   │     │   (SQLite)  │       │ipt/ufw/nft │
└─────────────┘      └─────────────┘     └─────────────┘       └────────────┘
                                              
                                         
```

---

## License

MIT — Use only on systems you own or have permission to protect.
