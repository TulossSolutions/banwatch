# Changelog

All notable changes to BanWatch are documented in this file.

Versioning: `0.x.y` — **x** increments for new features or behavior changes, **y** for fixes and documentation. Until `1.0.0`, minor releases may still change configuration defaults.

## [0.6.0] - 2026-08-31

### Added
- Period-based reports with hostname, timezone, equal-duration comparisons, ban lifecycle counts, reasons and expirations
- Read-only firewall rule checks and daemon heartbeat monitoring for configured log readers
- Multipart text/HTML email via sendmail, configurable email_from and report_hostname
- Persistent report scheduling with retries after 15 and 30 minutes, surviving daemon restarts
- Regression tests for reporting, SQLite migration, timezone boundaries, mail failures, monitoring and firewall transitions

### Changed
- Compact responsive email layout without the redundant Active threat containment banner or repeated ACTIVE labels
- Reporting split into data collection, rendering, delivery and monitoring modules
- Events and top IPs use the configured reporting period (24 hours, 7 days or 30 days)
- HTML/email KPI references advance only after successful primary delivery or local saving when no delivery is configured
- JSON/CSV exports no longer send notifications or change the HTML report reference
- New ban/release/expiry activity is tracked from this upgrade; historical transitions are not invented

### Fixed
- 24-hour counts now use indexed epoch timestamps instead of comparing incompatible date strings
- Legacy attack times are converted using the server's local timezone while retaining the original timestamp column
- iptables command construction no longer repeats the executable name
- Failed firewall operations no longer produce new quarantine/release records; repeat bans reapply the firewall rule
- Detection-only mode no longer creates new active quarantine records

### Upgrade Notes
- Back up /etc/banwatch before upgrading; migration is additive and preserves existing history
- Old wall-clock timestamps cannot disambiguate repeated daylight-saving hours; new events use unambiguous epoch times
- KPI references restart because their definitions changed; the first successful HTML report establishes a new reference
- Existing database/firewall discrepancies are reported, never automatically repaired or re-applied in bulk
- Without sendmail, GNU mail remains available as an HTML-only fallback; transport acceptance is not delivery confirmation

## [0.5.0] - 2026-08-30

### Added
- Shell installer for local checkouts or GitHub downloads, with configurable install paths and optional setup/systemd integration
- Report KPI changes compared with the previous saved report, persisted in SQLite report snapshots

### Changed
- Report generation date appears below Daily Report in the header
- Report footer uses the package version instead of a hardcoded version
- README introduces BanWatch as a lightweight Fail2ban alternative with UFW-like simplicity, with a quickstart, feature list, supported OS guidance, and installer documentation

### Fixed
- systemd startup waits for the double-forked daemon PID to become available
- Daemon process retains the flock lock for its lifetime

### Upgrade
- Run the installer from this release's extracted source archive, then restart the existing BanWatch service
- The installer moves runtime code to /usr/local/lib/banwatch; existing configuration, firewall rules, and history are preserved
- The report_snapshots table is created automatically on first database access; the first report has no comparison baseline

## [0.4.0] - 2026-08-21

### Added
- PostgreSQL signature for startup-packet probes (`no PostgreSQL user name specified`), requires `%h` in `log_line_prefix`

### Changed
- HTML report redesigned with email-client-safe inline styling (no external CSS, renders in Gmail/Outlook)

### Fixed
- Tail threads no longer die permanently on transient `database is locked` errors; per-line errors are logged and skipped
- SQLite database now runs in WAL mode with a 30s busy timeout, eliminating lock contention between tail threads

## [0.3.0] - 2026-08-15

### Added
- `banwatch scan` one-off backfill command to analyze existing log history
- PostgreSQL `pg_hba.conf` authentication-failure rule (critical)
- SSH signatures from real auth.log analysis: pam_unix failures with `rhost`, connection closed/reset during authentication, banner-exchange errors
- Web signatures from real access/error logs: `eval-stdin.php` RCE, `allow_url_include`/`php://input` probes, CONNECT tunnel attempts, sensitive-file scanning (`.env`, `.git`, cloud/CI secrets, AI-agent configs, shell dotfiles), encoded traversal variants, WordPress probing (`xmlrpc.php`, `wlwmanifest.xml`), phpinfo/Xdebug probes, generic `open() failed` and forbidden-rule hits

### Fixed
- Invalid UTF-8 bytes in log files are tolerated instead of crashing the tail threads

## [0.2.1] - 2026-08-15

### Fixed
- Repository forces LF line endings so the `banwatch` shebang survives a Windows checkout + scp copy

### Changed
- README: clarified install steps, Windows/scp gotchas, and systemd usage

## [0.2.0] - 2026-08-12

### Added
- Report emails sent via the system `mail` command instead of a local SMTP server
- Reports are emailed as HTML body with `BanWatch <hello@tuloss.com>` sender

## [0.1.0] - 2026-08-10

### Added
- Initial release: real-time log tailing, weighted rule matching, automatic quarantine via iptables/ufw/nftables
- Services: ssh, web, database, ftp, mail, vpn (39 auto-detected log paths)
- Allowlist, dry-run mode, ban duration with escalation, HTML/JSON/CSV reports, webhook digests, systemd unit generation, interactive setup wizard
