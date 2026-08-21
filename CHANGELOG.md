# Changelog

All notable changes to BanWatch are documented in this file.

Versioning: `0.x.y` — **x** increments for new features or behavior changes, **y** for fixes and documentation. Until `1.0.0`, minor releases may still change configuration defaults.

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
