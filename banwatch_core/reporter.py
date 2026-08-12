import html
import json
import logging
import subprocess
import urllib.request
from datetime import datetime

from .paths import REPORT_DIR


class Reporter:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.cfg = cfg

    def generate_html(self) -> str:
        stats = self.db.get_stats()
        breakdown = self.db.get_service_breakdown()
        offenders = self.db.get_top_offenders(10)

        bd_rows = ""
        for svc, total, active in breakdown:
            svc_html = html.escape(str(svc).upper())
            pct = round((active / max(total, 1)) * 100)
            bd_rows += f"""
            <tr>
                <td>{svc_html}</td>
                <td>{total}</td>
                <td><span class="badge active">{active}</span></td>
                <td>
                    <div class="bar"><div class="bar-fill" style="width:{pct}%"></div></div>
                    <small>{pct}% still quarantined</small>
                </td>
            </tr>
            """

        max_events = max((o["events"] for o in offenders), default=1)
        o_rows = ""
        for i, entry in enumerate(offenders, start=1):
            ip_html = html.escape(str(entry["ip"]))
            service_html = html.escape(str(entry["service"]).upper())
            events = int(entry["events"])
            last_seen_html = html.escape(str(entry["last_seen"])[:19])
            pct = round(events / max(max_events, 1) * 100)
            o_rows += f"""
            <tr>
                <td><span class="rank">{i}</span></td>
                <td><code>{ip_html}</code></td>
                <td>{service_html}</td>
                <td>
                    <div class="events">{events}</div>
                    <div class="bar"><div class="bar-fill" style="width:{pct}%"></div></div>
                </td>
                <td>{last_seen_html}</td>
            </tr>
            """

        return f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BanWatch Report</title>
<style>
:root{{--bg:#ffffff;--card:#f8fafc;--accent:#0284c7;--danger:#dc2626;--success:#16a34a;--text:#0f172a;--muted:#64748b;--border:#e2e8f0;--code-bg:#f1f5f9;--hover:rgba(2,132,199,.06)}}
:root[data-theme="dark"]{{--bg:#0f172a;--card:#1e293b;--accent:#38bdf8;--danger:#ef4444;--success:#22c55e;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--code-bg:#0f172a;--hover:rgba(56,189,248,.08)}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:40px 20px;transition:background .25s,color .25s}}
.container{{max-width:1100px;margin:0 auto}}
header{{text-align:center;margin-bottom:40px;position:relative}}
header h1{{font-size:2.4rem;color:var(--accent);letter-spacing:-1px}}
header p{{color:var(--muted);margin-top:8px}}
.theme-toggle{{position:absolute;top:0;right:0;background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px 14px;font-size:.85rem;cursor:pointer;transition:background .25s}}
.theme-toggle:hover{{background:var(--hover)}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:20px;margin-bottom:40px}}
.kpi{{background:var(--card);padding:28px;border-radius:12px;text-align:center;border:1px solid var(--border);transition:transform .2s}}
.kpi:hover{{transform:translateY(-3px)}}
.kpi .num{{font-size:2.8rem;font-weight:800;color:var(--accent)}}
.kpi .label{{color:var(--muted);font-size:.95rem;margin-top:6px;text-transform:uppercase;letter-spacing:.5px}}
.kpi.danger .num{{color:var(--danger)}}
.kpi.success .num{{color:var(--success)}}
section{{background:var(--card);border-radius:12px;padding:28px;margin-bottom:30px;border:1px solid var(--border)}}
section h2{{font-size:1.3rem;margin-bottom:18px;color:var(--accent);display:flex;align-items:center;gap:10px}}
table{{width:100%;border-collapse:collapse;font-size:.95rem}}
th{{text-align:left;padding:14px 12px;color:var(--muted);font-weight:600;border-bottom:2px solid var(--border);text-transform:uppercase;font-size:.8rem;letter-spacing:.5px}}
td{{padding:14px 12px;border-bottom:1px solid var(--border);vertical-align:middle}}
tr:hover td{{background:var(--hover)}}
code{{background:var(--code-bg);padding:3px 8px;border-radius:4px;font-family:monospace;font-size:.9rem;color:var(--accent)}}
.rank{{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:50%;background:var(--accent);color:#fff;font-weight:700;font-size:.85rem}}
.badge{{display:inline-block;padding:4px 10px;border-radius:20px;font-size:.75rem;font-weight:700;text-transform:uppercase}}
.badge.active{{background:rgba(239,68,68,.15);color:var(--danger)}}
.badge.released{{background:rgba(34,197,94,.15);color:var(--success)}}
.bar{{height:6px;background:var(--border);border-radius:3px;overflow:hidden;margin-top:6px;max-width:200px}}
.bar-fill{{height:100%;background:var(--accent);border-radius:3px}}
.events{{font-weight:700;color:var(--danger)}}
.timestamp{{text-align:center;color:var(--muted);margin-top:30px;font-size:.9rem}}
@media (prefers-color-scheme:dark){{:root:not([data-theme]){{--bg:#0f172a;--card:#1e293b;--accent:#38bdf8;--danger:#ef4444;--success:#22c55e;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--code-bg:#0f172a;--hover:rgba(56,189,248,.08)}}}}
</style>
</head>
<body>
<div class="container">
<header>
<button class="theme-toggle" id="themeToggle" onclick="toggleTheme()">Toggle Dark</button>
<h1>BanWatch</h1>
<p>Security Report - {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
</header>

<div class="kpi-grid">
<div class="kpi"><div class="num">{stats["total_entries"]}</div><div class="label">Total Entries</div></div>
<div class="kpi danger"><div class="num">{stats["active_quarantined"]}</div><div class="label">Currently Quarantined</div></div>
<div class="kpi success"><div class="num">{stats["attacks_24h"]}</div><div class="label">Attacks (24h)</div></div>
<div class="kpi"><div class="num">{len(self.cfg["services"])}</div><div class="label">Services Protected</div></div>
</div>

<section>
<h2>Breakdown by Service</h2>
<table>
<tr><th>Service</th><th>Total Quarantined</th><th>Active</th><th>Status</th></tr>
{bd_rows}
</table>
</section>

<section>
<h2>Top 10 Offenders</h2>
<table>
<tr><th>#</th><th>IP Address</th><th>Service</th><th>Events</th><th>Last Seen</th></tr>
{o_rows}
</table>
</section>

<p class="timestamp">Generated by BanWatch v1.0</p>
</div>
<script>
(function(){{
  var saved = localStorage.getItem('banwatch-theme');
  if (saved) {{ document.documentElement.setAttribute('data-theme', saved); }}
}})();
function toggleTheme(){{
  var root = document.documentElement;
  var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  localStorage.setItem('banwatch-theme', next);
}}
</script>
</body>
</html>"""

    def generate_json(self) -> str:
        stats = self.db.get_stats()
        breakdown = [
            {"service": s, "total": t, "active": a}
            for s, t, a in self.db.get_service_breakdown()
        ]
        return json.dumps(
            {
                "generated_at": datetime.now().isoformat(),
                "stats": stats,
                "breakdown": breakdown,
                "bans": self.db.get_ban_list(100),
            },
            indent=2,
        )

    def generate_csv(self) -> str:
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ip", "service", "reason", "attempts", "first_seen", "last_seen", "status"])
        for e in self.db.get_ban_list(100):
            writer.writerow(
                [e["ip"], e["service"], e["reason"], e["attempts"], e["first_seen"], e["last_seen"], e["status"]]
            )
        return buf.getvalue()

    def save_and_maybe_email(self, format: str = "html"):
        if format == "html":
            report = self.generate_html()
        elif format == "json":
            report = self.generate_json()
        elif format == "csv":
            report = self.generate_csv()
        else:
            raise ValueError(f"unknown report format: {format}")

        ts = datetime.now().strftime("%Y%m%d_%H%M")
        path = REPORT_DIR / f"report_{ts}.{format}"
        path.write_text(report)
        try:
            path.chmod(0o640)
        except OSError:
            pass
        logging.info(f"Report saved: {path}")

        html_report = self.generate_html() if format != "html" else report
        if self.cfg.get("email"):
            self._send_email(html_report)
        if self.cfg.get("webhooks"):
            self._send_webhooks(html_report)
        return path

    def _build_digest(self) -> str:
        stats = self.db.get_stats()
        breakdown = self.db.get_service_breakdown()
        lines = [
            f"BanWatch Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"Total entries: {stats['total_entries']}",
            f"Currently quarantined: {stats['active_quarantined']}",
            f"Attacks (24h): {stats['attacks_24h']}",
        ]
        if breakdown:
            lines.append(
                "Breakdown: "
                + ", ".join(f"{s}: {a} active / {t} total" for s, t, a in breakdown)
            )
        return "\n".join(lines)

    def _send_webhooks(self, report_html: str):
        digest = self._build_digest()
        for hook in self.cfg["webhooks"]:
            try:
                self._post_webhook(hook, digest)
            except Exception as e:
                logging.warning(f"Could not send webhook to {hook.get('url')}: {e}")

    def _post_webhook(self, hook: dict, digest: str):
        url = hook["url"]
        wtype = hook.get("type", "generic")
        if wtype == "slack":
            payload = {"text": digest}
        elif wtype == "discord":
            payload = {"content": digest}
        else:
            payload = {"text": digest}

        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        logging.info(f"Webhook ({wtype}) sent to {url}")

    def _send_email(self, report_html: str):
        email = self.cfg["email"]
        try:
            proc = subprocess.run(
                [
                    "mail",
                    "--content-type=text/html",
                    "-s",
                    f"BanWatch Report - {datetime.now().strftime('%Y-%m-%d')}",
                    "-r",
                    "BanWatch <hello@tuloss.com>",
                    email,
                ],
                input=report_html,
                text=True,
                capture_output=True,
                timeout=60,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}")
            logging.info(f"Report emailed to {email}")
        except Exception as e:
            logging.warning(f"Could not email report: {e}")
