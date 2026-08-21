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

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
        services_count = len(self.cfg["services"])

        # ------------------------------------------------------------------
        # Service breakdown
        # ------------------------------------------------------------------
        bd_rows = ""

        for svc, total, active in breakdown:
            svc_html = html.escape(str(svc).upper())
            total = int(total)
            active = int(active)

            pct = round((active / max(total, 1)) * 100)

            bd_rows += f"""
            <tr>
                <td style="
                    padding:14px 0;
                    border-bottom:1px solid #e5e7eb;
                    font-family:Arial,Helvetica,sans-serif;
                    font-size:13px;
                    font-weight:700;
                    color:#111827;
                ">
                    {svc_html}
                </td>

                <td style="
                    padding:14px 12px;
                    border-bottom:1px solid #e5e7eb;
                    font-family:Arial,Helvetica,sans-serif;
                    font-size:13px;
                    color:#4b5563;
                    text-align:right;
                ">
                    {total}
                </td>

                <td style="
                    padding:14px 12px;
                    border-bottom:1px solid #e5e7eb;
                    text-align:right;
                ">
                    <span style="
                        display:inline-block;
                        padding:4px 8px;
                        background:#fef2f2;
                        color:#dc2626;
                        border-radius:999px;
                        font-family:Arial,Helvetica,sans-serif;
                        font-size:11px;
                        font-weight:700;
                    ">
                        {active} ACTIVE
                    </span>
                </td>

                <td style="
                    padding:14px 0;
                    border-bottom:1px solid #e5e7eb;
                    width:42%;
                ">
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                        <tr>
                            <td style="
                                padding:0;
                                background:#e5e7eb;
                                border-radius:999px;
                                height:6px;
                                line-height:6px;
                                font-size:0;
                            ">
                                <div style="
                                    width:{pct}%;
                                    height:6px;
                                    background:#dc2626;
                                    border-radius:999px;
                                    line-height:6px;
                                    font-size:0;
                                ">&nbsp;</div>
                            </td>
                        </tr>
                    </table>

                    <div style="
                        margin-top:5px;
                        font-family:Arial,Helvetica,sans-serif;
                        font-size:10px;
                        color:#9ca3af;
                    ">
                        {pct}% still quarantined
                    </div>
                </td>
            </tr>
            """

        # ------------------------------------------------------------------
        # Top offenders
        # ------------------------------------------------------------------
        max_events = max(
            (int(o["events"]) for o in offenders),
            default=1
        )

        o_rows = ""

        for i, entry in enumerate(offenders, start=1):
            ip_html = html.escape(str(entry["ip"]))
            service_html = html.escape(str(entry["service"]).upper())
            events = int(entry["events"])
            last_seen_html = html.escape(str(entry["last_seen"])[:19])

            pct = round(events / max(max_events, 1) * 100)

            # Highlight the top 3 ranks.
            if i == 1:
                rank_bg = "#dc2626"
            elif i == 2:
                rank_bg = "#374151"
            elif i == 3:
                rank_bg = "#6b7280"
            else:
                rank_bg = "#e5e7eb"

            rank_color = "#ffffff" if i <= 3 else "#4b5563"

            o_rows += f"""
            <tr>
                <td style="
                    padding:15px 8px 15px 0;
                    border-bottom:1px solid #e5e7eb;
                    width:42px;
                ">
                    <span style="
                        display:inline-block;
                        width:26px;
                        height:26px;
                        line-height:26px;
                        text-align:center;
                        border-radius:50%;
                        background:{rank_bg};
                        color:{rank_color};
                        font-family:Arial,Helvetica,sans-serif;
                        font-size:11px;
                        font-weight:700;
                    ">
                        {i}
                    </span>
                </td>

                <td style="
                    padding:15px 10px;
                    border-bottom:1px solid #e5e7eb;
                ">
                    <span style="
                        font-family:'Courier New',Courier,monospace;
                        font-size:13px;
                        color:#111827;
                        font-weight:700;
                    ">
                        {ip_html}
                    </span>
                </td>

                <td style="
                    padding:15px 10px;
                    border-bottom:1px solid #e5e7eb;
                    font-family:Arial,Helvetica,sans-serif;
                    font-size:11px;
                    font-weight:700;
                    color:#6b7280;
                ">
                    {service_html}
                </td>

                <td style="
                    padding:15px 10px;
                    border-bottom:1px solid #e5e7eb;
                    width:28%;
                ">
                    <div style="
                        font-family:Arial,Helvetica,sans-serif;
                        font-size:13px;
                        font-weight:700;
                        color:#dc2626;
                    ">
                        {events}
                        <span style="
                            font-size:10px;
                            font-weight:400;
                            color:#9ca3af;
                        ">
                            events
                        </span>
                    </div>

                    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
                        <tr>
                            <td style="
                                padding-top:6px;
                                background:#f1f5f9;
                                border-radius:999px;
                                height:4px;
                                line-height:4px;
                                font-size:0;
                            ">
                                <div style="
                                    width:{pct}%;
                                    height:4px;
                                    background:#dc2626;
                                    border-radius:999px;
                                    line-height:4px;
                                    font-size:0;
                                ">&nbsp;</div>
                            </td>
                        </tr>
                    </table>
                </td>

                <td style="
                    padding:15px 0 15px 10px;
                    border-bottom:1px solid #e5e7eb;
                    font-family:Arial,Helvetica,sans-serif;
                    font-size:11px;
                    color:#6b7280;
                    white-space:nowrap;
                ">
                    {last_seen_html}
                </td>
            </tr>
            """

        # ------------------------------------------------------------------
        # Empty states
        # ------------------------------------------------------------------
        if not bd_rows:
            bd_rows = """
            <tr>
                <td colspan="4" style="
                    padding:30px 0;
                    text-align:center;
                    font-family:Arial,Helvetica,sans-serif;
                    font-size:13px;
                    color:#9ca3af;
                ">
                    No service activity recorded.
                </td>
            </tr>
            """

        if not o_rows:
            o_rows = """
            <tr>
                <td colspan="5" style="
                    padding:30px 0;
                    text-align:center;
                    font-family:Arial,Helvetica,sans-serif;
                    font-size:13px;
                    color:#9ca3af;
                ">
                    No offenders recorded.
                </td>
            </tr>
            """

        # ------------------------------------------------------------------
        # Email
        # ------------------------------------------------------------------
        return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="light">
    <meta name="supported-color-schemes" content="light">
    <title>BanWatch Security Report</title>
    </head>

    <body style="
        margin:0;
        padding:0;
        background:#f3f4f6;
        color:#111827;
        font-family:Arial,Helvetica,sans-serif;
    ">

    <!-- Preheader -->
    <div style="
        display:none;
        max-height:0;
        overflow:hidden;
        opacity:0;
        color:transparent;
    ">
        BanWatch security report — {stats["active_quarantined"]} IPs currently quarantined.
    </div>

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"
           style="background:#f3f4f6;">
    <tr>
    <td align="center" style="padding:32px 12px;">

    <table role="presentation" cellpadding="0" cellspacing="0" border="0"
           width="100%"
           style="
               max-width:900px;
               background:#ffffff;
               border:1px solid #e5e7eb;
           ">

    <!-- ================================================================
         HEADER
         ================================================================ -->

    <tr>
    <td style="
        padding:28px 32px;
        background:#111111;
    ">

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
    <tr>

    <td valign="middle">

        <div style="
            font-family:Arial,Helvetica,sans-serif;
            font-size:20px;
            line-height:24px;
            font-weight:800;
            letter-spacing:-0.5px;
            color:#ffffff;
        ">
            Ban<span style="color:#ef4444;">Watch</span>
        </div>

        <div style="
            margin-top:5px;
            font-family:Arial,Helvetica,sans-serif;
            font-size:10px;
            line-height:14px;
            font-weight:700;
            letter-spacing:1.5px;
            color:#9ca3af;
            text-transform:uppercase;
        ">
            Security Intelligence
        </div>

    </td>

    <td align="right" valign="middle">

        <span style="
            display:inline-block;
            padding:6px 10px;
            border:1px solid #374151;
            border-radius:999px;
            color:#d1d5db;
            font-family:Arial,Helvetica,sans-serif;
            font-size:10px;
            font-weight:700;
            letter-spacing:.5px;
        ">
            DAILY REPORT
        </span>

    </td>

    </tr>
    </table>

    </td>
    </tr>

    <!-- ================================================================
         REPORT INTRO
         ================================================================ -->

    <tr>
    <td style="padding:34px 32px 22px;">

        <div style="
            font-family:Arial,Helvetica,sans-serif;
            font-size:11px;
            line-height:16px;
            font-weight:700;
            letter-spacing:1.2px;
            text-transform:uppercase;
            color:#dc2626;
        ">
            Security report
        </div>

        <h1 style="
            margin:7px 0 0;
            font-family:Arial,Helvetica,sans-serif;
            font-size:28px;
            line-height:34px;
            letter-spacing:-.8px;
            color:#111827;
            font-weight:800;
        ">
            Threat activity overview
        </h1>

        <p style="
            margin:8px 0 0;
            font-family:Arial,Helvetica,sans-serif;
            font-size:13px;
            line-height:20px;
            color:#6b7280;
        ">
            Generated {generated_at}
        </p>

    </td>
    </tr>

    <!-- ================================================================
         KPI GRID
         ================================================================ -->

    <tr>
    <td style="padding:0 32px 30px;">

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
    <tr>

    <!-- Total -->
    <td width="25%" valign="top" style="padding-right:6px;">
    <div style="
        border:1px solid #e5e7eb;
        background:#fafafa;
        padding:18px;
        min-height:82px;
    ">
        <div style="
            font-size:25px;
            line-height:30px;
            font-weight:800;
            color:#111827;
        ">
            {stats["total_entries"]}
        </div>

        <div style="
            margin-top:5px;
            font-size:10px;
            line-height:14px;
            color:#6b7280;
            text-transform:uppercase;
            letter-spacing:.7px;
            font-weight:700;
        ">
            Total entries
        </div>
    </div>
    </td>

    <!-- Quarantined -->
    <td width="25%" valign="top" style="padding:0 3px;">
    <div style="
        border:1px solid #fecaca;
        background:#fff7f7;
        padding:18px;
        min-height:82px;
    ">
        <div style="
            font-size:25px;
            line-height:30px;
            font-weight:800;
            color:#dc2626;
        ">
            {stats["active_quarantined"]}
        </div>

        <div style="
            margin-top:5px;
            font-size:10px;
            line-height:14px;
            color:#b91c1c;
            text-transform:uppercase;
            letter-spacing:.7px;
            font-weight:700;
        ">
            Active quarantine
        </div>
    </div>
    </td>

    <!-- Attacks -->
    <td width="25%" valign="top" style="padding:0 3px;">
    <div style="
        border:1px solid #e5e7eb;
        background:#fafafa;
        padding:18px;
        min-height:82px;
    ">
        <div style="
            font-size:25px;
            line-height:30px;
            font-weight:800;
            color:#111827;
        ">
            {stats["attacks_24h"]}
        </div>

        <div style="
            margin-top:5px;
            font-size:10px;
            line-height:14px;
            color:#6b7280;
            text-transform:uppercase;
            letter-spacing:.7px;
            font-weight:700;
        ">
            Attacks · 24h
        </div>
    </div>
    </td>

    <!-- Services -->
    <td width="25%" valign="top" style="padding-left:6px;">
    <div style="
        border:1px solid #e5e7eb;
        background:#fafafa;
        padding:18px;
        min-height:82px;
    ">
        <div style="
            font-size:25px;
            line-height:30px;
            font-weight:800;
            color:#111827;
        ">
            {services_count}
        </div>

        <div style="
            margin-top:5px;
            font-size:10px;
            line-height:14px;
            color:#6b7280;
            text-transform:uppercase;
            letter-spacing:.7px;
            font-weight:700;
        ">
            Services protected
        </div>
    </div>
    </td>

    </tr>
    </table>

    </td>
    </tr>

    <!-- ================================================================
         ACTIVE ALERT
         ================================================================ -->

    <tr>
    <td style="padding:0 32px 30px;">

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"
           style="
               border-left:4px solid #dc2626;
               background:#fff7f7;
           ">
    <tr>
    <td style="padding:15px 18px;">

        <div style="
            font-size:11px;
            line-height:16px;
            font-weight:800;
            color:#991b1b;
            text-transform:uppercase;
            letter-spacing:.7px;
        ">
            Active threat containment
        </div>

        <div style="
            margin-top:3px;
            font-size:13px;
            line-height:20px;
            color:#4b5563;
        ">
            <strong style="color:#111827;">
                {stats["active_quarantined"]}
            </strong>
            IP addresses are currently quarantined across
            <strong style="color:#111827;">
                {services_count}
            </strong>
            protected services.
        </div>

    </td>
    </tr>
    </table>

    </td>
    </tr>

    <!-- ================================================================
         SERVICE BREAKDOWN
         ================================================================ -->

    <tr>
    <td style="padding:0 32px 34px;">

        <div style="
            padding-bottom:13px;
            border-bottom:2px solid #111827;
        ">
            <span style="
                font-size:16px;
                line-height:22px;
                font-weight:800;
                color:#111827;
            ">
                Service breakdown
            </span>

            <span style="
                float:right;
                font-size:10px;
                line-height:22px;
                color:#9ca3af;
                text-transform:uppercase;
                letter-spacing:.7px;
                font-weight:700;
            ">
                QUARANTINE STATUS
            </span>
        </div>

        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
                <td style="
                    padding:10px 0;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                    text-transform:uppercase;
                    letter-spacing:.6px;
                ">
                    Service
                </td>

                <td align="right" style="
                    padding:10px 12px;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                    text-transform:uppercase;
                    letter-spacing:.6px;
                ">
                    Total
                </td>

                <td align="right" style="
                    padding:10px 12px;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                    text-transform:uppercase;
                    letter-spacing:.6px;
                ">
                    Active
                </td>

                <td style="
                    padding:10px 0;
                    width:42%;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                    text-transform:uppercase;
                    letter-spacing:.6px;
                ">
                    Status
                </td>
            </tr>

            {bd_rows}

        </table>

    </td>
    </tr>

    <!-- ================================================================
         TOP OFFENDERS
         ================================================================ -->

    <tr>
    <td style="padding:0 32px 34px;">

        <div style="
            padding-bottom:13px;
            border-bottom:2px solid #111827;
        ">
            <span style="
                font-size:16px;
                line-height:22px;
                font-weight:800;
                color:#111827;
            ">
                Top offenders
            </span>

            <span style="
                float:right;
                font-size:10px;
                line-height:22px;
                color:#9ca3af;
                text-transform:uppercase;
                letter-spacing:.7px;
                font-weight:700;
            ">
                TOP 10 BY EVENTS
            </span>
        </div>

        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">

            <tr>
                <td style="
                    padding:10px 8px 10px 0;
                    width:42px;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                ">
                    #
                </td>

                <td style="
                    padding:10px;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                    text-transform:uppercase;
                    letter-spacing:.6px;
                ">
                    IP address
                </td>

                <td style="
                    padding:10px;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                    text-transform:uppercase;
                    letter-spacing:.6px;
                ">
                    Service
                </td>

                <td style="
                    padding:10px;
                    width:28%;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                    text-transform:uppercase;
                    letter-spacing:.6px;
                ">
                    Events
                </td>

                <td style="
                    padding:10px 0 10px 10px;
                    font-size:10px;
                    font-weight:700;
                    color:#9ca3af;
                    text-transform:uppercase;
                    letter-spacing:.6px;
                ">
                    Last seen
                </td>
            </tr>

            {o_rows}

        </table>

    </td>
    </tr>

    <!-- ================================================================
         FOOTER
         ================================================================ -->

    <tr>
    <td style="
        padding:22px 32px;
        background:#111111;
    ">

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
    <tr>

    <td>
        <div style="
            font-size:13px;
            line-height:18px;
            font-weight:800;
            color:#ffffff;
        ">
            Ban<span style="color:#ef4444;">Watch</span>
        </div>

        <div style="
            margin-top:4px;
            font-size:10px;
            line-height:15px;
            color:#6b7280;
        ">
            Automated security monitoring &amp; IP quarantine
        </div>
    </td>

    <td align="right">
        <div style="
            font-size:10px;
            line-height:15px;
            color:#6b7280;
        ">
            BanWatch v1.0
        </div>

        <div style="
            margin-top:3px;
            font-size:10px;
            line-height:15px;
            color:#4b5563;
        ">
            Report generated automatically
        </div>
    </td>

    </tr>
    </table>

    </td>
    </tr>

    </table>

    <!-- Outer footer -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"
           style="max-width:900px;">
    <tr>
    <td align="center" style="padding:18px 20px;">

        <div style="
            font-family:Arial,Helvetica,sans-serif;
            font-size:10px;
            line-height:15px;
            color:#9ca3af;
        ">
            This report was generated by BanWatch.
            Keep it confidential and intended for authorized recipients only.
        </div>

    </td>
    </tr>
    </table>

    </td>
    </tr>
    </table>

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
