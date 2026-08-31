import html
import re
from datetime import datetime

from . import __version__


def esc(value):
    return html.escape(str(value), quote=True)


def when(timestamp, full=False):
    if not timestamp:
        return 'Not observed'
    try:
        value = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else datetime.fromtimestamp(timestamp)
        return value.astimezone().strftime('%Y-%m-%d %H:%M %Z (UTC%z)' if full else '%d %b %H:%M')
    except (ValueError, TypeError, OverflowError, OSError):
        return 'Unknown date'


def period_label(start, end, report_year):
    same_year = start.year == end.year
    same_month = same_year and start.month == end.month
    start_format = '%d' if same_month else ('%d %b' if same_year else '%d %b %Y')
    end_format = '%d %b' if same_year and end.year == report_year else '%d %b %Y'
    same_time = start.strftime('%H:%M') == end.strftime('%H:%M')
    same_offset = start.utcoffset() == end.utcoffset()
    if same_time and same_offset:
        return '%s\u2013%s, %s' % (start.strftime(start_format), end.strftime(end_format), end.strftime('%H:%M'))
    # Keep both clock times and zones when an elapsed-time period crosses DST.
    start_format = '%d %b' if same_year and start.year == report_year else '%d %b %Y'
    suffix = ', %H:%M' + (' %Z' if not same_offset else '')
    return '%s \u2013 %s' % (start.strftime(start_format + suffix), end.strftime(end_format + suffix))


def report_dates(data):
    start, end, previous = [datetime.fromtimestamp(stamp).astimezone() for stamp in
                            (data['start'], data['end'], data['start'] - data['seconds'])]
    return (end.strftime('%d %b %Y, %H:%M %Z'),
            period_label(start, end, end.year), period_label(previous, start, end.year))


def reason_summary(reason):
    match = re.fullmatch(r'(\d+) score \((\d+) events\) on [^;\r\n]+(?:; rule:.*)?', reason or '', re.S)
    if match:
        return 'Score %s \u00b7 %s events' % match.groups()
    return reason


def delta(value, previous, positive_good=False, neutral=False):
    if value is None or previous is None:
        return '<span style="color:#6b7280">No baseline</span>'
    change = value - previous
    color = '#6b7280'
    if change and not neutral:
        color = '#15803d' if (change > 0) == positive_good else '#b91c1c'
    return '<span style="color:%s">%s</span>' % (color, format(change, '+,d') if change else '0')


def service_rows(data):
    counts = {s: (total, active) for s, total, active in data['breakdown']}
    names = sorted(set(data['configured_services']) | set(counts) | set(data['events_by_service']))
    rows = []
    for name in names:
        health = data['health']['services'].get(name)
        if name not in data['configured_services']:
            state = 'Not configured'
        elif not health:
            state = 'Unverified'
        elif not health['total']:
            state = 'No logs'
        else:
            state = '%s/%s reading' % (health['healthy'], health['total'])
        detail = ''
        if health:
            detail = 'Last read: ' + when(health['last_read'])
            if health['errors']:
                detail += ' - %s errors' % health['errors']
        total, active = counts.get(name, (0, 0))
        pct = round(active / max(total, 1) * 100)
        rows.append('''<tr>
<td class="service-cell" style="padding:14px 0;border-bottom:1px solid #e5e7eb;font-size:13px;line-height:18px;overflow-wrap:anywhere;vertical-align:top;">
<strong>%s</strong><div style="font-size:10px;color:#9ca3af;margin-top:5px;">%s events in period</div></td>
<td class="service-cell" style="padding:14px 12px;border-bottom:1px solid #e5e7eb;font-size:13px;color:#4b5563;text-align:right;vertical-align:top;overflow-wrap:anywhere;">%s</td>
<td class="service-cell" style="padding:14px 12px;border-bottom:1px solid #e5e7eb;text-align:right;vertical-align:top;overflow-wrap:anywhere;">
<span style="display:inline-block;max-width:100%%;box-sizing:border-box;padding:4px 8px;background:#fef2f2;color:#dc2626;border-radius:999px;font-size:11px;font-weight:700;">%s</span></td>
<td class="service-cell" style="padding:14px 0;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:anywhere;">
<div style="background:#e5e7eb;border-radius:999px;height:6px;line-height:6px;font-size:0;"><div style="width:%s%%;height:6px;background:#dc2626;border-radius:999px;line-height:6px;font-size:0;">&nbsp;</div></div>
<div style="margin-top:5px;font-size:10px;line-height:14px;color:#9ca3af;">%s%% still quarantined</div>
<div style="margin-top:5px;font-size:11px;line-height:17px;color:#4b5563;">Log readers: %s</div>
<div style="font-size:10px;line-height:14px;color:#9ca3af;">%s</div></td></tr>''' % (
            esc(name.upper()), format(data['events_by_service'].get(name, 0), ','),
            format(total, ','), format(active, ','), pct, pct, esc(state), esc(detail)))
    return ''.join(rows) or '<tr><td colspan="4" style="padding:14px 0;font-size:13px;">No services configured.</td></tr>'


def render_text(data, compact=False):
    stats, fw = data['stats'], data['firewall']
    baseline = data['baseline']
    lines = [
        'BanWatch %s report | %s' % (data['frequency'].title(), data['hostname']),
        'Generated: ' + when(data['end'], True),
        'Period: %s to %s' % (when(data['start'], True), when(data['end'], True)),
        'Previous period: %s to %s' % (when(data['start']-data['seconds'], True), when(data['start'], True)),
        'Comparison report (%s): %s' % (data['baseline_kind'], when(baseline.get('generated_at'), True) if baseline else 'First report'),
    ]
    if compact:
        generated, period, previous = report_dates(data)
        lines[1:4] = ['Generated ' + generated, 'Period: ' + period, 'Previous: ' + previous]
    for key, label in [('total_entries', 'IPs ever banned'), ('active_quarantined', 'Active bans'), ('monitored', 'Monitored services')]:
        current = data['metrics'][key]
        prior = baseline.get(key)
        suffix = 'no baseline' if prior is None or current is None else format(current-prior, '+d') + ' vs comparison report'
        lines.append('%s: %s (%s)' % (label, current if current is not None else 'unverified', suffix))
    lines.extend([
        'Events: %s (%+d vs previous period)' % (data['events'], data['events']-data['previous_events']),
        'Mode: ' + data['mode'],
        'Firewall rule check: %s (%s/%s)' % (fw['status'],fw.get('present', '?'),fw['expected']),
        'Rule presence does not verify rule ordering or packet delivery.',
        'Ban activity since %s: %s new, %s repeat, %s released, %s expired' % (
            when(max(data['tracking_since'],data['start']),True),
            *(data['actions'].get(k,0) for k in ['ban','reban','release','expire'])),
        '', 'Service breakdown (events in period, current active bans):',
    ])
    for service, total, active in data['breakdown']:
        lines.append('%s: %s events, %s active bans' % (service,data['events_by_service'].get(service,0),active))
    lines.append('\nTop IPs in period:')
    for row in data['offenders']:
        reason = reason_summary(row.get('reason')) if compact else row.get('reason')
        lines.append('%s | %s | %s events | %s | %s | expires %s' % (
            row['ip'],row['service'],row['events'],row.get('status') or 'observed',
            reason or '-',when(row.get('banned_until')) if row.get('banned_until') else 'not scheduled'))
    return '\n'.join(lines + ['', 'BanWatch v' + __version__])


def render_html(data):
    stats, baseline, health, fw = data['stats'], data['baseline'], data['health'], data['firewall']
    generated, period, previous = report_dates(data)
    cards = [
        (format(stats['total_entries'], ','), 'IPs ever banned', delta(stats['total_entries'],baseline.get('total_entries'),neutral=True)),
        (format(stats['active_quarantined'], ','), 'Active bans', delta(stats['active_quarantined'],baseline.get('active_quarantined'),neutral=True)),
        (format(data['events'], ','), 'Events in period', delta(data['events'],data['previous_events']) + ' <span style="color:#6b7280;font-weight:400;">vs previous period</span>'),
        (('%s / %s' % (health['monitored'],len(data['configured_services']))) if health['verified'] else 'Unknown',
         'Monitored services', delta(data['metrics']['monitored'],baseline.get('monitored'),positive_good=True)),
    ]
    kpis = ''.join('<td class="kpi" width="25%%" valign="top" style="padding:0 5px;vertical-align:top;">'
                   '<div class="kpi-card" style="border:1px solid %s;background:%s;padding:18px;min-height:82px;">'
                   '<div style="font-size:%spx;line-height:30px;font-weight:800;color:%s;overflow-wrap:anywhere;">%s</div>'
                   '<div style="margin-top:6px;font-size:10px;line-height:14px;font-weight:700;text-transform:uppercase;color:%s;">%s</div>'
                   '<div style="font-size:10px;line-height:14px;margin-top:7px;font-weight:700;">%s</div></div></td>' % (
                       '#fecaca' if i == 1 else '#e5e7eb', '#fff7f7' if i == 1 else '#fafafa',
                       25 if len(value) < 10 else 14, '#dc2626' if i == 1 else '#111827', value,
                       '#b91c1c' if i == 1 else '#6b7280', label, change)
                   for i,(value,label,change) in enumerate(cards))
    reference = ('Other KPI changes vs %s (%s).' % (when(baseline['generated_at'],True),data['baseline_kind'])) if baseline else 'First report: no earlier comparison for other KPIs.'
    warnings = []
    if not health['verified']:
        warnings.append('Monitoring is unverified: no current daemon heartbeat.')
    elif health['monitored'] < len(data['configured_services']):
        warnings.append('Some configured services have unavailable log readers; see service breakdown.')
    if fw['status'] == 'rules missing':
        warnings.append('%s active database records have no matching firewall rule.' % fw['missing'])
    elif fw['status'] in ('unverified', 'disabled or unverified'):
        warnings.append('Firewall rule presence could not be verified.')
    if data['invalid_timestamps']:
        warnings.append('%s historical events have invalid dates and are excluded from period counts.' % data['invalid_timestamps'])
    alert = ''.join('<p style="margin:12px 0;padding:12px;border-left:3px solid #b45309;background:#fffbeb;color:#78350f;font-size:13px;">%s</p>' % esc(w) for w in warnings)
    offenders = []
    max_events = max((row['events'] for row in data['offenders']), default=1)
    for rank, row in enumerate(data['offenders'], start=1):
        state = row.get('status') or 'observed'
        until = row.get('banned_until')
        expiry = ('Until ' + when(until)) if until and state == 'quarantined' else ('No expiry' if state == 'quarantined' else '')
        rank_bg = ['#dc2626', '#374151', '#6b7280'][rank-1] if rank <= 3 else '#e5e7eb'
        offenders.append('''<tr class="offender-row">
<td class="rank-cell" style="padding:15px 0;border-bottom:1px solid #e5e7eb;vertical-align:top;">
<span style="display:inline-block;width:26px;height:26px;line-height:26px;text-align:center;border-radius:50%%;background:%s;color:%s;font-size:11px;font-weight:700;">%s</span></td>
<td class="ip-cell" style="padding:15px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:anywhere;">
<strong style="font-family:'Courier New',monospace;font-size:13px;line-height:18px;">%s</strong>
<div style="font-size:11px;line-height:17px;color:#6b7280;margin-top:5px;">%s</div>
<div style="font-size:11px;line-height:17px;color:#6b7280;">%s</div>
<div style="font-size:11px;line-height:17px;color:#6b7280;margin-top:4px;">%s</div></td>
<td class="offender-meta" style="padding:15px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:anywhere;font-size:11px;line-height:18px;font-weight:700;color:#6b7280;">
<span class="mobile-label" style="display:none;font-size:10px;font-weight:400;">Service</span>%s</td>
<td class="offender-meta" style="padding:15px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:anywhere;">
<strong style="font-size:13px;line-height:18px;color:#dc2626;">%s</strong> <span style="font-size:10px;color:#9ca3af;">events</span>
<div style="background:#f3f4f6;height:4px;margin-top:7px;border-radius:999px;font-size:0;line-height:4px;"><div style="width:%s%%;height:4px;background:#dc2626;border-radius:999px;font-size:0;line-height:4px;">&nbsp;</div></div></td>
<td class="offender-meta" style="padding:15px 0 15px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:anywhere;font-size:11px;line-height:18px;color:#6b7280;">
<span class="mobile-label" style="display:none;font-size:10px;">Last seen</span>%s</td></tr>''' % (
            rank_bg, '#ffffff' if rank <= 3 else '#6b7280', rank, esc(row['ip']), esc(state.title()),
            esc(expiry), esc(reason_summary(row.get('reason')) or 'No ban recorded'), esc(row['service'].upper()),
            format(row['events'], ','), round(row['events'] / max(max_events, 1) * 100), esc(when(row['last_seen']))))
    top_rows = ''.join(offenders) or '<tr><td colspan="5" style="padding:15px 0;font-size:13px;">No events recorded in this period.</td></tr>'
    actions = ' &nbsp; '.join('<strong>%s</strong> %s' % (format(data['actions'].get(key,0),','), label)
                            for key,label in [('ban','new bans'),('reban','repeat bans'),('release','released'),('expire','expired')])
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BanWatch report</title>
<style>
@media only screen and (max-width:520px) {
 .outer {padding:12px 6px!important;} .content {padding:18px 12px!important;}
 .kpi {display:inline-block!important;width:50%%!important;box-sizing:border-box;padding:4px!important;}
 .kpi-card {padding:12px!important;min-height:100px!important;} .service-cell {padding:12px 3px!important;}
 .service-cell strong {font-size:11px!important;}
 .offenders thead {display:none!important;} .offender-row {display:block!important;border-bottom:1px solid #e5e7eb;font-size:0;}
 .rank-cell {display:block!important;float:left;padding:15px 0!important;border:0!important;}
 .ip-cell {display:block!important;padding:15px 0 8px 36px!important;border:0!important;}
 .offender-meta {display:inline-block!important;width:33.333%%!important;box-sizing:border-box;padding:8px 4px 15px!important;border:0!important;}
 .mobile-label {display:block!important;}
}
</style></head>
<body style="margin:0;padding:0;background:#f3f4f6;color:#111827;font-family:Arial,Helvetica,sans-serif;letter-spacing:0;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:#f3f4f6;border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;"><tr><td class="outer" align="center" style="padding:32px 12px;">
<!--[if mso]><table role="presentation" width="900"><tr><td><![endif]-->
<table role="presentation" class="shell" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;max-width:900px;background:#ffffff;border:1px solid #e5e7eb;border-collapse:collapse;table-layout:fixed;font-family:Arial,Helvetica,sans-serif;">
<tr><td class="content" style="padding:28px 32px;background:#111111;color:#ffffff;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;table-layout:fixed;border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;"><tr>
<td style="width:42%%;vertical-align:top;"><div style="font-size:20px;line-height:24px;font-weight:800;">Ban<span style="color:#ef4444;">Watch</span></div>
<div style="font-size:11px;line-height:17px;color:#d1d5db;margin-top:7px;overflow-wrap:anywhere;word-break:break-all;">%(host)s</div></td>
<td style="text-align:right;vertical-align:top;"><div style="display:inline-block;border:1px solid #374151;border-radius:999px;padding:6px 10px;font-size:10px;line-height:14px;font-weight:700;">%(frequency)s REPORT</div>
<div style="font-size:10px;line-height:15px;color:#9ca3af;margin-top:7px;overflow-wrap:anywhere;">Generated %(generated)s</div></td></tr></table>
</td></tr>
<tr><td class="content" style="padding:34px 32px 22px;">
<h1 style="font-size:28px;line-height:34px;font-weight:800;margin:8px 0 14px;">Threat activity overview</h1>
<p style="margin:0 0 5px;font-size:12px;line-height:20px;color:#4b5563;">Period: %(period)s</p>
<p style="margin:0;font-size:11px;line-height:17px;color:#6b7280;">Previous: %(previous_period)s</p>
</td></tr>
<tr><td class="content" style="padding:0 27px 30px;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;table-layout:fixed;border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;"><tr>%(kpis)s</tr></table>
<p style="font-size:11px;line-height:17px;color:#6b7280;margin:12px 5px 0;">%(reference)s</p>
</td></tr>
<tr><td class="content" style="padding:0 32px 30px;">
<p style="font-size:12px;line-height:20px;margin:0;"><strong>%(mode)s</strong> &nbsp; Firewall: %(firewall)s</p>
<p style="font-size:11px;line-height:17px;color:#6b7280;margin:4px 0;">Rule presence checked; packet-path ordering is not audited.</p>
%(alerts)s
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;table-layout:fixed;border-collapse:collapse;border-bottom:2px solid #111827;margin-top:24px;font-family:Arial,Helvetica,sans-serif;"><tr>
<td style="padding:0 0 12px;"><h2 style="font-size:16px;line-height:22px;font-weight:800;margin:0;">Service breakdown</h2></td></tr></table>
<table width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;table-layout:fixed;border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;"><thead><tr>
<th class="service-cell" scope="col" width="26%%" style="padding:12px 0;text-align:left;font-size:10px;color:#9ca3af;text-transform:uppercase;">Service</th>
<th class="service-cell" scope="col" width="16%%" style="padding:12px;text-align:right;font-size:10px;color:#9ca3af;text-transform:uppercase;">Total</th>
<th class="service-cell" scope="col" width="16%%" style="padding:12px;text-align:right;font-size:10px;color:#9ca3af;text-transform:uppercase;">Active</th>
<th class="service-cell" scope="col" width="42%%" style="padding:12px 0;text-align:left;font-size:10px;color:#9ca3af;text-transform:uppercase;">Status</th>
</tr></thead><tbody>%(services)s</tbody></table>
<p style="font-size:12px;line-height:22px;margin:14px 0 3px;">%(actions)s</p>
<p style="font-size:11px;line-height:17px;color:#6b7280;margin:0;">Ban actions tracked from %(tracking)s within this period.</p>
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;table-layout:fixed;border-collapse:collapse;border-bottom:2px solid #111827;margin-top:24px;font-family:Arial,Helvetica,sans-serif;"><tr>
<td style="padding:0 0 12px;"><h2 style="font-size:16px;line-height:22px;font-weight:800;margin:0;">Top offenders</h2></td></tr></table>
<table class="offenders" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;table-layout:fixed;border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;"><thead><tr>
<th scope="col" width="6%%" style="padding:12px 0;text-align:left;font-size:10px;color:#9ca3af;text-transform:uppercase;">#</th>
<th scope="col" width="28%%" style="padding:12px 8px;text-align:left;font-size:10px;color:#9ca3af;text-transform:uppercase;">IP address</th>
<th scope="col" width="14%%" style="padding:12px 8px;text-align:left;font-size:10px;color:#9ca3af;text-transform:uppercase;">Service</th>
<th scope="col" width="28%%" style="padding:12px 8px;text-align:left;font-size:10px;color:#9ca3af;text-transform:uppercase;">Events</th>
<th scope="col" width="24%%" style="padding:12px 0 12px 8px;text-align:left;font-size:10px;color:#9ca3af;text-transform:uppercase;">Last seen</th>
</tr></thead><tbody>%(offenders)s</tbody></table>
</td></tr>
<tr><td class="content" style="padding:22px 32px;background:#111111;color:#d1d5db;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;table-layout:fixed;border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;"><tr>
<td style="width:60%%;vertical-align:top;"><div style="font-size:13px;line-height:18px;font-weight:800;color:#ffffff;">Ban<span style="color:#ef4444;">Watch</span></div>
<div style="font-size:10px;line-height:15px;color:#6b7280;margin-top:4px;">Automated security monitoring &amp; IP quarantine</div></td>
<td style="text-align:right;vertical-align:top;font-size:10px;line-height:15px;color:#6b7280;">BanWatch v%(version)s<div style="margin-top:3px;color:#4b5563;">Report generated automatically</div></td>
</tr></table>
</td></tr></table>
<!--[if mso]></td></tr></table><![endif]-->
<p style="max-width:900px;margin:0;padding:18px 20px;font-size:10px;line-height:15px;color:#9ca3af;">This report was generated by BanWatch. Keep it confidential and intended for authorized recipients only.</p>
</td></tr></table></body></html>''' % {
        'host': esc(data['hostname']), 'frequency': esc(data['frequency'].upper()),
        'generated': esc(generated), 'period': esc(period), 'previous_period': esc(previous),
        'kpis': kpis, 'reference': esc(reference), 'mode': esc(data['mode']),
        'firewall': esc('%s (%s/%s)' % (fw['status'],fw.get('present','?'),fw['expected'])),
        'alerts': alert, 'services': service_rows(data), 'actions': actions,
        'tracking': esc(when(max(data['tracking_since'],data['start']),True)),
        'offenders': top_rows, 'version': esc(__version__),
    }
