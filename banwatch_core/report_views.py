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



def report_warnings(data):
    health, fw = data['health'], data['firewall']
    warnings = []
    if not health['verified']:
        warnings.append('Monitoring is unverified: no current daemon heartbeat.')
    elif health['monitored'] < len(data['configured_services']):
        warnings.append('Some configured services have unavailable log readers.')
    if fw['status'] == 'rules missing':
        warnings.append('%s active database records have no matching firewall rule.' % fw['missing'])
    elif fw['status'] in ('unverified', 'disabled or unverified'):
        warnings.append('Firewall rule presence could not be verified.')
    if data['invalid_timestamps']:
        warnings.append('%s historical events have invalid dates and are excluded from period counts.' % data['invalid_timestamps'])
    return warnings


def service_health(data, name):
    health = data['health']['services'].get(name)
    if name not in data['configured_services']:
        return 'Not configured', False, ''
    if not health:
        return 'Unverified', False, ''
    if not health['total']:
        return 'No logs', False, ''

    healthy = health['healthy'] == health['total'] and not health['errors']
    state = 'OK' if healthy else '%s/%s reading' % (health['healthy'], health['total'])

    detail = ''
    if not healthy:
        detail = 'Last read ' + when(health['last_read'])
        if health['errors']:
            detail += ' · %s errors' % health['errors']
    return state, healthy, detail


def service_rows(data):
    counts = {s: (total, active) for s, total, active in data['breakdown']}
    names = sorted(set(data['configured_services']) | set(counts) | set(data['events_by_service']))
    rows = []
    for name in names:
        _, active = counts.get(name, (0, 0))
        events = data['events_by_service'].get(name, 0)
        state, healthy, detail = service_health(data, name)
        status_color = '#166534' if healthy else '#b45309'
        status_bg = '#f0fdf4' if healthy else '#fffbeb'
        detail_html = ('<div style="margin-top:3px;font-size:10px;line-height:14px;color:#92400e;">%s</div>' % esc(detail)) if detail else ''
        rows.append('''<tr>
<td style="padding:12px 0;border-bottom:1px solid #e5e7eb;font-size:13px;line-height:18px;font-weight:700;overflow-wrap:anywhere;">%s</td>
<td style="padding:12px 8px;border-bottom:1px solid #e5e7eb;font-size:13px;line-height:18px;text-align:right;color:#374151;">%s</td>
<td style="padding:12px 8px;border-bottom:1px solid #e5e7eb;font-size:13px;line-height:18px;text-align:right;color:#374151;">%s</td>
<td style="padding:12px 0 12px 8px;border-bottom:1px solid #e5e7eb;text-align:right;vertical-align:top;">
<span style="display:inline-block;padding:3px 7px;border-radius:999px;background:%s;color:%s;font-size:10px;line-height:14px;font-weight:700;">%s</span>%s</td>
</tr>''' % (
            esc(name.upper()), format(events, ','), format(active, ','), status_bg, status_color, esc(state), detail_html
        ))
    return ''.join(rows) or '<tr><td colspan="4" style="padding:12px 0;font-size:13px;color:#6b7280;">No services configured.</td></tr>'


def signed_change(current, previous):
    if current is None or previous is None:
        return 'No baseline'
    change = current - previous
    return '%+d' % change if change else '0'


def render_text(data, compact=False):
    stats, health, fw = data['stats'], data['health'], data['firewall']
    baseline = data.get('baseline') or {}
    generated, period, previous = report_dates(data)
    warnings = report_warnings(data)

    status = 'OK - protection healthy' if not warnings else 'WARNING - action may be required'
    monitored = ('%s/%s services monitored' % (health['monitored'], len(data['configured_services']))) if health['verified'] else 'service monitoring unverified'
    firewall = 'Firewall %s/%s' % (fw.get('present', '?'), fw['expected']) if fw['status'] not in ('unverified', 'disabled or unverified') else 'Firewall unverified'

    events_change = signed_change(data['events'], data['previous_events'])
    bans_change = signed_change(stats['active_quarantined'], baseline.get('active_quarantined'))
    actions = data['actions']

    lines = [
        'BANWATCH - %s REPORT' % data['frequency'].upper(),
        '%s | %s' % (data['hostname'], period),
        '',
        'STATUS',
        status,
        '%s | %s' % (monitored, firewall),
    ]

    if warnings:
        lines.extend([''] + ['- ' + warning for warning in warnings])

    lines.extend([
        '',
        'ACTIVITY',
        '%s events (%s vs previous period)' % (format(data['events'], ','), events_change),
        '%s active bans (%s vs comparison report)' % (format(stats['active_quarantined'], ','), bans_change),
        '%s new | %s repeat | %s released | %s expired' % (
            format(actions.get('ban', 0), ','),
            format(actions.get('reban', 0), ','),
            format(actions.get('release', 0), ','),
            format(actions.get('expire', 0), ','),
        ),
        '',
        'SERVICES',
    ])

    counts = {s: (total, active) for s, total, active in data['breakdown']}
    names = sorted(set(data['configured_services']) | set(counts) | set(data['events_by_service']))
    if names:
        for name in names:
            _, active = counts.get(name, (0, 0))
            state, _, detail = service_health(data, name)
            line = '%-12s %s events | %s active | %s' % (
                name.upper()[:12],
                format(data['events_by_service'].get(name, 0), ','),
                format(active, ','),
                state,
            )
            if detail:
                line += ' | ' + detail
            lines.append(line)
    else:
        lines.append('No services configured.')

    lines.extend(['', 'TOP ACTIVITY'])
    if data['offenders']:
        for rank, row in enumerate(data['offenders'][:3], start=1):
            state = row.get('status') or 'observed'
            reason = reason_summary(row.get('reason')) if compact else row.get('reason')
            line = '%s. %s - %s - %s events - %s' % (
                rank, row['ip'], row['service'].upper(), format(row['events'], ','), state
            )
            until = row.get('banned_until')
            if until and state == 'quarantined':
                line += ' until ' + when(until)
            lines.append(line)
            if reason:
                lines.append('   ' + reason)
    else:
        lines.append('No events recorded in this period.')

    lines.extend([
        '',
        'DETAILS',
        'Previous: ' + previous,
        'Generated: ' + generated,
        'Mode: ' + data['mode'],
        'Firewall: %s (%s/%s)' % (fw['status'], fw.get('present', '?'), fw['expected']),
        'Rule presence does not verify rule ordering or packet delivery.',
        '',
        'BanWatch v' + __version__,
    ])
    return '\n'.join(lines)


def render_html(data):
    stats = data['stats']
    baseline = data.get('baseline') or {}
    health = data['health']
    fw = data['firewall']
    generated, period, previous = report_dates(data)
    warnings = report_warnings(data)
    healthy = not warnings

    status_label = 'Protection healthy' if healthy else 'Attention required'
    status_icon = '&#10003;' if healthy else '!'
    status_color = '#166534' if healthy else '#92400e'
    status_bg = '#f0fdf4' if healthy else '#fffbeb'
    status_border = '#bbf7d0' if healthy else '#fde68a'

    monitored = ('%s/%s services monitored' % (health['monitored'], len(data['configured_services']))) if health['verified'] else 'Service monitoring unverified'
    firewall_summary = ('Firewall %s/%s' % (fw.get('present', '?'), fw['expected'])) if fw['status'] not in ('unverified', 'disabled or unverified') else 'Firewall unverified'

    event_change = signed_change(data['events'], data['previous_events'])
    active_change = signed_change(stats['active_quarantined'], baseline.get('active_quarantined'))

    if warnings:
        items = ''.join('<tr><td style="padding:4px 0;font-size:12px;line-height:18px;color:#78350f;">&bull;&nbsp; %s</td></tr>' % esc(w) for w in warnings)
        alerts = '''<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="margin-top:12px;border-collapse:collapse;">%s</table>''' % items
    else:
        alerts = '<div style="margin-top:8px;font-size:12px;line-height:18px;color:#166534;">No monitoring issues detected.</div>'

    actions = data['actions']
    action_line = '<strong>%s</strong> new &nbsp;&middot;&nbsp; <strong>%s</strong> repeat &nbsp;&middot;&nbsp; <strong>%s</strong> released &nbsp;&middot;&nbsp; <strong>%s</strong> expired' % (
        format(actions.get('ban', 0), ','),
        format(actions.get('reban', 0), ','),
        format(actions.get('release', 0), ','),
        format(actions.get('expire', 0), ','),
    )

    offenders = []
    for rank, row in enumerate(data['offenders'][:3], start=1):
        state = row.get('status') or 'observed'
        until = row.get('banned_until')
        state_line = state.title()
        if until and state == 'quarantined':
            state_line += ' until ' + when(until)
        reason = reason_summary(row.get('reason')) or ''
        reason_html = '<div style="margin-top:3px;font-size:11px;line-height:16px;color:#9ca3af;">%s</div>' % esc(reason) if reason else ''
        offenders.append('''<tr>
<td width="34" valign="top" style="padding:13px 0;border-bottom:1px solid #e5e7eb;">
<div style="width:24px;height:24px;line-height:24px;text-align:center;border-radius:50%%;background:#111827;color:#ffffff;font-size:11px;font-weight:700;">%s</div>
</td>
<td valign="top" style="padding:13px 8px;border-bottom:1px solid #e5e7eb;overflow-wrap:anywhere;">
<div style="font-family:'Courier New',monospace;font-size:13px;line-height:18px;font-weight:700;color:#111827;">%s</div>
<div style="margin-top:2px;font-size:11px;line-height:16px;color:#6b7280;">%s &middot; %s</div>
%s
</td>
<td width="84" valign="top" align="right" style="padding:13px 0;border-bottom:1px solid #e5e7eb;">
<div style="font-size:15px;line-height:18px;font-weight:800;color:#111827;">%s</div>
<div style="font-size:10px;line-height:14px;color:#9ca3af;text-transform:uppercase;">events</div>
</td>
</tr>''' % (
            rank, esc(row['ip']), esc(row['service'].upper()), esc(state_line), reason_html, format(row['events'], ',')
        ))
    top_rows = ''.join(offenders) or '<tr><td style="padding:13px 0;font-size:13px;color:#6b7280;">No events recorded in this period.</td></tr>'

    baseline_note = 'No earlier KPI baseline.'
    if baseline.get('generated_at'):
        baseline_note = 'KPI comparison: %s (%s).' % (when(baseline['generated_at'], True), data['baseline_kind'])

    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BanWatch report</title>
<style>
@media only screen and (max-width:520px) {
 .outer {padding:10px 6px!important;}
 .content {padding-left:18px!important;padding-right:18px!important;}
 .metric-number {font-size:25px!important;line-height:30px!important;}
 .metric-cell {padding:14px 10px!important;}
 .service-table th,.service-table td {font-size:11px!important;}
}
</style></head>
<body style="margin:0;padding:0;background:#f3f4f6;color:#111827;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;background:#f3f4f6;border-collapse:collapse;"><tr><td class="outer" align="center" style="padding:24px 12px;">
<!--[if mso]><table role="presentation" width="640"><tr><td><![endif]-->
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-collapse:collapse;">

<tr><td class="content" style="padding:22px 24px;background:#111111;color:#ffffff;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;border-collapse:collapse;"><tr>
<td valign="top"><div style="font-size:18px;line-height:22px;font-weight:800;">Ban<span style="color:#ef4444;">Watch</span></div>
<div style="margin-top:5px;font-size:11px;line-height:16px;color:#d1d5db;overflow-wrap:anywhere;">%(host)s</div></td>
<td valign="top" align="right"><div style="font-size:10px;line-height:14px;font-weight:700;color:#d1d5db;text-transform:uppercase;">%(frequency)s report</div>
<div style="margin-top:4px;font-size:10px;line-height:14px;color:#6b7280;">%(period)s</div></td>
</tr></table></td></tr>

<tr><td class="content" style="padding:24px;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;border:1px solid %(status_border)s;background:%(status_bg)s;border-collapse:collapse;"><tr><td style="padding:17px 18px;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;border-collapse:collapse;"><tr>
<td width="34" valign="top"><div style="width:24px;height:24px;line-height:24px;text-align:center;border-radius:50%%;background:%(status_color)s;color:#ffffff;font-size:13px;font-weight:800;">%(status_icon)s</div></td>
<td valign="top"><div style="font-size:17px;line-height:22px;font-weight:800;color:%(status_color)s;">%(status_label)s</div>
<div style="margin-top:4px;font-size:12px;line-height:18px;color:#4b5563;">%(monitored)s &nbsp;&middot;&nbsp; %(firewall_summary)s</div>%(alerts)s</td>
</tr></table></td></tr></table></td></tr>

<tr><td class="content" style="padding:0 24px 24px;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;border-collapse:collapse;table-layout:fixed;"><tr>
<td class="metric-cell" width="50%%" valign="top" style="padding:16px;border:1px solid #e5e7eb;background:#fafafa;">
<div class="metric-number" style="font-size:30px;line-height:34px;font-weight:800;color:#111827;">%(events)s</div>
<div style="margin-top:4px;font-size:10px;line-height:14px;font-weight:700;text-transform:uppercase;color:#6b7280;">Events</div>
<div style="margin-top:6px;font-size:11px;line-height:16px;color:#6b7280;">%(event_change)s vs previous period</div></td>
<td width="8"></td>
<td class="metric-cell" width="50%%" valign="top" style="padding:16px;border:1px solid #e5e7eb;background:#fafafa;">
<div class="metric-number" style="font-size:30px;line-height:34px;font-weight:800;color:#111827;">%(active)s</div>
<div style="margin-top:4px;font-size:10px;line-height:14px;font-weight:700;text-transform:uppercase;color:#6b7280;">Active bans</div>
<div style="margin-top:6px;font-size:11px;line-height:16px;color:#6b7280;">%(active_change)s vs comparison report</div></td>
</tr></table>
<div style="padding:12px 2px 0;font-size:12px;line-height:19px;color:#4b5563;">%(action_line)s</div></td></tr>

<tr><td class="content" style="padding:0 24px 26px;">
<div style="padding-bottom:8px;border-bottom:2px solid #111827;font-size:14px;line-height:20px;font-weight:800;text-transform:uppercase;letter-spacing:.03em;">Services</div>
<table class="service-table" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;table-layout:fixed;border-collapse:collapse;"><thead><tr>
<th width="37%%" style="padding:10px 0;text-align:left;font-size:9px;line-height:13px;color:#9ca3af;text-transform:uppercase;">Service</th>
<th width="18%%" style="padding:10px 8px;text-align:right;font-size:9px;line-height:13px;color:#9ca3af;text-transform:uppercase;">Events</th>
<th width="18%%" style="padding:10px 8px;text-align:right;font-size:9px;line-height:13px;color:#9ca3af;text-transform:uppercase;">Active</th>
<th width="27%%" style="padding:10px 0 10px 8px;text-align:right;font-size:9px;line-height:13px;color:#9ca3af;text-transform:uppercase;">Health</th>
</tr></thead><tbody>%(services)s</tbody></table></td></tr>

<tr><td class="content" style="padding:0 24px 28px;">
<div style="padding-bottom:8px;border-bottom:2px solid #111827;font-size:14px;line-height:20px;font-weight:800;text-transform:uppercase;letter-spacing:.03em;">Top activity</div>
<table width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;border-collapse:collapse;table-layout:fixed;">%(offenders)s</table></td></tr>

<tr><td class="content" style="padding:18px 24px;background:#f9fafb;border-top:1px solid #e5e7eb;">
<div style="font-size:10px;line-height:16px;color:#6b7280;"><strong style="color:#374151;">Details</strong><br>
Previous: %(previous_period)s<br>Generated: %(generated)s<br>Mode: %(mode)s &middot; Firewall: %(firewall)s<br>%(baseline_note)s<br>
Rule presence does not verify rule ordering or packet delivery.</div></td></tr>

<tr><td class="content" style="padding:16px 24px;background:#111111;color:#9ca3af;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;border-collapse:collapse;"><tr>
<td style="font-size:10px;line-height:15px;">BanWatch &middot; Automated security monitoring &amp; IP quarantine</td>
<td align="right" style="font-size:10px;line-height:15px;">v%(version)s</td>
</tr></table></td></tr>

</table>
<!--[if mso]></td></tr></table><![endif]-->
<div style="max-width:640px;padding:13px 16px;font-size:9px;line-height:14px;color:#9ca3af;text-align:left;">Confidential automated security report for authorized recipients.</div>
</td></tr></table></body></html>''' % {
        'host': esc(data['hostname']),
        'frequency': esc(data['frequency'].upper()),
        'period': esc(period),
        'generated': esc(generated),
        'previous_period': esc(previous),
        'status_border': status_border,
        'status_bg': status_bg,
        'status_color': status_color,
        'status_icon': status_icon,
        'status_label': esc(status_label),
        'monitored': esc(monitored),
        'firewall_summary': esc(firewall_summary),
        'alerts': alerts,
        'events': format(data['events'], ','),
        'event_change': esc(event_change),
        'active': format(stats['active_quarantined'], ','),
        'active_change': esc(active_change),
        'action_line': action_line,
        'services': service_rows(data),
        'offenders': top_rows,
        'mode': esc(data['mode']),
        'firewall': esc('%s (%s/%s)' % (fw['status'], fw.get('present', '?'), fw['expected'])),
        'baseline_note': esc(baseline_note),
        'version': esc(__version__),
    }
