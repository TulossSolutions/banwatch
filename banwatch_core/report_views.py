import html
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
        rows.append('<tr><td><strong>%s</strong></td><td class="number">%s</td>'
                    '<td class="number">%s</td><td>%s<div class="muted">%s</div></td></tr>' % (
                        esc(name.upper()), format(data['events_by_service'].get(name, 0), ','),
                        format(counts.get(name, (0,0))[1], ','), esc(state), esc(detail)))
    return ''.join(rows) or '<tr><td colspan="4">No services configured.</td></tr>'


def render_text(data):
    stats, fw = data['stats'], data['firewall']
    baseline = data['baseline']
    lines = [
        'BanWatch %s report | %s' % (data['frequency'].title(), data['hostname']),
        'Generated: ' + when(data['end'], True),
        'Period: %s to %s' % (when(data['start'], True), when(data['end'], True)),
        'Previous period: %s to %s' % (when(data['start']-data['seconds'], True), when(data['start'], True)),
        'Comparison report (%s): %s' % (data['baseline_kind'], when(baseline.get('generated_at'), True) if baseline else 'First report'),
    ]
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
        lines.append('%s | %s | %s events | %s | %s | expires %s' % (
            row['ip'],row['service'],row['events'],row.get('status') or 'observed',
            row.get('reason') or '-',when(row.get('banned_until')) if row.get('banned_until') else 'not scheduled'))
    return '\n'.join(lines + ['', 'BanWatch v' + __version__])


def render_html(data):
    stats, baseline, health, fw = data['stats'], data['baseline'], data['health'], data['firewall']
    cards = [
        (format(stats['total_entries'], ','), 'IPs ever banned', delta(stats['total_entries'],baseline.get('total_entries'),neutral=True)),
        (format(stats['active_quarantined'], ','), 'Active bans', delta(stats['active_quarantined'],baseline.get('active_quarantined'),neutral=True)),
        (format(data['events'], ','), 'Events in period', delta(data['events'],data['previous_events']) + ' <span class="muted">vs previous period</span>'),
        (('%s / %s' % (health['monitored'],len(data['configured_services']))) if health['verified'] else 'Unknown',
         'Monitored services', delta(data['metrics']['monitored'],baseline.get('monitored'),positive_good=True)),
    ]
    kpis = ''.join('<td class="kpi" width="25%%" valign="top" style="padding:6px;vertical-align:top;">'
                   '<div style="border-top:2px solid #111827;padding:12px 0;">'
                   '<div style="font-size:%spx;line-height:32px;font-weight:700;overflow-wrap:anywhere;">%s</div>'
                   '<div style="font-size:12px;line-height:18px;color:#4b5563;">%s</div>'
                   '<div style="font-size:11px;line-height:17px;margin-top:5px;">%s</div></div></td>' % (24 if len(value)<10 else 14,value,label,change)
                   for value,label,change in cards)
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
    for row in data['offenders']:
        state = row.get('status') or 'observed'
        until = row.get('banned_until')
        expiry = ('Until ' + when(until)) if until and state == 'quarantined' else ('No expiry' if state == 'quarantined' else '')
        offenders.append('<tr><td><strong class="ip">%s</strong><div class="muted">%s</div></td>'
                         '<td class="number"><strong>%s</strong><div class="muted">%s</div></td>'
                         '<td>%s<div class="muted">%s</div><div class="muted reason">%s</div></td></tr>' % (
                             esc(row['ip']),esc(row['service'].upper()),format(row['events'],','),esc(when(row['last_seen'])),
                             esc(state.title()),esc(expiry),esc(row.get('reason') or 'No ban recorded')))
    top_rows = ''.join(offenders) or '<tr><td colspan="3">No events recorded in this period.</td></tr>'
    actions = ' &nbsp; '.join('<strong>%s</strong> %s' % (format(data['actions'].get(key,0),','), label)
                            for key,label in [('ban','new bans'),('reban','repeat bans'),('release','released'),('expire','expired')])
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BanWatch report</title>
<style>
body,table,td,th {font-family:Arial,Helvetica,sans-serif;letter-spacing:0;}
body {margin:0;padding:0;background:#f3f4f6;color:#111827;}
table {border-collapse:collapse;} .shell {width:100%%;max-width:720px;table-layout:fixed;}
.content {padding:22px 28px;} .muted {color:#6b7280;font-size:11px;line-height:17px;font-weight:400;}
.data {width:100%%;table-layout:fixed;} .data td,.data th {padding:11px 6px;border-bottom:1px solid #e5e7eb;text-align:left;font-size:12px;line-height:18px;overflow-wrap:anywhere;word-wrap:break-word;}
.data th {font-size:11px;color:#4b5563;font-weight:700;} .data .number {text-align:right;} .ip {font-family:'Courier New',monospace;font-size:12px;}
h2 {font-size:16px;line-height:22px;margin:22px 0 6px;} p {line-height:20px;} .reason {margin-top:4px;}
@media only screen and (max-width:520px) {
 .content {padding:16px 12px!important;} .kpi {display:inline-block!important;width:50%%!important;box-sizing:border-box;}
 .data td,.data th {padding:9px 3px!important;} .brand {font-size:19px!important;} .report-title {font-size:12px!important;}
}
</style></head>
<body><table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:#f3f4f6;"><tr><td align="center">
<!--[if mso]><table role="presentation" width="720"><tr><td><![endif]-->
<table role="presentation" class="shell" width="100%%" cellpadding="0" cellspacing="0" border="0" style="width:100%%;max-width:720px;background:#ffffff;table-layout:fixed;">
<tr><td class="content" style="padding:22px 28px;background:#111111;color:#ffffff;">
<table role="presentation" width="100%%" style="width:100%%;table-layout:fixed;"><tr>
<td style="width:42%%;vertical-align:top;"><div class="brand" style="font-size:23px;line-height:28px;font-weight:700;">Ban<span style="color:#f87171;">Watch</span></div>
<div style="font-size:12px;line-height:18px;color:#d1d5db;margin-top:7px;overflow-wrap:anywhere;word-break:break-all;">%(host)s</div></td>
<td style="text-align:right;vertical-align:top;"><div class="report-title" style="font-size:14px;line-height:20px;font-weight:700;">%(frequency)s REPORT</div>
<div style="font-size:11px;line-height:17px;color:#d1d5db;margin-top:5px;">Generated %(generated)s</div></td></tr></table>
</td></tr>
<tr><td class="content" style="padding:22px 28px;">
<p style="margin:0 0 5px;font-size:12px;color:#4b5563;">%(period)s</p>
<p style="margin:0 0 16px;font-size:11px;color:#6b7280;">Previous period: %(previous_period)s</p>
<table role="presentation" width="100%%" style="width:100%%;table-layout:fixed;"><tr>%(kpis)s</tr></table>
<p class="muted" style="font-size:11px;line-height:17px;color:#6b7280;margin:0 0 16px;">%(reference)s</p>
<p style="font-size:12px;margin:0;"><strong>%(mode)s</strong> &nbsp; Firewall: %(firewall)s</p>
<p class="muted" style="font-size:11px;line-height:17px;color:#6b7280;margin:4px 0;">Rule presence checked; packet-path ordering is not audited.</p>
%(alerts)s
<h2 style="font-size:16px;line-height:22px;margin:24px 0 6px;">Service breakdown</h2>
<table class="data" width="100%%" style="width:100%%;table-layout:fixed;"><thead><tr>
<th scope="col" width="22%%">Service</th><th scope="col" width="15%%" class="number">Events</th><th scope="col" width="15%%" class="number">Active</th><th scope="col" width="48%%">Log readers</th>
</tr></thead><tbody>%(services)s</tbody></table>
<p style="font-size:12px;line-height:22px;margin:14px 0 3px;">%(actions)s</p>
<p class="muted" style="font-size:11px;line-height:17px;color:#6b7280;margin:0;">Ban actions tracked from %(tracking)s within this period.</p>
<h2 style="font-size:16px;line-height:22px;margin:24px 0 6px;">Top IPs in this period</h2>
<table class="data" width="100%%" style="width:100%%;table-layout:fixed;"><thead><tr>
<th scope="col" width="39%%">IP / service</th><th scope="col" width="21%%" class="number">Events / last seen</th><th scope="col" width="40%%">Ban status / reason</th>
</tr></thead><tbody>%(offenders)s</tbody></table>
</td></tr>
<tr><td class="content" style="padding:18px 28px;background:#111111;color:#d1d5db;font-size:11px;line-height:18px;">
BanWatch v%(version)s &nbsp; | &nbsp; %(host)s<br>Confidential security report
</td></tr></table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr></table></body></html>''' % {
        'host': esc(data['hostname']), 'frequency': esc(data['frequency'].upper()),
        'generated': esc(when(data['end'],True)), 'period': esc(when(data['start'],True) + ' to ' + when(data['end'],True)),
        'previous_period': esc(when(data['start']-data['seconds'],True) + ' to ' + when(data['start'],True)),
        'kpis': kpis, 'reference': esc(reference), 'mode': esc(data['mode']),
        'firewall': esc('%s (%s/%s)' % (fw['status'],fw.get('present','?'),fw['expected'])),
        'alerts': alert, 'services': service_rows(data), 'actions': actions,
        'tracking': esc(when(max(data['tracking_since'],data['start']),True)),
        'offenders': top_rows, 'version': esc(__version__),
    }
