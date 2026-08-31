import csv
import hashlib
import io
import json
import logging
import socket
import time
from datetime import datetime

from .firewall import Firewall
from .monitoring import read_health
from .paths import REPORT_DIR
from .report_delivery import ReportDeliveryError, send_email, send_webhooks
from .report_views import render_html, render_text


REPORT_INTERVALS = {'daily': 86400, 'weekly': 604800, 'monthly': 2592000}


class Reporter:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.cfg = cfg
        self.frequency = cfg.get('report_frequency', 'weekly')
        self.interval = REPORT_INTERVALS[self.frequency]
        # Ignore old snapshots whose 24h counters and service definitions differ.
        identity = [2, self.frequency, cfg.get('email'), cfg.get('webhooks', [])]
        self.scope = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()

    def collect(self):
        data = self.db.report_data(time.time(), self.interval, self.scope)
        data['hostname'] = self.cfg.get('report_hostname') or socket.gethostname()
        data['frequency'] = self.frequency
        data['health'] = read_health(self.cfg)
        data['firewall'] = Firewall(self.cfg.get('firewall', 'none'), self.cfg.get('dry_run', False)).audit(data['active_ips'])
        data['mode'] = 'Detection only' if self.cfg.get('dry_run') or self.cfg.get('firewall') == 'none' else 'Blocking enabled'
        data['configured_services'] = self.cfg['services']
        data['baseline_kind'] = 'HTML report, mail accepted' if self.cfg.get('email') else 'saved HTML report'
        data['metrics'] = {
            'total_entries': data['stats']['total_entries'],
            'active_quarantined': data['stats']['active_quarantined'],
            'monitored': data['health']['monitored'] if data['health']['verified'] else None,
        }
        return data

    def generate_html(self) -> str:
        return render_html(self.collect())

    def generate_json(self) -> str:
        return self._json(self.collect())

    def generate_csv(self) -> str:
        return self._csv(self.collect())

    @staticmethod
    def _json(data):
        return json.dumps({
            'generated_at': datetime.fromtimestamp(data['end']).isoformat(),
            'stats': data['stats'],
            'breakdown': [{'service': service, 'total': total, 'active': active}
                          for service, total, active in data['breakdown']],
            'bans': data['bans'],
        }, indent=2)

    @staticmethod
    def _csv(data):
        buf = io.StringIO()
        writer = csv.writer(buf)
        fields = ['ip', 'service', 'reason', 'attempts', 'first_seen', 'last_seen', 'status', 'banned_until']
        writer.writerow(fields)
        for entry in data['bans']:
            writer.writerow(entry.get(field) for field in fields)
        return buf.getvalue()

    def save_and_maybe_email(self, format: str = 'html'):
        if format not in ('html', 'json', 'csv'):
            raise ValueError('unknown report format: ' + format)
        data = self.collect()
        if format == 'html':
            report = render_html(data)
        elif format == 'json':
            report = self._json(data)
        else:
            report = self._csv(data)
        stamp = datetime.fromtimestamp(data['end']).strftime('%Y%m%d_%H%M%S_%f')
        path = REPORT_DIR / ('report_' + stamp + '.' + format)
        with path.open('x', encoding='utf-8') as output:
            output.write(report)
        path.chmod(0o640)
        logging.info('Report saved: %s', path)
        text = render_text(data)
        if self.cfg.get('email'):
            html_report = report if format == 'html' else render_html(data)
            subject = 'BanWatch [%s] %s report - %s' % (
                data['hostname'], self.frequency, datetime.fromtimestamp(data['end']).astimezone().strftime('%Y-%m-%d %Z'))
            send_email(self.cfg, subject, text, html_report)
        hooks_ok = send_webhooks(self.cfg.get('webhooks', []), text)
        if not hooks_ok and not self.cfg.get('email'):
            raise ReportDeliveryError('Webhook report was not accepted')
        # Restored export notifications do not change the existing baseline policy.
        if format == 'html':
            self.db.save_report_baseline(self.scope, data['end'], data['metrics'])
        return path

    def run_scheduled(self, now=None):
        now = time.time() if now is None else now
        if now < self.db.next_report_due(self.scope, self.interval, now):
            return False
        success = False
        try:
            self.save_and_maybe_email()
            success = True
        except Exception:
            logging.exception('Scheduled report failed; persistent retry policy applies')
        self.db.finish_report_attempt(self.scope, self.interval, now, success)
        return success
