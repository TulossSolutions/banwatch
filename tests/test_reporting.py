import csv
import io
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import Mock, patch

from banwatch_core import database, monitoring, report_delivery, reporter
from banwatch_core.config import validate_config
from banwatch_core.detector import DetectorEngine
from banwatch_core.firewall import Firewall
from banwatch_core.report_views import period_label, reason_summary, render_html, render_text, report_dates


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for target, key, value in [(database, 'DB_FILE', self.root/'history.db'),
                                    (database, 'ensure_dirs', lambda: None),
                                    (reporter, 'REPORT_DIR', self.root)]:
            p = patch.object(target,key,value)
            p.start()
            self.addCleanup(p.stop)
        self.db = database.BanwatchDB()
        self.addCleanup(lambda: self.db.conn.close())
        self.cfg = validate_config({'services': ['ssh'], 'report_frequency': 'daily', 'firewall': 'none'})
        self.report = reporter.Reporter(self.db,self.cfg)
        self.end = datetime(2026,8,31,12,tzinfo=timezone.utc).timestamp()

    def event(self, timestamp, ip='203.0.113.1'):
        self.db.conn.execute('INSERT INTO attacks(ip,service,pattern,line,timestamp,occurred_at) VALUES (?,?,?,?,?,?)',
                             (ip,'ssh','test','test',datetime.fromtimestamp(timestamp).isoformat(),timestamp))
        self.db.conn.commit()

    def test_exact_period_boundaries_and_top_ips(self):
        for stamp in [self.end-172800,self.end-86400-1,self.end-86400,self.end-1,self.end]:
            self.event(stamp)
        self.event(self.end-86401,'203.0.113.2')
        data = self.db.report_data(self.end,86400,self.report.scope)
        self.assertEqual(data['events'],2)
        self.assertEqual(data['previous_events'],3)
        self.assertEqual([r['ip'] for r in data['offenders']],['203.0.113.1'])

    def test_weekly_and_monthly_windows(self):
        self.event(self.end-5*86400)
        self.event(self.end-15*86400)
        self.assertEqual(self.db.report_data(self.end,604800,'week')['events'],1)
        self.assertEqual(self.db.report_data(self.end,2592000,'month')['events'],2)

    def test_cli_counter_uses_epoch_not_sql_text(self):
        self.event(self.end-86401)
        self.event(self.end-1)
        with patch.object(database.time,'time',return_value=self.end):
            self.assertEqual(self.db.get_stats()['attacks_24h'],1)

    def test_report_reads_consistent_snapshot_during_external_write(self):
        self.event(self.end-1)
        original = self.db.get_stats
        def write_after_stats():
            result = original()
            connection = sqlite3.connect(str(self.root/'history.db'))
            connection.execute('INSERT INTO attacks (ip,service,occurred_at) VALUES (?,?,?)',('203.0.113.2','ssh',self.end-1))
            connection.commit()
            connection.close()
            return result
        with patch.object(self.db,'get_stats',side_effect=write_after_stats):
            self.assertEqual(self.db.report_data(self.end,86400,self.report.scope)['events'],1)
        self.assertEqual(self.db.report_data(self.end,86400,self.report.scope)['events'],2)

    def test_migration_resumes_and_preserves_history(self):
        stamp = '2026-08-30T12:34:56'
        self.db.conn.execute('INSERT INTO attacks (ip,service,timestamp) VALUES (?,?,?)',('203.0.113.7','ssh',stamp))
        self.db.conn.commit()
        self.db._init_reporting()
        row = self.db.conn.execute('SELECT timestamp,occurred_at FROM attacks').fetchone()
        self.assertEqual(row,(stamp,datetime.fromisoformat(stamp).timestamp()))
        self.db._init_reporting()
        self.assertEqual(self.db.conn.execute('SELECT COUNT(*) FROM attacks').fetchone()[0],1)

    def test_legacy_database_without_epoch_column(self):
        self.db.conn.close()
        legacy = self.root/'old.db'
        connection = sqlite3.connect(str(legacy))
        connection.execute('CREATE TABLE attacks(id INTEGER PRIMARY KEY,ip TEXT,service TEXT,pattern TEXT,line TEXT,timestamp TEXT)')
        connection.execute("INSERT INTO attacks VALUES (1,'203.0.113.1','ssh','','','2026-08-30T14:00:00')")
        connection.commit()
        connection.close()
        with patch.object(database,'DB_FILE',legacy):
            self.db = database.BanwatchDB()
        self.assertEqual(self.db.conn.execute('SELECT COUNT(*) FROM attacks WHERE occurred_at IS NOT NULL').fetchone()[0],1)
        self.assertEqual(self.db.conn.execute('PRAGMA integrity_check').fetchone()[0],'ok')

    def test_invalid_legacy_date_is_reported(self):
        self.db.conn.execute("INSERT INTO attacks (timestamp) VALUES ('bad date')")
        self.db.conn.commit()
        with self.assertLogs(level='WARNING'):
            self.db._init_reporting()
        self.assertEqual(self.db.report_data(self.end,86400,'test')['invalid_timestamps'],1)

    @unittest.skipUnless(hasattr(time,'tzset'), 'Requires POSIX timezone switching')
    def test_dst_windows_are_exact_elapsed_seconds(self):
        old = os.environ.get('TZ')
        try:
            os.environ['TZ']='Europe/Paris'
            time.tzset()
            for end in [datetime(2026,3,29,12,tzinfo=timezone.utc).timestamp(),datetime(2026,10,25,12,tzinfo=timezone.utc).timestamp()]:
                self.event(end-86400)
                self.event(end-86401)
                self.assertEqual(self.db.report_data(end,86400,'dst')['events'],1)
        finally:
            if old is None:
                os.environ.pop('TZ',None)
            else:
                os.environ['TZ']=old
            time.tzset()

    def test_failed_email_preserves_baseline(self):
        self.cfg['email']='admin@example.com'
        self.report=reporter.Reporter(self.db,self.cfg)
        self.db.save_report_baseline(self.report.scope,1,{'total_entries': 7})
        with patch.object(reporter,'send_email',side_effect=report_delivery.ReportDeliveryError('failed')):
            with self.assertRaises(report_delivery.ReportDeliveryError):
                self.report.save_and_maybe_email()
        self.assertEqual(self.db.report_data(self.end,86400,self.report.scope)['baseline']['total_entries'],7)

    def test_exports_restore_notifications_without_changing_baseline(self):
        self.cfg['email']='admin@example.com'
        self.cfg['webhooks']=[{'url':'https://example.com/hook','type':'generic'}]
        with patch.object(reporter,'send_email') as send, patch.object(reporter,'send_webhooks',return_value=True) as hooks:
            for fmt in ['json','csv']:
                path=self.report.save_and_maybe_email(fmt)
                self.assertTrue(path.exists())
                self.assertIn('<html',send.call_args.args[3])
            self.assertEqual(send.call_count,2)
            self.assertEqual(hooks.call_count,2)
        self.assertEqual(self.db.report_data(self.end,86400,self.report.scope)['baseline'],{})

    def test_json_export_preserves_legacy_schema(self):
        self.db.quarantine('203.0.113.1','ssh','test')
        data=json.loads(self.report.generate_json())
        self.assertEqual(set(data),{'generated_at','stats','breakdown','bans'})
        datetime.fromisoformat(data['generated_at'])
        self.assertEqual(data['breakdown'],[{'service':'ssh','total':1,'active':1}])
        self.assertEqual(data['bans'][0]['ip'],'203.0.113.1')
        self.assertEqual(set(data['stats']),{'total_entries','active_quarantined','by_service','attacks_24h'})

    def test_only_html_advances_an_existing_comparison_reference(self):
        self.cfg['email']='admin@example.com'
        report=reporter.Reporter(self.db,self.cfg)
        self.db.save_report_baseline(report.scope,1,{'total_entries':7,'active_quarantined':4,'monitored':1})
        with patch.object(reporter,'send_email') as send:
            for fmt in ['json','csv']:
                report.save_and_maybe_email(fmt)
                baseline=self.db.report_data(self.end,86400,report.scope)['baseline']
                self.assertEqual(baseline['generated_at'],1)
                self.assertEqual(baseline['total_entries'],7)
            report.save_and_maybe_email('html')
        baseline=self.db.report_data(self.end,86400,report.scope)['baseline']
        self.assertGreater(baseline['generated_at'],1)
        self.assertEqual(baseline['total_entries'],0)
        self.assertEqual(send.call_count,3)

    def test_csv_preserves_raw_fields_and_keeps_banned_until(self):
        reason='=raw, "quoted"\nlog text'
        self.db.quarantine('203.0.113.1','ssh',reason,ban_duration=3600)
        rows=list(csv.reader(io.StringIO(self.report.generate_csv())))
        self.assertEqual(rows[0],['ip','service','reason','attempts','first_seen','last_seen','status','banned_until'])
        self.assertEqual(rows[1][2],reason)
        self.assertTrue(rows[1][7])

    def test_saved_json_uses_legacy_schema_and_html_notification(self):
        self.cfg['email']='admin@example.com'
        with patch.object(reporter,'send_email') as send:
            path=self.report.save_and_maybe_email('json')
        self.assertEqual(set(json.loads(path.read_text(encoding='utf-8'))),{'generated_at','stats','breakdown','bans'})
        self.assertIn('<html',send.call_args.args[3])

    def test_success_uses_only_one_collection_and_persists_its_metrics(self):
        data=self.report.collect()
        with patch.object(self.report,'collect',return_value=data) as collect:
            self.report.save_and_maybe_email()
            collect.assert_called_once()
        baseline=self.db.report_data(self.end,86400,self.report.scope)['baseline']
        self.assertEqual(baseline['generated_at'],data['end'])
        self.assertEqual(baseline['total_entries'],data['metrics']['total_entries'])

    def test_older_concurrent_report_does_not_rewind_baseline(self):
        self.db.save_report_baseline('test',200,{'total_entries':2})
        self.db.save_report_baseline('test',100,{'total_entries':1})
        self.assertEqual(self.db.report_data(self.end,86400,'test')['baseline']['total_entries'],2)

    def test_scope_changes_when_frequency_or_recipient_changes(self):
        other=reporter.Reporter(self.db,{**self.cfg,'report_frequency':'weekly'})
        self.assertNotEqual(other.scope,self.report.scope)
        other=reporter.Reporter(self.db,{**self.cfg,'email':'other@example.com'})
        self.assertNotEqual(other.scope,self.report.scope)

    def test_service_configuration_changes_keep_kpi_reference(self):
        other=reporter.Reporter(self.db,{**self.cfg,'services':['ssh','web']})
        self.assertEqual(other.scope,self.report.scope)

    def test_bad_webhook_does_not_retry_an_accepted_email(self):
        cfg={**self.cfg,'email':'admin@example.com','webhooks':[{'url':'invalid-url'}]}
        r=reporter.Reporter(self.db,cfg)
        with patch.object(reporter,'send_email') as send,self.assertLogs(level='WARNING'):
            r.save_and_maybe_email()
        send.assert_called_once()
        self.assertTrue(self.db.report_data(self.end,86400,r.scope)['baseline'])

    def test_failed_webhook_only_report_keeps_reference(self):
        r=reporter.Reporter(self.db,{**self.cfg,'webhooks':[{'url':'invalid-url'}]})
        with self.assertRaises(report_delivery.ReportDeliveryError),self.assertLogs(level='WARNING'):
            r.save_and_maybe_email()
        self.assertFalse(self.db.report_data(self.end,86400,r.scope)['baseline'])

    def test_schedule_survives_recreation(self):
        due=self.db.next_report_due(self.report.scope,86400,100)
        self.assertEqual(due,86500)
        second=database.BanwatchDB()
        try:
            self.assertEqual(second.next_report_due(self.report.scope,86400,200),due)
        finally:
            second.conn.close()

    def test_scheduler_retries_twice_then_waits_normal_interval(self):
        due=self.db.next_report_due(self.report.scope,86400,100)
        with patch.object(self.report,'save_and_maybe_email',side_effect=RuntimeError('no transport')):
            for delay in [900,1800,86400]:
                with self.assertLogs(level='ERROR'):
                    self.assertFalse(self.report.run_scheduled(due))
                next_due=self.db.next_report_due(self.report.scope,86400,due)
                self.assertEqual(next_due,due+delay)
                due=next_due

    def test_scheduler_success_and_not_due(self):
        self.db.next_report_due(self.report.scope,86400,100)
        with patch.object(self.report,'save_and_maybe_email') as save:
            self.assertFalse(self.report.run_scheduled(200))
            save.assert_not_called()
            self.assertTrue(self.report.run_scheduled(86500))
        self.assertEqual(self.db.next_report_due(self.report.scope,86400,86500),172900)

    def test_html_escapes_values_and_omits_redundant_sections(self):
        data=self.report.collect()
        data['hostname']='<script>alert(1)</script>'
        rendered=render_html(data)
        self.assertNotIn('<script>',rendered)
        self.assertIn('&lt;script&gt;',rendered)
        self.assertNotIn('Active threat containment',rendered)
        self.assertNotIn(' ACTIVE',rendered)
        self.assertIn('No events recorded in this period',rendered)
        self.assertIn('No baseline',rendered)

    def test_ban_lifecycle_records_real_actions(self):
        self.db.quarantine('203.0.113.1','ssh','test')
        self.db.release('203.0.113.1')
        self.db.release('203.0.113.1')
        self.db.quarantine('203.0.113.1','ssh','again')
        self.db.mark_expired('203.0.113.1')
        self.assertEqual([r[0] for r in self.db.conn.execute('SELECT action FROM ban_events')],['ban','release','reban','expire'])

    def test_report_design_and_data_are_preserved(self):
        data=self.report.collect()
        data['breakdown']=[('ssh',8,2)]
        data['events_by_service']={'ssh':3}
        data['health']['verified']=True
        data['health']['monitored']=1
        data['health']['services']={'ssh':{'healthy':1,'total':1,'last_read':self.end,'errors':0}}
        data['offenders']=[{'ip':'203.0.113.9','service':'ssh','events':3,'last_seen':self.end,
                            'status':'quarantined','reason':'<untrusted>','banned_until':self.end+3600}]
        rendered=render_html(data)
        for text in ['Protection healthy','max-width:640px',
                     'background:#f0fdf4','>Events</th>','>Active</th>',
                     '>Health</th>','>OK</span>', 'width:24px;height:24px',
                     'Top activity','&lt;untrusted&gt;','Quarantined until ',
                     'Automated security monitoring &amp; IP quarantine']:
            self.assertIn(text,rendered)
        self.assertNotIn(' ACTIVE',rendered)

    def test_requested_report_labels_are_removed(self):
        rendered=self.report.generate_html()
        for text in ['Security Intelligence','Security report','Quarantine status','Events in this period']:
            self.assertNotIn(text,rendered)
        for text in ['Services','Top activity','Events','Active bans']:
            self.assertIn(text,rendered)

    def test_compact_period_labels_keep_month_year_and_dst_boundaries(self):
        summer=timezone(timedelta(hours=2),'CEST')
        winter=timezone(timedelta(hours=1),'CET')
        cases=[
            (datetime(2026,8,30,9,55,tzinfo=summer),datetime(2026,8,31,9,55,tzinfo=summer),2026,'30\u201331 Aug, 09:55'),
            (datetime(2026,8,31,9,55,tzinfo=summer),datetime(2026,9,1,9,55,tzinfo=summer),2026,'31 Aug\u201301 Sep, 09:55'),
            (datetime(2025,12,31,9,55,tzinfo=winter),datetime(2026,1,1,9,55,tzinfo=winter),2026,'31 Dec 2025\u201301 Jan 2026, 09:55'),
            (datetime(2025,12,30,9,55,tzinfo=winter),datetime(2025,12,31,9,55,tzinfo=winter),2026,'30\u201331 Dec 2025, 09:55'),
            (datetime(2026,3,28,8,55,tzinfo=winter),datetime(2026,3,29,9,55,tzinfo=summer),2026,'28 Mar, 08:55 CET \u2013 29 Mar, 09:55 CEST'),
            (datetime(2026,10,24,10,55,tzinfo=summer),datetime(2026,10,25,9,55,tzinfo=winter),2026,'24 Oct, 10:55 CEST \u2013 25 Oct, 09:55 CET'),
        ]
        for start,end,year,expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(period_label(start,end,year),expected)

    def test_compact_dates_are_used_in_both_email_parts(self):
        data=self.report.collect()
        generated,period,previous=report_dates(data)
        self.assertEqual(generated,datetime.fromtimestamp(data['end']).astimezone().strftime('%d %b %Y, %H:%M %Z'))
        for rendered in [render_html(data),render_text(data,compact=True)]:
            for value in ['Generated: '+generated,period,'Previous: '+previous]:
                self.assertIn(value,rendered)
        self.assertIn('Previous:',render_text(data))

    def test_compact_reasons_preserve_raw_database_exports_and_webhooks(self):
        reason=r'8 score (6 events) on ssh; rule: (?P<ip>\d+\.\d+).*secret'
        self.db.quarantine('203.0.113.1','ssh',reason)
        self.event(time.time()-1)
        self.cfg['email']='admin@example.com'
        self.cfg['webhooks']=[{'url':'https://example.com/hook','type':'generic'}]
        with patch.object(reporter,'send_email') as send,patch.object(reporter,'send_webhooks',return_value=True) as hooks:
            self.report.save_and_maybe_email('html')
        for body in send.call_args.args[2:4]:
            self.assertIn('Score 8 \u00b7 6 events',body)
            self.assertNotIn('; rule:',body)
        self.assertIn(reason,hooks.call_args.args[1])
        self.assertEqual(self.db.get_ban_list(1)[0]['reason'],reason)
        self.assertEqual(json.loads(self.report.generate_json())['bans'][0]['reason'],reason)
        self.assertEqual(list(csv.DictReader(io.StringIO(self.report.generate_csv())))[0]['reason'],reason)

    def test_custom_reasons_remain_unchanged_and_html_escaped(self):
        for reason in [None,'manual review','<script>custom</script>','Unexpected; rule: custom']:
            self.assertEqual(reason_summary(reason),reason)
        self.assertEqual(reason_summary('5 score (6 events) on web'),'Score 5 \u00b7 6 events')
        data=self.report.collect()
        data['offenders']=[{'ip':'203.0.113.1','service':'ssh','events':1,'last_seen':self.end,
                            'reason':'<script>custom</script>'}]
        self.assertIn('&lt;script&gt;custom&lt;/script&gt;',render_html(data))

    def test_stylesheet_contains_only_mobile_rules(self):
        rendered=self.report.generate_html()
        styles=re.findall(r'<style>(.*?)</style>',rendered,re.S)
        self.assertEqual(len(styles),1)
        css=styles[0].strip()
        self.assertTrue(css.startswith('@media only screen and (max-width:520px) {'))
        depth=0
        for index,char in enumerate(css[css.index('{'):],start=css.index('{')):
            depth += (char == '{') - (char == '}')
            if depth == 0:
                self.assertEqual(index,len(css)-1)
                break
        self.assertEqual(depth,0)
        inline_only=re.sub(r'<style>.*?</style>','',rendered,flags=re.S)
        for text in ['max-width:640px','background:#111111','background:#fafafa',
                     'font-size:30px','border-bottom:2px solid #111827']:
            self.assertIn(text,inline_only)

    def test_firewall_failure_does_not_create_quarantine(self):
        cfg={**self.cfg,'firewall':'iptables','threshold':1}
        fw=Mock()
        fw.block.return_value=False
        engine=DetectorEngine(cfg,self.db,fw)
        with self.assertLogs(level='ERROR'):
            engine._track_attempt('203.0.113.9','ssh','line',5)
        self.assertFalse(self.db.is_quarantined('203.0.113.9'))

    def test_repeat_ban_reapplies_firewall(self):
        self.db.quarantine('203.0.113.9','ssh','old')
        self.db.release('203.0.113.9')
        fw=Mock()
        fw.block.return_value=True
        engine=DetectorEngine({**self.cfg,'firewall':'iptables','threshold':1},self.db,fw)
        engine._track_attempt('203.0.113.9','ssh','line',5)
        fw.block.assert_called_once_with('203.0.113.9')
        self.assertTrue(self.db.is_quarantined('203.0.113.9'))
        self.assertNotEqual(self.db.get_ban_list(1)[0]['reason'],'old')

    def test_dry_run_never_creates_active_ban(self):
        fw=Mock()
        engine=DetectorEngine({**self.cfg,'dry_run':True,'threshold':1},self.db,fw)
        engine._track_attempt('203.0.113.9','ssh','line',5)
        fw.block.assert_not_called()
        self.assertFalse(self.db.is_quarantined('203.0.113.9'))


class TransportAndHealthTests(unittest.TestCase):
    def test_multipart_mail_contains_plain_and_html(self):
        cfg=validate_config({'email':'admin@example.com','email_from':'Operator <ops@example.com>'})
        with patch.object(report_delivery.shutil,'which',return_value='/usr/sbin/sendmail'), patch.object(report_delivery.subprocess,'run',return_value=Mock(returncode=0)) as run:
            report_delivery.send_email(cfg,'BanWatch [server] daily report','plain text','<p>HTML</p>')
        message=BytesParser(policy=policy.default).parsebytes(run.call_args.kwargs['input'])
        self.assertEqual(message.get_content_type(),'multipart/alternative')
        self.assertIn('plain text',message.get_body(preferencelist=('plain',)).get_content())
        self.assertIn('HTML',message.get_body(preferencelist=('html',)).get_content())
        self.assertEqual(str(message['From']),'Operator <ops@example.com>')

    def test_email_header_injection_rejected(self):
        for field in ['email','email_from','report_hostname']:
            with self.assertRaises(ValueError):
                validate_config({field:'a@example.com\r\nBcc: other@example.com'})

    def test_recipient_is_bare_but_sender_accepts_display_name(self):
        with self.assertRaisesRegex(ValueError,'bare recipient'):
            validate_config({'email':'Admin <admin@example.com>'})
        cfg=validate_config({'email':'admin@example.com','email_from':'BanWatch <hello@tuloss.com>'})
        self.assertEqual(cfg['email'],'admin@example.com')
        self.assertEqual(cfg['email_from'],'BanWatch <hello@tuloss.com>')

    def test_iptables_command_does_not_duplicate_executable(self):
        fw=Firewall('iptables')
        with patch.object(fw,'_run',side_effect=[1,0]) as run:
            self.assertTrue(fw.block('203.0.113.1'))
        self.assertEqual(run.call_args.args[0],['iptables','-A','INPUT','-s','203.0.113.1','-j','DROP'])

    def test_audit_is_read_only_and_does_not_count_partial_rules(self):
        output='-A INPUT -s 203.0.113.1/32 -j DROP\n-A INPUT -s 203.0.113.2/32 -p tcp -j DROP\n'
        with patch('banwatch_core.firewall.subprocess.run',return_value=Mock(stdout=output)) as run:
            audit=Firewall('iptables').audit(['203.0.113.1','203.0.113.2'])
        self.assertEqual(audit['missing'],1)
        self.assertEqual(run.call_args.args[0],['iptables-save','-t','filter'])

    def test_firewall_check_failure_is_unknown(self):
        with patch('banwatch_core.firewall.subprocess.run',side_effect=OSError('denied')):
            self.assertEqual(Firewall('iptables').audit(['203.0.113.1'])['status'],'unverified')

    def test_live_stale_and_incomplete_heartbeat(self):
        with tempfile.TemporaryDirectory() as folder:
            health_path=Path(folder)/'health.json'
            pid_path=Path(folder)/'pid'
            cfg={'services':['ssh'],'log_paths':{'ssh':['auth.log','missing.log']}}
            pid_path.write_text(str(os.getpid()))
            state={'pid':os.getpid(),'checked_at':time.time(),'readers':{'ssh:auth.log':{'state':'reading','last_read':1}}}
            health_path.write_text(json.dumps(state))
            with patch.object(monitoring,'HEALTH_FILE',health_path),patch.object(monitoring,'PID_FILE',pid_path),patch.object(monitoring.os,'kill'):
                result=monitoring.read_health(cfg)
                self.assertTrue(result['verified'])
                self.assertEqual(result['monitored'],0)
                self.assertEqual(result['services']['ssh']['healthy'],1)
                state['checked_at']-=100
                health_path.write_text(json.dumps(state))
                self.assertFalse(monitoring.read_health(cfg)['verified'])


if __name__ == '__main__':
    unittest.main()
