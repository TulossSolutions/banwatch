import json
import logging
import shutil
import subprocess
import urllib.request
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path


class ReportDeliveryError(RuntimeError):
    pass


def send_email(cfg, subject, text, report_html):
    message = EmailMessage()
    message['From'] = cfg.get('email_from', 'BanWatch <hello@tuloss.com>')
    message['To'] = cfg['email']
    message['Subject'] = subject
    message['Date'] = formatdate(localtime=True)
    message['Message-ID'] = make_msgid()
    message.set_content(text)
    message.add_alternative(report_html, subtype='html')
    sendmail = shutil.which('sendmail')
    if not sendmail and Path('/usr/sbin/sendmail').is_file():
        sendmail = '/usr/sbin/sendmail'
    try:
        if sendmail:
            proc = subprocess.run(
                [sendmail, '-oi', '-f', parseaddr(message['From'])[1], '-t'],
                input=message.as_bytes(policy=SMTP), capture_output=True, timeout=60,
            )
        else:
            # Preserve support for installations that only expose GNU mail.
            logging.warning('sendmail unavailable; using HTML-only GNU mail fallback')
            proc = subprocess.run(
                ['mail', '--content-type=text/html; charset=UTF-8', '-s', subject,
                 '-r', str(message['From']), '--', cfg['email']],
                input=report_html.encode('utf-8'), capture_output=True, timeout=60,
            )
        if proc.returncode:
            raise ReportDeliveryError('Mail transport rejected the report (exit %s)' % proc.returncode)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReportDeliveryError('Mail transport unavailable or timed out') from exc
    logging.info('Report accepted by local mail transport (delivery not confirmed)')


def send_webhooks(hooks, text):
    successful = True
    for hook in hooks:
        key = 'content' if hook.get('type') == 'discord' else 'text'
        try:
            request = urllib.request.Request(hook['url'], data=json.dumps({key: text}).encode('utf-8'),
                                             headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read(1024)
        except Exception:
            successful = False
            logging.warning('Report webhook failed (%s); endpoint redacted', hook.get('type', 'generic'))
    return successful
