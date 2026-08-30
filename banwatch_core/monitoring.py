import json
import os
import time

from .paths import HEALTH_FILE, PID_FILE


def write_health(detector):
    payload = {'pid': os.getpid(), 'checked_at': time.time(), 'readers': detector.health_snapshot()}
    temporary = HEALTH_FILE.with_suffix('.tmp')
    temporary.write_text(json.dumps(payload), encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(HEALTH_FILE)


def read_health(cfg):
    try:
        health = json.loads(HEALTH_FILE.read_text(encoding='utf-8'))
        pid = int(PID_FILE.read_text().strip())
        age = time.time() - health['checked_at']
        if health['pid'] != pid or not 0 <= age <= 90:
            raise ValueError('Stale heartbeat')
        os.kill(pid, 0)
        readers = health['readers']
    except (OSError, ValueError, KeyError, TypeError):
        return {'verified': False, 'services': {}, 'monitored': 0}
    services = {}
    for service in cfg['services']:
        paths = list(dict.fromkeys(p for p in cfg.get('log_paths', {}).get(service, []) if p))
        states = [readers.get(service + ':' + p, {}) for p in paths]
        healthy = sum(s.get('state') == 'reading' for s in states)
        services[service] = {
            'healthy': healthy, 'total': len(paths),
            'last_read': max((s.get('last_read', 0) for s in states), default=0),
            'errors': sum(s.get('errors', 0) for s in states),
        }
    return {'verified': True, 'services': services,
            'monitored': sum(s['total'] > 0 and s['healthy'] == s['total'] for s in services.values())}
