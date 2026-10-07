"""External health check and private Bark notification, with persistent cooldown."""
import argparse
import hashlib
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path
import time

def get(url, max_bytes=16_000_000):
    with urllib.request.urlopen(url, timeout=35) as response:
        body = response.read(max_bytes + 1)
        if response.status != 200 or len(body) > max_bytes:
            raise RuntimeError('HTTP or size failure')
        return body

def health(base):
    state = json.loads(get(base.rstrip('/') + '/health'))
    if not state.get('ok'):
        raise RuntimeError('Worker unhealthy')
    manifest = json.loads(get(base.rstrip('/') + '/manifest.json'))
    if manifest.get('version') != state.get('version'):
        raise RuntimeError('Version mismatch')
    if len(manifest.get('files', {})) != 8:
        raise RuntimeError('Incomplete manifest')
    for item in manifest['files'].values():
        body = get(base.rstrip('/') + item['path'])
        if len(body) != item['bytes'] or hashlib.sha256(body).hexdigest() != item['sha256']:
            raise RuntimeError('Ruleset verification failure')

def notify(failed, state_path, reason):
    path = Path(state_path)
    prior = json.loads(path.read_text()) if path.exists() else {}
    now = time.time()
    should_send = failed and (not prior.get('failed') or now - prior.get('sent_at', 0) >= 21600)
    should_send |= not failed and bool(prior.get('failed'))
    if should_send:
        endpoint = os.environ.get('BARK_URL')
        if not endpoint:
            raise RuntimeError('BARK_URL secret missing')
        data = urllib.parse.urlencode({
            'title': 'Loon 规则服务故障' if failed else 'Loon 规则服务恢复',
            'body': reason if failed else '外部监控已确认规则服务及文件校验恢复正常。',
            'group': 'Loon规则服务', 'ttl': '600'}).encode()
        # Keep endpoint/credential out of logs, redirect chains, and public artifacts.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        request = urllib.request.Request(endpoint, data=data, method='POST')
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
                payload = json.loads(response.read(65536))
                if response.status != 200 or payload.get('code') != 200:
                    raise RuntimeError('Notification was rejected')
        except Exception:
            raise RuntimeError('Notification delivery failed') from None
        prior['sent_at'] = now
    prior['failed'] = failed
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prior))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--failure', action='store_true')
    args = parser.parse_args()
    failed = args.failure
    reason = '规则更新、部署或镜像任务异常。请检查任务日志；未通过校验的规则不会发布。'
    if not failed:
        try:
            base = os.environ.get('WORKER_URL')
            if not base:
                raise RuntimeError('Worker URL missing')
            # A deployment can change between two HTTP requests. Retry before alerting.
            for attempt in range(3):
                try:
                    health(base)
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    time.sleep(5)
        except Exception:
            failed = True
            reason = '外部监控检测到服务不可用、规则损坏或超过 72 小时未成功更新。请检查 Worker 和更新任务。'
    notify(failed, os.environ.get('ALERT_STATE', 'alert-state/state.json'), reason)
    print('Health check failed' if failed else 'Health check passed')
    if failed:
        raise SystemExit(1)
