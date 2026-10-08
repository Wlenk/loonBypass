"""External health check and private Bark notification, with persistent cooldown."""
import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import time

RULESETS = ('netease-music', 'tencent-games', 'tiktok', 'douyin',
            'netease-other', 'tencent', 'alibaba', 'china')

class CheckError(RuntimeError):
    """A diagnostic containing only public paths, statuses and fixed messages."""

def get(url, max_bytes=16_000_000):
    path = urllib.parse.urlsplit(url).path
    try:
        with urllib.request.urlopen(url, timeout=35) as response:
            body = response.read(max_bytes + 1)
            if response.status != 200:
                raise CheckError(f'{path}: HTTP {response.status}')
            if len(body) > max_bytes:
                raise CheckError(f'{path}: response exceeds size limit')
            return body
    except urllib.error.HTTPError as error:
        # Do not print response bodies, headers or URLs containing credentials.
        code = re.search(rb'error code:\s*(1\d{3})\b', error.read(4096))
        detail = f'; Cloudflare error {code[1].decode()}' if code else ''
        raise CheckError(f'{path}: HTTP {error.code}{detail}') from None
    except CheckError:
        raise
    except Exception:
        raise CheckError(f'{path}: connection or timeout failure') from None

def read_json(url):
    body = get(url)
    try:
        result = json.loads(body)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, UnicodeError):
        raise CheckError(f'{urllib.parse.urlsplit(url).path}: invalid JSON') from None

def health(base):
    origin = urllib.parse.urlsplit(base)
    if (origin.scheme != 'https' or not origin.hostname or origin.username or
            origin.password or origin.query or origin.fragment or origin.path not in ('', '/')):
        raise CheckError('WORKER_URL must be a public HTTPS origin without credentials or a path')
    base = base.rstrip('/')
    state = read_json(base + '/health')
    if state.get('ok') is not True:
        raise CheckError('/health: Worker unhealthy')
    manifest = read_json(base + '/manifest.json')
    if manifest.get('version') != state.get('version'):
        raise CheckError('/manifest.json: version mismatch during deployment')
    files = manifest.get('files')
    if manifest.get('schema') != 1 or not isinstance(files, dict) or set(files) != set(RULESETS):
        raise CheckError('/manifest.json: incomplete or invalid manifest')
    try:
        checked = datetime.fromisoformat(manifest['checked_at'].replace('Z', '+00:00'))
        if checked.tzinfo is None:
            raise ValueError()
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        if age < -300 or age >= 72 * 3600:
            raise ValueError()
    except (KeyError, TypeError, AttributeError, ValueError):
        raise CheckError('/manifest.json: rules have not been verified within 72 hours or timestamp is invalid') from None
    for name in RULESETS:
        item = files[name]
        path = f'/rules/{name}.list'
        if (not isinstance(item, dict) or item.get('path') != path or
                type(item.get('bytes')) is not int or item['bytes'] < 1 or
                type(item.get('count')) is not int or item['count'] < 1 or
                not isinstance(item.get('sha256'), str) or
                not re.fullmatch(r'[a-f0-9]{64}', item['sha256'])):
            raise CheckError(f'{path}: invalid manifest entry')
        body = get(base + path)
        if len(body) != item['bytes'] or hashlib.sha256(body).hexdigest() != item['sha256']:
            raise CheckError(f'{path}: length or SHA-256 verification failure')

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
        except urllib.error.HTTPError as error:
            raise RuntimeError(f'Notification delivery failed: HTTP {error.code}') from None
        except Exception:
            raise RuntimeError('Notification delivery failed') from None
        prior['sent_at'] = now
    prior['failed'] = failed
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prior))
    return 'sent' if should_send else ('cooldown' if failed else 'not needed')

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--failure', action='store_true')
    args = parser.parse_args(argv)
    failed = args.failure
    reason = '规则更新、部署或镜像任务异常。请检查 GitHub Actions；服务当前版本需要重新检查。'
    if not failed:
        try:
            base = os.environ.get('WORKER_URL')
            if not base:
                raise CheckError('WORKER_URL missing')
            # A deployment can change between two HTTP requests. Retry before alerting.
            for attempt in range(3):
                try:
                    health(base)
                    break
                except CheckError:
                    if attempt == 2:
                        raise
                    time.sleep(5)
        except CheckError as error:
            failed = True
            print(f'Health check failed: {error}')
            reason = f'外部监控检查失败：{error}。请检查 Worker 和更新任务。'
    try:
        result = notify(failed, os.environ.get('ALERT_STATE', 'alert-state/state.json'), reason)
    except RuntimeError as error:
        print(str(error))
        return 1
    print(f'Notification: {result}')
    if args.failure:
        # The original workflow step already failed. This step reports delivery only.
        print('Failure notification handled; see the original failed workflow step.')
        return 0
    if not failed:
        print('Health check passed: all 8 rulesets verified')
    return int(failed)

if __name__ == '__main__':
    raise SystemExit(main())
