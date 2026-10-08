"""External health check and private Bark notification, with persistent cooldown."""
import argparse
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import time

RULESETS = ('netease-music', 'tencent-games', 'tiktok', 'douyin', 'china-cdn',
            'netease-other', 'tencent', 'alibaba', 'china')

class CheckError(RuntimeError):
    """A diagnostic containing only public paths, statuses and fixed messages."""

def health(base, expected_version=None):
    origin = urllib.parse.urlsplit(base)
    if (origin.scheme != 'https' or not origin.hostname or origin.username or
            origin.password or origin.query or origin.fragment or origin.path not in ('', '/')):
        raise CheckError('WORKER_URL must be a public HTTPS origin without credentials or a path')
    # Use the same verifier as the local setup assistant, without changing identity headers.
    command = ['node', str(Path(__file__).with_name('verify-service.mjs')), base]
    if expected_version:
        command.append(expected_version)
    child_env = {key: value for key, value in os.environ.items()
                 if key not in ('BARK_URL', 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID')}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=80, env=child_env)
    except FileNotFoundError:
        raise CheckError('Node.js 22 or newer is required for service verification') from None
    except subprocess.TimeoutExpired:
        raise CheckError('Service verification timed out') from None
    if result.returncode:
        detail = result.stderr.strip()
        if detail.startswith('规则服务检查失败：'):
            detail = re.sub(r'https?://\S+', '[URL]', detail.splitlines()[0])[:400]
        else:
            detail = 'Service verification process failed'
        raise CheckError(detail)
    try:
        checked = json.loads(result.stdout)
        names = {item['name'] for item in checked['rulesets']}
        supported = [set(RULESETS)]
        if not expected_version:
            supported.append(set(RULESETS) - {'china-cdn'})
        if (checked.get('ok') is not True or names not in supported or
                (expected_version and checked.get('version') != expected_version)):
            raise ValueError()
        return checked
    except (ValueError, KeyError, TypeError, AttributeError):
        raise CheckError('Service verifier returned an invalid result') from None

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
    parser.add_argument('--expected-manifest')
    args = parser.parse_args(argv)
    failed = args.failure
    reason = '规则更新、部署或镜像任务异常。请检查 GitHub Actions；服务当前版本需要重新检查。'
    if not failed:
        try:
            base = os.environ.get('WORKER_URL')
            if not base:
                raise CheckError('WORKER_URL missing')
            expected_version = None
            if args.expected_manifest:
                try:
                    expected_version = json.loads(Path(args.expected_manifest).read_text())['version']
                    if not isinstance(expected_version, str) or not re.fullmatch(r'[a-f0-9]{64}', expected_version):
                        raise ValueError()
                except (OSError, ValueError, KeyError, TypeError):
                    raise CheckError('Expected deployment manifest is invalid') from None
            # A deployment can change between two HTTP requests. Retry before alerting.
            for attempt in range(3):
                try:
                    verified = health(base, expected_version)
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
        print(f"Health check passed: all {len(verified['rulesets'])} rulesets verified")
        print(f"Verified version: {verified['version']}")
    return int(failed)

if __name__ == '__main__':
    raise SystemExit(main())
