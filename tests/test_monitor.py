import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('monitor_checks', ROOT / 'scripts/monitor.py')
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class MonitorChecks(unittest.TestCase):
    def fixture(self):
        body = b'DOMAIN-SUFFIX,example.com\n'
        manifest = {
            'schema': 1, 'version': 'verified-version',
            'checked_at': datetime.now(timezone.utc).isoformat(),
            'files': {name: {'path': f'/rules/{name}.list', 'count': 1,
                            'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                      for name in monitor.RULESETS},
        }
        def get(url):
            if url.endswith('/health'):
                return json.dumps({'ok': True, 'version': manifest['version']}).encode()
            if url.endswith('/manifest.json'):
                return json.dumps(manifest).encode()
            return body
        return manifest, get

    def test_complete_service_verifies_all_eight_files(self):
        _, get = self.fixture()
        with patch.object(monitor, 'get', side_effect=get) as fetch:
            monitor.health('https://rules.example')
        self.assertEqual(fetch.call_count, 10)

    def test_old_or_future_manifest_is_rejected_even_if_health_says_ok(self):
        for delta in (timedelta(hours=-73), timedelta(minutes=6)):
            manifest, get = self.fixture()
            manifest['checked_at'] = (datetime.now(timezone.utc) + delta).isoformat()
            with patch.object(monitor, 'get', side_effect=get):
                with self.assertRaisesRegex(monitor.CheckError, 'timestamp|72 hours'):
                    monitor.health('https://rules.example')

    def test_corrupt_or_unsafe_manifest_cannot_pass(self):
        manifest, get = self.fixture()
        original = copy.deepcopy(manifest)
        for changes in ({'sha256': '0' * 64}, {'path': 'https://private.example/token'},
                        {'bytes': 1}, {'count': 0}):
            manifest['files'] = copy.deepcopy(original['files'])
            manifest['files']['china'].update(changes)
            with patch.object(monitor, 'get', side_effect=get):
                with self.assertRaises(monitor.CheckError) as error:
                    monitor.health('https://rules.example')
            self.assertNotIn('private.example', str(error.exception))

    def test_http_block_is_identified_without_logging_response_or_credentials(self):
        error = urllib.error.HTTPError('https://rules.example/health', 403, 'blocked', {},
                                      io.BytesIO(b'error code: 1010 private credential'))
        with patch.object(monitor.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaises(monitor.CheckError) as caught:
                monitor.get('https://rules.example/health')
        self.assertEqual(str(caught.exception), '/health: HTTP 403; Cloudflare error 1010')

    def test_notification_http_error_does_not_expose_endpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            endpoint = 'https://private.example/private-token'
            error = urllib.error.HTTPError(endpoint, 401, 'private-token', {}, io.BytesIO())
            with patch.dict(monitor.os.environ, {'BARK_URL': endpoint}), \
                 patch.object(monitor.urllib.request, 'build_opener') as opener:
                opener.return_value.open.side_effect = error
                with self.assertRaisesRegex(RuntimeError, 'HTTP 401') as caught:
                    monitor.notify(True, str(Path(temp) / 'state.json'), 'failure')
            self.assertNotIn('private-token', str(caught.exception))
            self.assertNotIn('private.example', str(caught.exception))

    def test_failure_notification_success_does_not_claim_delivery_failed(self):
        with patch.object(monitor, 'notify', return_value='sent') as notify, \
             patch.object(monitor, 'health') as health, patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(monitor.main(['--failure']), 0)
        notify.assert_called_once()
        health.assert_not_called()

    def test_failed_health_remains_failed_after_successful_notification(self):
        with patch.dict(monitor.os.environ, {'WORKER_URL': 'https://rules.example'}), \
             patch.object(monitor, 'health', side_effect=monitor.CheckError('/health: HTTP 503')), \
             patch.object(monitor, 'notify', return_value='sent'), \
             patch.object(monitor.time, 'sleep'), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(monitor.main([]), 1)
        self.assertIn('/health: HTTP 503', output.getvalue())


if __name__ == '__main__':
    unittest.main()
