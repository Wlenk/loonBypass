import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('monitor_checks', ROOT / 'scripts/monitor.py')
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class MonitorChecks(unittest.TestCase):
    def verified(self):
        return {'ok': True, 'version': 'a' * 64,
                'rulesets': [{'name': name} for name in monitor.RULESETS]}

    def test_shared_verifier_checks_expected_version_without_notification_secrets(self):
        result = SimpleNamespace(returncode=0, stdout=json.dumps(self.verified()), stderr='')
        with patch.dict(monitor.os.environ, {'BARK_URL': 'private-token', 'CLOUDFLARE_API_TOKEN': 'private-key'}), \
             patch.object(monitor.subprocess, 'run', return_value=result) as run:
            checked = monitor.health('https://rules.example', 'a' * 64)
        command = run.call_args.args[0]
        self.assertEqual(command[-1], 'a' * 64)
        self.assertTrue(command[1].endswith('verify-service.mjs'))
        self.assertNotIn('BARK_URL', run.call_args.kwargs['env'])
        self.assertNotIn('CLOUDFLARE_API_TOKEN', run.call_args.kwargs['env'])
        self.assertTrue(checked['ok'])

    def test_blocked_verifier_is_reported_without_exposing_urls(self):
        result = SimpleNamespace(returncode=1, stdout='', stderr=
                                 '规则服务检查失败：/health: HTTP 403；Cloudflare error 1010 https://private.example/token')
        with patch.object(monitor.subprocess, 'run', return_value=result):
            with self.assertRaises(monitor.CheckError) as caught:
                monitor.health('https://rules.example')
        self.assertIn('HTTP 403', str(caught.exception))
        self.assertIn('1010', str(caught.exception))
        self.assertNotIn('private.example', str(caught.exception))

    def test_invalid_child_results_cannot_pass(self):
        for output in ('not JSON', '{"ok":true}', json.dumps({**self.verified(), 'version': 'b' * 64})):
            result = SimpleNamespace(returncode=0, stdout=output, stderr='')
            with patch.object(monitor.subprocess, 'run', return_value=result):
                with self.assertRaises(monitor.CheckError):
                    monitor.health('https://rules.example', 'a' * 64)

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

    def test_healthy_service_uses_exact_generated_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / 'manifest.json'
            manifest.write_text(json.dumps({'version': 'a' * 64}))
            with patch.dict(monitor.os.environ, {'WORKER_URL': 'https://rules.example'}), \
                 patch.object(monitor, 'health', return_value=self.verified()) as health, \
                 patch.object(monitor, 'notify', return_value='not needed'), \
                 patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(monitor.main(['--expected-manifest', str(manifest)]), 0)
            health.assert_called_once_with('https://rules.example', 'a' * 64)


if __name__ == '__main__':
    unittest.main()
