import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build', ROOT / 'scripts/build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
spec2 = importlib.util.spec_from_file_location('monitor', ROOT / 'scripts/monitor.py')
monitor = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(monitor)

class Reliability(unittest.TestCase):
    def test_bad_sources_rejected(self):
        for data in ['', '# empty', '<html>error</html>', 'DOMAIN-SUFFIX,x.com,DIRECT', 'IP-CIDR,999.1.1.0/24']:
            with self.assertRaises(ValueError): build.parse(data)

    def test_domain_conversion(self):
        self.assertEqual(build.parse('+.qq.com\n.tiktok.com\nwx.qq.com', True),
                         ['DOMAIN-SUFFIX,qq.com', 'DOMAIN-SUFFIX,tiktok.com', 'DOMAIN,wx.qq.com'])
        self.assertEqual(build.validate('DOMAIN-SUFFIX,xn--fiqs8s'), 'DOMAIN-SUFFIX,xn--fiqs8s')

    def test_failed_build_preserves_previous_files(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            original = (ROOT / 'public/manifest.json').read_bytes()
            (p / 'manifest.json').write_bytes(original)
            (p / 'rules').mkdir()
            (p / 'rules/china.list').write_text('previous verified snapshot')
            with patch.object(build, 'fetch_source', return_value=('x', ['DOMAIN,x.com'])), \
                 patch.object(build, 'compile_rules', return_value={'china': ['DOMAIN,x.com']}):
                with self.assertRaises(ValueError): build.build(output=p)
            self.assertEqual((p / 'manifest.json').read_bytes(), original)
            self.assertEqual((p / 'rules/china.list').read_text(), 'previous verified snapshot')

    def test_notification_cooldown_and_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'state.json'
            p.write_text(json.dumps({'failed': True, 'sent_at': 100000}))
            with patch.object(monitor.time, 'time', return_value=100001), \
                 patch.object(monitor.urllib.request, 'build_opener') as opener:
                monitor.notify(True, str(p), 'failure')
                opener.assert_not_called()
            # A recovery requires notification, rather than silently deleting the incident.
            with patch.dict(monitor.os.environ, {'BARK_URL': ''}):
                with self.assertRaises(RuntimeError): monitor.notify(False, str(p), '')
            self.assertTrue(json.loads(p.read_text())['failed'])

if __name__ == '__main__': unittest.main()
