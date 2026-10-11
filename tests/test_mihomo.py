import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mihomo_build', ROOT / 'scripts/build_mihomo.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class MihomoChecks(unittest.TestCase):
    def test_limited_conversion_preserves_policy_and_ip_options(self):
        rows = ['DOMAIN-SUFFIX,weixin.qq.com', 'USER-AGENT,WeChat*',
                'IP-CIDR,1.2.3.4/32,no-resolve', 'IP-ASN,45090,no-resolve']
        converted, skipped = builder.convert(rows)
        self.assertEqual(converted, [rows[0], rows[2], rows[3]])
        self.assertEqual(skipped, 1)
        for row in ('DOMAIN-WILDCARD,*.qq.com', 'PROTOCOL,STUN', '<html>'):
            with self.assertRaises(ValueError):
                builder.convert([row])

    def test_unknown_or_corrupt_input_does_not_replace_verified_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            shutil.copytree(ROOT / 'public/rules', output / 'rules')
            shutil.copy(ROOT / 'public/manifest.json', output / 'manifest.json')
            (output / 'mihomo').mkdir()
            (output / 'mihomo/china-domain.mrs').write_bytes(b'previous verified snapshot')
            before = (output / 'manifest.json').read_bytes()
            (output / 'rules/tencent.list').write_text('corrupt source')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                builder.build(output, '/not-executed')
            self.assertEqual((output / 'manifest.json').read_bytes(), before)
            self.assertEqual((output / 'mihomo/china-domain.mrs').read_bytes(), b'previous verified snapshot')

    def test_sealed_profile_schema_and_nonce_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            for value in ({}, {'schema': 1, 'nonce': '', 'ciphertext': 'a' * 44}):
                path.write_text(json.dumps(value))
                with self.assertRaises((ValueError, KeyError)):
                    builder.profile_digest(path)

    def test_official_core_round_trip_preserves_exact_and_suffix_domains(self):
        compiler = Path(os.environ.get('MIHOMO_BIN', ROOT / 'tmp/mihomo-core'))
        if not compiler.exists():
            self.skipTest('Pinned official compiler not installed')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source, binary, restored = path / 'source.list', path / 'rules.mrs', path / 'restored.list'
            for behavior, rows in [('domain', ['+.qq.com', 'exact.example.com']),
                                   ('ipcidr', ['1.2.3.0/24', '2001:db8::/32'])]:
                source.write_text('\n'.join(rows) + '\n')
                for fmt, origin, target in [('text', source, binary), ('mrs', binary, restored)]:
                    result = subprocess.run([str(compiler.resolve()), 'convert-ruleset', behavior, fmt,
                                             str(origin), str(target)], capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0)
                self.assertEqual(set(restored.read_text().splitlines()), set(rows))


if __name__ == '__main__':
    unittest.main()
