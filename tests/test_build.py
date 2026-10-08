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
    def cdn_sources(self):
        return {'META_Douyin': ['DOMAIN-SUFFIX,douyincdn.com',
                                 'DOMAIN-SUFFIX,hypercachenode.com'],
                'DouYin': ['DOMAIN-SUFFIX,supercachenode.com'],
                'META_TikTok': ['DOMAIN-SUFFIX,tiktokcdn.com'],
                'TikTok': ['DOMAIN-KEYWORD,tiktok']}

    def test_cdn_separates_bilibili_video_and_images(self):
        rows = build.compile_cdn(self.cdn_sources())
        for domain in ('bilivideo.com', 'bilivideo.cn', 'bilivideo.net', 'acgvideo.com'):
            self.assertIn('DOMAIN-SUFFIX,' + domain, rows)
        for host in ('i0.hdslb.com', 'archive.biliimg.com', 'api.bilibili.com'):
            self.assertFalse(any(build.domains_overlap('DOMAIN,' + host, row) for row in rows))
        self.assertIn('DOMAIN,s1.hdslb.com', rows)
        for image in ('hdslb.com', 'biliimg.com', 'i0.hdslb.com'):
            with self.assertRaises(ValueError):
                build.compile_cdn(self.cdn_sources(), ['DOMAIN-SUFFIX,' + image])

    def test_douyin_tiktok_and_shared_byte_resources_never_join_cdn(self):
        rows = ['DOMAIN-SUFFIX,' + host for host in
                ('douyincdn.com', 'hypercachenode.com', 'supercachenode.com',
                 'byteimg.com', 'tiktokcdn.com', 'new-tiktok-static.com', 'alicdn.com')]
        self.assertEqual(build.compile_cdn(self.cdn_sources(), rows), ['DOMAIN-SUFFIX,alicdn.com'])
        sources = self.cdn_sources()
        sources['DouYin'].append('DOMAIN,new-byte-resource.alicdn.com')
        self.assertEqual(build.compile_cdn(sources, ['DOMAIN-SUFFIX,alicdn.com']), [])

    def test_cdn_cannot_direct_entire_cloud_providers_or_ip_ranges(self):
        for row in ('DOMAIN-SUFFIX,aliyuncs.com', 'DOMAIN-SUFFIX,myqcloud.com',
                    'DOMAIN-SUFFIX,akamaized.net', 'DOMAIN-SUFFIX,cn',
                    'IP-CIDR,1.2.3.0/24', 'IP-ASN,13335', 'DOMAIN-KEYWORD,cdn'):
            with self.assertRaises(ValueError): build.compile_cdn(self.cdn_sources(), [row])

    def test_specialist_music_games_and_byte_rules_precede_cdn_without_changing_old_lists(self):
        sources = {name: [] for name in build.SOURCES}
        sources.update(self.cdn_sources())
        sources['NetEaseMusic'] = ['DOMAIN-SUFFIX,music.163.com']
        sources['Tencent'] = ['DOMAIN-SUFFIX,gtimg.com']
        groups = build.compile_rules(sources)
        self.assertEqual(list(groups)[:5],
                         ['netease-music', 'tencent-games', 'tiktok', 'douyin', 'china-cdn'])
        self.assertIn('DOMAIN-SUFFIX,gtimg.com', groups['tencent'])
        for host, expected in [('game.gtimg.com', 'tencent-games'),
                               ('static.gtimg.com', 'china-cdn'),
                               ('tiktok.any-new-host.com', 'tiktok'),
                               ('vod.douyincdn.com', 'douyin')]:
            matched = next(name for name, rows in groups.items() if any(
                (row.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,')) and
                 build.domains_overlap('DOMAIN,' + host, row)) or
                (row.startswith('DOMAIN-KEYWORD,') and row.split(',')[1] in host)
                for row in rows))
            self.assertEqual(matched, expected)

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
