"""Compile public upstream rules. Never reads a private Loon configuration."""
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/'
META = 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/'
NAMES = ['NetEaseMusic', 'NetEase', 'WeChat', 'Tencent', 'Alibaba', 'AliPay',
         'TikTok', 'DouYin', 'ChinaMax', 'ChinaIPs']
SOURCES = {n: BASE + f'{n}/{n}.list' for n in NAMES}
SOURCES.update({n + 'Domain': BASE + f'{n}/{n}_Domain.list'
                for n in ['Tencent', 'Alibaba', 'ChinaMax']})
SOURCES.update({'META_TencentGames': META + 'tencent-games.list',
                'META_TikTok': META + 'tiktok.list', 'META_Douyin': META + 'douyin.list'})
TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
         'IP-ASN', 'USER-AGENT', 'GEOIP'}
GAMES = ['game.qq.com', 'games.qq.com', 'qqgame.qq.com', 'pvp.qq.com',
         'smoba.qq.com', 'lol.qq.com', 'lolm.qq.com', 'cf.qq.com', 'cfm.qq.com',
         'codm.qq.com', 'dnf.qq.com', 'dnfm.qq.com', 'speed.qq.com',
         'speedm.qq.com', 'hlddz.qq.com', 'peng.qq.com', 'syzs.qq.com',
         'tgp.qq.com', 'msdk.qq.com', 'gamer.qq.com', 'game.gtimg.com',
         'gamedownload.qq.com', 'tencentgames.com', 'pvp.net', 'riotcdn.net', 'riotgames.com']

def validate(row):
    f = row.split(',')
    if len(f) not in [2, 3] or f[0] not in TYPES or not f[1]:
        raise ValueError('Unsupported or malformed rule')
    if len(f) == 3 and (not f[0].startswith('IP-') or f[2] != 'no-resolve'):
        raise ValueError('Unexpected rule options')
    if f[0] in ['IP-CIDR', 'IP-CIDR6']:
        net = ipaddress.ip_network(f[1], strict=False)
        if net.version != (6 if f[0] == 'IP-CIDR6' else 4):
            raise ValueError('IP family mismatch')
    elif f[0] == 'IP-ASN':
        if not f[1].isdigit():
            raise ValueError('Invalid ASN')
    elif f[0] in ['DOMAIN', 'DOMAIN-SUFFIX']:
        if not re.fullmatch(r'[\w.-]+', f[1]) or '.' not in f[1]:
            # TLD suffixes such as cn are legitimate Loon rules.
            if f[0] != 'DOMAIN-SUFFIX' or not re.fullmatch(r'(?:[a-z]+|xn--[a-z0-9-]+)', f[1]):
                raise ValueError('Invalid domain')
    return row

def parse(text, domain=False):
    result = []
    for raw in text.splitlines():
        row = raw.strip()
        if not row or row.startswith('#'):
            continue
        if row.startswith(('PROCESS-NAME,', 'PROCESS-PATH,')):
            continue
        if domain:
            row = ('DOMAIN-SUFFIX,' + row[2:] if row.startswith('+.') else
                   'DOMAIN-SUFFIX,' + row[1:] if row.startswith('.') else 'DOMAIN,' + row)
        result.append(validate(row))
    if not result:
        raise ValueError('Empty source')
    return result

def fetch_source(item, fixture=None):
    name, url = item
    if fixture:
        path = Path(fixture) / (name + '.list')
        if not path.exists():
            path = Path(fixture) / (name + '.txt')
        text = path.read_text()
    else:
        request = urllib.request.Request(url, headers={'User-Agent': 'Loon-Rule-Compiler/1.0'})
        with urllib.request.urlopen(request, timeout=45) as response:
            if response.status != 200:
                raise ValueError('Upstream HTTP failure: ' + name)
            data = response.read(16_000_001)
            if len(data) > 16_000_000:
                raise ValueError('Source too large: ' + name)
            text = data.decode('utf-8-sig')
    return name, parse(text, 'Domain' in name or name.startswith('META_'))

def compile_rules(src):
    music = []
    for row in src['NetEaseMusic']:
        f = row.split(',')
        if row == 'DOMAIN-SUFFIX,163yun.com':
            continue
        if f[0] in ['IP-CIDR', 'IP-CIDR6'] and ipaddress.ip_network(f[1], strict=False).prefixlen < 31:
            continue
        music.append(row)
    excluded = {'snssdk.com', 'capcut.com', 'marscode.com', 'trae.ai',
                'trae-api-sg.mchost.guru', 'lf16-pkgcdn.pitaya-clientai.com'}
    groups = {
        'netease-music': music,
        'tencent-games': src['META_TencentGames'] + ['DOMAIN-SUFFIX,' + x for x in GAMES],
        'tiktok': src['META_TikTok'] + [r for r in src['TikTok'] if r.split(',')[1] not in excluded],
        'douyin': src['META_Douyin'] + src['DouYin'],
        'netease-other': src['NetEase'],
        'tencent': src['WeChat'] + src['TencentDomain'] + src['Tencent'],
        'alibaba': src['AliPay'] + src['AlibabaDomain'] + src['Alibaba'],
        'china': src['ChinaMaxDomain'] + src['ChinaMax'] + src['ChinaIPs'] + ['GEOIP,CN'],
    }
    seen = set()
    for name, rows in groups.items():
        groups[name] = [r for r in dict.fromkeys(rows) if r not in seen]
        seen.update(groups[name])
    return groups

def build(fixture=None, output=None):
    output = Path(output or ROOT / 'public')
    old = json.loads((output / 'manifest.json').read_text()) if (output / 'manifest.json').exists() else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        src = dict(pool.map(lambda item: fetch_source(item, fixture), SOURCES.items()))
    groups = compile_rules(src)
    minimums = {'netease-music': 10, 'tencent-games': 40, 'tiktok': 15, 'douyin': 20,
                'netease-other': 60, 'tencent': 1000, 'alibaba': 500, 'china': 60000}
    files = {}
    bodies = {}
    for name, rows in groups.items():
        prior = old['files'].get(name, {}).get('count', 0) if old else 0
        if len(rows) < minimums[name] or (prior and len(rows) < prior * .8):
            raise ValueError('Rejected empty/truncated or >20% count loss: ' + name)
        body = ('# Loon native rules; generated from attributed public sources.\n' + '\n'.join(rows) + '\n').encode()
        files[name] = {'path': f'/rules/{name}.list', 'count': len(rows),
                       'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        bodies[name] = body
    version = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    manifest = {'schema': 1, 'version': version, 'checked_at': datetime.now(timezone.utc).isoformat(),
                'files': files, 'sources': SOURCES}
    # Everything validates before any live assets are replaced. Deployment is a new Worker version.
    output.mkdir(parents=True, exist_ok=True)
    (output / 'rules').mkdir(exist_ok=True)
    for name, body in bodies.items():
        (output / 'rules' / (name + '.list')).write_bytes(body)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({n: f['count'] for n, f in files.items()}))
    return manifest

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture')
    parser.add_argument('--output')
    args = parser.parse_args()
    build(args.fixture, args.output)
