"""Derive Mihomo assets from the same verified public Loon snapshot.

Large China domain and IP sets use MRS; small mixed platform sets use classical
text. HTTP requests never compile anything. Private profile contents are opaque.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ('netease-music', 'tencent-games', 'tiktok', 'douyin', 'china-cdn',
             'netease-other', 'tencent', 'alibaba')
NAMES = (*PLATFORMS, 'china-domain', 'china-ipcidr', 'china-other')
SUPPORTED = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
             'IP-ASN', 'GEOIP'}


def convert(rows):
    result, skipped = [], 0
    for row in rows:
        if not row or row.startswith('#'):
            continue
        kind = row.split(',', 1)[0]
        if kind == 'USER-AGENT':
            # Mihomo routes encrypted HTTPS by destination/process, not HTTP UA.
            skipped += 1
            continue
        if kind not in SUPPORTED:
            raise ValueError('Unsupported Mihomo source rule type')
        result.append(row)
    return list(dict.fromkeys(result)), skipped


def profile_digest(path):
    data = path.read_bytes()
    envelope = json.loads(data)
    if (set(envelope) != {'schema', 'nonce', 'ciphertext'} or envelope['schema'] != 1 or
            len(base64.b64decode(envelope['nonce'], validate=True)) != 12 or
            not 32 <= len(base64.b64decode(envelope['ciphertext'], validate=True)) <= 1_000_000):
        raise ValueError('Invalid sealed private profile envelope')
    return hashlib.sha256(data).hexdigest()


def build(output=None, compiler=None):
    output = Path(output or ROOT / 'public')
    compiler = str(Path(compiler or os.environ.get('MIHOMO_BIN', 'tmp/mihomo-core')).resolve())
    native = json.loads((output / 'manifest.json').read_text())
    groups, skipped = {}, {}
    for name in (*PLATFORMS, 'china'):
        entry = native['files'][name]
        if entry['path'] != f'/rules/{name}.list':
            raise ValueError('Unexpected source path')
        body = (output / 'rules' / f'{name}.list').read_bytes()
        if len(body) != entry['bytes'] or hashlib.sha256(body).hexdigest() != entry['sha256']:
            raise ValueError('Native snapshot digest mismatch: ' + name)
        groups[name], skipped[name] = convert(body.decode().splitlines())
    china = groups.pop('china')
    groups['china-domain'] = [('+.' if row.startswith('DOMAIN-SUFFIX,') else '') + row.split(',')[1]
                             for row in china if row.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,'))]
    groups['china-ipcidr'] = [row.split(',')[1] for row in china
                             if row.startswith(('IP-CIDR,', 'IP-CIDR6,'))]
    groups['china-other'] = [row for row in china if row.split(',')[0] not in
                            {'DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR', 'IP-CIDR6'}]
    minimums = dict(zip(PLATFORMS, (10, 40, 15, 20, 40, 60, 1000, 500)))
    minimums.update({'china-domain': 60000, 'china-ipcidr': 1000, 'china-other': 1})
    previous_path = output / 'mihomo/manifest.json'
    previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
    files, bodies = {}, {}
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        for name, rows in groups.items():
            prior = previous.get('files', {}).get(name, {}).get('count', 0)
            if len(rows) < minimums[name] or (prior and len(rows) < prior * .8):
                raise ValueError('Rejected empty/truncated Mihomo set: ' + name)
            behavior = 'domain' if name == 'china-domain' else 'ipcidr' if name == 'china-ipcidr' else 'classical'
            fmt = 'mrs' if behavior != 'classical' else 'text'
            body = ('# Derived from verified public sources; see /manifest.json.\n' + '\n'.join(rows) + '\n').encode()
            if fmt == 'mrs':
                source, target = temp / f'{name}.list', temp / f'{name}.mrs'
                source.write_bytes(body)
                process = subprocess.run([compiler, 'convert-ruleset', behavior, 'text', str(source), str(target)],
                                         capture_output=True, timeout=60)
                if process.returncode or not target.exists():
                    raise ValueError('Mihomo binary conversion failed: ' + name)
                body = target.read_bytes()
                # Official MRS output is a Zstandard frame containing MRS v1.
                if not body.startswith(b'\x28\xb5\x2f\xfd'):
                    raise ValueError('Invalid MRS output: ' + name)
            path = f'/mihomo/{name}.{fmt if fmt == "mrs" else "list"}'
            files[name] = {'path': path, 'behavior': behavior, 'format': fmt,
                           'count': len(rows), 'bytes': len(body),
                           'sha256': hashlib.sha256(body).hexdigest()}
            bodies[path] = body
    sealed_sha = profile_digest(output / 'sealed-profiles/windows-mihomo.json')
    version = hashlib.sha256(json.dumps({'files': files, 'profile_sha256': sealed_sha}, sort_keys=True).encode()).hexdigest()
    manifest = {'schema': 1, 'version': version, 'source_version': native['version'],
                'checked_at': native['checked_at'], 'compiler': 'mihomo v1.19.32',
                'profile_sha256': sealed_sha, 'skipped_user_agent': skipped, 'files': files}
    native['mihomo'] = {'path': '/mihomo/manifest.json', 'version': version, 'files': len(files)}
    # All conversion and validation completes before replacing the bundle.
    (output / 'mihomo').mkdir(exist_ok=True)
    for path, body in bodies.items():
        (output / path.lstrip('/')).write_bytes(body)
    previous_path.write_text(json.dumps(manifest, indent=2) + '\n')
    (output / 'manifest.json').write_text(json.dumps(native, indent=2) + '\n')
    print(json.dumps({name: item['count'] for name, item in files.items()}))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output')
    parser.add_argument('--compiler')
    args = parser.parse_args()
    build(args.output, args.compiler)
