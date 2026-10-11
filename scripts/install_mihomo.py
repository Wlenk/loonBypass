"""Fetch the pinned official compiler, checking the release asset before execution."""
import argparse
import gzip
import hashlib
from pathlib import Path
import urllib.request

VERSION = 'v1.19.32'
SHA256 = 'ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20'
URL = f'https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/mihomo-linux-amd64-compatible-{VERSION}.gz'


def install(path):
    target = Path(path)
    archive = target.with_suffix('.gz')
    target.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        with urllib.request.urlopen(URL, timeout=90) as response:
            data = response.read(50_000_001)
        if hashlib.sha256(data).hexdigest() != SHA256:
            raise ValueError('Official Mihomo archive digest mismatch')
        archive.write_bytes(data)
    target.write_bytes(gzip.decompress(archive.read_bytes()))
    target.chmod(0o700)
    print(f'Official Mihomo {VERSION} archive verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='tmp/mihomo-core')
    install(parser.parse_args().output)
