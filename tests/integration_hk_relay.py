"""Kernel-level regression: isolated client/HK/home namespaces, no Internet traffic."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('relay', ROOT / 'deploy/hk-relay.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
CONFIG = {'direct_port': 56306, 'relay_port': 59349, 'home_port': 40710}


def run(*args, input=None, check=True):
    return subprocess.run(args, input=input, capture_output=True, text=True,
                          timeout=30, check=check)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run only in an isolated Linux CI runner with sudo and iproute2/nftables')
    prefix = 'cv' + str(os.getpid())
    namespaces = {name: prefix + name for name in ('hub', 'client', 'hk', 'home')}
    processes = []

    def ns(name, *args, **kwargs):
        return run('ip', 'netns', 'exec', namespaces[name], *args, **kwargs)

    def server(name, host, port, tcp=False):
        script = ('import socket; s=socket.socket(); s.bind(("0.0.0.0",22)); s.listen(); '
                  '\nwhile True:\n c,a=s.accept(); c.sendall(b"ssh-rule-kept"); c.close()' if tcp else
                  f'import socket,json; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(({host!r},{port}));'
                  '\nwhile True:\n d,a=s.recvfrom(4096); s.sendto(json.dumps({"data":d.decode(),"peer":a[0]}).encode(),a)')
        processes.append(subprocess.Popen(['ip', 'netns', 'exec', namespaces[name], sys.executable,
                                           '-u', '-c', script], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))

    def request(port, expected=True):
        script = f'''import json,socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
s.connect(('1.1.1.1',{port})); s.send(b'kernel-relay-check')
try:
 data=s.recv(4096)
except (TimeoutError,OSError):
 raise SystemExit(0 if not {expected!r} else 1)
assert {expected!r}, 'unrelated UDP service became reachable'
print(data.decode())
'''
        result = ns('client', sys.executable, '-c', script)
        return json.loads(result.stdout) if expected else None

    def install(target):
        snapshot = json.loads(ns('hk', 'nft', '-j', 'list', 'ruleset').stdout)
        plan = relay.nft_plan(CONFIG, target, 'eth0', snapshot)
        ns('hk', 'nft', '--check', '-f', '-', input=plan)
        ns('hk', 'nft', '-f', '-', input=plan)
        after = json.loads(ns('hk', 'nft', '-j', 'list', 'ruleset').stdout)
        comments = [item['rule'].get('comment') for item in after['nftables'] if 'rule' in item]
        assert comments.count('keep-ssh') == 2
        assert sum(item in relay.OWNED_COMMENTS for item in comments) == 6

    try:
        for value in namespaces.values():
            run('ip', 'netns', 'add', value)
        ns('hub', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
        ns('hub', 'ip', 'link', 'set', 'br0', 'up')
        for index, name in enumerate(('hk', 'client', 'home'), 1):
            left, right = prefix + str(index) + 'a', prefix + str(index) + 'b'
            run('ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
            run('ip', 'link', 'set', left, 'netns', namespaces[name])
            run('ip', 'link', 'set', right, 'netns', namespaces['hub'])
            ns(name, 'ip', 'link', 'set', left, 'name', 'eth0')
            ns(name, 'ip', 'addr', 'add', f'1.1.1.{index}/24', 'dev', 'eth0')
            ns(name, 'ip', 'link', 'set', 'eth0', 'up')
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
            ns('hub', 'ip', 'link', 'set', right, 'master', 'br0')
            ns('hub', 'ip', 'link', 'set', right, 'up')
        ns('home', 'ip', 'addr', 'add', '1.1.1.4/24', 'dev', 'eth0')
        ns('hk', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        initial = '''table inet host {
 chain input { type filter hook input priority 0; policy drop; tcp dport 22 accept comment "keep-ssh"; }
 chain forward { type filter hook forward priority 0; policy drop; }
}
table ip second {
 chain input { type filter hook input priority 5; policy drop; tcp dport 22 accept comment "keep-ssh"; }
 chain forward { type filter hook forward priority 5; policy drop; }
}
'''
        ns('hk', 'nft', '-f', '-', input=initial)
        server('hk', '0.0.0.0', 56306)
        server('hk', '0.0.0.0', 55555)
        server('hk', '', 22, tcp=True)
        server('home', '1.1.1.3', 40710)
        server('home', '1.1.1.4', 40710)
        time.sleep(.5)
        install('1.1.1.3')
        assert request(56306)['data'] == 'kernel-relay-check'
        response = request(59349)
        assert response['data'] == 'kernel-relay-check' and response['peer'] == '1.1.1.1', response
        request(55555, expected=False)
        ns('client', sys.executable, '-c',
           'import socket; s=socket.create_connection(("1.1.1.1",22),2); assert s.recv(100)==b"ssh-rule-kept"')
        install('1.1.1.4')
        assert request(59349)['peer'] == '1.1.1.1'
        install('1.1.1.4')
        assert request(59349)['data'] == 'kernel-relay-check'
        print(json.dumps({'kernel_nft_syntax': True, 'multiple_drop_chains': True,
                          'udp_dnat_snat_roundtrip': True, 'direct_udp_port': True,
                          'unrelated_port_stays_blocked': True, 'ssh_rule_preserved': True,
                          'ddns_refresh_and_idempotence': True}))
    finally:
        for process in processes:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
        for value in reversed(list(namespaces.values())):
            run('ip', 'netns', 'delete', value, check=False)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print((error.stderr or error.stdout or str(error))[:4000], file=sys.stderr)
        raise
