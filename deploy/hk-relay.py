#!/usr/bin/env python3
"""Refresh only this deployment's UDP DNAT/SNAT after the home DDNS changes."""
import ipaddress
import json
import socket
import subprocess
from pathlib import Path

ROOT = Path('/etc/cloudvpn-hy2')
STATE = Path('/var/lib/cloudvpn-hy2/relay.json')


def run(*args, check=True, input=None):
    return subprocess.run(args, check=check, input=input, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)


def target_ip(host):
    addresses = sorted({item[4][0] for item in
                        socket.getaddrinfo(host, 40710, socket.AF_INET, socket.SOCK_DGRAM)})
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise RuntimeError('Home DDNS did not resolve to a public IPv4; keeping old rules')
    return addresses[0]


def apply(config, ip, prior):
    route = json.loads(run('ip', '-j', 'route', 'get', ip).stdout)[0]
    interface = route['dev']
    if not interface.replace('_', '').replace('-', '').replace('.', '').isalnum():
        raise RuntimeError('Unexpected interface name')
    active = run('systemctl', 'is-active', '--quiet', 'firewalld', check=False).returncode == 0
    port = int(config['relay_port'])
    remote = int(config['home_port'])
    if active:
        zone = run('firewall-cmd', '--get-zone-of-interface=' + interface, check=False).stdout.strip()
        if not zone or zone == 'no zone':
            zone = run('firewall-cmd', '--get-default-zone').stdout.strip()
        forward = f'port={port}:proto=udp:toport={remote}:toaddr={ip}'
        snat = f'rule family="ipv4" destination address="{ip}/32" masquerade'
        for permanent in (False, True):
            prefix = ['firewall-cmd'] + (['--permanent'] if permanent else [])
            prefix += ['--zone=' + zone]
            # No flush/reload: unrelated firewall and SSH rules remain intact.
            run(*prefix, '--add-port=' + str(config['direct_port']) + '/udp')
            run(*prefix, '--add-rich-rule=' + snat)
            if prior and prior.get('ip') != ip and prior.get('backend') == 'firewalld':
                old = f'port={port}:proto=udp:toport={remote}:toaddr={prior["ip"]}'
                old_prefix = ['firewall-cmd'] + (['--permanent'] if permanent else [])
                old_prefix += ['--zone=' + prior['zone']]
                run(*old_prefix, '--remove-forward-port=' + old, check=False)
                run(*old_prefix, '--remove-rich-rule=' +
                    f'rule family="ipv4" destination address="{prior["ip"]}/32" masquerade', check=False)
            run(*prefix, '--add-forward-port=' + forward)
        result = {'ip': ip, 'backend': 'firewalld', 'zone': zone}
    else:
        rules = json.loads(run('nft', '-j', 'list', 'ruleset').stdout)
        for item in rules.get('nftables', []):
            chain = item.get('chain', {})
            if (chain.get('hook') in ('input', 'forward') and
                    chain.get('table') != 'cloudvpn_hk_relay'):
                raise RuntimeError('Existing non-firewalld input/forward firewall; integrate explicitly first')
        exists = run('nft', 'list', 'table', 'ip', 'cloudvpn_hk_relay', check=False).returncode == 0
        text = ('delete table ip cloudvpn_hk_relay\n' if exists else '') + f'''
table ip cloudvpn_hk_relay {{
 chain prerouting {{
  type nat hook prerouting priority dstnat; policy accept;
  iifname "{interface}" fib daddr type local udp dport {port} dnat to {ip}:{remote}
 }}
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  ip daddr {ip} udp dport {remote} ct status dnat masquerade
 }}
}}
'''
        # nft applies one transaction: either all our changes commit or none do.
        run('nft', '--check', '-f', '-', input=text)
        run('nft', '-f', '-', input=text)
        result = {'ip': ip, 'backend': 'nftables'}
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(result) + '\n')
    temporary.replace(STATE)
    return result


def main():
    config = json.loads((ROOT / 'relay-config.json').read_text())
    ip = target_ip(config['home_host'])
    prior = json.loads(STATE.read_text()) if STATE.exists() else {}
    result = apply(config, ip, prior)
    print(json.dumps({'relay_target': f'{ip}:{config["home_port"]}', **result}))


if __name__ == '__main__':
    main()
