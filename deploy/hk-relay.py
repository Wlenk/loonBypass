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
    result = subprocess.run(args, check=False, input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()[:3000]
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {detail}')
    return result


OWNED_COMMENTS = {'cloudvpn-hk:hy2-input', 'cloudvpn-hk:relay-forward', 'cloudvpn-hk:relay-reply'}


def nft_plan(config, ip, interface, rules):
    """Keep existing policies/rules and add explicit service-only exceptions.

    A separate accept chain cannot override another base chain's drop. Install
    the exceptions in every existing IPv4/inet input or forward filter chain.
    """
    target = ipaddress.ip_address(ip)
    if target.version != 4 or not target.is_global:
        raise RuntimeError('Relay target must be a public IPv4')
    direct, relay, remote = (int(config[key]) for key in ('direct_port', 'relay_port', 'home_port'))
    if any(not 1 <= port <= 65535 for port in (direct, relay, remote)) or direct == relay:
        raise RuntimeError('Invalid service ports')
    quote = json.dumps
    commands, filters = [], []
    items = rules.get('nftables', [])
    for item in items:
        rule = item.get('rule', {})
        if rule.get('comment') in OWNED_COMMENTS and rule.get('family') in ('ip', 'inet'):
            commands.append('delete rule {} {} {} handle {}'.format(rule['family'],
                quote(rule['table']), quote(rule['chain']), int(rule['handle'])))
        chain = item.get('chain', {})
        if (chain.get('family') in ('ip', 'inet') and chain.get('type') == 'filter' and
                chain.get('hook') in ('input', 'forward')):
            filters.append(chain)
    exists = any(item.get('table', {}).get('family') == 'ip' and
                 item.get('table', {}).get('name') == 'cloudvpn_hk_relay' for item in items)
    if exists:
        commands.append('delete table ip cloudvpn_hk_relay')
    commands.append(f'''table ip cloudvpn_hk_relay {{
 chain prerouting {{
  type nat hook prerouting priority dstnat; policy accept;
  iifname {quote(interface)} fib daddr type local udp dport {relay} dnat to {ip}:{remote}
 }}
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  ip daddr {ip} udp dport {remote} ct status dnat ct original proto-dst {relay} masquerade
 }}
}}''')
    for chain in filters:
        prefix = 'insert rule {} {} {} '.format(chain['family'], quote(chain['table']), quote(chain['name']))
        family = 'meta nfproto ipv4 ' if chain['family'] == 'inet' else ''
        if chain['hook'] == 'input':
            commands.append(prefix + family + f'iifname {quote(interface)} udp dport {direct} '
                'accept comment "cloudvpn-hk:hy2-input"')
        else:
            commands.append(prefix + family + f'iifname {quote(interface)} ip daddr {ip} '
                f'udp dport {remote} ct status dnat ct direction original '
                f'ct original proto-dst {relay} accept comment "cloudvpn-hk:relay-forward"')
            commands.append(prefix + family + f'oifname {quote(interface)} ip saddr {ip} '
                f'udp sport {remote} ct status dnat ct direction reply '
                f'ct original proto-dst {relay} accept comment "cloudvpn-hk:relay-reply"')
    return '\n'.join(commands) + '\n'


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
        text = nft_plan(config, ip, interface, rules)
        # Backup for diagnosis only; this service never restores the whole host
        # firewall or flushes any unrelated table, chain, rule, or policy.
        backup = STATE.parent / 'firewall-before-first-relay.json'
        if not backup.exists():
            backup.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with backup.open('x') as stream:
                json.dump(rules, stream)
            backup.chmod(0o600)
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
