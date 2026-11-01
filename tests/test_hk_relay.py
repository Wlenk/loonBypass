import copy
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hk_relay', Path(__file__).resolve().parents[1] / 'deploy/hk-relay.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)
CONFIG = {'relay_port': 59349, 'home_port': 40710, 'direct_port': 56306}


class RelaySafety(unittest.TestCase):
    def test_failed_or_private_ddns_never_produces_firewall_rules(self):
        for ip in ['127.0.0.1', '192.168.1.10', '100.64.0.1', '169.254.169.254']:
            with patch.object(relay.socket, 'getaddrinfo', return_value=[(None, None, None, None, (ip, 40710))]):
                with self.assertRaises(RuntimeError):
                    relay.target_ip('home.invalid')

    def test_existing_drop_firewall_gets_only_service_specific_exceptions(self):
        rules = {'nftables': [
            {'table': {'family': 'inet', 'name': 'host'}},
            {'chain': {'family': 'inet', 'table': 'host', 'name': 'input',
                       'type': 'filter', 'hook': 'input', 'policy': 'drop'}},
            {'chain': {'family': 'inet', 'table': 'host', 'name': 'forward',
                       'type': 'filter', 'hook': 'forward', 'policy': 'drop'}},
            {'rule': {'family': 'inet', 'table': 'host', 'chain': 'input',
                      'handle': 31, 'comment': 'keep-ssh-rule', 'expr': [{'accept': None}]}},
        ]}
        before = copy.deepcopy(rules)
        plan = relay.nft_plan(CONFIG, '1.1.1.1', 'eth0', rules)
        self.assertEqual(rules, before)
        self.assertNotIn('flush', plan)
        self.assertNotIn('delete rule', plan)
        self.assertNotIn('delete chain', plan)
        exceptions = [row for row in plan.splitlines() if row.startswith('insert rule')]
        self.assertEqual(len(exceptions), 3)
        self.assertIn('udp dport 56306', exceptions[0])
        for row in exceptions[1:]:
            self.assertIn('ct original proto-dst 59349', row)
            self.assertIn('ct status dnat', row)
            self.assertIn('1.1.1.1', row)
        self.assertTrue(all('meta nfproto ipv4' in row for row in exceptions))

    def test_ddns_refresh_deletes_only_owned_rules_and_own_nat_table(self):
        rules = {'nftables': [
            {'table': {'family': 'ip', 'name': 'cloudvpn_hk_relay'}},
            {'chain': {'family': 'ip', 'table': 'filter', 'name': 'FORWARD',
                       'type': 'filter', 'hook': 'forward', 'policy': 'drop'}},
            {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'FORWARD', 'handle': 12,
                      'comment': 'cloudvpn-hk:relay-forward'}},
            {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'FORWARD', 'handle': 13,
                      'comment': 'unrelated-rule'}},
        ]}
        plan = relay.nft_plan(CONFIG, '8.8.8.8', 'eth0', rules)
        self.assertIn('delete rule ip "filter" "FORWARD" handle 12', plan)
        self.assertNotIn('handle 13', plan)
        self.assertIn('delete table ip cloudvpn_hk_relay', plan)
        self.assertNotIn('delete table ip filter', plan)
        self.assertIn('ip daddr 8.8.8.8', plan)

    def test_unrelated_families_and_non_base_chains_stay_untouched(self):
        rules = {'nftables': [
            {'chain': {'family': 'ip6', 'table': 'v6', 'name': 'input', 'type': 'filter', 'hook': 'input'}},
            {'chain': {'family': 'inet', 'table': 'host', 'name': 'custom', 'type': 'filter'}},
        ]}
        plan = relay.nft_plan(CONFIG, '1.1.1.1', 'eth0', rules)
        self.assertNotIn('insert rule', plan)
        self.assertNotIn('delete ', plan)

    def test_nft_diagnostics_are_retained_on_failure(self):
        result = subprocess.CompletedProcess(('nft',), 1, '', 'syntax error: unexpected token')
        with patch.object(relay.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'syntax error'):
                relay.run('nft', '--check', '-f', '-', input='broken')

    def test_failed_validation_never_applies_or_replaces_target_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'relay.json'
            state.write_text('{"ip":"8.8.8.8"}')
            writes = []
            def run(*args, **kwargs):
                if args[0] == 'ip':
                    return subprocess.CompletedProcess(args, 0, '[{"dev":"eth0"}]', '')
                if args[0] == 'systemctl':
                    return subprocess.CompletedProcess(args, 1, '', '')
                if args[:2] == ('nft', '-j'):
                    return subprocess.CompletedProcess(args, 0, '{"nftables":[]}', '')
                if '--check' in args:
                    raise RuntimeError('test kernel validation failure')
                writes.append(args)
            with patch.object(relay, 'STATE', state), patch.object(relay, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'validation failure'):
                    relay.apply(CONFIG, '1.1.1.1', {'ip': '8.8.8.8'})
            self.assertEqual(writes, [])
            self.assertEqual(state.read_text(), '{"ip":"8.8.8.8"}')

    def test_empty_dns_keeps_last_working_target(self):
        with patch.object(relay.socket, 'getaddrinfo', return_value=[]):
            with self.assertRaises(RuntimeError): relay.target_ip('home.invalid')


if __name__ == '__main__': unittest.main()
