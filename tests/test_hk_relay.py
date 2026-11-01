import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hk_relay', Path(__file__).resolve().parents[1] / 'deploy/hk-relay.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class RelaySafety(unittest.TestCase):
    def test_failed_or_private_ddns_never_produces_firewall_rules(self):
        for ip in ['127.0.0.1', '192.168.1.10', '100.64.0.1', '169.254.169.254']:
            with patch.object(relay.socket, 'getaddrinfo', return_value=[(None, None, None, None, (ip, 40710))]):
                with self.assertRaises(RuntimeError):
                    relay.target_ip('home.invalid')

    def test_existing_foreign_firewall_is_not_overwritten(self):
        config = {'relay_port': 59349, 'home_port': 40710, 'direct_port': 56306}
        def run(*args, **kwargs):
            output = ('[{"dev":"eth0"}]' if args[0] == 'ip' else
                      '{"nftables":[{"chain":{"table":"unrelated","hook":"forward","policy":"drop"}}]}')
            return subprocess.CompletedProcess(args, 1 if args[0] == 'systemctl' else 0, output, '')
        with patch.object(relay, 'run', side_effect=run) as calls:
            with self.assertRaises(RuntimeError):
                relay.apply(config, '1.1.1.1', {})
            self.assertFalse(any('-f' in args.args for args in calls.call_args_list))

    def test_empty_dns_keeps_last_working_target(self):
        with patch.object(relay.socket, 'getaddrinfo', return_value=[]):
            with self.assertRaises(RuntimeError): relay.target_ip('home.invalid')


if __name__ == '__main__': unittest.main()
