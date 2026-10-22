"""Device discovery diagnostics without packets, sudo, or network changes."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import portal_capture as network


class DeviceDiscoveryTests(unittest.TestCase):
    def setUp(self):
        def patched(target, name, **kwargs):
            patcher = patch.object(target, name, **kwargs)
            value = patcher.start()
            self.addCleanup(patcher.stop)
            return value

        patched(network, 'IFACE', new='en0')
        patched(network, 'PS5', new='192.0.2.10')
        patched(network, 'PORTAL', new='192.0.2.20')
        self.uid = patched(network.os, 'geteuid', return_value=0, create=True)
        self.command = patched(network.subprocess, 'run',
                               return_value=SimpleNamespace(stdout=''))
        self.hardware = patched(network, 'get_if_hwaddr',
                                return_value='02:00:00:00:00:01')
        self.query = patched(network, 'srp', return_value=([], []))

    def reply(self, ip, address, operation=2):
        packet = network.Ether(src=address) / network.ARP(
            op=operation, psrc=ip, hwsrc=address)
        return (None, packet)

    def test_missing_device_with_root_names_peer_instead_of_requesting_sudo(self):
        for name, ip in (('PS5', network.PS5), ('Portal', network.PORTAL)):
            with self.subTest(device=name):
                with self.assertRaises(RuntimeError) as raised:
                    network.mac(ip)
                message = str(raised.exception)
                self.assertIn(name, message)
                self.assertIn(ip, message)
                self.assertIn('en0', message)
                self.assertIn('did not respond', message)
                self.assertIn('no network changes made', message)
                self.assertNotIn('sudo', message.lower())
        self.assertEqual(self.query.call_count, 2)

    def test_missing_privilege_still_requests_sudo_without_raw_query(self):
        self.uid.return_value = 1000
        with self.assertRaisesRegex(RuntimeError, 'sudo'):
            network.mac(network.PORTAL)
        self.query.assert_not_called()
        self.hardware.assert_not_called()

    def test_cached_address_is_normalized_without_raw_query(self):
        self.command.return_value.stdout = '? (192.0.2.20) at 2:0:0:0:0:3 on en0 ifscope'
        self.assertEqual(network.mac(network.PORTAL), '02:00:00:00:00:03')
        self.query.assert_not_called()

    def test_unique_reply_is_accepted_and_unrelated_packets_are_ignored(self):
        self.query.return_value = ([
            self.reply(network.PORTAL, '02:00:00:00:00:03'),
            self.reply(network.PORTAL, '02:00:00:00:00:03'),
            self.reply(network.PS5, '02:00:00:00:00:02'),
            self.reply(network.PORTAL, '02:00:00:00:00:04', operation=1),
        ], [])
        self.assertEqual(network.mac(network.PORTAL), '02:00:00:00:00:03')

    def test_conflicting_replies_are_rejected_as_duplicate_ip_not_permission(self):
        self.query.return_value = ([
            self.reply(network.PORTAL, '02:00:00:00:00:03'),
            self.reply(network.PORTAL, '02:00:00:00:00:04'),
        ], [])
        with self.assertRaises(RuntimeError) as raised:
            network.mac(network.PORTAL)
        self.assertIn('duplicate IP', str(raised.exception))
        self.assertNotIn('sudo', str(raised.exception).lower())


if __name__ == '__main__':
    unittest.main()
