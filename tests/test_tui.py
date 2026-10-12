"""Offline wizard tests; no real packets, sudo, or host network changes."""
import contextlib
import json
import os
import signal
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import portal_active_probe as probe
import portal_capture as network
import portal_tui as tui


class ConfigurationTests(unittest.TestCase):
    def test_existing_enrollment_is_preserved_and_legacy_schema_still_valid(self):
        config = {'interface': 'en4', 'ps5_ip': '192.168.1.20', 'portal_ip': '192.168.1.30'}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            path.write_text(json.dumps(config))
            self.assertEqual(tui.load_config(path), config)
            network.validate_config(tui.validate_form(tui.load_config(path)))

    def test_example_addresses_do_not_look_like_real_enrollment(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            path.write_text(json.dumps({'interface': 'en0', 'ps5_ip': '192.0.2.10',
                                        'portal_ip': '192.0.2.20'}))
            self.assertEqual(tui.load_config(path)['ps5_ip'], '')
            self.assertEqual(tui.load_config(path)['portal_ip'], '')

    def test_bad_peer_addresses_and_interfaces_are_rejected_before_start(self):
        valid = {'interface': 'en0', 'ps5_ip': '192.168.1.20', 'portal_ip': '192.168.1.30'}
        for changes in ({'ps5_ip': ''}, {'portal_ip': '999.1.1.1'}, {'ps5_ip': '127.0.0.1'},
                        {'portal_ip': '0.0.0.0'}, {'portal_ip': valid['ps5_ip']},
                        {'interface': 'en0;id'}, {'ps5_ip': '224.0.0.1'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                tui.validate_form(dict(valid, **changes))

    @unittest.skipIf(os.name == 'nt', 'POSIX permissions')
    def test_atomic_save_is_private_and_remains_compatible_with_old_launchers(self):
        config = {'interface': 'en0', 'ps5_ip': '192.168.1.20', 'portal_ip': '192.168.1.30'}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            tui.save_private_json(path, config)
            self.assertEqual(json.loads(path.read_text()), config)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(set(json.loads(path.read_text())),
                             {'interface', 'ps5_ip', 'portal_ip'})

    def test_failed_save_keeps_original_enrollment_and_removes_temp_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            path.write_text('original')
            with patch.object(Path, 'replace', side_effect=OSError('synthetic write failure')):
                with self.assertRaises(OSError):
                    tui.save_private_json(path, {'interface': 'en0'})
            self.assertEqual(path.read_text(), 'original')
            self.assertEqual(list(Path(folder).iterdir()), [path])


class TimingTests(unittest.TestCase):
    def test_existing_cli_timing_is_unchanged(self):
        window = probe.RelayWindow(100)
        self.assertEqual(window.ready_at, 105)
        self.assertEqual(window.deadline, 140)
        self.assertEqual(window.watchdog_seconds, 55)

    def test_wizard_has_full_two_minutes_after_ready_and_later_watchdog(self):
        window = probe.RelayWindow(0, tui.CONNECT_SECONDS, tui.CONFIRM_SECONDS)
        self.assertEqual(window.remaining(window.ready_at), 120)
        self.assertEqual(window.phase(95), 'waiting')
        self.assertEqual(window.remaining(95), 30)
        self.assertEqual(window.watchdog_seconds, 155)
        self.assertGreater(window.watchdog_seconds, window.connect_deadline + 15)

    def test_connection_in_last_second_has_its_own_confirmation_window(self):
        window = probe.RelayWindow(0, 120, 15)
        window.startup(124.9)
        self.assertEqual(window.phase(125), 'confirming')
        self.assertAlmostEqual(window.deadline, 139.9)
        self.assertEqual(window.remaining(125), 15)
        window.startup(139)
        self.assertAlmostEqual(window.deadline, 139.9, msg='Retransmissions cannot extend the relay forever')

    def test_unbounded_timeouts_are_rejected(self):
        for connect, confirm in ((0, 15), (121, 15), (60, -1), (60, 31)):
            with self.subTest(connect=connect, confirm=confirm), self.assertRaises(ValueError):
                probe.RelayWindow(0, connect, confirm)


class ResultTests(unittest.TestCase):
    def confirmed_report(self):
        return {'completed': True, 'unique_mutated_sequences': 1,
                'high_target_confirmed': True, 'restoration_errors': [],
                'egress_witness': {'all_expected_observed': True},
                'ps5_messages': [{'type': 'CONNECTIONQUALITY', 'target_bitrate_raw': 63_106_000}]}

    def test_result_uses_console_target_and_independent_egress_evidence(self):
        result = tui.summarize(self.confirmed_report())
        self.assertEqual(result.kind, 'success')
        self.assertAlmostEqual(result.target, 63.106)

    def test_restoration_failure_has_priority_over_high_target(self):
        report = self.confirmed_report()
        report['restoration_errors'] = ['ARP restore: synthetic']
        self.assertEqual(tui.summarize(report).kind, 'error')

    def test_cancelled_or_unverified_sessions_never_show_success(self):
        for changes in ({'completed': False, 'run_error': 'Cancelled by user'},
                        {'egress_witness': {'all_expected_observed': False}},
                        {'high_target_confirmed': False}):
            with self.subTest(changes=changes):
                self.assertNotEqual(tui.summarize(dict(self.confirmed_report(), **changes)).kind, 'success')

    def test_zero_traffic_points_to_fresh_connection_rather_than_ps5_rejection(self):
        result = tui.summarize({'completed': True, 'counts': {}, 'unique_mutated_sequences': 0,
                                'restoration_errors': []})
        self.assertEqual(result.title, 'No new connection detected')
        self.assertIn('CONNECT NOW', result.advice)


@unittest.skipIf(os.name == 'nt', 'Mocked POSIX relay lifecycle')
class RelayLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.recovery = self.root / 'recovery'
        self.recovery.mkdir()
        self.clock = 0
        self.events = []
        self.actions = []
        self.rx, self.tx, self.watcher = MagicMock(), MagicMock(), MagicMock()
        self.watcher.poll.return_value = None
        self.watcher.terminate.side_effect = lambda: self.actions.append('watchdog_stop')
        self.rx.select.side_effect = self.advance
        self.witness = MagicMock()
        self.witness.report.return_value = {'all_expected_observed': False}
        self.state = {'config': {'interface': 'en0', 'ps5_ip': '192.0.2.10', 'portal_ip': '192.0.2.20'},
                      'own_mac': '02:00:00:00:00:01', 'ps5_mac': '02:00:00:00:00:02',
                      'portal_mac': '02:00:00:00:00:03', 'sysctl': dict(zip(network.KEYS, ['0', '1']))}
        self.handlers = {sig: object() for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        overrides = (
            patch.object(probe.os, 'geteuid', return_value=0),
            patch.dict(probe.os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}),
            patch.object(probe.os, 'chown'),
            patch.object(probe.network, 'ROOT', self.root),
            patch.object(probe.network, 'configure'),
            patch.object(probe.network, 'preflight', return_value=self.state),
            patch.object(probe.network, 'frames', return_value=[b'arp1', b'arp2']),
            patch.object(probe.network, 'syswrite'),
            patch.object(probe.network, 'sysread', side_effect=lambda key: self.state['sysctl'][key]),
            patch.object(probe.conf, 'L2listen', return_value=self.rx),
            patch.object(probe.conf, 'L2socket', return_value=self.tx),
            patch.object(probe, 'Witness', return_value=self.witness),
            patch.object(probe.tempfile, 'mkdtemp', return_value=str(self.recovery)),
            patch.object(probe, 'Path', side_effect=self.local_path),
            patch.object(probe.time, 'monotonic', side_effect=lambda: self.clock),
            patch.object(probe.signal, 'getsignal', side_effect=lambda sig: self.handlers[sig]),
        )
        for override in overrides:
            self.stack.enter_context(override)
        self.signal = self.stack.enter_context(patch.object(probe.signal, 'signal'))
        self.spawn = self.stack.enter_context(patch.object(probe.subprocess, 'Popen', return_value=self.watcher))
        self.restore = self.stack.enter_context(patch.object(probe.network, 'restore', side_effect=self.restored))

    def local_path(self, path):
        return self.root / 'relay.lock' if str(path) == '/var/run/portal-lab-capture.lock' else Path(path)

    def advance(self, *args, **kwargs):
        self.clock += 1
        return False

    def restored(self, state):
        self.actions.append('restore')
        return []

    def progress(self, event):
        self.events.append((self.clock, event))
        return True

    def run_relay(self, callback=None):
        return probe.run(True, finish_on_high_target=True, connect_timeout=tui.CONNECT_SECONDS,
                         confirmation_timeout=tui.CONFIRM_SECONDS, progress=callback or self.progress)

    def test_no_connection_waits_full_window_and_guard_outlasts_old_deadline(self):
        report = self.run_relay()
        self.assertEqual(self.clock, 125)
        ready = [event for _, event in self.events if event['type'] == 'ready']
        self.assertEqual(ready[0]['seconds'], 120)
        tick = [event for at, event in self.events if at == 95 and event['type'] == 'tick'][0]
        self.assertEqual(tick['seconds'], 30)
        command = self.spawn.call_args.args[0]
        self.assertEqual(command[command.index('--watchdog-seconds') + 1], '155')
        self.assertEqual(report['unique_mutated_sequences'], 0)
        self.assertEqual(report['restoration_errors'], [])
        self.assertLess(self.actions.index('restore'), self.actions.index('watchdog_stop'))
        self.assertFalse((self.root / 'relay.lock').exists())

    def test_cancel_restores_network_then_handlers_and_supports_retry(self):
        def cancel(event):
            self.progress(event)
            return False if event['type'] == 'tick' and self.clock >= 6 else True
        report = self.run_relay(cancel)
        self.assertFalse(report['completed'])
        self.assertEqual(report['run_error'], 'Cancelled by user')
        self.assertEqual(report['restoration_errors'], [])
        for sig, handler in self.handlers.items():
            self.assertIn(unittest.mock.call(sig, handler), self.signal.call_args_list)
        self.assertFalse((self.root / 'relay.lock').exists())
        self.run_relay(cancel)
        self.assertEqual(self.restore.call_count, 2)

    def test_cancel_on_checking_does_not_get_lost_or_start_the_relay(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_relay(lambda event: False if event['type'] == 'checking' else True)
        self.tx.send.assert_not_called()
        self.spawn.assert_not_called()
        self.restore.assert_not_called()

    def test_cancel_during_preparation_is_honored_before_sending_arp(self):
        report = self.run_relay(lambda event: False if event['type'] == 'preparing' else True)
        self.assertEqual(report['run_error'], 'Cancelled by user')
        self.tx.send.assert_not_called()
        self.restore.assert_called_once()

    def test_late_startup_can_complete_acceptance_and_three_target_reports(self):
        # Drive the actual loop with a startup at second 124 (119s after READY).
        # Stopping at 125s would cut off all of the console responses.
        startup = b'\0' * 17 + b'seq1'
        payloads = [startup, b'accept', b'stream', b'quality', b'quality', b'quality']
        self.rx.recv_raw.side_effect = [(None, b'frame', None) for _ in payloads]

        def select(*args, **kwargs):
            self.clock += 1
            return 124 <= self.clock <= 129

        def observe(payload, events):
            event = {'accept': {'type': 'BANG', 'key_accepted': 1, 'version_accepted': 1},
                     'stream': {'type': 'STREAMINFO'},
                     'quality': {'type': 'CONNECTIONQUALITY', 'target_bitrate_raw': 63_106_000}}
            events.append(event[payload.decode()])

        self.rx.select.side_effect = select
        self.witness.report.return_value = {'all_expected_observed': True}
        transformed = [(b'outbound', payload, 'out' if index == 0 else 'in', index == 0)
                       for index, payload in enumerate(payloads)]
        with patch.object(probe, 'transform', side_effect=transformed), \
                patch.object(probe, 'observe', side_effect=observe), \
                patch.object(probe, 'CONFIRM_TARGET', 50_000_000):
            report = self.run_relay()
        self.assertEqual(self.clock, 129)
        self.assertTrue(report['high_target_confirmed'])
        self.assertEqual(report['unique_mutated_sequences'], 1)
        self.witness.expect.assert_called_once_with(b'outbound')
        self.assertEqual(tui.summarize(report).kind, 'success')

    def test_send_failure_restores_before_stopping_watchdog(self):
        self.tx.send.side_effect = OSError('synthetic send failure')
        report = self.run_relay()
        self.assertIn('synthetic send failure', report['run_error'])
        self.assertFalse(report['completed'])
        self.assertEqual(report['restoration_errors'], [])
        self.assertLess(self.actions.index('restore'), self.actions.index('watchdog_stop'))

    def test_failed_restoration_retains_watchdog_and_blocks_overlapping_retry(self):
        self.restore.side_effect = lambda state: ['ARP restore: synthetic failure']
        report = self.run_relay()
        self.assertEqual(tui.summarize(report).kind, 'error')
        self.watcher.terminate.assert_not_called()
        self.assertTrue((self.root / 'relay.lock').exists())
        with self.assertRaises(probe.PreflightError):
            self.run_relay()

    def test_dead_guard_stops_relay_and_restores(self):
        self.watcher.poll.return_value = 1
        report = self.run_relay()
        self.assertIn('watchdog exited', report['run_error'])
        self.restore.assert_called_once()

    def test_unrestored_sysctl_keeps_independent_recovery_and_lock(self):
        self.stack.enter_context(patch.object(probe.network, 'sysread', return_value='0'))
        report = self.run_relay()
        self.assertTrue(report['restoration_errors'])
        self.watcher.terminate.assert_not_called()
        self.assertTrue((self.root / 'relay.lock').exists())

    def test_preflight_rejection_does_not_change_network(self):
        self.stack.enter_context(patch.object(probe.network, 'preflight', side_effect=RuntimeError('wrong LAN')))
        with self.assertRaisesRegex(probe.PreflightError, 'wrong LAN'):
            self.run_relay()
        self.tx.send.assert_not_called()
        self.restore.assert_not_called()
        self.spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
