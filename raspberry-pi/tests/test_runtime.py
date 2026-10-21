"""Unit tests for `linux_native.py` and `guardian.py` runtime, preflight, nft, and fault injection."""
import base64
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import guardian
import linux_native
import portal_active_probe as probe
from nat import capture_filters, parse
from tests.test_nat import (
    PI_IP,
    PI_MAC,
    PORTAL_IP,
    PORTAL_MAC,
    PS5_IP,
    PS5_MAC,
    build_tcp_frame,
    build_udp_frame,
    build_ipv4_header,
    fragment_ip_payload,
    ones_complement_sum,
    verify_frame_checksums,
)


def encode_varint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def pb_varint(field_no, value):
    return encode_varint((field_no << 3) | 0) + encode_varint(value)


def pb_bytes(field_no, raw):
    return encode_varint((field_no << 3) | 2) + encode_varint(len(raw)) + raw


def build_ps5_telemetry_payload(kind, *, target_bitrate=85000000):
    header = bytearray(26)
    header[0] = 0x00
    header[13] = 0x00
    header[14] = 0x01
    header[25] = 0x00
    if kind == 'BANG':
        inner = pb_varint(1, 20) + pb_varint(3, 1) + pb_varint(4, 1)
        body = pb_varint(1, 1) + pb_bytes(3, inner)
    elif kind == 'STREAMINFO':
        body = pb_varint(1, 13)
    elif kind == 'CONNECTIONQUALITY':
        inner = pb_varint(1, target_bitrate)
        body = pb_varint(1, 16) + pb_bytes(17, inner)
    elif kind == 'DISCONNECT':
        body = pb_varint(1, 8)
    else:
        raise ValueError(kind)
    return bytes(header) + body


class FakeClock:
    def __init__(self, initial=1000.0):
        self.now = float(initial)

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += float(delta)
        return self.now


class FakeRawSocket:
    def __init__(self, rx_frames=None, clock=None, drop_count=0):
        self.rx_frames = list(rx_frames or [])
        self.clock = clock
        self.sent_frames = []
        self.closed = False
        self.packets_stat = len(self.rx_frames)
        self.drops_stat = drop_count
        self.fail_send_einval_once_under_60 = False
        self.fail_send_einval_always = False
        self.short_send_length = None

    def select(self, sockets, remain=0.02):
        if self.rx_frames:
            return [self]
        if self.clock is not None:
            self.clock.advance(0.25)
        return []

    def recv_raw(self, bufsize=65535):
        if not self.rx_frames:
            if self.clock is not None:
                self.clock.advance(0.25)
            return None, None, None
        item = self.rx_frames.pop(0)
        if isinstance(item, tuple):
            frame, dt = item
            if self.clock is not None:
                self.clock.advance(dt)
        else:
            frame = item
            if self.clock is not None:
                self.clock.advance(0.05)
        return None, frame, (self.clock() if self.clock is not None else 0.0)

    def send(self, frame):
        raw = bytes(frame)
        if self.fail_send_einval_always:
            raise OSError(errno.EINVAL, 'Simulated EINVAL')
        if self.fail_send_einval_once_under_60 and len(raw) < 60:
            self.fail_send_einval_once_under_60 = False
            raise OSError(errno.EINVAL, 'Simulated short frame EINVAL')
        self.sent_frames.append(raw)
        if self.short_send_length is not None:
            return self.short_send_length
        return len(raw)

    def get_stats(self):
        return (self.packets_stat, self.drops_stat)

    def close(self):
        self.closed = True


class FakeGuardianProcess:
    """Controllable guardian process double recording handshake and lifecycle events."""

    def __init__(
        self,
        state_path,
        parent_pid,
        runtime,
        *,
        event_log=None,
        first_line='PORTS_RESERVED\n',
        second_line='GUARD_READY\n',
        exit_during_loop=False,
        wait_rc=0,
        recovery_errors=None,
    ):
        self.state_path = Path(state_path)
        self.parent_pid = parent_pid
        self.runtime = Path(runtime)
        self.event_log = event_log if event_log is not None else []
        self.pid = 42424
        self.exit_during_loop = exit_during_loop
        self.wait_rc = wait_rc
        self.recovery_errors = list(recovery_errors or [])
        self._poll_calls = 0
        self._terminated = False

        self.stdin = self._StdinRecorder(self)
        self.stdout = self._StdoutResponder(self, [first_line, second_line])
        self.event_log.append('guardian_spawned_ports_reserved')

    class _StdinRecorder:
        def __init__(self, owner):
            self.owner = owner
            self.buffer = bytearray()
            self.closed = False

        def write(self, data):
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.buffer.extend(data)
            if b'RX_READY' in data:
                self.owner.event_log.append('rx_ready_received_nft_installed')
            if b'TX_CLOSED' in data:
                self.owner.event_log.append('tx_closed_received')
            return len(data)

        def flush(self):
            pass

        def close(self):
            self.closed = True
            self.owner.event_log.append('guardian_stdin_closed')

    class _StdoutResponder:
        def __init__(self, owner, lines):
            self.owner = owner
            self.lines = list(lines)

        def readline(self):
            if not self.lines:
                return b''
            line = self.lines.pop(0)
            if line.strip() == 'GUARD_READY':
                self.owner.event_log.append('guardian_ready_emitted')
            return line.encode('utf-8') if isinstance(line, str) else line

    def poll(self):
        self._poll_calls += 1
        if self.exit_during_loop and self._poll_calls >= 2:
            self._terminated = True
            return 1
        return 0 if self._terminated else None

    def wait(self, timeout=None):
        self._terminated = True
        state = json.loads(self.state_path.read_text(encoding='utf-8'))
        run_token = state.get('run_token', '')
        rec = {
            'time': guardian.utc(),
            'parent': self.parent_pid,
            'run_token': run_token,
            'reason': 'relay_closed',
            'errors': list(self.recovery_errors),
            'arp_frames_sent': 5 if not self.recovery_errors else 0,
            'peer_arp_table_verified': False,
            'note': 'ARP frame transmission does not prove peer ARP cache convergence.',
        }
        guardian.atomic_json(self.runtime / 'recovery.json', rec)
        guardian.update_status_after_recovery(
            self.runtime,
            self.parent_pid,
            run_token,
            'relay_closed',
            self.recovery_errors,
            {'arp_frames_sent': 5, 'note': rec['note']},
        )
        if not self.recovery_errors:
            guardian.remove_owned_marker(
                self.runtime / 'recovery-required', self.parent_pid, run_token
            )
            guardian.remove_owned_marker(
                self.runtime / 'portal-linux-native.lock', self.parent_pid, run_token
            )
        return self.wait_rc


class TestRuntimeAndGuardian(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base = Path(self.tmp.name)
        self.runtime = self.base / 'runtime'
        self.state_dir = self.base / 'state'
        self.sysfs = self.base / 'sys_class_net'
        self.proc = self.base / 'proc'
        self.vlan_proc = self.base / 'proc_vlan'
        self.nft_bin = self.base / 'nft'
        self.nft_bin.write_text('#!/bin/sh\n', encoding='utf-8')

        # Build synthetic sysfs and procfs for eth0
        eth0 = self.sysfs / 'eth0'
        (eth0 / 'statistics').mkdir(parents=True)
        (eth0 / 'type').write_text('1\n', encoding='utf-8')
        (eth0 / 'operstate').write_text('up\n', encoding='utf-8')
        (eth0 / 'address').write_text(PI_MAC + '\n', encoding='utf-8')
        (eth0 / 'mtu').write_text('1500\n', encoding='utf-8')
        (eth0 / 'uevent').write_text('INTERFACE=eth0\nIFINDEX=2\n', encoding='utf-8')
        (eth0 / 'ifindex').write_text('2\n', encoding='utf-8')
        (eth0 / 'iflink').write_text('2\n', encoding='utf-8')
        (eth0 / 'statistics' / 'rx_dropped').write_text('10\n', encoding='utf-8')
        (eth0 / 'statistics' / 'rx_missed_errors').write_text('2\n', encoding='utf-8')

        (self.proc / 'sys' / 'net' / 'ipv4' / 'conf' / 'eth0').mkdir(parents=True)
        (self.proc / 'sys' / 'net' / 'ipv4' / 'ip_forward').write_text('0\n', encoding='utf-8')
        (self.proc / 'sys' / 'net' / 'ipv4' / 'conf' / 'eth0' / 'forwarding').write_text(
            '0\n', encoding='utf-8'
        )
        self.vlan_proc.mkdir(parents=True)

        self.config = {
            'network': {
                'interface': 'eth0',
                'ps5_ip': PS5_IP,
                'portal_ip': PORTAL_IP,
            },
            'profile': '100',
            'ps5_mac': PS5_MAC,
            'portal_mac': PORTAL_MAC,
        }
        self.commands_run = []

    def tearDown(self):
        self.tmp.cleanup()

    def make_runner(
        self,
        *,
        gro='off',
        lro='off',
        extra_ethtool='',
        route_gateway=None,
        neigh_mac=None,
        neigh_state=('REACHABLE',),
        neigh_rows=None,
        link_kind=None,
        link_type='ether',
    ):
        def runner(cmd, **kwargs):
            self.commands_run.append(list(cmd))
            # Verify no forbidden global commands are ever invoked
            joined = ' '.join(str(x) for x in cmd)
            for forbidden in ('flush', 'sysctl', 'ethtool -K', 'route add', 'route change', 'route del'):
                if forbidden in joined:
                    raise AssertionError(f'Forbidden system modification command called: {cmd}')

            if 'ethtool' in str(cmd[0]):
                out = (
                    f'Features for eth0:\n'
                    f'generic-receive-offload: {gro}\n'
                    f'large-receive-offload: {lro} [fixed]\n'
                    f'{extra_ethtool}'
                )
                return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr='')
            if cmd[:5] == ['ip', '-d', '-j', 'link', 'show']:
                iface = cmd[-1]
                row = {'ifname': iface, 'link_type': link_type}
                if link_kind:
                    row['linkinfo'] = {'info_kind': link_kind}
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([row]), stderr='')
            if cmd[:4] == ['ip', '-j', '-4', 'route']:
                peer = cmd[-1]
                row = {'dst': peer, 'dev': 'eth0', 'prefsrc': PI_IP, 'type': 'unicast'}
                if route_gateway:
                    row['gateway'] = route_gateway
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([row]), stderr='')
            if cmd[:4] == ['ip', '-j', '-4', 'neigh']:
                if neigh_rows is not None:
                    rows = list(neigh_rows)
                else:
                    rows = []
                    if neigh_mac is not None:
                        entry = {'dst': PS5_IP, 'state': list(neigh_state)}
                        if neigh_mac:
                            entry['lladdr'] = neigh_mac
                        rows.append(entry)
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(rows), stderr='')
            raise AssertionError(f'Unexpected command: {cmd}')

        return runner

    def build_verified_state(self, *, allow_test_veth=False, **runner_kwargs):
        runner = self.make_runner(**runner_kwargs)
        return linux_native.state_for(
            self.config,
            sysfs_root=self.sysfs,
            proc_root=self.proc,
            proc_vlan_root=self.vlan_proc,
            runner=runner,
            nft_bin=self.nft_bin,
            allow_test_veth=allow_test_veth,
        )

    def test_preflight_offload_topology_forwarding_and_route_checks(self):
        state = self.build_verified_state()
        self.assertEqual(state['up_ip'], PI_IP)
        self.assertEqual(state['mtu'], 1500)
        self.assertEqual(
            state['offloads']['required_disabled_keys'],
            ['generic-receive-offload', 'large-receive-offload'],
        )

        # GRO enabled -> rejected with exact offload key name
        with self.assertRaises(RuntimeError) as ctx_gro:
            self.build_verified_state(gro='on', lro='off')
        self.assertIn('generic-receive-offload', str(ctx_gro.exception))

        # LRO enabled -> rejected with exact offload key name
        with self.assertRaises(RuntimeError) as ctx_lro:
            self.build_verified_state(gro='off', lro='on')
        self.assertIn('large-receive-offload', str(ctx_lro.exception))

        # Both GRO and LRO + rx-gro-hw enabled -> reports all enabled keys
        with self.assertRaises(RuntimeError) as ctx_both:
            self.build_verified_state(gro='on', lro='on', extra_ethtool='rx-gro-hw: on\n')
        msg = str(ctx_both.exception)
        self.assertIn('generic-receive-offload', msg)
        self.assertIn('large-receive-offload', msg)
        self.assertIn('rx-gro-hw', msg)

        # Reject VLAN, bridge, bond, wireless
        for bad_iface in ('eth0.10', 'vlan10', 'br0', 'bond0', 'wlan0', 'lo'):
            bad_cfg = dict(self.config, network=dict(self.config['network'], interface=bad_iface))
            with self.assertRaises(ValueError):
                linux_native.validate_config(bad_cfg)

        # Reject sysfs bridge port or jumbo MTU > 1500
        (self.sysfs / 'eth0' / 'brport').mkdir()
        with self.assertRaises(RuntimeError):
            self.build_verified_state()
        (self.sysfs / 'eth0' / 'brport').rmdir()

        (self.sysfs / 'eth0' / 'mtu').write_text('9000\n', encoding='utf-8')
        with self.assertRaises(RuntimeError):
            self.build_verified_state()
        (self.sysfs / 'eth0' / 'mtu').write_text('1500\n', encoding='utf-8')

        # Reject IPv4 forwarding enabled
        (self.proc / 'sys' / 'net' / 'ipv4' / 'ip_forward').write_text('1\n', encoding='utf-8')
        with self.assertRaises(RuntimeError):
            self.build_verified_state()
        (self.proc / 'sys' / 'net' / 'ipv4' / 'ip_forward').write_text('0\n', encoding='utf-8')

        # Reject gateway route or neighbor MAC conflict
        with self.assertRaises(RuntimeError):
            self.build_verified_state(route_gateway='192.0.2.1')
        with self.assertRaises(RuntimeError):
            self.build_verified_state(neigh_mac='00:00:5e:00:53:99')

    def test_tx_send_length_and_short_frame_einval_single_padding_retry(self):
        counts = {'send_errors': 0, 'tx_padded_retries': 0}
        sock = FakeRawSocket()

        # 54-byte frame with single EINVAL on <60B frame -> padded to 60B once, IP total unchanged
        f54 = build_tcp_frame(
            PI_MAC, PS5_MAC, PI_IP, PS5_IP, 58001, 9295, flags=0x10, payload=b''
        )
        self.assertEqual(len(f54), 54)
        sock.fail_send_einval_once_under_60 = True
        sent_n = guardian.send_raw_frame(sock, f54, counts)
        self.assertEqual(sent_n, 60)
        self.assertEqual(counts['tx_padded_retries'], 1)
        self.assertEqual(counts['send_errors'], 0)
        padded_sent = sock.sent_frames[-1]
        self.assertEqual(len(padded_sent), 60)
        # IP total length at [16:18] is still 40 (54 - 14), payload untouched
        self.assertEqual(int.from_bytes(padded_sent[16:18], 'big'), 40)
        self.assertEqual(padded_sent[:54], f54)

        # >= 60-byte frame with EINVAL is NOT padded or retried
        f60 = build_udp_frame(PI_MAC, PS5_MAC, PI_IP, PS5_IP, 58001, 9296, b'X' * 18)
        self.assertEqual(len(f60), 60)
        sock.fail_send_einval_always = True
        with self.assertRaises(OSError):
            guardian.send_raw_frame(sock, f60, counts)
        self.assertEqual(counts['send_errors'], 1)
        sock.fail_send_einval_always = False

        # Short send return value raises RuntimeError
        sock.short_send_length = 20
        with self.assertRaises(RuntimeError):
            guardian.send_raw_frame(sock, f60, counts)
        self.assertEqual(counts['send_errors'], 2)

    def test_nft_contract_exclusive_create_and_run_token_ownership(self):
        state = self.build_verified_state()
        state['run_token'] = 'deadbeefcafe1234'
        ruleset = guardian.build_nft_ruleset(state)
        self.assertIn('create table inet portal_native_nat', ruleset)
        self.assertNotIn('add table', ruleset)
        self.assertIn('type filter hook prerouting priority -450; policy accept;', ruleset)
        self.assertIn(
            f'iifname "eth0" ip saddr {PS5_IP} ip daddr {PI_IP} '
            'meta l4proto { tcp, udp } th dport 58001-58064 '
            'counter drop comment "portal_run_token=deadbeefcafe1234"',
            ruleset,
        )

        # Verify install_nft_table order: list (must fail) -> --check -> -f -
        nft_calls = []
        def nft_runner(cmd, **kwargs):
            nft_calls.append((list(cmd), kwargs.get('input')))
            if cmd[1:3] == ['list', 'table']:
                return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='No such file or directory')
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

        guardian.install_nft_table(state, runner=nft_runner, nft_bin=self.nft_bin)
        self.assertEqual(len(nft_calls), 3)
        self.assertEqual(nft_calls[0][0][1:], ['list', 'table', 'inet', 'portal_native_nat'])
        self.assertEqual(nft_calls[1][0][1:], ['--check', '-f', '-'])
        self.assertEqual(nft_calls[1][1], ruleset)
        self.assertEqual(nft_calls[2][0][1:], ['-f', '-'])
        self.assertEqual(nft_calls[2][1], ruleset)

        # Pre-existing table (even empty) -> refused before --check or install
        def existing_table_runner(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout='table inet portal_native_nat {}\n', stderr='')

        with self.assertRaises(RuntimeError) as ctx_exists:
            guardian.install_nft_table(state, runner=existing_table_runner, nft_bin=self.nft_bin)
        self.assertIn('already exists', str(ctx_exists.exception))

        # Syntax check failure -> refused before install
        def syntax_fail_runner(cmd, **kwargs):
            if cmd[1:3] == ['list', 'table']:
                return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='does not exist')
            if '--check' in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='syntax error')
            raise AssertionError('Install should not be called when --check fails')

        with self.assertRaises(RuntimeError) as ctx_chk:
            guardian.install_nft_table(state, runner=syntax_fail_runner, nft_bin=self.nft_bin)
        self.assertIn('syntax check failed', str(ctx_chk.exception))

        # Ownership deletion: mismatched run_token refuses to delete table
        delete_calls = []
        def mismatch_runner(cmd, **kwargs):
            delete_calls.append(list(cmd))
            if cmd[1:3] == ['list', 'table']:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout='table inet portal_native_nat { comment "portal_run_token=other_token_9999" }\n',
                    stderr='',
                )
            raise AssertionError('delete table must not be called on run_token mismatch')

        errs = guardian.delete_owned_nft_table(
            'deadbeefcafe1234', runner=mismatch_runner, nft_bin=self.nft_bin
        )
        self.assertEqual(len(errs), 1)
        self.assertIn('run_token mismatch', errs[0])
        self.assertEqual(len(delete_calls), 1)

        # Matching run_token deletes table cleanly
        deleted_ok = []
        def match_runner(cmd, **kwargs):
            deleted_ok.append(list(cmd))
            if cmd[1:3] == ['list', 'table']:
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout='table inet portal_native_nat { comment "portal_run_token=deadbeefcafe1234" }\n',
                    stderr='',
                )
            return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

        errs_ok = guardian.delete_owned_nft_table(
            'deadbeefcafe1234', runner=match_runner, nft_bin=self.nft_bin
        )
        self.assertEqual(errs_ok, [])
        self.assertEqual(deleted_ok[-1][1:], ['delete', 'table', 'inet', 'portal_native_nat'])

    def test_guardian_port_reservations_and_fault_injections(self):
        # Verify reserve_ports binds 64 TCP + 64 UDP ports without SO_REUSEADDR/SO_REUSEPORT
        bound = []
        sockopts_called = []

        class MockBindSocket:
            def __init__(self, family, kind, fail_on_port=None):
                self.family = family
                self.kind = kind
                self.fail_on_port = fail_on_port
                self.closed = False

            def setsockopt(self, *args):
                sockopts_called.append(args)

            def bind(self, addr):
                if self.fail_on_port and addr[1] == self.fail_on_port:
                    raise OSError(errno.EADDRINUSE, 'Port in use')
                bound.append((self.kind, addr))

            def close(self):
                self.closed = True

        created_sockets = []
        def factory_ok(family, kind):
            s = MockBindSocket(family, kind)
            created_sockets.append(s)
            return s

        reserved = guardian.reserve_ports(PI_IP, socket_factory=factory_ok)
        self.assertEqual(len(reserved), 128)
        self.assertEqual(len(bound), 128)
        self.assertEqual(sockopts_called, [])
        guardian.close_sockets(reserved)
        self.assertTrue(all(s.closed for s in created_sockets))

        # Busy port on 58010 -> closes all previously opened sockets and raises EADDRINUSE
        partial_sockets = []
        def factory_busy(family, kind):
            s = MockBindSocket(family, kind, fail_on_port=58010)
            partial_sockets.append(s)
            return s

        with self.assertRaises(OSError):
            guardian.reserve_ports(PI_IP, socket_factory=factory_busy)
        self.assertTrue(all(s.closed for s in partial_sockets))

    def test_guardian_lifecycle_heartbeat_timeout_and_parent_death_via_pidfd(self):
        state = self.build_verified_state()
        state['run_token'] = 'token_guardian_test_01'
        state_path = self.runtime / 'restore-state.json'
        guardian.atomic_json(state_path, state)
        guardian.write_owned_marker(
            self.runtime / 'portal-linux-native.lock', 9999, state['run_token'], exclusive=True
        )
        guardian.write_owned_marker(
            self.runtime / 'recovery-required', 9999, state['run_token'], exclusive=False
        )

        # Simulate heartbeat timeout in run_guardian:
        # 1. Parent sends RX_READY
        # 2. Selector times out on second call (heartbeat timeout)
        # 3. ParentMonitor kills parent via pidfd BEFORE ARP restore and nft delete
        call_order = []

        class FakeParentMonitor:
            def __init__(self, pid):
                self.pidfd = 777
                call_order.append('pidfd_opened')

            def is_alive(self):
                return True

            def ensure_stopped(self, tx_closed_confirmed=False, timeout=3.0):
                call_order.append(f'parent_stopped_verified(tx_closed={tx_closed_confirmed})')
                return True

            def close(self):
                call_order.append('pidfd_closed')

        fake_arp_sock = FakeRawSocket()
        def arp_opener(iface, socket_factory=None):
            call_order.append('arp_socket_opened')
            return fake_arp_sock

        class FakePortSocket:
            def __init__(self, *args):
                pass
            def bind(self, addr):
                if addr[1] == 58001 and 'ports_reserved' not in call_order:
                    call_order.append('ports_reserved')
            def close(self):
                if 'ports_released' not in call_order:
                    call_order.append('ports_released')

        def nft_runner(cmd, **kwargs):
            if cmd[1:3] == ['list', 'table']:
                if 'nft_installed' not in call_order:
                    return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='does not exist')
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=f'table inet portal_native_nat {{ comment "portal_run_token={state["run_token"]}" }}\n',
                    stderr='',
                )
            if '--check' in cmd:
                call_order.append('nft_syntaxcheck')
                return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
            if cmd[1:] == ['-f', '-']:
                call_order.append('nft_installed')
                return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
            if cmd[1:3] == ['delete', 'table']:
                call_order.append('nft_deleted')
                return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
            raise AssertionError(cmd)

        stdin_buf = io.BytesIO(b'RX_READY\n')
        stdout_buf = io.StringIO()
        select_calls = [0]

        def fake_selector(rlist, wlist, xlist, timeout=None):
            select_calls[0] += 1
            if select_calls[0] == 1:
                call_order.append('rx_ready_waited')
                return [stdin_buf], [], []
            # Second call simulates heartbeat timeout
            call_order.append('heartbeat_timeout_detected')
            return [], [], []

        rc = guardian.run_guardian(
            state_path,
            9999,
            runtime=self.runtime,
            stdin_stream=stdin_buf,
            stdout_stream=stdout_buf,
            socket_factory=FakePortSocket,
            arp_socket_opener=arp_opener,
            runner=nft_runner,
            nft_bin=self.nft_bin,
            parent_monitor_factory=FakeParentMonitor,
            selector=fake_selector,
            sleeper=lambda _s: None,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(
            stdout_buf.getvalue().splitlines(), ['PORTS_RESERVED', 'GUARD_READY']
        )
        # Verify strict startup and teardown order
        self.assertEqual(
            call_order,
            [
                'pidfd_opened',
                'arp_socket_opened',
                'ports_reserved',
                'rx_ready_waited',
                'nft_syntaxcheck',
                'nft_installed',
                'heartbeat_timeout_detected',
                'parent_stopped_verified(tx_closed=False)',
                'nft_deleted',
                'ports_released',
                'pidfd_closed',
            ],
        )
        # Verify 5 ARP repair frames were sent on guardian's independent ARP socket
        self.assertEqual(len(fake_arp_sock.sent_frames), 5)
        rec = json.loads((self.runtime / 'recovery.json').read_text(encoding='utf-8'))
        self.assertEqual(rec['reason'], 'heartbeat_timeout')
        self.assertFalse(rec['peer_arp_table_verified'])
        self.assertFalse((self.runtime / 'portal-linux-native.lock').exists())

    def test_cleanup_failure_preserves_recovery_failed_and_blocks_restart(self):
        state = self.build_verified_state()
        clock = FakeClock()
        rx_sock = FakeRawSocket([], clock=clock)
        tx_sock = FakeRawSocket([], clock=clock)

        def spawner(state_path, parent_pid, runtime):
            return FakeGuardianProcess(
                state_path,
                parent_pid,
                runtime,
                wait_rc=1,
                recovery_errors=['nft table inet portal_native_nat run_token mismatch; refusing to delete unowned table'],
            )

        with self.assertRaises(RuntimeError) as ctx_err:
            linux_native.run(
                self.config,
                runtime=self.runtime,
                active=False,
                seconds=1,
                state_builder=lambda _c: state,
                rx_socket_opener=lambda _i, _f: rx_sock,
                tx_socket_opener=lambda _i: tx_sock,
                guardian_spawner=spawner,
                recovery_runner=lambda *a, **kw: ['nft table inet portal_native_nat run_token mismatch; refusing to delete unowned table'],
                clock=clock,
                sleeper=lambda _s: None,
                selector=lambda r, w, x, t=None: (r, [], []),
                sysfs_root=self.sysfs,
            )
        self.assertIn('run_token mismatch', str(ctx_err.exception))

        # Parent MUST NOT overwrite recovery_failed with stopped
        status = json.loads((self.runtime / 'status.json').read_text(encoding='utf-8'))
        self.assertEqual(status['state'], 'recovery_failed')
        self.assertEqual(status['recovery']['state'], 'recovery_failed')
        self.assertTrue((self.runtime / 'recovery-required').exists())
        self.assertTrue((self.runtime / 'portal-linux-native.lock').exists())
        # Baseline run summary must NOT be written when recovery failed
        self.assertFalse((self.runtime / 'baseline-run.json').exists())

        # Subsequent run must fail closed while recovery_failed / recovery-required is present
        with self.assertRaises(RuntimeError) as ctx_blocked:
            linux_native.run(
                self.config,
                runtime=self.runtime,
                active=False,
                seconds=1,
                state_builder=lambda _c: state,
            )
        self.assertIn('Previous relay recovery failed', str(ctx_blocked.exception))

    def test_missing_ready_and_early_guardian_death_fault_injections(self):
        state = self.build_verified_state()
        clock = FakeClock()
        rx_sock = FakeRawSocket([], clock=clock)
        tx_sock = FakeRawSocket([], clock=clock)

        # 1. Guardian fails to emit GUARD_READY -> zero ARP redirection frames sent!
        def spawner_no_ready(state_path, parent_pid, runtime):
            return FakeGuardianProcess(
                state_path,
                parent_pid,
                runtime,
                first_line='PORTS_RESERVED\n',
                second_line='NFT_ERROR\n',
                wait_rc=1,
            )

        fallback_called = []
        def fake_fallback(*args, **kwargs):
            fallback_called.append(True)
            return []

        with self.assertRaises(RuntimeError) as ctx_nr:
            linux_native.run(
                self.config,
                runtime=self.runtime,
                active=False,
                seconds=2,
                state_builder=lambda _c: state,
                rx_socket_opener=lambda _i, _f: rx_sock,
                tx_socket_opener=lambda _i: tx_sock,
                guardian_spawner=spawner_no_ready,
                recovery_runner=fake_fallback,
                clock=clock,
                sleeper=lambda _s: None,
                selector=lambda r, w, x, t=None: (r, [], []),
                sysfs_root=self.sysfs,
            )
        self.assertIn('Guardian did not become ready', str(ctx_nr.exception))
        # No ARP redirection frames were transmitted by parent
        self.assertEqual(tx_sock.sent_frames, [])
        self.assertTrue(fallback_called)

        # Clean runtime for next fault injection
        for p in self.runtime.iterdir():
            p.unlink()

        # 2. Guardian dies early during packet loop -> parent stops immediately and runs idempotent recovery
        tx_sock2 = FakeRawSocket([], clock=clock)
        def spawner_dies_early(state_path, parent_pid, runtime):
            return FakeGuardianProcess(
                state_path,
                parent_pid,
                runtime,
                exit_during_loop=True,
                wait_rc=1,
            )

        fallback_runs = []
        def fallback_recover_ok(st, rt, pid, reason, **kw):
            fallback_runs.append(reason)
            guardian.remove_owned_marker(Path(rt) / 'recovery-required', pid, st['run_token'])
            guardian.remove_owned_marker(Path(rt) / 'portal-linux-native.lock', pid, st['run_token'])
            return []

        with self.assertRaises(RuntimeError) as ctx_early:
            linux_native.run(
                self.config,
                runtime=self.runtime,
                active=False,
                seconds=10,
                state_builder=lambda _c: state,
                rx_socket_opener=lambda _i, _f: FakeRawSocket([], clock=clock),
                tx_socket_opener=lambda _i: tx_sock2,
                guardian_spawner=spawner_dies_early,
                recovery_runner=fallback_recover_ok,
                clock=clock,
                sleeper=lambda _s: None,
                selector=lambda r, w, x, t=None: (r, [], []),
                sysfs_root=self.sysfs,
            )
        self.assertIn('Guardian exited unexpectedly', str(ctx_early.exception))
        self.assertEqual(fallback_runs, ['parent_fallback_recovery'])

    def test_baseline_zero_mutation_active_gate_and_driver_packet_pipeline(self):
        state = self.build_verified_state()
        clock = FakeClock()

        # Construct realistic traffic for the driver pipeline:
        # 1. Outbound TCP SYN (Portal -> PS5)
        tcp_syn = build_tcp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50100, 9295, seq=500, flags=0x02
        )
        # 2. Inbound TCP SYN-ACK (PS5 -> Pi:58001)
        tcp_synack = build_tcp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9295, 58001, seq=900, ack=501, flags=0x12
        )
        # 3. Outbound UDP 9296 INIT (Portal -> PS5)
        udp_init = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50200, 9296, b'INIT_PACKET_PAYLOAD_1234'
        )
        # 4. Outbound UDP 9296 BIG (Portal -> PS5) on same flow (50200 -> 9296)
        big_payload = bytearray(64)
        big_payload[1:5] = b'SESS'
        big_payload[17:21] = b'SEQ1'
        udp_big = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50200, 9296, bytes(big_payload)
        )
        # 5. Oversize coalesced frame (> 1514 bytes) -> must be dropped and counted
        oversize_frame = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50200, 9296, b'Z' * 1600
        )
        self.assertGreater(len(oversize_frame), 1514)
        # 6. Inbound PS5 telemetry packets on UDP 9296 -> Pi:58001
        pkt_bang = build_udp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9296, 58001, build_ps5_telemetry_payload('BANG')
        )
        pkt_stream = build_udp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9296, 58001, build_ps5_telemetry_payload('STREAMINFO')
        )
        pkt_qual1 = build_udp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9296, 58001, build_ps5_telemetry_payload('CONNECTIONQUALITY')
        )
        pkt_qual2 = build_udp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9296, 58001, build_ps5_telemetry_payload('CONNECTIONQUALITY')
        )
        pkt_qual3 = build_udp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9296, 58001, build_ps5_telemetry_payload('CONNECTIONQUALITY')
        )

        baseline_frames = [
            tcp_syn,
            tcp_synack,
            udp_init,
            udp_big,
            oversize_frame,
            pkt_bang,
            pkt_stream,
            pkt_qual1,
            pkt_qual2,
            pkt_qual3,
        ]
        rx_baseline = FakeRawSocket(baseline_frames, clock=clock, drop_count=3)
        tx_baseline = FakeRawSocket([], clock=clock)
        event_log = []

        def open_rx(iface, filt):
            event_log.append('rx_opened')
            return rx_baseline

        def open_tx(iface):
            event_log.append('tx_opened')
            return tx_baseline

        def spawner(state_path, parent_pid, runtime):
            return FakeGuardianProcess(state_path, parent_pid, runtime, event_log=event_log)

        # Verify ZERO calls to probe.mutate during baseline run
        with mock.patch.object(probe, 'mutate', wraps=probe.mutate) as spy_mutate:
            status_base = linux_native.run(
                self.config,
                runtime=self.runtime,
                active=False,
                seconds=2,
                state_builder=lambda _c: state,
                rx_socket_opener=open_rx,
                tx_socket_opener=open_tx,
                guardian_spawner=spawner,
                clock=clock,
                sleeper=lambda _s: None,
                selector=lambda r, w, x, t=None: (r, [], []),
                sysfs_root=self.sysfs,
            )
            self.assertEqual(spy_mutate.call_count, 0)

        # Verify exact startup and shutdown sequence in event_log
        self.assertEqual(
            event_log[:5],
            [
                'guardian_spawned_ports_reserved',
                'rx_opened',
                'tx_opened',
                'rx_ready_received_nft_installed',
                'guardian_ready_emitted',
            ],
        )
        self.assertEqual(status_base['mode'], 'baseline')
        self.assertEqual(status_base['state'], 'stopped')
        self.assertEqual(status_base['counts']['forwarded_out'], 3)  # tcp_syn, udp_init, udp_big
        self.assertEqual(status_base['counts']['forwarded_in'], 6)   # tcp_synack + 5 udp telemetry
        self.assertEqual(status_base['counts']['dropped_oversize'], 1)
        self.assertEqual(status_base['counts'].get('modified_packets_including_retransmits', 0), 0)
        self.assertEqual(status_base['capture_loss']['socket_drops'], 3)

        # Transport counters & PS5 messages NEVER self-accept baseline!
        self.assertTrue((self.runtime / 'baseline-run.json').exists())
        self.assertFalse((self.runtime / 'baseline-accepted.json').exists())
        with self.assertRaises(RuntimeError) as ctx_no_receipt:
            linux_native.run(
                self.config,
                runtime=self.runtime,
                active=True,
                seconds=2,
                state_builder=lambda _c: state,
            )
        self.assertIn('missing baseline-accepted.json', str(ctx_no_receipt.exception))

        # accept_baseline requires explicit non-empty human assertion
        with self.assertRaises(ValueError):
            linux_native.accept_baseline(self.config, self.runtime, '', state=state)

        receipt = linux_native.accept_baseline(
            self.config,
            self.runtime,
            'Coordinator verified Portal baseline picture and controls on eth0.',
            state=state,
        )
        self.assertTrue(receipt['restored'])
        self.assertTrue((self.runtime / 'baseline-accepted.json').exists())

        # Any mismatch in peer IP, peer MAC, interface, or code hash rejects active mode
        mismatched_state = dict(state, up_ip='192.0.2.99')
        with self.assertRaises(RuntimeError) as ctx_mismatch:
            linux_native.run(
                self.config,
                runtime=self.runtime,
                active=True,
                seconds=2,
                state_builder=lambda _c: mismatched_state,
            )
        self.assertIn('does not match', str(ctx_mismatch.exception))

        # Now run active mode with matching receipt and verify INIT->BIG port stability + mutation
        rx_active = FakeRawSocket(
            [udp_init, udp_big, pkt_bang, pkt_stream, pkt_qual1, pkt_qual2, pkt_qual3],
            clock=clock,
        )
        tx_active = FakeRawSocket([], clock=clock)

        def fake_mutate(payload):
            if payload.startswith(b'\x00SESS'):
                mutated = bytearray(payload)
                mutated[-1] ^= 0x04
                return bytes(mutated), True
            return payload, False

        with mock.patch.object(probe, 'mutate', side_effect=fake_mutate) as mock_active_mutate:
            status_active = linux_native.run(
                self.config,
                runtime=self.runtime,
                active=True,
                seconds=2,
                state_builder=lambda _c: state,
                rx_socket_opener=lambda _i, _f: rx_active,
                tx_socket_opener=lambda _i: tx_active,
                guardian_spawner=lambda sp, pp, rt: FakeGuardianProcess(sp, pp, rt),
                clock=clock,
                sleeper=lambda _s: None,
                selector=lambda r, w, x, t=None: (r, [], []),
                sysfs_root=self.sysfs,
            )
            self.assertEqual(mock_active_mutate.call_count, 2)

        self.assertEqual(status_active['mode'], 'active')
        self.assertEqual(status_active['counts']['modified_packets_including_retransmits'], 1)
        self.assertEqual(status_active['counts']['unique_modified_startups'], 1)
        self.assertTrue(status_active['ps5_telemetry']['ps5_high_target_confirmed'])
        self.assertEqual(status_active['ps5_telemetry']['last_target_bps'], 85000000)

        # Filter non-ARP IPv4 packets transmitted by tx_active and verify INIT and BIG kept port 58001
        ipv4_sent = [f for f in tx_active.sent_frames if f[12:14] == b'\x08\x00']
        self.assertEqual(len(ipv4_sent), 7)
        for frame in ipv4_sent:
            verify_frame_checksums(self, frame)
        out_init_info = parse(ipv4_sent[0])
        out_big_info = parse(ipv4_sent[1])
        self.assertEqual(out_init_info['sport'], 58001)
        self.assertEqual(out_big_info['sport'], 58001)

    def test_parent_monitor_pid_reuse_and_stalled_parent_fail_closed(self):
        # PID reuse before pidfd verification raises RuntimeError and closes pidfd
        closed_fds = []
        class DummyFd:
            def close(self):
                closed_fds.append(True)

        with self.assertRaises(RuntimeError) as ctx_reuse:
            guardian.ParentMonitor(
                12345,
                pidfd_opener=lambda _pid, _flags: DummyFd(),
                ppid_getter=lambda: 99999,
            )
        self.assertIn('exited before pidfd verification', str(ctx_reuse.exception))
        self.assertEqual(len(closed_fds), 1)

        # When parent cannot be stopped, idempotent_recover fails closed without sending ARP or deleting nft
        state = self.build_verified_state()
        state['run_token'] = 'aabbccddeeff0011'
        guardian.write_owned_marker(
            self.runtime / 'portal-linux-native.lock', 5555, state['run_token'], exclusive=True
        )
        guardian.write_owned_marker(
            self.runtime / 'recovery-required', 5555, state['run_token'], exclusive=False
        )
        arp_sock = FakeRawSocket()
        nft_called = []
        errs = guardian.idempotent_recover(
            state,
            self.runtime,
            5555,
            'heartbeat_timeout',
            arp_socket=arp_sock,
            runner=lambda cmd, **kw: nft_called.append(cmd),
            tx_stopped_verified=False,
        )
        self.assertEqual(len(errs), 1)
        self.assertIn('Could not verify that relay stopped transmitting', errs[0])
        self.assertEqual(arp_sock.sent_frames, [])
        self.assertEqual(nft_called, [])
        self.assertTrue((self.runtime / 'portal-linux-native.lock').exists())
        self.assertTrue((self.runtime / 'recovery-required').exists())

        # Unrelated lock (different PID or different run_token) is never deleted
        self.assertFalse(
            guardian.remove_owned_marker(
                self.runtime / 'portal-linux-native.lock', 7777, state['run_token']
            )
        )
        self.assertFalse(
            guardian.remove_owned_marker(
                self.runtime / 'portal-linux-native.lock', 5555, 'wrong_token_0000'
            )
        )
        self.assertTrue((self.runtime / 'portal-linux-native.lock').exists())

    @staticmethod
    def build_launchspec_payload(total_udp_payload_len=None):
        """Build a LaunchSpec UDP payload accepted by real `portal_active_probe.mutate`."""
        raw_plain = bytearray(b'A' * 1722)
        # Put realistic ASCII digits at OFFSET=334 ("25000")
        raw_plain[334:339] = b'25000'
        b64_field = base64.b64encode(bytes(raw_plain))
        assert len(b64_field) == 2296
        pb_inner = pb_varint(1, 20) + pb_bytes(3, b64_field)
        prefix_hdr = bytearray(29)
        prefix_hdr[0] = 0
        prefix_hdr[1:5] = b'SESS'
        prefix_hdr[5:9] = b'\x00' * 4
        prefix_hdr[13] = 0
        prefix_hdr[14] = 1
        prefix_hdr[17:21] = b'SEQ9'
        prefix_hdr[21:26] = b'\x00' * 5
        prefix_hdr[26:29] = b'\x08\x00\x12'
        full_body = bytes(prefix_hdr) + encode_varint(len(pb_inner)) + pb_inner
        if total_udp_payload_len is not None:
            full_body = full_body[:total_udp_payload_len]
        total_len_field = len(full_body) - 13
        return full_body[:15] + total_len_field.to_bytes(2, 'big') + full_body[17:]

    def test_validate_seconds_stop_marker_and_real_launchspec_mutate_checksum(self):
        # Default is 120s; non-positive or non-finite values are rejected
        self.assertEqual(linux_native.validate_seconds(None), 120)
        self.assertEqual(linux_native.validate_seconds(180), 180)
        self.assertEqual(linux_native.validate_seconds(300), 300)
        self.assertIsNone(
            linux_native.validate_seconds(None, active=True, continuous=True)
        )
        with self.assertRaises(ValueError):
            linux_native.validate_seconds(None, active=False, continuous=True)
        with self.assertRaises(ValueError):
            linux_native.validate_seconds(120, active=True, continuous=True)
        for invalid in (0, -5, float('inf'), float('-inf'), float('nan'), True, '120'):
            with self.assertRaises(ValueError):
                linux_native.validate_seconds(invalid)

        # 1. Production MTU 1500 fragmented LaunchSpec fixture (2332B UDP payload -> 2 IPv4 fragments <= 1500B)
        full_payload = self.build_launchspec_payload()
        self.assertEqual(len(full_payload), 2332)
        probe.OFFSET = 334
        probe.PATCH_DELTA = linux_native.PROFILES['100']
        expected_mutated_full, was_changed = probe.mutate(full_payload)
        self.assertTrue(was_changed)
        self.assertNotEqual(expected_mutated_full, full_payload)

        state = self.build_verified_state()
        self.assertEqual(state['mtu'], 1500)

        udp_len = 8 + len(full_payload)
        pseudo_orig = (
            socket.inet_aton(PORTAL_IP)
            + socket.inet_aton(PS5_IP)
            + struct.pack('!BBH', 0, 17, udp_len)
        )
        udp_wo_csum = struct.pack('!HHHH', 50999, 9296, udp_len, 0) + full_payload
        orig_csum = ones_complement_sum(pseudo_orig + udp_wo_csum) or 0xFFFF
        full_udp_segment = struct.pack('!HHHH', 50999, 9296, udp_len, orig_csum) + full_payload

        # Fragment at standard Ethernet MTU 1500: frag0 has 1480B IP payload (1500B IP total, 1514B frame),
        # frag1 has remaining 860B IP payload (880B IP total, 894B frame).
        frag0, frag1 = fragment_ip_payload(
            PORTAL_MAC,
            PI_MAC,
            PORTAL_IP,
            PS5_IP,
            17,
            full_udp_segment,
            [1480, len(full_udp_segment) - 1480],
            ip_id=0x5150,
        )
        self.assertEqual(len(frag0), 1514)
        self.assertEqual(parse(frag0)['total'], 1500)
        self.assertEqual(len(frag1), 894)
        self.assertEqual(parse(frag1)['total'], 880)

        init_frame = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50999, 9296, b'INIT_BEFORE_LAUNCHSPEC'
        )

        # Baseline (active=False) on MTU 1500: zero mutation, fragments forwarded on same NAT port 58001
        flows_base = linux_native.Flows()
        counts_base = linux_native.collections.Counter()
        with mock.patch.object(probe, 'mutate', wraps=probe.mutate) as spy_base:
            r_init_b = linux_native.process_packet(init_frame, state, flows_base, 10.0, False, counts_base)
            r_f0_b = linux_native.process_packet(frag0, state, flows_base, 10.1, False, counts_base)
            r_f1_b = linux_native.process_packet(frag1, state, flows_base, 10.2, False, counts_base)
            self.assertEqual(spy_base.call_count, 0)

        self.assertIsNotNone(r_init_b)
        self.assertIsNotNone(r_f0_b)
        self.assertIsNotNone(r_f1_b)
        self.assertFalse(r_f0_b[2])
        self.assertFalse(r_f1_b[2])
        for rw_pkt in (r_init_b[0], r_f0_b[0], r_f1_b[0]):
            verify_frame_checksums(self, rw_pkt)
        self.assertEqual(parse(r_init_b[0])['sport'], 58001)
        self.assertEqual(parse(r_f0_b[0])['sport'], 58001)

        # Active (active=True) on MTU 1500: real probe.mutate mutates frag0, frag1 follows on same flow/port 58001,
        # and reassembled UDP datagram matches expected_mutated_full with valid UDP checksum!
        flows_act = linux_native.Flows()
        counts_act = linux_native.collections.Counter()
        seen_act = linux_native.collections.OrderedDict()
        confirm_act = probe.TargetConfirmation()
        r_init_a = linux_native.process_packet(
            init_frame, state, flows_act, 20.0, True, counts_act, seen=seen_act, confirmation=confirm_act
        )
        r_f0_a = linux_native.process_packet(
            frag0, state, flows_act, 20.1, True, counts_act, seen=seen_act, confirmation=confirm_act
        )
        r_f1_a = linux_native.process_packet(
            frag1, state, flows_act, 20.2, True, counts_act, seen=seen_act, confirmation=confirm_act
        )
        self.assertIsNotNone(r_init_a)
        self.assertIsNotNone(r_f0_a)
        self.assertIsNotNone(r_f1_a)
        self.assertFalse(r_init_a[2])
        self.assertTrue(r_f0_a[2])
        self.assertFalse(r_f1_a[2])
        self.assertEqual(counts_act['unique_modified_startups'], 1)
        self.assertEqual(counts_act['modified_packets_including_retransmits'], 1)
        self.assertTrue(confirm_act.armed)

        for rw_pkt in (r_init_a[0], r_f0_a[0], r_f1_a[0]):
            verify_frame_checksums(self, rw_pkt)
        self.assertEqual(parse(r_init_a[0])['sport'], 58001)
        self.assertEqual(parse(r_f0_a[0])['sport'], 58001)

        reassembled_udp = bytearray()
        for rw_pkt in (r_f0_a[0], r_f1_a[0]):
            info_rw = parse(rw_pkt)
            ip_rw = rw_pkt[14 : 14 + info_rw['total']]
            reassembled_udp.extend(ip_rw[info_rw['ihl'] :])
        self.assertEqual(len(reassembled_udp), len(full_udp_segment))
        self.assertEqual(bytes(reassembled_udp[8:]), expected_mutated_full)
        nat_pseudo = (
            socket.inet_aton(PI_IP)
            + socket.inet_aton(PS5_IP)
            + struct.pack('!BBH', 0, 17, len(reassembled_udp))
        )
        self.assertEqual(ones_complement_sum(nat_pseudo + reassembled_udp), 0)

        # 2. Single-frame MTU<=1500 LaunchSpec datagram fixture (1400B UDP payload, 1442B frame <= 1514B)
        compact_payload = self.build_launchspec_payload(total_udp_payload_len=1400)
        compact_frame = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50999, 9296, compact_payload
        )
        self.assertLessEqual(len(compact_frame), 1514)
        self.assertLessEqual(parse(compact_frame)['total'], 1500)
        r_compact = linux_native.process_packet(
            compact_frame, state, flows_act, 21.0, True, counts_act
        )
        self.assertIsNotNone(r_compact)
        pkt_compact, _, changed_compact, _ = r_compact
        self.assertTrue(changed_compact)
        verify_frame_checksums(self, pkt_compact)
        self.assertEqual(parse(pkt_compact)['sport'], 58001)

    def test_p1_guardian_retains_port_reservations_until_pidfd_confirms_parent_death(self):
        state = self.build_verified_state()
        state['run_token'] = 'token_p1_hold_reservations'
        state_path = self.runtime / 'restore-state.json'
        guardian.atomic_json(state_path, state)
        guardian.write_owned_marker(
            self.runtime / 'portal-linux-native.lock', 8888, state['run_token'], exclusive=True
        )
        guardian.write_owned_marker(
            self.runtime / 'recovery-required', 8888, state['run_token'], exclusive=False
        )

        events = []
        reserved_sockets = []
        arp_sock = FakeRawSocket()

        class TrackedPortSocket:
            def __init__(self, family, kind):
                self.family = family
                self.kind = kind
                self.addr = None
                self.closed = False
                reserved_sockets.append(self)

            def bind(self, addr):
                self.addr = addr

            def close(self):
                if not self.closed:
                    self.closed = True
                    if sum(1 for s in reserved_sockets if s.closed) == len(reserved_sockets):
                        events.append('all_128_reserved_ports_closed')

        class DelayedStopParentMonitor:
            def __init__(self, pid):
                self.pid = pid
                self.pidfd = 555
                self.alive = True
                self.stop_calls = 0
                events.append('pidfd_opened')

            def is_alive(self):
                return self.alive

            def ensure_stopped(self, tx_closed_confirmed=False, timeout=3.0):
                self.stop_calls += 1
                if self.stop_calls == 1:
                    events.append('ensure_stopped_failed_parent_still_alive')
                    raise RuntimeError(f'Parent relay PID {self.pid} did not terminate within {timeout}s')
                events.append('ensure_stopped_succeeded')
                return True

            def close(self):
                events.append('pidfd_closed')

        def arp_opener(iface, socket_factory=None):
            events.append('arp_socket_opened')
            return arp_sock

        def nft_runner(cmd, **kwargs):
            if cmd[1:3] == ['list', 'table']:
                if 'nft_installed' not in events:
                    return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='does not exist')
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=f'table inet portal_native_nat {{ comment "portal_run_token={state["run_token"]}" }}\n',
                    stderr='',
                )
            if '--check' in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
            if cmd[1:] == ['-f', '-']:
                events.append('nft_installed')
                return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
            if cmd[1:3] == ['delete', 'table']:
                events.append('nft_deleted')
                return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
            raise AssertionError(cmd)

        stdin_buf = io.BytesIO(b'RX_READY\n')
        stdout_buf = io.StringIO()
        select_step = [0]
        mid_failure_snapshot = {}

        def fake_selector(rlist, wlist, xlist, timeout=None):
            select_step[0] += 1
            if select_step[0] == 1:
                return [stdin_buf], [], []
            if select_step[0] == 2:
                # Trigger heartbeat timeout while parent is still alive
                return [], [], []
            if select_step[0] == 3:
                # At this point ensure_stopped() has failed once!
                # Verify all 129 sockets (1 arp_socket + 128 reserved) are STILL OPEN,
                # recovery_failed and ownership markers are on disk, and ARP/nft cleanup has NOT run yet!
                mid_failure_snapshot['open_reserved_count'] = sum(
                    1 for s in reserved_sockets if not s.closed
                )
                mid_failure_snapshot['arp_socket_closed'] = arp_sock.closed
                mid_failure_snapshot['arp_frames_sent_before_death'] = len(arp_sock.sent_frames)
                mid_failure_snapshot['nft_deleted_before_death'] = ('nft_deleted' in events)
                mid_failure_snapshot['status'] = json.loads(
                    (self.runtime / 'status.json').read_text(encoding='utf-8')
                )
                mid_failure_snapshot['lock_exists'] = (
                    self.runtime / 'portal-linux-native.lock'
                ).exists()
                mid_failure_snapshot['recovery_marker_exists'] = (
                    self.runtime / 'recovery-required'
                ).exists()
                events.append('pidfd_death_notification_delivered')
                return [555], [], []
            raise AssertionError(f'Unexpected selector call {select_step[0]}')

        rc = guardian.run_guardian(
            state_path,
            8888,
            runtime=self.runtime,
            stdin_stream=stdin_buf,
            stdout_stream=stdout_buf,
            socket_factory=TrackedPortSocket,
            arp_socket_opener=arp_opener,
            runner=nft_runner,
            nft_bin=self.nft_bin,
            parent_monitor_factory=DelayedStopParentMonitor,
            selector=fake_selector,
            sleeper=lambda _s: None,
        )
        self.assertEqual(rc, 1)

        # Verify snapshot taken AFTER failed ensure_stopped and BEFORE pidfd death notification:
        self.assertEqual(mid_failure_snapshot['open_reserved_count'], 128)
        self.assertFalse(mid_failure_snapshot['arp_socket_closed'])
        self.assertEqual(mid_failure_snapshot['arp_frames_sent_before_death'], 0)
        self.assertFalse(mid_failure_snapshot['nft_deleted_before_death'])
        self.assertEqual(mid_failure_snapshot['status']['state'], 'recovery_failed')
        self.assertTrue(mid_failure_snapshot['lock_exists'])
        self.assertTrue(mid_failure_snapshot['recovery_marker_exists'])

        # Verify ordered cleanup AFTER pidfd death notification:
        self.assertEqual(len(arp_sock.sent_frames), 5)
        self.assertTrue(arp_sock.closed)
        self.assertTrue(all(s.closed for s in reserved_sockets))
        self.assertEqual(
            events,
            [
                'pidfd_opened',
                'arp_socket_opened',
                'nft_installed',
                'ensure_stopped_failed_parent_still_alive',
                'pidfd_death_notification_delivered',
                'nft_deleted',
                'all_128_reserved_ports_closed',
                'pidfd_closed',
            ],
        )
        # recovery_failed and ownership markers MUST remain preserved
        final_status = json.loads((self.runtime / 'status.json').read_text(encoding='utf-8'))
        self.assertEqual(final_status['state'], 'recovery_failed')
        self.assertEqual(final_status['recovery']['arp_frames_sent'], 5)
        self.assertTrue((self.runtime / 'portal-linux-native.lock').exists())
        self.assertTrue((self.runtime / 'recovery-required').exists())

    def test_p2_kernel_capture_filter_attached_tx_non_receiving_and_fragment_filtering(self):
        state = self.build_verified_state()
        filt = capture_filters(state)['eth0']

        # 1. Verify LinuxRawSocket attaches SO_ATTACH_FILTER before bind() and LinuxTxSocket binds protocol 0
        ops = []

        class RecordingKernelSocket:
            def __init__(self, family, kind, proto):
                ops.append(('socket', family, kind, proto))
                self.closed = False

            def setsockopt(self, level, optname, value):
                ops.append(('setsockopt', level, optname, value))

            def bind(self, addr):
                ops.append(('bind', addr))

            def setblocking(self, flag):
                ops.append(('setblocking', flag))

            def close(self):
                self.closed = True

        rx_sock = linux_native.LinuxRawSocket(
            'eth0', capture_filter=filt, socket_factory=RecordingKernelSocket
        )
        attach_idx = next(
            i
            for i, item in enumerate(ops)
            if item[0] == 'setsockopt' and item[2] == linux_native.SO_ATTACH_FILTER
        )
        bind_idx = next(i for i, item in enumerate(ops) if item[0] == 'bind')
        self.assertLess(attach_idx, bind_idx)
        rx_sock.close()

        # Missing capture_filter on RX socket must fail closed
        with self.assertRaises(ValueError):
            linux_native.LinuxRawSocket('eth0', capture_filter=None, socket_factory=RecordingKernelSocket)

        ops.clear()
        tx_sock = linux_native.LinuxTxSocket('eth0', socket_factory=RecordingKernelSocket)
        self.assertEqual(ops[0], ('socket', linux_native.AF_PACKET, socket.SOCK_RAW, 0))
        self.assertIn(('bind', ('eth0', 0)), ops)
        self.assertEqual(linux_native.evaluate_bpf(tx_sock.bpf_instructions, b'\x00' * 60), 0)
        tx_sock.close()

        ops.clear()
        arp_s = guardian.open_arp_socket('eth0', socket_factory=RecordingKernelSocket)
        self.assertEqual(ops[0], ('socket', guardian.AF_PACKET, socket.SOCK_RAW, 0))
        self.assertIn(('bind', ('eth0', 0)), ops)
        arp_s.close()

        # 2. Verify compiled BPF filter rejects unrelated traffic and preserves bidirectional first + subsequent fragments
        insns = linux_native.compile_capture_bpf(filt)

        # Unrelated frames (must all be rejected by kernel BPF filter -> return 0):
        arp_broadcast = b'\xff\xff\xff\xff\xff\xff' + bytes.fromhex(PORTAL_MAC.replace(':', '')) + b'\x08\x06' + b'\x00' * 28
        ipv6_frame = bytes.fromhex(PI_MAC.replace(':', '')) + bytes.fromhex(PORTAL_MAC.replace(':', '')) + b'\x86\xdd' + b'\x00' * 40
        unrelated_ssh = build_tcp_frame(
            '00:00:5e:00:53:99', PI_MAC, '192.0.2.99', PI_IP, 54321, 22, flags=0x02
        )
        own_tx_frame = build_udp_frame(
            PI_MAC, PS5_MAC, PI_IP, PS5_IP, 58001, 9296, b'own_tx'
        )
        portal_to_pi_direct = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PI_IP, 53000, 53, b'dns'
        )
        for un_frame in (arp_broadcast, ipv6_frame, unrelated_ssh, own_tx_frame, portal_to_pi_direct):
            self.assertEqual(linux_native.evaluate_bpf(insns, un_frame), 0)

        # Bidirectional fragmented UDP packets (first AND subsequent fragments must be accepted by BPF filter!):
        out_payload = b'O' * 400
        out_udp = struct.pack('!HHHH', 54320, 9296, 8 + len(out_payload), 0) + out_payload
        out_frags = fragment_ip_payload(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 17, out_udp, [200, len(out_udp) - 200], ip_id=0x6001
        )
        in_payload = b'I' * 400
        in_udp = struct.pack('!HHHH', 9296, 58001, 8 + len(in_payload), 0) + in_payload
        in_frags = fragment_ip_payload(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 17, in_udp, [200, len(in_udp) - 200], ip_id=0x6002
        )

        flows = linux_native.Flows()
        counts = linux_native.collections.Counter()
        for frag in out_frags + in_frags:
            self.assertEqual(linux_native.evaluate_bpf(insns, frag), linux_native.MAX_RAW_RECV)
            res = linux_native.process_packet(frag, state, flows, 100.0, False, counts)
            self.assertIsNotNone(res)
            verify_frame_checksums(self, res[0], expect_zero_udp_csum=True)

    def test_p2_production_veth_rejection_even_when_named_eth0_and_test_flag(self):
        # 1. `ip -d -j link show dev eth0` reports info_kind="veth" -> rejected without --allow-test-veth
        with self.assertRaises(RuntimeError) as ctx_veth:
            self.build_verified_state(link_kind='veth', allow_test_veth=False)
        self.assertIn('veth', str(ctx_veth.exception))

        # Accepted only when allow_test_veth=True (--allow-test-veth)
        st_veth = self.build_verified_state(link_kind='veth', allow_test_veth=True)
        self.assertEqual(st_veth['config']['interface'], 'eth0')

        # 2. sysfs ifindex != iflink (or DEVTYPE=veth) on eth0 -> rejected without --allow-test-veth
        (self.sysfs / 'eth0' / 'iflink').write_text('99\n', encoding='utf-8')
        with self.assertRaises(RuntimeError) as ctx_iflink:
            self.build_verified_state(allow_test_veth=False)
        self.assertIn('veth', str(ctx_iflink.exception))
        st_iflink_ok = self.build_verified_state(allow_test_veth=True)
        self.assertEqual(st_iflink_ok['config']['interface'], 'eth0')
        (self.sysfs / 'eth0' / 'iflink').write_text('2\n', encoding='utf-8')

        # 3. Non-veth virtual link kinds (e.g. macvlan, bridge) are rejected even with allow_test_veth=True
        for bad_kind in ('macvlan', 'bridge', 'vlan'):
            with self.assertRaises(RuntimeError):
                self.build_verified_state(link_kind=bad_kind, allow_test_veth=True)

    def test_p2_asleep_peer_stale_or_failed_neighbor_accepted_and_live_conflict_rejected(self):
        wrong_mac = '00:00:5e:00:53:99'

        # Empty neighbor table (peers asleep) -> accepted
        st_empty = self.build_verified_state(neigh_rows=[])
        self.assertEqual(st_empty['ps5_mac'], PS5_MAC)

        # FAILED entry without lladdr or with stale wrong lladdr -> accepted
        st_failed_no_mac = self.build_verified_state(
            neigh_rows=[{'dst': PS5_IP, 'state': ['FAILED']}]
        )
        self.assertEqual(st_failed_no_mac['ps5_mac'], PS5_MAC)

        st_failed_old_mac = self.build_verified_state(
            neigh_rows=[{'dst': PS5_IP, 'lladdr': wrong_mac, 'state': ['FAILED']}]
        )
        self.assertEqual(st_failed_old_mac['ps5_mac'], PS5_MAC)

        # STALE or INCOMPLETE entry with old wrong lladdr -> accepted
        for non_live in ('STALE', 'INCOMPLETE', 'DELAY', 'PROBE'):
            st_non_live = self.build_verified_state(
                neigh_rows=[
                    {'dst': PS5_IP, 'lladdr': wrong_mac, 'state': [non_live]},
                    {'dst': PORTAL_IP, 'lladdr': wrong_mac, 'state': [non_live]},
                ]
            )
            self.assertEqual(st_non_live['portal_mac'], PORTAL_MAC)

        # Live REACHABLE or PERMANENT entry with conflicting MAC -> rejected!
        for live_state in ('REACHABLE', 'PERMANENT'):
            with self.assertRaises(RuntimeError) as ctx_conflict:
                self.build_verified_state(
                    neigh_rows=[{'dst': PS5_IP, 'lladdr': wrong_mac, 'state': [live_state]}]
                )
            self.assertIn('conflicting live neighbor MAC', str(ctx_conflict.exception))

    def test_p2_netns_harness_delayed_startup_early_relay_death_and_cleanup_failure(self):
        harness = Path(ROOT_DIR) / 'tests' / 'linux_netns_e2e.sh'
        mock_bin = self.base / 'mock_bin'
        mock_bin.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env['PATH'] = f'{mock_bin}:{env.get("PATH", "")}'
        env['PYTHON_BIN'] = sys.executable

        # 1. Delayed startup: server ready file, relay state=running, and Portal ARP appear after delay
        ip_log = self.base / 'ip_calls.log'
        neigh_counter = self.base / 'neigh_count'
        neigh_counter.write_text('0\n', encoding='utf-8')
        mock_ip = mock_bin / 'ip'
        mock_ip.write_text(
            f"""#!/usr/bin/env bash
echo "$@" >> "{ip_log}"
if [[ "$*" == *"neigh show"* ]]; then
    c=$(cat "{neigh_counter}")
    c=$((c + 1))
    echo "$c" > "{neigh_counter}"
    if [[ $c -lt 3 ]]; then
        echo '[{{"dst":"{PS5_IP}","lladdr":"{PS5_MAC}","state":["REACHABLE"]}}]'
    else
        echo '[{{"dst":"{PS5_IP}","lladdr":"{PI_MAC}","state":["REACHABLE"]}}]'
    fi
    exit 0
fi
if [[ "$1" == "netns" && "$2" == "exec" ]]; then
    shift 3
    exec "$@"
fi
exit 0
""",
            encoding='utf-8',
        )
        mock_ip.chmod(0o755)

        delayed_script = f"""
set -euo pipefail
LINUX_NETNS_LIB_ONLY=1 source "{harness}"
ready_file="{self.base}/srv_ready"
status_file="{self.runtime}/status.json"
mkdir -p "{self.runtime}"
echo '{{"state": "starting"}}' > "$status_file"

(
    sleep 0.1
    echo "ready" > "$ready_file"
    sleep 0.1
    echo '{{"state": "running"}}' > "$status_file"
    for _ in {{1..100}}; do
        if [[ -f "{self.runtime}/disabled" ]]; then
            exit 0
        fi
        sleep 0.03
    done
    exit 1
) >/dev/null 2>&1 &
bg_pid=$!

wait_for_server_ready "$ready_file" "$bg_pid" 40 0.02
wait_for_relay_running "$status_file" "$bg_pid" 40 0.02
wait_for_portal_arp "ns_portal_test" "{PS5_IP}" "{PI_MAC}" "$bg_pid" 40 0.02
stop_relay_controlled "ns_pi_test" "{self.runtime}" "$bg_pid" 40 0.02
"""
        proc_delayed = subprocess.run(
            ['/bin/bash', '-c', delayed_script],
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(proc_delayed.returncode, 0, proc_delayed.stderr)

        # 2. Early relay death: relay exits before reaching state=running -> non-zero exit
        early_death_script = f"""
set -euo pipefail
LINUX_NETNS_LIB_ONLY=1 source "{harness}"
status_file="{self.runtime}/status_dead.json"
echo '{{"state": "starting"}}' > "$status_file"
(exit 1) &
dead_pid=$!
wait "$dead_pid" || true
wait_for_relay_running "$status_file" "$dead_pid" 10 0.01
"""
        proc_dead = subprocess.run(
            ['/bin/bash', '-c', early_death_script],
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        self.assertNotEqual(proc_dead.returncode, 0)
        self.assertIn('exited before reaching running state', proc_dead.stderr)

        # 3. Cleanup failure: `ip netns del` failing for a created netns must exit non-zero
        del_attempts = self.base / 'del_attempts.log'
        mock_ip.write_text(
            f"""#!/usr/bin/env bash
if [[ "$1" == "netns" && "$2" == "del" ]]; then
    echo "$3" >> "{del_attempts}"
    if [[ "$3" == "ns_fail_del" ]]; then
        exit 1
    fi
    exit 0
fi
exit 0
""",
            encoding='utf-8',
        )
        mock_ip.chmod(0o755)

        cleanup_fail_script = f"""
set -euo pipefail
LINUX_NETNS_LIB_ONLY=1 source "{harness}"
CREATED_NETNS=("ns_ok_del" "ns_fail_del")
TMP_DIR="{self.base}/cleanup_tmp"
mkdir -p "$TMP_DIR"
trap cleanup EXIT
exit 0
"""
        proc_cleanup_fail = subprocess.run(
            ['/bin/bash', '-c', cleanup_fail_script],
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        self.assertNotEqual(proc_cleanup_fail.returncode, 0)
        self.assertIn('Failed to delete isolated netns ns_fail_del', proc_cleanup_fail.stderr)
        self.assertEqual(
            del_attempts.read_text(encoding='utf-8').splitlines(),
            ['ns_ok_del', 'ns_fail_del'],
        )

    def test_parent_monitor_missing_pidfd_is_unknown(self):
        monitor = guardian.ParentMonitor(
            12345, pidfd_opener=lambda *_: object(),
            ppid_getter=lambda: 12345, selector=lambda *_: ([], [], []),
        )
        monitor.pidfd = None
        with self.assertRaisesRegex(RuntimeError, 'unknown'):
            monitor.is_alive()
        with self.assertRaisesRegex(RuntimeError, 'unknown'):
            monitor.ensure_stopped()
        self.assertTrue(monitor.ensure_stopped(tx_closed_confirmed=True))

    def test_guardian_faults_hold_live_socket_descriptors_and_cleanup_in_order(self):
        # Anonymous local socketpairs exercise real descriptor lifetime without
        # opening an IP listener or touching the LAN. nft and parent I/O are fake.
        for fault in ('selector', 'no_pidfd', 'no_pidfd_eof', 'is_alive', 'atomic_recovery',
                      'atomic_status', 'idempotent_recover', 'combined', 'late_tx'):
            with self.subTest(fault=fault), contextlib.ExitStack() as stack:
                runtime = self.base / fault
                state = self.build_verified_state()
                state['run_token'] = 'token_retention_faults'
                state_path = runtime / 'restore-state.json'
                guardian.atomic_json(state_path, state)
                for name in ('portal-linux-native.lock', 'recovery-required'):
                    guardian.write_owned_marker(runtime / name, 8888, state['run_token'])
                events, sockets, delays, error_counts = [], [], [], []
                verified = False
                stdin = io.BytesIO(b'RX_READY\n' if fault == 'no_pidfd_eof'
                                   else b'RX_READY\nTX_CLOSED\n')
                select_calls = 0

                class LiveSocket:
                    def __init__(self, *args):
                        self.sock, self.peer = socket.socketpair()
                        stack.callback(self.sock.close)
                        stack.callback(self.peer.close)
                        self.peer.setblocking(False)
                        self.is_arp = not sockets
                        sockets.append(self)

                    def bind(self, addr):
                        pass

                    def send(self, frame):
                        self_check.assertTrue(verified)
                        events.append('arp')
                        return len(frame)

                    def close(self):
                        events.append('arp_closed' if self.is_arp else 'port_closed')
                        self.sock.close()

                self_check = self

                class Monitor:
                    pidfd = None if fault in ('no_pidfd', 'no_pidfd_eof', 'combined', 'late_tx') else 555

                    def __init__(self, pid):
                        pass

                    def is_alive(self):
                        if fault in ('is_alive', 'combined'):
                            raise OSError(f'is_alive failure {len(delays)}')
                        if self.pidfd is None:
                            raise RuntimeError('Parent state unknown: pidfd unavailable')
                        return True

                    def ensure_stopped(self, **kwargs):
                        raise OSError(f'stop verification failure {len(delays)}')

                    def close(self):
                        events.append('monitor_closed')

                def assert_held():
                    self.assertEqual(len(sockets), 129)
                    for sock in sockets:
                        self.assertGreaterEqual(sock.sock.fileno(), 0)
                        os.fstat(sock.sock.fileno())
                        # An implicitly closed socket yields EOF, not EAGAIN.
                        with self.assertRaises(BlockingIOError):
                            sock.peer.recv(1)
                    self.assertNotIn('arp', events)
                    self.assertNotIn('nft_deleted', events)
                    for name in ('portal-linux-native.lock', 'recovery-required'):
                        self.assertTrue((runtime / name).exists())

                def selector(read, *_):
                    nonlocal select_calls, verified
                    select_calls += 1
                    if select_calls == 1:
                        return [stdin], [], []
                    if select_calls == 2:
                        return [], [], []
                    assert_held()
                    if fault == 'no_pidfd_eof' and select_calls == 3:
                        return [stdin], [], []
                    if len(delays) == 12:
                        verified = True
                        events.append('tx_closed' if fault == 'late_tx' else 'death_verified')
                        return ([stdin] if fault == 'late_tx' else [555]), [], []
                    if fault in ('selector', 'combined'):
                        raise OSError(f'select failure {len(delays)}')
                    return [], [], []

                def sleeper(delay):
                    if verified:
                        return  # ARP pacing after verification
                    assert_held()
                    delays.append(delay)
                    self.assertLessEqual(len(delays), 12, 'retention failed to observe death')
                    if len(delays) == 12 and fault != 'late_tx':
                        Monitor.pidfd = 555

                def runner(cmd, **kwargs):
                    output = ''
                    rc = 0
                    if cmd[1:3] == ['list', 'table']:
                        if 'nft_installed' not in events:
                            rc = 1
                        else:
                            output = f'portal_run_token={state["run_token"]}'
                    elif cmd[1:] == ['-f', '-']:
                        events.append('nft_installed')
                    elif cmd[1:3] == ['delete', 'table']:
                        self.assertTrue(verified)
                        self.assertEqual(events.count('arp'), 5)
                        events.append('nft_deleted')
                    return subprocess.CompletedProcess(cmd, rc, output, '')

                real_atomic = guardian.atomic_json
                real_recover = guardian.idempotent_recover

                def atomic(path, data, *args, **kwargs):
                    if not verified and (
                        (fault in ('atomic_recovery', 'combined') and Path(path).name == 'recovery.json')
                        or (fault == 'atomic_status' and Path(path).name == 'status.json')
                    ):
                        assert_held()
                        raise OSError(f'write failure {len(delays)}')
                    return real_atomic(path, data, *args, **kwargs)

                def recover(*args, **kwargs):
                    error_counts.append(len(kwargs.get('extra_errors', [])))
                    if not verified and fault == 'idempotent_recover':
                        assert_held()
                        raise OSError(f'recovery failure {len(delays)}')
                    return real_recover(*args, **kwargs)

                stack.enter_context(mock.patch.object(guardian, 'atomic_json', side_effect=atomic))
                stack.enter_context(mock.patch.object(guardian, 'idempotent_recover', side_effect=recover))
                # run_guardian normally changes signal disposition in its own process.
                stack.enter_context(mock.patch.object(guardian.signal, 'signal'))
                rc = guardian.run_guardian(
                    state_path, 8888, runtime=runtime, stdin_stream=stdin,
                    stdout_stream=io.StringIO(), socket_factory=LiveSocket,
                    arp_socket_opener=lambda *a, **kw: LiveSocket(),
                    parent_monitor_factory=Monitor, selector=selector,
                    runner=runner, sleeper=sleeper,
                )
                self.assertEqual(rc, 1)  # recovery_failed evidence stays sticky
                self.assertTrue(verified)
                self.assertEqual(delays, [0.1, 0.2, 0.4, 0.8, 1.6, 3.2] + [5.0] * 6)
                self.assertLessEqual(max(error_counts), 3)
                self.assertEqual(events.count('arp'), 5)
                self.assertEqual(events.count('port_closed'), 128)
                self.assertLess(events.index('nft_deleted'), events.index('port_closed'))
                for sock in sockets:
                    self.assertEqual(sock.sock.fileno(), -1)
                    self.assertEqual(sock.peer.recv(1), b'')

    def test_unfragmented_mutation_checksum_excludes_trailing_ip_bytes(self):
        state = self.build_verified_state()
        payload = self.build_launchspec_payload(1200)
        with mock.patch.object(probe, 'OFFSET', 334), mock.patch.object(
            probe, 'PATCH_DELTA', linux_native.PROFILES['100']
        ):
            expected, changed = probe.mutate(payload)
            self.assertTrue(changed)
            for tail in (b'', b'\x91', b'\x91\x82\x73\x64'):
                with self.subTest(tail=tail):
                    frame = build_udp_frame(
                        PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50999, 9296, payload,
                    )
                    udp = frame[34:]
                    frame = frame[:14] + build_ipv4_header(
                        PORTAL_IP, PS5_IP, 17, len(udp) + len(tail),
                    ) + udp + tail
                    pseudo = socket.inet_aton(PORTAL_IP) + socket.inet_aton(PS5_IP)
                    pseudo += struct.pack('!BBH', 0, 17, len(udp))
                    self.assertEqual(ones_complement_sum(pseudo + udp), 0)
                    result = linux_native.process_packet(
                        frame, state, linux_native.Flows(), 1.0, True,
                        linux_native.collections.Counter(),
                    )
                    self.assertIsNotNone(result)
                    mutated = result[0]
                    self.assertTrue(result[2])
                    self.assertEqual(mutated[42:42 + len(payload)], expected)
                    self.assertEqual(mutated[34 + len(udp):], tail)
                    self.assertEqual(len(mutated), len(frame))
                    self.assertEqual(int.from_bytes(mutated[38:40], 'big'), len(udp))
                    pseudo = mutated[26:34] + struct.pack('!BBH', 0, 17, len(udp))
                    self.assertEqual(ones_complement_sum(pseudo + mutated[34:34 + len(udp)]), 0)
                    self.assertEqual(ones_complement_sum(mutated[14:34]), 0)

    def test_netns_cleanup_discovery_kill_wait_and_owned_names(self):
        harness = Path(ROOT_DIR) / 'tests' / 'linux_netns_e2e.sh'
        # All namespace and signal commands are shell functions; no real kill or
        # namespace operation runs. Successful disappearance uses a nonexistent PID.
        for case, expected_rc in (('discover', 1), ('kill', 1), ('wait', 1),
                                  ('rediscover', 1), ('disappeared', 0), ('empty', 0)):
            with self.subTest(case=case):
                count = self.base / f'{case}_count'
                log = self.base / f'{case}_log'
                count.write_text('0\n')
                script = r'''
LINUX_NETNS_LIB_ONLY=1 source "$1"
CREATED_NETNS=(owned_namespace)
TMP_DIR=''
ip() {
    echo "$*" >> "$CALL_LOG"
    [[ "$*" == "netns pids owned_namespace" || "$*" == "netns del owned_namespace" ]] || return 99
    if [[ "$2" == del ]]; then return 0; fi
    local n
    n=$(cat "$COUNT_FILE")
    n=$((n + 1))
    echo "$n" > "$COUNT_FILE"
    [[ "$CASE" == discover ]] && return 1
    [[ "$CASE" == rediscover && "$n" -gt 1 ]] && return 1
    [[ "$CASE" == empty ]] && return 0
    [[ "$CASE" == disappeared && "$n" -gt 1 ]] && return 0
    echo 2147483647
}
kill() {
    echo "kill $*" >> "$CALL_LOG"
    [[ "$CASE" == wait ]]
}
sleep() { echo 'sleep' >> "$CALL_LOG"; }
cleanup_created_resources 3 0.01
'''
                env = dict(os.environ, CASE=case, COUNT_FILE=str(count), CALL_LOG=str(log),
                           PYTHON_BIN=sys.executable)
                proc = subprocess.run(
                    ['/bin/bash', '-c', script, 'cleanup-test', str(harness)],
                    env=env, text=True, capture_output=True, timeout=5,
                )
                self.assertEqual(proc.returncode, expected_rc, proc.stderr)
                calls = log.read_text().splitlines()
                self.assertEqual('netns del owned_namespace' in calls, expected_rc == 0)
                self.assertLessEqual(calls.count('sleep'), 2)
                self.assertLessEqual(int(count.read_text()), 4)

    def test_continuous_active_and_persistent_acceptance_across_simulated_reboot(self):
        # Verify production default paths
        self.assertEqual(linux_native.DEFAULT_RUNTIME, Path('/run/portal-linux-native'))
        self.assertEqual(linux_native.DEFAULT_STATE_DIR, Path('/var/lib/portal-linux-native'))
        self.assertEqual(
            linux_native.resolve_state_dir(linux_native.DEFAULT_RUNTIME),
            Path('/var/lib/portal-linux-native'),
        )

        state = self.build_verified_state()
        clock = FakeClock()

        # Baseline cannot use continuous=True
        with self.assertRaises(ValueError):
            linux_native.run(
                self.config,
                runtime=self.runtime,
                state_dir=self.state_dir,
                active=False,
                continuous=True,
                state_builder=lambda _c: state,
            )

        # 1. Run finite baseline with separate volatile `runtime` and persistent `state_dir`
        status_base = linux_native.run(
            self.config,
            runtime=self.runtime,
            state_dir=self.state_dir,
            active=False,
            seconds=1,
            state_builder=lambda _c: state,
            rx_socket_opener=lambda _i, _f: FakeRawSocket([], clock=clock),
            tx_socket_opener=lambda _i: FakeRawSocket([], clock=clock),
            guardian_spawner=lambda sp, pp, rt: FakeGuardianProcess(sp, pp, rt),
            clock=clock,
            sleeper=lambda _s: None,
            selector=lambda r, w, x, t=None: (r, [], []),
            sysfs_root=self.sysfs,
        )
        self.assertEqual(status_base['state'], 'stopped')

        # 2. Record human physical acceptance into persistent `state_dir`
        receipt = linux_native.accept_baseline(
            self.config,
            self.runtime,
            'Physical baseline verified on Pi4 eth0 before reboot test.',
            state=state,
            state_dir=self.state_dir,
        )
        self.assertTrue(receipt['restored'])
        receipt_path = self.state_dir / 'baseline-accepted.json'
        self.assertTrue(receipt_path.exists())
        self.assertFalse((self.runtime / 'baseline-accepted.json').exists())

        # Verify strict permissions (0700 dirs, 0600 receipt)
        self.assertEqual(stat.S_IMODE(self.runtime.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.state_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)

        # 3. Simulate Pi reboot: wipe volatile `self.runtime` completely!
        shutil.rmtree(self.runtime)
        self.assertFalse(self.runtime.exists())
        self.assertTrue(receipt_path.exists())

        # 4. Run continuous active mode (`continuous=True, seconds=None`) after simulated reboot;
        # stop cleanly via `request_stop(self.runtime)` once running status is written.
        rx_cont = FakeRawSocket([], clock=clock)
        tx_cont = FakeRawSocket([], clock=clock)
        select_ticks = [0]

        def stop_after_running(sockets, remain=0.02):
            select_ticks[0] += 1
            clock.advance(0.5)
            if select_ticks[0] >= 3:
                linux_native.request_stop(self.runtime)
            return []

        rx_cont.select = stop_after_running

        status_cont = linux_native.run(
            self.config,
            runtime=self.runtime,
            state_dir=self.state_dir,
            active=True,
            seconds=None,
            continuous=True,
            state_builder=lambda _c: state,
            rx_socket_opener=lambda _i, _f: rx_cont,
            tx_socket_opener=lambda _i: tx_cont,
            guardian_spawner=lambda sp, pp, rt: FakeGuardianProcess(sp, pp, rt),
            clock=clock,
            sleeper=lambda _s: None,
            selector=lambda r, w, x, t=None: (r, [], []),
            sysfs_root=self.sysfs,
        )
        self.assertEqual(status_cont['mode'], 'active')
        self.assertIsNone(status_cont['seconds_limit'])
        self.assertEqual(status_cont['state'], 'stopped')

        summary = linux_native.read_status_summary(self.runtime, state_dir=self.state_dir)
        self.assertEqual(summary['state_dir'], str(self.state_dir))
        self.assertIsNotNone(summary['baseline_accepted'])
        self.assertFalse(summary['lock_present'])


if __name__ == '__main__':
    unittest.main()
