#!/usr/bin/env python3
"""Linux same-interface Ethernet header NAT relay for PlayStation Portal and PS5.

Architecture:
- Single Ethernet interface (default `eth0`), same-interface raw RX/TX (`AF_PACKET`).
- Strict MAC/IP/interface filtering (`packet_direction`), rejecting own TX,
  unrelated traffic, malformed packets, and >MTU / GRO-LRO coalesced frames.
- Preflight verifies IPv4 forwarding is disabled, direct LAN routing for both
  peers, distinct IPs/MACs, standard Ethernet MTU (<=1500), and GRO/LRO offloads
  disabled without modifying any system or interface settings.
- Guardian process holds TCP/UDP port reservations (58001-58064), installs the
  scoped `inet portal_native_nat` pre-defrag (-450) drop rule in a single
  `create table` transaction after `nft --check`, tracks parent via `pidfd`,
  and repairs Portal ARP + removes the owned nft table on shutdown or crash.
- Default mode is finite-duration `baseline` (default 120s) with zero mutation
  calls. `active` mode requires explicit selection (finite `--seconds` or
  `--continuous`) and a human-asserted `baseline-accepted.json` receipt stored
  in persistent `/var/lib/portal-linux-native` (separate from volatile locks in
  `/run/portal-linux-native`) and bound to code hash, interface, and peer IPs/MACs.
"""
import argparse
import collections
import ctypes
import errno
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

import scapy.config

scapy.config.conf.load_layers = ['l2', 'inet']

import portal_active_probe as probe
from guardian import (
    AF_PACKET,
    ETH_P_ALL,
    NFT_BIN,
    atomic_json,
    close_sockets,
    ensure_private_dir,
    idempotent_recover,
    portal_arp_frame,
    read_json_safe,
    remove_owned_marker,
    run_guardian,
    send_raw_frame,
    utc,
    write_owned_marker,
)
from nat import (
    PORTS,
    Flows,
    capture_filters,
    packet_direction,
    parse,
    replace_checksum,
    rewrite,
)

ROOT = Path(__file__).resolve().parent
DEFAULT_RUNTIME = Path('/run/portal-linux-native')
LEGACY_VAR_RUN_RUNTIME = Path('/var/run/portal-linux-native')
DEFAULT_STATE_DIR = Path('/var/lib/portal-linux-native')
DEFAULT_CONFIG = ROOT / 'auto-config.json'
DEFAULT_BASELINE_SECONDS = 120
CAPTURE_BUFFER = 262144
MAX_RAW_RECV = 65535
SOL_PACKET = getattr(socket, 'SOL_PACKET', 263)
SO_ATTACH_FILTER = getattr(socket, 'SO_ATTACH_FILTER', 26)
PACKET_STATISTICS = 6
PACKET_IGNORE_OUTGOING = 23
PACKET_OUTGOING = 4
LIVE_NEIGHBOR_STATES = frozenset({'REACHABLE', 'PERMANENT'})

PROFILES = {
    '65': b'\x04',
    '100': bytes.fromhex('03501b0005'),
    '150': bytes.fromhex('0300550004'),
    '200': bytes.fromhex('00501b0005'),
}
CONFIRM_TARGETS = {
    '65': 50000000,
    '100': 80000000,
    '150': 90000000,
    '200': 120000000,
}
REQUIRED_DISABLED_OFFLOADS = (
    'generic-receive-offload',
    'large-receive-offload',
)
ADDITIONAL_FORBIDDEN_GRO_KEYS = (
    'rx-gro-hw',
    'rx-gro-list',
)
OFFLOAD_SHORT_ALIASES = {
    'gro': 'generic-receive-offload',
    'lro': 'large-receive-offload',
}
CODE_PROVENANCE_FILES = (
    'linux_native.py',
    'nat.py',
    'guardian.py',
    'header_nat.py',
    'portal_active_probe.py',
    'protocol.py',
)


def normal_mac(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value.strip()):
        raise ValueError(f'Invalid Ethernet MAC address: {value!r}')
    mac = value.strip().lower()
    if int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00':
        raise ValueError(f'Expected unicast Ethernet MAC address: {value!r}')
    return mac


def validate_unicast_ipv4(value):
    addr = ipaddress.IPv4Address(value)
    if (
        addr.is_multicast
        or addr.is_loopback
        or addr.is_unspecified
        or addr.is_reserved
        or int(addr) == 0xFFFFFFFF
    ):
        raise ValueError(f'Expected unicast IPv4 address: {value!r}')
    return str(addr)


def validate_interface_name(iface, allow_test_veth=False):
    if not isinstance(iface, str) or not iface.strip():
        raise ValueError('Interface name is required')
    iface = iface.strip()
    if '.' in iface or iface.startswith(('vlan', 'br', 'bond', 'wl', 'wlan', 'lo', 'tun', 'tap', 'docker')):
        raise ValueError(f'Unsupported interface type (no VLAN/bridge/bond/Wi-Fi): {iface!r}')
    if re.fullmatch(r'eth[0-9]+', iface):
        return iface
    if allow_test_veth and re.fullmatch(r'veth[a-zA-Z0-9_-]{1,11}', iface):
        return iface
    raise ValueError(
        f'Expected single physical Ethernet interface such as eth0 (got {iface!r})'
    )


def validate_config(config, allow_test_veth=False):
    if not isinstance(config, dict):
        raise ValueError('Configuration must be a JSON object')
    allowed_keys = {'network', 'profile', 'ps5_mac', 'portal_mac', 'two_way'}
    if not {'network', 'profile', 'ps5_mac', 'portal_mac'} <= set(config) or not set(config) <= allowed_keys:
        raise ValueError('Config requires network, profile, ps5_mac, and portal_mac')
    if config.get('two_way', False) not in (False, None):
        raise ValueError('Single-interface NAT mode does not use two_way')
    net_cfg = config['network']
    if not isinstance(net_cfg, dict) or set(net_cfg) != {'interface', 'ps5_ip', 'portal_ip'}:
        raise ValueError('Config network requires interface, ps5_ip, and portal_ip')
    iface = validate_interface_name(net_cfg['interface'], allow_test_veth=allow_test_veth)
    ps5_ip = validate_unicast_ipv4(net_cfg['ps5_ip'])
    portal_ip = validate_unicast_ipv4(net_cfg['portal_ip'])
    if ps5_ip == portal_ip:
        raise ValueError('PS5 and Portal IPv4 addresses must differ')
    profile = str(config['profile'])
    if profile not in PROFILES:
        raise ValueError(f'Unsupported profile: {profile!r}')
    ps5_mac = normal_mac(config['ps5_mac'])
    portal_mac = normal_mac(config['portal_mac'])
    if ps5_mac == portal_mac:
        raise ValueError('PS5 and Portal MAC addresses must differ')
    return {
        'network': {
            'interface': iface,
            'ps5_ip': ps5_ip,
            'portal_ip': portal_ip,
        },
        'profile': profile,
        'ps5_mac': ps5_mac,
        'portal_mac': portal_mac,
    }


def load_config(path=DEFAULT_CONFIG, allow_test_veth=False):
    raw = json.loads(Path(path).read_text(encoding='utf-8'))
    return validate_config(raw, allow_test_veth=allow_test_veth)


def validate_seconds(seconds, *, active=False, continuous=False):
    if continuous:
        if not active:
            raise ValueError(
                'Continuous mode (--continuous) is only allowed in active mode; baseline must be finite'
            )
        if seconds is not None:
            raise ValueError('Duration --seconds cannot be combined with --continuous')
        return None
    if seconds is None:
        return DEFAULT_BASELINE_SECONDS
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        raise ValueError('Duration --seconds must be a positive finite number')
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError('Duration --seconds must be finite and > 0')
    return float(seconds) if isinstance(seconds, float) and not seconds.is_integer() else int(seconds)


def parse_ethtool_offloads(text):
    """Parse `ethtool -k <iface>` output into normalized feature states."""
    features = {}
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line or ':' not in line or line.lower().startswith('features for '):
            continue
        key, value = line.split(':', 1)
        key = key.strip().lower()
        key = OFFLOAD_SHORT_ALIASES.get(key, key)
        state_token = value.strip().split()[0].lower() if value.strip() else ''
        if state_token in ('on', 'off'):
            features[key] = state_token
    return features


def check_offloads(iface, runner=subprocess.run, ethtool_bin=None):
    """Check GRO/LRO receive offloads without modifying interface settings."""
    candidates = [ethtool_bin] if ethtool_bin else ['/usr/sbin/ethtool', '/sbin/ethtool', 'ethtool']
    last_exc = None
    proc = None
    for binary in candidates:
        if not binary:
            continue
        try:
            proc = runner([str(binary), '-k', iface], text=True, capture_output=True, check=False, timeout=3)
            break
        except FileNotFoundError as exc:
            last_exc = exc
    if proc is None:
        raise RuntimeError(f'ethtool is required to verify {iface} offloads') from last_exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or '').strip()
        raise RuntimeError(f'Failed to query offloads on {iface}: {detail}')
    features = parse_ethtool_offloads(proc.stdout)
    enabled = []
    missing = []
    for key in REQUIRED_DISABLED_OFFLOADS:
        val = features.get(key)
        if val is None:
            missing.append(key)
        elif val != 'off':
            enabled.append(key)
    for extra in ADDITIONAL_FORBIDDEN_GRO_KEYS:
        if features.get(extra) == 'on':
            enabled.append(extra)
    if missing:
        raise RuntimeError(
            f'Could not verify required offload keys on {iface}: {", ".join(missing)}'
        )
    if enabled:
        raise RuntimeError(
            f'Unsupported receive offloads enabled on {iface}; '
            f'required disabled offload keys: {", ".join(enabled)}'
        )
    return {
        'features': features,
        'required_disabled_keys': list(REQUIRED_DISABLED_OFFLOADS),
        'enabled_unsupported_keys': enabled,
    }


def check_interface_sysfs(
    iface,
    sysfs_root=Path('/sys/class/net'),
    proc_vlan_root=Path('/proc/net/vlan'),
    allow_test_veth=False,
):
    """Verify single Ethernet interface topology, link kind, and MTU via sysfs."""
    iface_dir = Path(sysfs_root) / iface
    if not iface_dir.exists():
        raise RuntimeError(f'Network interface {iface} does not exist')
    if (Path(proc_vlan_root) / iface).exists():
        raise RuntimeError(f'VLAN interfaces are not supported: {iface}')
    uevent = ''
    if (iface_dir / 'uevent').exists():
        uevent = (iface_dir / 'uevent').read_text(encoding='utf-8', errors='replace').lower()
    for forbidden in ('devtype=vlan', 'devtype=bridge', 'devtype=bond', 'devtype=wlan'):
        if forbidden in uevent:
            raise RuntimeError(f'Unsupported interface DEVTYPE on {iface}: {forbidden}')
    is_veth_sysfs = (
        'devtype=veth' in uevent
        or 'driver=veth' in uevent
        or (iface_dir / 'veth').exists()
        or iface.startswith('veth')
    )
    if not is_veth_sysfs and (iface_dir / 'ifindex').exists() and (iface_dir / 'iflink').exists():
        try:
            ifindex = int((iface_dir / 'ifindex').read_text(encoding='utf-8').strip())
            iflink = int((iface_dir / 'iflink').read_text(encoding='utf-8').strip())
            if ifindex != iflink:
                is_veth_sysfs = True
        except (OSError, ValueError):
            pass
    if is_veth_sysfs and not allow_test_veth:
        raise RuntimeError(
            f'Virtual veth interface {iface} is rejected in production (require physical Ethernet or explicit --allow-test-veth)'
        )
    for subdir, label in (
        ('bridge', 'bridge'),
        ('brport', 'bridge port'),
        ('bonding', 'bond master'),
        ('bonding_slave', 'bond slave'),
        ('master', 'enslaved interface'),
        ('wireless', 'wireless interface'),
        ('phy80211', 'wireless interface'),
    ):
        if (iface_dir / subdir).exists():
            raise RuntimeError(f'Unsupported {label} on {iface}; single physical Ethernet required')
    if (iface_dir / 'type').exists():
        arp_type = (iface_dir / 'type').read_text(encoding='utf-8').strip()
        if arp_type != '1':
            raise RuntimeError(f'Interface {iface} is not Ethernet ARPHRD_ETHER (type={arp_type})')
    if (iface_dir / 'operstate').exists():
        operstate = (iface_dir / 'operstate').read_text(encoding='utf-8').strip().lower()
        if operstate == 'down':
            raise RuntimeError(f'Interface {iface} link is down')
    own_mac = normal_mac((iface_dir / 'address').read_text(encoding='utf-8').strip())
    mtu = int((iface_dir / 'mtu').read_text(encoding='utf-8').strip())
    if mtu < 68 or mtu > 1500:
        raise RuntimeError(f'Unsupported MTU {mtu} on {iface}; expected 68..1500')
    return {'own_mac': own_mac, 'mtu': mtu}


def check_interface_link_type(iface, runner=subprocess.run, allow_test_veth=False):
    """Query `ip -d -j link show dev <iface>` to detect virtual link kinds (such as veth named eth0)."""
    try:
        proc = runner(
            ['ip', '-d', '-j', 'link', 'show', 'dev', iface],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f'ip binary is required to verify link type for {iface}') from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or '').strip()
        raise RuntimeError(f'Link type lookup failed for {iface}: {detail}')
    rows = json.loads(proc.stdout or '[]')
    if len(rows) != 1:
        raise RuntimeError(f'Expected single link entry for {iface}')
    row = rows[0]
    link_type = str(row.get('link_type') or 'ether').lower()
    if link_type != 'ether':
        raise RuntimeError(f'Interface {iface} link_type is {link_type!r}; expected ether')
    info_kind = str((row.get('linkinfo') or {}).get('info_kind') or '').strip().lower()
    if info_kind == 'veth':
        if not allow_test_veth:
            raise RuntimeError(
                f'Virtual veth interface {iface} is rejected in production (require physical Ethernet or explicit --allow-test-veth)'
            )
    elif info_kind:
        raise RuntimeError(
            f'Unsupported virtual interface link kind {info_kind!r} on {iface}; single physical Ethernet required'
        )
    return info_kind or 'physical'


def read_interface_drop_counters(iface, sysfs_root=Path('/sys/class/net')):
    stats_dir = Path(sysfs_root) / iface / 'statistics'
    result = {'rx_dropped': 0, 'rx_missed_errors': 0}
    for key in tuple(result):
        path = stats_dir / key
        try:
            result[key] = int(path.read_text(encoding='utf-8').strip())
        except (OSError, ValueError):
            result[key] = 0
    return result


def check_routes_and_forwarding(iface, ps5_ip, portal_ip, proc_root=Path('/proc'), runner=subprocess.run):
    """Verify IPv4 forwarding is disabled and both peers route directly on iface."""
    proc_root = Path(proc_root)
    for rel in ('sys/net/ipv4/ip_forward', f'sys/net/ipv4/conf/{iface}/forwarding'):
        fpath = proc_root / rel
        if not fpath.exists():
            raise RuntimeError(f'Missing sysctl file: {fpath}')
        if fpath.read_text(encoding='utf-8').strip() != '0':
            raise RuntimeError(f'IPv4 forwarding is enabled in {fpath}; refusing to start')
    own_ips = set()
    for peer_ip in (ps5_ip, portal_ip):
        proc = runner(
            ['ip', '-j', '-4', 'route', 'get', peer_ip],
            text=True,
            capture_output=True,
            check=False,
            timeout=3,
        )
        if proc.returncode != 0:
            raise RuntimeError(f'Route lookup failed for {peer_ip}: {(proc.stderr or proc.stdout).strip()}')
        rows = json.loads(proc.stdout or '[]')
        if (
            len(rows) != 1
            or rows[0].get('dev') != iface
            or rows[0].get('gateway')
            or rows[0].get('type', 'unicast') != 'unicast'
        ):
            raise RuntimeError(f'Peer {peer_ip} does not route directly through {iface}')
        prefsrc = validate_unicast_ipv4(rows[0].get('prefsrc', ''))
        if prefsrc in (ps5_ip, portal_ip):
            raise RuntimeError(f'Local interface IP {prefsrc} conflicts with peer IP')
        own_ips.add(prefsrc)
    if len(own_ips) != 1:
        raise RuntimeError('Peers do not share a single local source IPv4 address')
    return own_ips.pop()


def _parse_neighbor_states(raw_state):
    if isinstance(raw_state, str):
        return {raw_state.strip().upper()} if raw_state.strip() else set()
    if isinstance(raw_state, (list, tuple, set)):
        return {str(item).strip().upper() for item in raw_state if str(item).strip()}
    return set()


def check_neighbor_conflicts(iface, ps5_ip, ps5_mac, portal_ip, portal_mac, runner=subprocess.run):
    """Reject setup only if kernel neighbor table reports a conflicting live MAC for a peer."""
    try:
        proc = runner(
            ['ip', '-j', '-4', 'neigh', 'show', 'dev', iface],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except FileNotFoundError:
        return
    if proc.returncode != 0 or not (proc.stdout or '').strip():
        return
    try:
        rows = json.loads(proc.stdout)
    except ValueError:
        return
    expected = {ps5_ip: ps5_mac, portal_ip: portal_mac}
    for row in rows:
        dst = row.get('dst')
        lladdr = row.get('lladdr')
        states = _parse_neighbor_states(row.get('state'))
        # Stale, FAILED, INCOMPLETE, or unverified entries for asleep peers must not block enrollment.
        if not (states & LIVE_NEIGHBOR_STATES):
            continue
        if dst in expected and lladdr:
            actual = normal_mac(lladdr)
            if actual != expected[dst]:
                raise RuntimeError(
                    f'Enrolled peer {dst} has conflicting live neighbor MAC {actual} '
                    f'(expected {expected[dst]}, state={sorted(states)})'
                )


def state_for(
    config,
    sysfs_root=Path('/sys/class/net'),
    proc_root=Path('/proc'),
    proc_vlan_root=Path('/proc/net/vlan'),
    runner=subprocess.run,
    nft_bin=NFT_BIN,
    allow_test_veth=False,
):
    """Run read-only Linux preflight and build verified relay state."""
    c = validate_config(config, allow_test_veth=allow_test_veth)
    iface = c['network']['interface']
    ps5_ip = c['network']['ps5_ip']
    portal_ip = c['network']['portal_ip']

    if not Path(nft_bin).exists():
        raise RuntimeError(f'Required nft binary not found at {nft_bin}')

    sysfs_info = check_interface_sysfs(
        iface,
        sysfs_root=sysfs_root,
        proc_vlan_root=proc_vlan_root,
        allow_test_veth=allow_test_veth,
    )
    check_interface_link_type(iface, runner=runner, allow_test_veth=allow_test_veth)
    own_mac = sysfs_info['own_mac']
    mtu = sysfs_info['mtu']
    if len({own_mac, c['ps5_mac'], c['portal_mac']}) != 3:
        raise RuntimeError('Pi, PS5, and Portal MAC addresses must be distinct')

    offload_info = check_offloads(iface, runner=runner)
    own_ip = check_routes_and_forwarding(
        iface, ps5_ip, portal_ip, proc_root=proc_root, runner=runner
    )
    if len({own_ip, ps5_ip, portal_ip}) != 3:
        raise RuntimeError('Pi, PS5, and Portal IPv4 addresses must be distinct')

    check_neighbor_conflicts(
        iface, ps5_ip, c['ps5_mac'], portal_ip, c['portal_mac'], runner=runner
    )

    return {
        'config': dict(c['network']),
        'profile': c['profile'],
        'own_mac': own_mac,
        'own_ip': own_ip,
        'up_interface': iface,
        'up_mac': own_mac,
        'up_ip': own_ip,
        'ps5_mac': c['ps5_mac'],
        'portal_mac': c['portal_mac'],
        'mtu': mtu,
        'offloads': {
            'required_disabled_keys': offload_info['required_disabled_keys'],
            'generic-receive-offload': offload_info['features'].get('generic-receive-offload'),
            'large-receive-offload': offload_info['features'].get('large-receive-offload'),
        },
        'two_way': False,
    }


def code_sha256(root=ROOT):
    digest = hashlib.sha256()
    root = Path(root)
    for name in CODE_PROVENANCE_FILES:
        digest.update(name.encode('utf-8') + b'\0')
        digest.update((root / name).read_bytes())
    return digest.hexdigest()


def peer_binding(state):
    return {
        'interface': state['config']['interface'],
        'pi_ip': state.get('up_ip', state.get('own_ip')),
        'pi_mac': state['own_mac'],
        'ps5_ip': state['config']['ps5_ip'],
        'ps5_mac': state['ps5_mac'],
        'portal_ip': state['config']['portal_ip'],
        'portal_mac': state['portal_mac'],
    }


def receipt_fingerprint(state, root=ROOT):
    payload = {
        'code_sha256': code_sha256(root),
        'binding': peer_binding(state),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode('utf-8')).hexdigest()


def resolve_state_dir(runtime=DEFAULT_RUNTIME, state_dir=None):
    """Resolve persistent acceptance directory (default `/var/lib/portal-linux-native`)."""
    if state_dir is not None:
        return Path(state_dir)
    runtime_path = Path(runtime)
    if runtime_path in (DEFAULT_RUNTIME, LEGACY_VAR_RUN_RUNTIME):
        return DEFAULT_STATE_DIR
    return runtime_path


def accept_baseline(
    config,
    runtime=DEFAULT_RUNTIME,
    assertion=None,
    state=None,
    root=ROOT,
    state_dir=None,
    **preflight_kwargs,
):
    """Record explicit human physical baseline acceptance bound to code, peers, and interface."""
    if not isinstance(assertion, str) or len(assertion.strip()) < 4:
        raise ValueError(
            'Explicit human physical verification assertion (--assert-physical-ok) is required'
        )
    runtime = Path(runtime)
    persistent_dir = ensure_private_dir(resolve_state_dir(runtime, state_dir))
    baseline_run = read_json_safe(runtime / 'baseline-run.json')
    if not isinstance(baseline_run, dict):
        baseline_run = read_json_safe(persistent_dir / 'baseline-run.json')
    if not isinstance(baseline_run, dict):
        raise RuntimeError('No completed baseline-run.json found; run baseline first')
    if not baseline_run.get('completed') or not baseline_run.get('restored'):
        raise RuntimeError('Last baseline run did not complete and restore cleanly')
    if baseline_run.get('errors'):
        raise RuntimeError('Last baseline run recorded errors; cannot accept baseline')

    verified_state = state if state is not None else state_for(config, **preflight_kwargs)
    expected_code = code_sha256(root)
    expected_binding = peer_binding(verified_state)
    expected_fp = receipt_fingerprint(verified_state, root=root)

    if (
        baseline_run.get('code_sha256') != expected_code
        or baseline_run.get('binding') != expected_binding
        or baseline_run.get('fingerprint') != expected_fp
    ):
        raise RuntimeError(
            'baseline-run.json does not match current code version, interface, or peer addresses'
        )

    receipt = {
        'accepted_at': utc(),
        'baseline_run_token': baseline_run.get('run_token'),
        'code_sha256': expected_code,
        'binding': expected_binding,
        'fingerprint': expected_fp,
        'restored': True,
        'assertion': assertion.strip(),
        'note': 'Human physical baseline assertion recorded; does not mark HEDEF complete.',
    }
    atomic_json(persistent_dir / 'baseline-accepted.json', receipt)
    return receipt


def verify_active_gate(state, runtime=DEFAULT_RUNTIME, root=ROOT, state_dir=None):
    """Require valid human-asserted baseline-accepted.json matching code and peer binding."""
    persistent_dir = resolve_state_dir(runtime, state_dir)
    receipt = read_json_safe(persistent_dir / 'baseline-accepted.json')
    if not isinstance(receipt, dict):
        raise RuntimeError(
            'Active mode refused: missing baseline-accepted.json receipt (run baseline then accept-baseline)'
        )
    assertion = receipt.get('assertion')
    if not isinstance(assertion, str) or len(assertion.strip()) < 4:
        raise RuntimeError('Active mode refused: baseline receipt lacks human physical assertion')
    if receipt.get('restored') is not True:
        raise RuntimeError('Active mode refused: baseline receipt does not confirm clean restoration')
    expected_code = code_sha256(root)
    expected_binding = peer_binding(state)
    expected_fp = receipt_fingerprint(state, root=root)
    if (
        receipt.get('code_sha256') != expected_code
        or receipt.get('binding') != expected_binding
        or receipt.get('fingerprint') != expected_fp
    ):
        raise RuntimeError(
            'Active mode refused: baseline acceptance receipt does not match current code, interface, or peer addresses'
        )
    return receipt


class _BpfInsn(ctypes.Structure):
    _fields_ = [
        ('code', ctypes.c_ushort),
        ('jt', ctypes.c_ubyte),
        ('jf', ctypes.c_ubyte),
        ('k', ctypes.c_uint),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ('len', ctypes.c_ushort),
        ('filter', ctypes.POINTER(_BpfInsn)),
    ]


_CAPTURE_CLAUSE_RE = re.compile(
    r'^\(?\s*ether\s+dst\s+([0-9a-fA-F:]{17})\s+and\s+ether\s+src\s+([0-9a-fA-F:]{17})\s+'
    r'and\s+ip\s+and\s+src\s+host\s+([0-9.]+)\s+and\s+dst\s+host\s+([0-9.]+)\s*\)?$'
)


def compile_capture_bpf(capture_filter):
    """Compile `capture_filters(state)` expression into classic BPF instructions (`sock_filter`)."""
    if not isinstance(capture_filter, str) or not capture_filter.strip():
        raise ValueError('Non-empty capture_filter is required for RX socket')
    raw_clauses = re.split(r'\s+or\s+', capture_filter.strip())
    parsed_clauses = []
    for raw_clause in raw_clauses:
        match = _CAPTURE_CLAUSE_RE.fullmatch(raw_clause.strip())
        if not match:
            raise ValueError(f'Unsupported capture_filter clause: {raw_clause!r}')
        dst_mac = normal_mac(match.group(1))
        src_mac = normal_mac(match.group(2))
        src_ip = validate_unicast_ipv4(match.group(3))
        dst_ip = validate_unicast_ipv4(match.group(4))
        dst_hi, dst_lo = struct.unpack('!IH', bytes.fromhex(dst_mac.replace(':', '')))
        src_hi, src_lo = struct.unpack('!IH', bytes.fromhex(src_mac.replace(':', '')))
        (src_ip_u32,) = struct.unpack('!I', socket.inet_aton(src_ip))
        (dst_ip_u32,) = struct.unpack('!I', socket.inet_aton(dst_ip))
        parsed_clauses.append((dst_hi, dst_lo, src_hi, src_lo, src_ip_u32, dst_ip_u32))

    num_clauses = len(parsed_clauses)
    accept_idx = 2 + 12 * num_clauses
    reject_idx = accept_idx + 1
    insns = [
        (0x28, 0, 0, 12),                      # ldh [12] (EtherType)
        (0x15, 0, reject_idx - 2, 0x0800),     # jeq #0x0800, 0, reject
    ]
    for idx, (dst_hi, dst_lo, src_hi, src_lo, src_ip_u32, dst_ip_u32) in enumerate(parsed_clauses):
        base = 2 + 12 * idx
        next_target = (2 + 12 * (idx + 1)) if (idx + 1 < num_clauses) else reject_idx
        insns.extend([
            (0x20, 0, 0, 0),                                              # ld [0] (dst_mac[0:4])
            (0x15, 0, next_target - (base + 2), dst_hi),
            (0x28, 0, 0, 4),                                              # ldh [4] (dst_mac[4:6])
            (0x15, 0, next_target - (base + 4), dst_lo),
            (0x20, 0, 0, 6),                                              # ld [6] (src_mac[0:4])
            (0x15, 0, next_target - (base + 6), src_hi),
            (0x28, 0, 0, 10),                                             # ldh [10] (src_mac[4:6])
            (0x15, 0, next_target - (base + 8), src_lo),
            (0x20, 0, 0, 26),                                             # ld [26] (ip.saddr)
            (0x15, 0, next_target - (base + 10), src_ip_u32),
            (0x20, 0, 0, 30),                                             # ld [30] (ip.daddr)
            (0x15, accept_idx - (base + 12), next_target - (base + 12), dst_ip_u32),
        ])
    insns.append((0x06, 0, 0, MAX_RAW_RECV))   # ret #65535
    insns.append((0x06, 0, 0, 0))              # ret #0
    return insns


def compile_reject_all_bpf():
    """Return a 1-instruction classic BPF filter that rejects all incoming packets."""
    return [(0x06, 0, 0, 0)]


def pack_sock_fprog(instructions):
    """Pack classic BPF instruction tuples into `(insn_array, sock_fprog)`."""
    if not instructions:
        raise ValueError('BPF instruction list cannot be empty')
    array_type = _BpfInsn * len(instructions)
    insn_array = array_type(
        *(
            _BpfInsn(code & 0xFFFF, jt & 0xFF, jf & 0xFF, k & 0xFFFFFFFF)
            for code, jt, jf, k in instructions
        )
    )
    fprog = _SockFprog(len(instructions), ctypes.cast(insn_array, ctypes.POINTER(_BpfInsn)))
    return insn_array, fprog


def evaluate_bpf(instructions, frame):
    """Execute classic BPF instructions against an Ethernet frame (returns snaplen, 0 = rejected)."""
    raw = bytes(frame or b'')
    acc = 0
    pc = 0
    total = len(instructions)
    while 0 <= pc < total:
        code, jt, jf, k = instructions[pc]
        if code == 0x20:
            if k + 4 > len(raw):
                return 0
            (acc,) = struct.unpack_from('!I', raw, k)
            pc += 1
        elif code == 0x28:
            if k + 2 > len(raw):
                return 0
            (acc,) = struct.unpack_from('!H', raw, k)
            pc += 1
        elif code == 0x30:
            if k + 1 > len(raw):
                return 0
            acc = raw[k]
            pc += 1
        elif code == 0x15:
            pc += 1 + (jt if acc == k else jf)
        elif code == 0x06:
            return k
        else:
            raise ValueError(f'Unsupported BPF opcode: {code:#x}')
    return 0


class LinuxRawSocket:
    """AF_PACKET raw Ethernet RX socket with attached kernel BPF filter and drop accounting."""

    def __init__(self, interface, capture_filter=None, socket_factory=socket.socket):
        if not capture_filter:
            raise ValueError('LinuxRawSocket RX listener requires a non-empty capture_filter')
        self.interface = interface
        self.capture_filter = capture_filter
        self.bpf_instructions = compile_capture_bpf(capture_filter)
        self._bpf_insns, self._bpf_fprog = pack_sock_fprog(self.bpf_instructions)
        self.sock = socket_factory(AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self._packets = 0
        self._drops = 0
        try:
            self.sock.setsockopt(
                socket.SOL_SOCKET, SO_ATTACH_FILTER, self._bpf_fprog
            )
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, CAPTURE_BUFFER)
            except OSError:
                pass
            try:
                self.sock.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
            except OSError:
                pass
            self.sock.bind((interface, ETH_P_ALL))
            self.sock.setblocking(False)
        except BaseException:
            self.sock.close()
            raise

    def fileno(self):
        return self.sock.fileno()

    def select(self, sockets, remain=0.02):
        ready, _, _ = select.select(sockets, [], [], remain)
        return ready

    def recv_raw(self, bufsize=MAX_RAW_RECV):
        try:
            frame, addr = self.sock.recvfrom(max(bufsize, MAX_RAW_RECV))
        except BlockingIOError:
            return None, None, None
        if addr and len(addr) >= 3 and addr[2] == PACKET_OUTGOING:
            return None, None, None
        if self.bpf_instructions and evaluate_bpf(self.bpf_instructions, frame) == 0:
            return None, None, None
        return None, frame, time.time()

    def send(self, frame):
        return self.sock.send(bytes(frame))

    def get_stats(self):
        try:
            raw = self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            if len(raw) >= 8:
                packets, drops = struct.unpack('II', raw[:8])
                self._packets += packets
                self._drops += drops
        except OSError:
            pass
        return (self._packets, self._drops)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class LinuxTxSocket:
    """Transmit-only AF_PACKET raw Ethernet socket that does not receive packets."""

    def __init__(self, interface, socket_factory=socket.socket):
        self.interface = interface
        self.bpf_instructions = compile_reject_all_bpf()
        self._bpf_insns, self._bpf_fprog = pack_sock_fprog(self.bpf_instructions)
        self.sock = socket_factory(AF_PACKET, socket.SOCK_RAW, 0)
        try:
            try:
                self.sock.setsockopt(
                    socket.SOL_SOCKET, SO_ATTACH_FILTER, self._bpf_fprog
                )
            except OSError:
                pass
            try:
                self.sock.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
            except OSError:
                pass
            self.sock.bind((interface, 0))
            self.sock.setblocking(False)
        except BaseException:
            self.sock.close()
            raise

    def fileno(self):
        return self.sock.fileno()

    def send(self, frame):
        return self.sock.send(bytes(frame))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def process_packet(
    frame,
    state,
    flows,
    now,
    active,
    counts,
    seen=None,
    confirmation=None,
    recent_events=None,
    interface=None,
):
    """Validate, optionally mutate (active only), and header-NAT a single raw Ethernet frame."""
    if not frame:
        return None
    iface = interface if interface is not None else state['config']['interface']
    mtu = state.get('mtu', 1500)
    max_frame_len = 14 + mtu
    if len(frame) > max_frame_len:
        counts['dropped_oversize'] += 1
        counts['rejected_frames'] += 1
        return None

    info = parse(frame)
    if info is None:
        counts['rejected_frames'] += 1
        return None
    if info['total'] > mtu:
        counts['dropped_oversize'] += 1
        counts['rejected_frames'] += 1
        return None

    direction = packet_direction(frame, info, state, iface)
    if direction is None:
        counts['rejected_frames'] += 1
        return None

    if info['protocol'] not in (6, 17):
        counts['rejected_frames'] += 1
        return None

    changed = False
    observed_events = []

    if direction == 'out':
        flow = flows.outgoing(info, now)
        if flow is None:
            counts['unmapped_out'] += 1
            return None

        source_frame = frame
        # Baseline mode completely bypasses mutation; probe.mutate is never called when active=False.
        if (
            active
            and info['protocol'] == 17
            and not info['offset']
            and 9296 in (info['sport'], info['dport'])
        ):
            ip_bytes = bytearray(frame[14 : 14 + info['total']])
            ihl = info['ihl']
            udp = ip_bytes[ihl:]
            if len(udp) >= 8:
                _, _, udp_len, orig_udp_csum = struct.unpack('!HHHH', udp[:8])
                frag_payload = None
                probe_input = None
                if not info['more'] and 8 <= udp_len <= len(udp):
                    frag_payload = bytes(udp[8:udp_len])
                    probe_input = frag_payload
                elif info['more'] and udp_len > len(udp) and len(udp) > 8:
                    frag_payload = bytes(udp[8:])
                    missing_bytes = (udp_len - 8) - len(frag_payload)
                    if 0 < missing_bytes <= 8192:
                        probe_input = frag_payload + (b'\x00' * missing_bytes)
                if probe_input is not None:
                    new_probe_payload, changed = probe.mutate(probe_input)
                    if changed and info['more']:
                        if (
                            len(new_probe_payload) != len(probe_input)
                            or new_probe_payload[len(frag_payload) :] != probe_input[len(frag_payload) :]
                        ):
                            changed = False
                    if changed:
                        new_payload = new_probe_payload[: len(frag_payload)]
                        if not info['more']:
                            rebuilt_udp = bytes(udp[:6]) + b'\x00\x00' + new_payload
                            pseudo = bytes(ip_bytes[12:20]) + b'\x00\x11' + struct.pack('!H', udp_len)
                            cs = probe.checksum(pseudo + rebuilt_udp) or 65535
                            rebuilt_udp = rebuilt_udp[:6] + struct.pack('!H', cs) + rebuilt_udp[8:]
                            rebuilt_udp += bytes(udp[udp_len:])
                        else:
                            if orig_udp_csum:
                                old_even = frag_payload + (b'\x00' if len(frag_payload) % 2 else b'')
                                new_even = new_payload + (b'\x00' if len(new_payload) % 2 else b'')
                                cs = replace_checksum(orig_udp_csum, old_even, new_even) or 65535
                            else:
                                cs = 0
                            rebuilt_udp = bytes(udp[:6]) + struct.pack('!H', cs) + new_payload
                        source_frame = bytes(frame[:14]) + bytes(ip_bytes[:ihl]) + rebuilt_udp
                        counts['modified_packets_including_retransmits'] += 1
                        if seen is not None:
                            ident = (info.get('sport'), frag_payload[1:5], frag_payload[17:21])
                            if ident not in seen:
                                seen[ident] = now
                                while len(seen) > 256:
                                    seen.popitem(last=False)
                                if confirmation is not None:
                                    confirmation.modified()
                                counts['unique_modified_startups'] += 1
                                if recent_events is not None:
                                    recent_events.append({
                                        'time': utc(),
                                        'type': 'STARTUP_MODIFIED',
                                        'profile': state.get('profile'),
                                    })

        packet = rewrite(
            source_frame,
            state.get('up_ip', state.get('own_ip')),
            state['config']['ps5_ip'],
            state.get('up_mac', state['own_mac']),
            state['ps5_mac'],
            sport=flow['port'],
        )
    else:
        flow = flows.incoming(info, now)
        if flow is None:
            counts['unmapped_in'] += 1
            return None
        packet = rewrite(
            frame,
            state['config']['ps5_ip'],
            state['config']['portal_ip'],
            state['own_mac'],
            state['portal_mac'],
            dport=flow['sport'],
        )
        if (
            info['protocol'] == 17
            and not info['offset']
            and not info['more']
            and 9296 in (flow['sport'], flow['dport'])
        ):
            ip_bytes = frame[14 : 14 + info['total']]
            ihl = info['ihl']
            if len(ip_bytes) >= ihl + 8:
                udp_length = int.from_bytes(ip_bytes[ihl + 4 : ihl + 6], 'big')
                if 8 <= udp_length <= len(ip_bytes) - ihl:
                    payload = ip_bytes[ihl + 8 : ihl + udp_length]
                    probe.observe(payload, observed_events)
                    for event in observed_events:
                        counts['ps5_' + event['type']] += 1
                        if confirmation is not None:
                            confirmation.observe(event)
                        if recent_events is not None:
                            recent_events.append(dict(event, time=utc()))

    if packet is None:
        counts['rejected_frames'] += 1
        return None
    return packet, direction, changed, observed_events


def default_spawn_guardian(state_path, parent_pid, runtime):
    return subprocess.Popen(
        [
            sys.executable,
            '-u',
            str(ROOT / 'guardian.py'),
            '--state-file',
            str(state_path),
            '--parent',
            str(parent_pid),
            '--runtime',
            str(runtime),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        start_new_session=True,
    )


def build_status_payload(
    *,
    state_name,
    active,
    state,
    pid,
    guardian_pid,
    seconds_limit,
    uptime_seconds,
    flows,
    counts,
    socket_stats,
    iface_drop_delta,
    rates_mbps,
    avg_rates_mbps,
    last_target_bps,
    last_mutation,
    confirmation_ready,
    recent_events,
    errors,
    recovery_info=None,
):
    return {
        'time': utc(),
        'state': state_name,
        'pid': pid,
        'guardian_pid': guardian_pid,
        'run_token': state.get('run_token'),
        'mode': 'active' if active else 'baseline',
        'profile': state.get('profile') if active else 'baseline_no_mutation',
        'interface': state['config']['interface'],
        'seconds_limit': seconds_limit,
        'uptime_seconds': round(uptime_seconds, 3),
        'active_flows': len(flows.up),
        'quarantined_ports': len(flows.quarantine),
        'cached_fragments': len(flows.fragments),
        'counts': dict(counts),
        'drop_and_send_errors': {
            'unmapped_out': counts['unmapped_out'],
            'unmapped_in': counts['unmapped_in'],
            'dropped_oversize': counts['dropped_oversize'],
            'rejected_frames': counts['rejected_frames'],
            'send_errors': counts['send_errors'],
        },
        'capture_loss': {
            'socket_packets': socket_stats[0],
            'socket_drops': socket_stats[1],
            'interface_rx_dropped_delta': iface_drop_delta.get('rx_dropped', 0),
            'interface_rx_missed_delta': iface_drop_delta.get('rx_missed_errors', 0),
        },
        'forwarded_mbps': rates_mbps,
        'average_forwarded_mbps': avg_rates_mbps,
        'ps5_telemetry': {
            'last_target_bps': last_target_bps,
            'ps5_high_target_confirmed': confirmation_ready,
            'last_mutation': last_mutation,
            'recent_session_events': list(recent_events),
        },
        'recovery': recovery_info
        or {
            'state': 'recovery_failed' if state_name == 'recovery_failed' else (
                'recovered' if state_name in ('stopped', 'recovered') else 'active_guardian'
            ),
            'errors': list(errors),
        },
        'errors': list(errors),
        'limits': [
            'Measured forwarded_mbps and PS5 target_bitrate_raw are separate metrics; neither alone proves gameplay quality.',
            'ARP restore frame transmission does not prove peer ARP table convergence.',
            'Pre-defrag (-450) first-fragment drop may leave non-initial PS5->Pi fragments in kernel reassembly queue until expiry.',
        ],
    }


def run(
    config,
    runtime=DEFAULT_RUNTIME,
    active=False,
    seconds=None,
    *,
    continuous=False,
    state_dir=None,
    state_builder=state_for,
    rx_socket_opener=None,
    tx_socket_opener=None,
    guardian_spawner=default_spawn_guardian,
    recovery_runner=idempotent_recover,
    clock=time.monotonic,
    sleeper=time.sleep,
    selector=select.select,
    sysfs_root=Path('/sys/class/net'),
    root=ROOT,
):
    """Execute bounded baseline or finite/continuous active NAT relay lifecycle."""
    seconds = validate_seconds(seconds, active=active, continuous=continuous)
    runtime = ensure_private_dir(Path(runtime))
    persistent_dir = resolve_state_dir(runtime, state_dir)
    lock_path = runtime / 'portal-linux-native.lock'
    recovery_marker = runtime / 'recovery-required'
    restore_state_path = runtime / 'restore-state.json'
    status_path = runtime / 'status.json'

    existing_status = read_json_safe(status_path)
    if recovery_marker.exists() or (
        isinstance(existing_status, dict) and existing_status.get('state') == 'recovery_failed'
    ):
        raise RuntimeError(
            'Previous relay recovery failed or is incomplete; inspect recovery.json before restarting'
        )

    # 1. Validation (preflight + active gate before any port/socket/nft/ARP action)
    state = dict(state_builder(config))
    run_token = state.get('run_token') or uuid.uuid4().hex
    state['run_token'] = run_token
    iface = state['config']['interface']

    if active:
        verify_active_gate(state, runtime, root=root, state_dir=persistent_dir)
        probe.OFFSET = 334
        probe.PATCH_DELTA = PROFILES[state['profile']]
        probe.CONFIRM_TARGET = CONFIRM_TARGETS[state['profile']]

    if rx_socket_opener is None:
        def rx_socket_opener(interface, capture_filter):
            return LinuxRawSocket(interface, capture_filter=capture_filter)

    if tx_socket_opener is None:
        def tx_socket_opener(interface):
            return LinuxTxSocket(interface)

    pid = os.getpid()
    rx = None
    tx = None
    guard = None
    owns_lock = False
    rx_ready_sent = False
    guard_ready = False
    running = True
    completed = False
    counts = collections.Counter()
    flows = Flows()
    seen = collections.OrderedDict()
    confirmation = probe.TargetConfirmation()
    recent_events = collections.deque(maxlen=40)
    last_target_bps = None
    last_mutation = None
    errors = []

    started = clock()
    rate_at = started
    rate_bytes = {'in': 0, 'out': 0}
    rates_mbps = {'in': 0.0, 'out': 0.0}
    initial_iface_drops = read_interface_drop_counters(iface, sysfs_root=sysfs_root)

    prev_handlers = {}
    def stop_handler(_sig, _frame):
        nonlocal running
        running = False

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            prev_handlers[sig] = signal.signal(sig, stop_handler)
        except (OSError, ValueError):
            pass

    try:
        try:
            write_owned_marker(lock_path, pid, run_token, exclusive=True)
        except FileExistsError as exc:
            raise RuntimeError('Another Linux NAT relay or unrecovered lock is active') from exc
        owns_lock = True
        atomic_json(restore_state_path, state)
        write_owned_marker(recovery_marker, pid, run_token, exclusive=False)

        # 2. Spawn guardian -> guardian reserves all TCP/UDP ports 58001-58064 first
        guard = guardian_spawner(restore_state_path, pid, runtime)
        ready, _, _ = selector([guard.stdout], [], [], 6.0)
        if not ready:
            raise RuntimeError('Guardian timed out while reserving NAT ports')
        first_line = guard.stdout.readline()
        if isinstance(first_line, bytes):
            first_line = first_line.decode('utf-8', errors='replace')
        first_line = first_line.strip()
        if first_line != 'PORTS_RESERVED':
            raise RuntimeError(f'Guardian failed to reserve ports (got {first_line!r})')

        # 3. Open RX listener and TX socket before nftables installation
        filters = capture_filters(state)
        rx = rx_socket_opener(iface, filters[iface])
        tx = tx_socket_opener(iface)

        # 4. Signal RX_READY -> guardian runs `nft --check` and atomic `create table` install
        guard.stdin.write(b'RX_READY\n')
        guard.stdin.flush()
        rx_ready_sent = True

        # 5. Wait for guardian ready confirmation (`GUARD_READY`) before any ARP redirection
        ready, _, _ = selector([guard.stdout], [], [], 6.0)
        if not ready:
            raise RuntimeError('Guardian timed out during nftables setup')
        second_line = guard.stdout.readline()
        if isinstance(second_line, bytes):
            second_line = second_line.decode('utf-8', errors='replace')
        second_line = second_line.strip()
        if second_line != 'GUARD_READY':
            raise RuntimeError(f'Guardian did not become ready (got {second_line!r})')
        guard_ready = True

        # 6. Portal ARP redirection only after GUARD_READY
        arp_frame = portal_arp_frame(state, repair=False)
        for _ in range(3):
            send_raw_frame(tx, arp_frame, counts)
            sleeper(0.05)

        started = clock()
        rate_at = started
        next_heartbeat = started
        next_arp = started + 1.0
        next_expiry = started + 1.0
        next_status = started

        while running and (seconds is None or (clock() - started) < seconds):
            now = clock()
            if (runtime / 'disabled').exists():
                break
            if guard.poll() is not None:
                raise RuntimeError('Guardian exited unexpectedly during relay operation')

            if now >= next_heartbeat:
                guard.stdin.write(b'.')
                guard.stdin.flush()
                next_heartbeat = now + 1.0

            if now >= next_arp:
                send_raw_frame(tx, arp_frame, counts)
                next_arp = now + 1.0

            if now >= next_expiry:
                flows.expire(now)
                next_expiry = now + 1.0

            if now >= next_status:
                elapsed_window = max(now - rate_at, 0.001)
                rates_mbps = {
                    d: round((counts['forwarded_bytes_' + d] - rate_bytes[d]) * 8 / elapsed_window / 1e6, 3)
                    for d in ('in', 'out')
                }
                rate_bytes = {d: counts['forwarded_bytes_' + d] for d in ('in', 'out')}
                rate_at = now
                total_elapsed = max(now - started, 0.001)
                avg_rates = {
                    d: round(counts['forwarded_bytes_' + d] * 8 / total_elapsed / 1e6, 3)
                    for d in ('in', 'out')
                }
                cur_drops = read_interface_drop_counters(iface, sysfs_root=sysfs_root)
                drop_delta = {
                    k: max(0, cur_drops[k] - initial_iface_drops.get(k, 0))
                    for k in cur_drops
                }
                sock_stats = rx.get_stats() if hasattr(rx, 'get_stats') else (0, 0)
                atomic_json(
                    status_path,
                    build_status_payload(
                        state_name='running',
                        active=active,
                        state=state,
                        pid=pid,
                        guardian_pid=getattr(guard, 'pid', None),
                        seconds_limit=seconds,
                        uptime_seconds=now - started,
                        flows=flows,
                        counts=counts,
                        socket_stats=sock_stats,
                        iface_drop_delta=drop_delta,
                        rates_mbps=rates_mbps,
                        avg_rates_mbps=avg_rates,
                        last_target_bps=last_target_bps,
                        last_mutation=last_mutation,
                        confirmation_ready=confirmation.ready,
                        recent_events=recent_events,
                        errors=errors,
                    ),
                )
                next_status = now + 2.0

            ready_socks = rx.select([rx], remain=0.02) if hasattr(rx, 'select') else [rx]
            if not ready_socks:
                continue

            _, frame, _ = rx.recv_raw(MAX_RAW_RECV)
            if not frame:
                continue

            processed = process_packet(
                frame,
                state,
                flows,
                now,
                active,
                counts,
                seen=seen,
                confirmation=confirmation,
                recent_events=recent_events,
                interface=iface,
            )
            if processed is None:
                continue
            packet, direction, changed, events = processed
            send_raw_frame(tx, packet, counts)
            counts['forwarded_' + direction] += 1
            counts['forwarded_bytes'] += len(packet)
            counts['forwarded_bytes_' + direction] += len(packet)
            if changed:
                last_mutation = utc()
            if direction == 'in' and events:
                for event in events:
                    if event.get('type') == 'CONNECTIONQUALITY':
                        last_target_bps = event.get('target_bitrate_raw')

        completed = True
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                signal.signal(sig, signal.SIG_IGN)
            except (OSError, ValueError):
                pass

        # Close RX and TX sockets FIRST so relay cannot send any further frames during recovery
        sock_stats = (0, 0)
        if rx is not None and hasattr(rx, 'get_stats'):
            try:
                sock_stats = rx.get_stats()
            except Exception:
                pass
        close_sockets([rx, tx])
        rx = tx = None

        need_fallback_recovery = False
        if guard is not None:
            try:
                if guard.poll() is None and guard.stdin is not None:
                    try:
                        guard.stdin.write(b'TX_CLOSED\n')
                        guard.stdin.flush()
                    except OSError:
                        pass
                if guard.stdin is not None:
                    try:
                        guard.stdin.close()
                    except OSError:
                        pass
                rc = guard.wait(timeout=12)
                if rc != 0:
                    need_fallback_recovery = True
            except subprocess.TimeoutExpired:
                errors.append('Guardian recovery timed out; lock retained')
                need_fallback_recovery = True
            except Exception as exc:
                errors.append(f'Guardian wait failed: {exc}')
                need_fallback_recovery = True

            rec_on_disk = read_json_safe(runtime / 'recovery.json')
            if isinstance(rec_on_disk, dict) and rec_on_disk.get('run_token') == run_token:
                for rec_err in rec_on_disk.get('errors') or []:
                    if rec_err not in errors:
                        errors.append(rec_err)
            elif rx_ready_sent or guard_ready:
                need_fallback_recovery = True

        if need_fallback_recovery and (rx_ready_sent or guard_ready):
            fallback_errors = recovery_runner(
                state,
                runtime,
                pid,
                'parent_fallback_recovery',
                table_installed=True,
                allow_missing_table=True,
                tx_stopped_verified=True,
                sleeper=sleeper,
            )
            for err in fallback_errors:
                if err not in errors:
                    errors.append(err)
        elif not rx_ready_sent and not guard_ready and owns_lock and not errors:
            remove_owned_marker(recovery_marker, pid, run_token)
            remove_owned_marker(lock_path, pid, run_token)

        # Check status.json and recovery.json on disk; NEVER overwrite recovery_failed
        disk_status = read_json_safe(status_path) or {}
        disk_recovery = read_json_safe(runtime / 'recovery.json') or {}
        if disk_recovery.get('run_token') == run_token:
            for err in disk_recovery.get('errors') or []:
                if err not in errors:
                    errors.append(err)
        if disk_status.get('run_token') == run_token:
            for err in disk_status.get('errors') or []:
                if err not in errors:
                    errors.append(err)

        recovery_failed = (
            bool(errors)
            or disk_status.get('state') == 'recovery_failed'
            or (
                disk_recovery.get('run_token') == run_token
                and bool(disk_recovery.get('errors'))
            )
        )
        if not recovery_failed and owns_lock:
            remove_owned_marker(recovery_marker, pid, run_token)
            remove_owned_marker(lock_path, pid, run_token)

        final_now = clock()
        total_elapsed = max(final_now - started, 0.001)
        avg_rates = {
            d: round(counts['forwarded_bytes_' + d] * 8 / total_elapsed / 1e6, 3)
            for d in ('in', 'out')
        }
        cur_drops = read_interface_drop_counters(iface, sysfs_root=sysfs_root)
        drop_delta = {
            k: max(0, cur_drops[k] - initial_iface_drops.get(k, 0))
            for k in cur_drops
        }
        final_state_name = 'recovery_failed' if recovery_failed else 'stopped'
        final_status = build_status_payload(
            state_name=final_state_name,
            active=active,
            state=state,
            pid=pid,
            guardian_pid=getattr(guard, 'pid', None) if guard is not None else None,
            seconds_limit=seconds,
            uptime_seconds=final_now - started,
            flows=flows,
            counts=counts,
            socket_stats=sock_stats,
            iface_drop_delta=drop_delta,
            rates_mbps=rates_mbps,
            avg_rates_mbps=avg_rates,
            last_target_bps=last_target_bps,
            last_mutation=last_mutation,
            confirmation_ready=confirmation.ready,
            recent_events=recent_events,
            errors=errors,
            recovery_info={
                'state': 'recovery_failed' if recovery_failed else 'recovered',
                'errors': list(errors),
                'last_recovery': disk_recovery if disk_recovery.get('run_token') == run_token else None,
            },
        )
        atomic_json(status_path, final_status)

        if not active and not recovery_failed:
            baseline_summary = {
                'time': utc(),
                'run_token': run_token,
                'code_sha256': code_sha256(root),
                'binding': peer_binding(state),
                'fingerprint': receipt_fingerprint(state, root=root),
                'seconds': seconds,
                'completed': completed,
                'restored': True,
                'accepted': False,
                'counts': dict(counts),
                'errors': list(errors),
                'note': 'Transport completion never self-accepts; run accept-baseline with human physical assertion.',
            }
            atomic_json(runtime / 'baseline-run.json', baseline_summary)
            if state_dir is not None:
                ensure_private_dir(persistent_dir)
                atomic_json(persistent_dir / 'baseline-run.json', baseline_summary)

        for sig, prev in prev_handlers.items():
            try:
                signal.signal(sig, prev)
            except (OSError, ValueError):
                pass

        if errors:
            raise RuntimeError('; '.join(errors))

    return final_status


def read_status_summary(runtime=DEFAULT_RUNTIME, state_dir=None):
    runtime = Path(runtime)
    persistent_dir = resolve_state_dir(runtime, state_dir)
    return {
        'runtime_dir': str(runtime),
        'state_dir': str(persistent_dir),
        'status': read_json_safe(runtime / 'status.json'),
        'recovery': read_json_safe(runtime / 'recovery.json'),
        'baseline_run': read_json_safe(runtime / 'baseline-run.json')
        or read_json_safe(persistent_dir / 'baseline-run.json'),
        'baseline_accepted': read_json_safe(persistent_dir / 'baseline-accepted.json'),
        'disabled': (runtime / 'disabled').exists(),
        'recovery_required': (runtime / 'recovery-required').exists(),
        'lock_present': (runtime / 'portal-linux-native.lock').exists(),
    }


def request_stop(runtime=DEFAULT_RUNTIME):
    runtime = ensure_private_dir(Path(runtime))
    disabled_path = runtime / 'disabled'
    fd = os.open(disabled_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    os.close(fd)
    return disabled_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'command',
        nargs='?',
        choices=(
            'baseline',
            'active',
            'preflight',
            'accept-baseline',
            'status',
            'state',
            'stop',
            'guardian',
        ),
        default='baseline',
    )
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    parser.add_argument('--runtime', type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument('--state-dir', type=Path, default=None)
    parser.add_argument('--seconds', type=float, default=None)
    parser.add_argument('--continuous', action='store_true')
    parser.add_argument('--profile', choices=tuple(PROFILES))
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--active', action='store_true')
    parser.add_argument('--assert-physical-ok', dest='assertion', type=str)
    parser.add_argument('--state-file', type=Path)
    parser.add_argument('--parent', type=int)
    parser.add_argument('--allow-test-veth', action='store_true')
    args = parser.parse_args(argv)

    runtime = args.runtime.resolve()
    state_dir = (
        args.state_dir.resolve()
        if args.state_dir is not None
        else resolve_state_dir(args.runtime)
    )
    cmd = args.command
    if args.active:
        cmd = 'active'
    elif args.baseline:
        cmd = 'baseline'

    if args.continuous and cmd != 'active':
        parser.error('--continuous is only supported in active mode; baseline must be finite')
    if args.continuous and args.seconds is not None:
        parser.error('--continuous cannot be combined with --seconds')

    if cmd in ('status', 'state'):
        summary = read_status_summary(runtime, state_dir=state_dir)
        print(json.dumps(summary, indent=2))
        return 0

    if cmd == 'stop':
        request_stop(runtime)
        print('Stop marker written.')
        return 0

    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Live operation requires root on Linux')

    if cmd == 'guardian':
        state_file = args.state_file or (runtime / 'restore-state.json')
        if args.parent is None:
            parser.error('--parent is required for guardian')
        return run_guardian(state_file, args.parent, runtime=runtime)

    cfg = load_config(args.config, allow_test_veth=args.allow_test_veth)
    if args.profile:
        cfg['profile'] = args.profile

    if cmd == 'preflight':
        verified = state_for(cfg, allow_test_veth=args.allow_test_veth)
        print(json.dumps(verified, indent=2))
        return 0

    if cmd == 'accept-baseline':
        receipt = accept_baseline(
            cfg,
            runtime,
            args.assertion,
            state_dir=state_dir,
            allow_test_veth=args.allow_test_veth,
        )
        print(json.dumps(receipt, indent=2))
        return 0

    ensure_private_dir(runtime)
    singleton_path = runtime / 'portal-linux-native.flock'
    with singleton_path.open('w') as singleton_file:
        try:
            fcntl.flock(singleton_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Another Linux native relay instance is already running')
        if (runtime / 'disabled').exists():
            print('Relay is disabled; remove disabled marker before starting.')
            return 1
        result = run(
            cfg,
            runtime=runtime,
            active=(cmd == 'active'),
            seconds=args.seconds,
            continuous=args.continuous,
            state_dir=state_dir,
            state_builder=lambda c: state_for(c, allow_test_veth=args.allow_test_veth),
        )
        print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
