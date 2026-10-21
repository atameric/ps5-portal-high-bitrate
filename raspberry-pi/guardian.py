"""Guardian process for Linux same-interface NAT relay.

Responsibilities:
- Hold TCP and UDP port reservations (58001-58064) without SO_REUSE*.
- Maintain an independent raw Ethernet ARP restoration socket.
- Install and remove only the owned `inet portal_native_nat` nftables table
  using `create table`, single-transaction syntax check + install, and
  `run_token` ownership verification before deletion.
- Track parent relay identity via Linux `pidfd` (`os.pidfd_open`) and stdin
  heartbeat; confirm relay can no longer transmit before restoring Portal ARP,
  removing the owned nft table, and releasing reserved ports.
- Preserve `recovery_failed` state and fail closed on any cleanup error.
"""
import argparse
import datetime
import errno
import ipaddress
import json
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

from nat import PORTS

NFT_BIN = Path('/usr/sbin/nft')
TABLE_FAMILY = 'inet'
TABLE_NAME = 'portal_native_nat'
CHAIN_NAME = 'prerouting'
PRIORITY = -450
PORT_RANGE = f'{PORTS[0]}-{PORTS[-1]}'
HEARTBEAT_TIMEOUT = 8.0
HANDSHAKE_TIMEOUT = 5.0
ARP_RESTORE_COUNT = 5
# 5 attempts at 0.35s intervals span 1.4s to outwait Linux 1s rapid-change ARP neighbor locktime
ARP_RESTORE_INTERVAL = 0.35
ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
AF_PACKET = getattr(socket, 'AF_PACKET', 17)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def ensure_private_dir(path, mode=0o700):
    path = Path(path)
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    return path


def atomic_json(path, data, mode=0o600):
    path = Path(path)
    ensure_private_dir(path.parent)
    tmp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    payload = (json.dumps(data, indent=2) + '\n').encode('utf-8')
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    tmp.replace(path)


def read_json_safe(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        return None


def write_owned_marker(path, pid, run_token, exclusive=False):
    path = Path(path)
    ensure_private_dir(path.parent)
    flags = os.O_CREAT | os.O_WRONLY | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        payload = json.dumps({'pid': int(pid), 'run_token': str(run_token)}) + '\n'
        os.write(fd, payload.encode('utf-8'))
    finally:
        os.close(fd)


def marker_matches_owner(path, pid, run_token):
    data = read_json_safe(path)
    if not isinstance(data, dict):
        return False
    return data.get('pid') == int(pid) and data.get('run_token') == str(run_token)


def remove_owned_marker(path, pid, run_token):
    path = Path(path)
    if marker_matches_owner(path, pid, run_token):
        path.unlink(missing_ok=True)
        return True
    return False


def portal_arp_frame(state, repair=False):
    """Build 42-byte Ethernet+ARP reply updating only Portal's entry for PS5."""
    own_mac = bytes.fromhex(state['own_mac'].replace(':', ''))
    portal_mac = bytes.fromhex(state['portal_mac'].replace(':', ''))
    ps5_mac = bytes.fromhex(state['ps5_mac'].replace(':', ''))
    ps5_ip = socket.inet_aton(state['config']['ps5_ip'])
    portal_ip = socket.inet_aton(state['config']['portal_ip'])
    sender_mac = ps5_mac if repair else own_mac
    eth_hdr = portal_mac + own_mac + struct.pack('!H', ETH_P_ARP)
    arp_hdr = struct.pack(
        '!HHBBH6s4s6s4s',
        1,          # HTYPE Ethernet
        0x0800,     # PTYPE IPv4
        6,          # HLEN
        4,          # PLEN
        2,          # OPER reply (is-at)
        sender_mac,
        ps5_ip,
        portal_mac,
        portal_ip,
    )
    return eth_hdr + arp_hdr


def send_raw_frame(sock, frame, counts=None):
    """Send raw Ethernet bytes and verify full length; retry once padded if <60B EINVAL."""
    raw = bytes(frame)
    try:
        sent = sock.send(raw)
    except OSError as exc:
        if exc.errno == errno.EINVAL and len(raw) < 60:
            padded = raw + (b'\x00' * (60 - len(raw)))
            try:
                sent = sock.send(padded)
            except OSError:
                if counts is not None:
                    counts['send_errors'] += 1
                raise
            if counts is not None:
                counts['tx_padded_retries'] += 1
            if sent != len(padded):
                if counts is not None:
                    counts['send_errors'] += 1
                raise RuntimeError(f'Incomplete padded Ethernet send: {sent} != {len(padded)}')
            return sent
        if counts is not None:
            counts['send_errors'] += 1
        raise
    if sent != len(raw):
        if counts is not None:
            counts['send_errors'] += 1
        raise RuntimeError(f'Incomplete Ethernet send: {sent} != {len(raw)}')
    return sent


def open_arp_socket(interface, socket_factory=socket.socket):
    sock = socket_factory(AF_PACKET, socket.SOCK_RAW, 0)
    try:
        sock.bind((interface, 0))
        return sock
    except BaseException:
        sock.close()
        raise


def close_sockets(sockets):
    for sock in sockets:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def reserve_ports(bind_ip, ports=PORTS, socket_factory=socket.socket):
    """Bind all TCP and UDP NAT ports on bind_ip without SO_REUSEADDR/SO_REUSEPORT."""
    ipaddress.IPv4Address(bind_ip)
    reserved = []
    try:
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            for port in ports:
                sock = socket_factory(socket.AF_INET, kind)
                reserved.append(sock)
                sock.bind((bind_ip, int(port)))
        return reserved
    except BaseException:
        close_sockets(reserved)
        raise


def build_nft_ruleset(state):
    """Build single-transaction nftables ruleset using exclusive `create table`."""
    iface = state['config']['interface']
    ps5_ip = state['config']['ps5_ip']
    up_ip = state.get('up_ip', state.get('own_ip'))
    run_token = state.get('run_token', '')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', iface):
        raise ValueError(f'Invalid interface name for nft: {iface!r}')
    if not re.fullmatch(r'[a-zA-Z0-9_-]{8,128}', str(run_token)):
        raise ValueError('Invalid run_token for nft ruleset')
    ipaddress.IPv4Address(ps5_ip)
    ipaddress.IPv4Address(up_ip)
    return (
        f'create table {TABLE_FAMILY} {TABLE_NAME}\n'
        f'create chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} {{\n'
        f'    type filter hook prerouting priority {PRIORITY}; policy accept;\n'
        f'}}\n'
        f'add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} '
        f'iifname "{iface}" ip saddr {ps5_ip} ip daddr {up_ip} '
        f'meta l4proto {{ tcp, udp }} th dport {PORT_RANGE} '
        f'counter drop comment "portal_run_token={run_token}"\n'
    )


def install_nft_table(state, runner=subprocess.run, nft_bin=NFT_BIN):
    """Verify table absence, run `nft --check`, then install in one transaction."""
    nft_path = str(nft_bin)
    existing = runner(
        [nft_path, 'list', 'table', TABLE_FAMILY, TABLE_NAME],
        text=True,
        capture_output=True,
        check=False,
    )
    if existing.returncode == 0:
        raise RuntimeError(
            f'nft table {TABLE_FAMILY} {TABLE_NAME} already exists; refusing to start'
        )
    ruleset = build_nft_ruleset(state)
    checked = runner(
        [nft_path, '--check', '-f', '-'],
        input=ruleset,
        text=True,
        capture_output=True,
        check=False,
    )
    if checked.returncode != 0:
        detail = (checked.stderr or checked.stdout or '').strip()
        raise RuntimeError(f'nft syntax check failed: {detail}')
    installed = runner(
        [nft_path, '-f', '-'],
        input=ruleset,
        text=True,
        capture_output=True,
        check=False,
    )
    if installed.returncode != 0:
        detail = (installed.stderr or installed.stdout or '').strip()
        raise RuntimeError(f'nft install failed: {detail}')
    return ruleset


def delete_owned_nft_table(run_token, runner=subprocess.run, nft_bin=NFT_BIN, allow_missing=False):
    """Delete `inet portal_native_nat` only after verifying `run_token` ownership."""
    if not run_token or not re.fullmatch(r'[a-zA-Z0-9_-]{8,128}', str(run_token)):
        return ['Invalid or missing run_token; refusing nft table deletion']
    nft_path = str(nft_bin)
    listed = runner(
        [nft_path, 'list', 'table', TABLE_FAMILY, TABLE_NAME],
        text=True,
        capture_output=True,
        check=False,
    )
    if listed.returncode != 0:
        msg = (listed.stderr or listed.stdout or '').strip()
        if allow_missing and ('No such file or directory' in msg or 'does not exist' in msg):
            return []
        return [f'nft list table failed: {msg or listed.returncode}']
    marker = f'portal_run_token={run_token}'
    if marker not in (listed.stdout or ''):
        return [
            f'nft table {TABLE_FAMILY} {TABLE_NAME} run_token mismatch; '
            'refusing to delete unowned table'
        ]
    deleted = runner(
        [nft_path, 'delete', 'table', TABLE_FAMILY, TABLE_NAME],
        text=True,
        capture_output=True,
        check=False,
    )
    if deleted.returncode != 0:
        msg = (deleted.stderr or deleted.stdout or '').strip()
        return [f'nft delete table failed: {msg or deleted.returncode}']
    return []


def restore_portal_arp(
    state,
    arp_socket=None,
    socket_factory=socket.socket,
    count=ARP_RESTORE_COUNT,
    interval=ARP_RESTORE_INTERVAL,
    sleeper=time.sleep,
):
    """Send ARP repair frames to Portal on guardian's independent socket."""
    errors = []
    sent_frames = 0
    owned_socket = None
    sock = arp_socket
    try:
        if sock is None:
            owned_socket = open_arp_socket(
                state['config']['interface'], socket_factory=socket_factory
            )
            sock = owned_socket
        frame = portal_arp_frame(state, repair=True)
        for idx in range(count):
            send_raw_frame(sock, frame)
            sent_frames += 1
            if idx + 1 < count and interval > 0:
                sleeper(interval)
    except Exception as exc:
        errors.append(f'ARP restore failed: {exc}')
    finally:
        if owned_socket is not None:
            close_sockets([owned_socket])
    return errors, {
        'arp_frames_sent': sent_frames,
        'peer_arp_table_verified': False,
        'note': 'ARP frame transmission does not prove peer ARP cache convergence.',
    }


class ParentMonitor:
    """Monitor parent relay process via Linux pidfd without PID reuse risk."""

    def __init__(
        self,
        parent_pid,
        pidfd_opener=None,
        ppid_getter=os.getppid,
        signal_sender=None,
        selector=select.select,
    ):
        self.parent_pid = int(parent_pid)
        self.ppid_getter = ppid_getter
        self.selector = selector
        self.signal_sender = signal_sender
        opener = pidfd_opener if pidfd_opener is not None else getattr(os, 'pidfd_open', None)
        if opener is None:
            raise RuntimeError('os.pidfd_open is required on Linux for parent tracking')
        self.pidfd = opener(self.parent_pid, 0)
        if self.ppid_getter() != self.parent_pid:
            self.close()
            raise RuntimeError(f'Parent {self.parent_pid} exited before pidfd verification')

    def is_alive(self):
        if self.pidfd is None:
            raise RuntimeError('Parent state unknown: pidfd unavailable')
        ready, _, _ = self.selector([self.pidfd], [], [], 0)
        if ready:
            return False
        return True

    def ensure_stopped(self, tx_closed_confirmed=False, timeout=3.0):
        """Ensure parent relay can no longer transmit packets."""
        if tx_closed_confirmed or not self.is_alive():
            return True
        if self.signal_sender is not None:
            self.signal_sender(self.pidfd, self.parent_pid, signal.SIGKILL)
        elif hasattr(signal, 'pidfd_send_signal'):
            try:
                signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
            except ProcessLookupError:
                return True
        elif self.ppid_getter() == self.parent_pid:
            try:
                os.kill(self.parent_pid, signal.SIGKILL)
            except ProcessLookupError:
                return True
        else:
            raise RuntimeError('Cannot signal parent process safely')
        ready, _, _ = self.selector([self.pidfd], [], [], timeout)
        if ready or not self.is_alive():
            return True
        raise RuntimeError(f'Parent relay PID {self.parent_pid} did not terminate within {timeout}s')

    def close(self):
        if self.pidfd is not None:
            if isinstance(self.pidfd, int):
                try:
                    os.close(self.pidfd)
                except OSError:
                    pass
            elif hasattr(self.pidfd, 'close'):
                try:
                    self.pidfd.close()
                except OSError:
                    pass
            self.pidfd = None


def update_status_after_recovery(runtime, parent_pid, run_token, reason, errors, arp_info):
    status_path = Path(runtime) / 'status.json'
    current = read_json_safe(status_path) or {}
    combined_errors = list(current.get('errors') or [])
    for err in errors:
        if err not in combined_errors:
            combined_errors.append(err)
    failed = bool(combined_errors) or current.get('state') == 'recovery_failed'
    if current and current.get('pid') not in (None, int(parent_pid)):
        if current.get('run_token') not in (None, str(run_token)) and not failed:
            return current
    updated = dict(current)
    updated.update(
        time=utc(),
        pid=current.get('pid', int(parent_pid)),
        run_token=current.get('run_token', str(run_token)),
        state='recovery_failed' if failed else 'recovered',
        errors=combined_errors,
        recovery={
            'state': 'recovery_failed' if failed else 'recovered',
            'reason': reason,
            'errors': combined_errors,
            'arp_frames_sent': arp_info.get('arp_frames_sent', 0),
            'peer_arp_table_verified': False,
            'note': arp_info.get('note', ''),
        },
    )
    atomic_json(status_path, updated)
    return updated


def idempotent_recover(
    state,
    runtime,
    parent_pid,
    reason,
    arp_socket=None,
    socket_factory=socket.socket,
    runner=subprocess.run,
    nft_bin=NFT_BIN,
    table_installed=True,
    allow_missing_table=False,
    tx_stopped_verified=True,
    sleeper=time.sleep,
    extra_errors=None,
):
    """Idempotent recovery shared by guardian and parent fallback."""
    runtime = Path(runtime)
    run_token = state.get('run_token', '')
    errors = list(extra_errors or [])
    arp_info = {
        'arp_frames_sent': 0,
        'peer_arp_table_verified': False,
        'note': 'ARP frame transmission does not prove peer ARP cache convergence.',
    }
    if not tx_stopped_verified:
        msg = 'Could not verify that relay stopped transmitting before recovery'
        if msg not in errors:
            errors.append(msg)
    else:
        arp_errors, arp_info = restore_portal_arp(
            state,
            arp_socket=arp_socket,
            socket_factory=socket_factory,
            sleeper=sleeper,
        )
        for err in arp_errors:
            if err not in errors:
                errors.append(err)
        if table_installed:
            nft_errors = delete_owned_nft_table(
                run_token,
                runner=runner,
                nft_bin=nft_bin,
                allow_missing=allow_missing_table,
            )
            for err in nft_errors:
                if err not in errors:
                    errors.append(err)

    existing_recovery = read_json_safe(runtime / 'recovery.json')
    if isinstance(existing_recovery, dict) and existing_recovery.get('run_token') == run_token:
        for prev_err in existing_recovery.get('errors') or []:
            if prev_err not in errors:
                errors.append(prev_err)

    recovery_record = {
        'time': utc(),
        'parent': int(parent_pid),
        'run_token': str(run_token),
        'reason': reason,
        'errors': errors,
        'arp_frames_sent': arp_info['arp_frames_sent'],
        'peer_arp_table_verified': False,
        'note': arp_info['note'],
    }
    atomic_json(runtime / 'recovery.json', recovery_record)
    update_status_after_recovery(runtime, parent_pid, run_token, reason, errors, arp_info)
    if not errors:
        remove_owned_marker(runtime / 'recovery-required', parent_pid, run_token)
        remove_owned_marker(runtime / 'portal-linux-native.lock', parent_pid, run_token)
    return errors


def run_guardian(
    state_path,
    parent_pid,
    runtime=None,
    stdin_stream=None,
    stdout_stream=None,
    socket_factory=socket.socket,
    arp_socket_opener=open_arp_socket,
    runner=subprocess.run,
    nft_bin=NFT_BIN,
    parent_monitor_factory=ParentMonitor,
    selector=select.select,
    heartbeat_timeout=HEARTBEAT_TIMEOUT,
    handshake_timeout=HANDSHAKE_TIMEOUT,
    sleeper=time.sleep,
):
    """Run guardian lifecycle: reserve ports -> wait RX_READY -> install nft -> watch heartbeat -> recover."""
    state_path = Path(state_path)
    runtime = Path(runtime) if runtime is not None else state_path.parent
    stdin_stream = sys.stdin.buffer if stdin_stream is None else stdin_stream
    stdout_stream = sys.stdout if stdout_stream is None else stdout_stream

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, signal.SIG_IGN)
        except (OSError, ValueError):
            pass

    state = json.loads(state_path.read_text(encoding='utf-8'))
    up_ip = state.get('up_ip', state.get('own_ip'))
    iface = state['config']['interface']

    reserved = []
    arp_socket = None
    parent_monitor = None
    nft_installed = False
    rx_ready_received = False
    tx_closed_confirmed = False
    reason = 'startup_aborted'
    startup_errors = []
    buffer = b''
    stdin_eof = False

    try:
        parent_monitor = parent_monitor_factory(parent_pid)
        arp_socket = arp_socket_opener(iface, socket_factory=socket_factory)
        reserved = reserve_ports(up_ip, PORTS, socket_factory=socket_factory)
        stdout_stream.write('PORTS_RESERVED\n')
        stdout_stream.flush()

        # Wait for parent to confirm RX listener and TX socket are ready before touching nftables
        ready, _, _ = selector([stdin_stream], [], [], handshake_timeout)
        if not ready:
            raise RuntimeError('Timed out waiting for parent RX_READY confirmation')
        line = stdin_stream.readline()
        if isinstance(line, bytes):
            line = line.decode('utf-8', errors='replace')
        if line.strip() != 'RX_READY':
            raise RuntimeError(f'Unexpected parent handshake line: {line.strip()!r}')
        rx_ready_received = True

        install_nft_table(state, runner=runner, nft_bin=nft_bin)
        nft_installed = True
        reason = 'relay_closed'
        stdout_stream.write('GUARD_READY\n')
        stdout_stream.flush()

        while True:
            watch = [stdin_stream]
            if parent_monitor.pidfd is not None:
                watch.append(parent_monitor.pidfd)
            ready, _, _ = selector(watch, [], [], heartbeat_timeout)
            if not ready:
                reason = 'heartbeat_timeout'
                break
            if parent_monitor.pidfd is not None and parent_monitor.pidfd in ready:
                reason = 'parent_died'
                break
            if stdin_stream in ready:
                chunk = stdin_stream.read1(4096) if hasattr(stdin_stream, 'read1') else os.read(stdin_stream.fileno(), 4096)
                if not chunk:
                    stdin_eof = True
                    if b'TX_CLOSED' in buffer:
                        tx_closed_confirmed = True
                        reason = 'relay_closed'
                    elif not parent_monitor.is_alive():
                        reason = 'parent_died'
                    else:
                        reason = 'relay_closed'
                    break
                buffer += chunk
                if b'TX_CLOSED' in buffer:
                    tx_closed_confirmed = True
                    reason = 'relay_closed'
                    break
    except Exception as exc:
        startup_errors.append(str(exc))
    finally:
        errors = list(startup_errors)
        if nft_installed or rx_ready_received:
            # Retain only the first error per failure site: repeated failures may
            # continue indefinitely and even include a different message each time.
            failure_sites = set()

            def remember_failure(site, exc):
                if site not in failure_sites:
                    failure_sites.add(site)
                    errors.append(f'{site}: {str(exc)[:512]}')

            tx_stopped_verified = tx_closed_confirmed
            try:
                if not tx_stopped_verified and parent_monitor is not None:
                    tx_stopped_verified = bool(
                        parent_monitor.ensure_stopped(
                            tx_closed_confirmed=tx_closed_confirmed
                        )
                    )
                else:
                    tx_stopped_verified = bool(tx_closed_confirmed)
            except Exception as exc:
                remember_failure('parent stop verification', exc)
                tx_stopped_verified = False

            retry_delay = 0.1
            while not tx_stopped_verified:
                # Reporting is best effort; failed writes must never unwind the
                # owner of the ARP socket, nft table and 128 port reservations.
                try:
                    idempotent_recover(
                        state, runtime, parent_pid, reason,
                        arp_socket=arp_socket, socket_factory=socket_factory,
                        runner=runner, nft_bin=nft_bin,
                        table_installed=nft_installed, allow_missing_table=False,
                        tx_stopped_verified=False, sleeper=sleeper,
                        extra_errors=errors,
                    )
                except Exception as exc:
                    remember_failure('recovery record', exc)

                try:
                    watch = [] if stdin_eof else [stdin_stream]
                    pidfd = parent_monitor.pidfd if parent_monitor is not None else None
                    if pidfd is not None:
                        watch.append(pidfd)
                    if watch:
                        ready, _, _ = selector(
                            watch, [], [], min(heartbeat_timeout, 5.0)
                        )
                        if pidfd is not None and pidfd in ready:
                            tx_stopped_verified = True
                        elif stdin_stream in ready:
                            chunk = (stdin_stream.read1(4096) if hasattr(stdin_stream, 'read1')
                                     else os.read(stdin_stream.fileno(), 4096))
                            stdin_eof = not chunk
                            buffer = (buffer + chunk)[-8192:]
                            if b'TX_CLOSED' in buffer:
                                tx_stopped_verified = True
                except Exception as exc:
                    remember_failure('parent monitoring', exc)

                if not tx_stopped_verified and parent_monitor is not None:
                    try:
                        tx_stopped_verified = (
                            parent_monitor.is_alive() is False
                            or parent_monitor.ensure_stopped(tx_closed_confirmed=False) is True
                        )
                    except Exception as exc:
                        remember_failure('parent stop verification', exc)

                if not tx_stopped_verified:
                    # Also back off when select fails immediately, stdin is at
                    # EOF, or no pidfd exists. Unknown never means dead.
                    sleeper(retry_delay)
                    retry_delay = min(retry_delay * 2, 5.0)

            if tx_stopped_verified:
                rec_errors = idempotent_recover(
                    state,
                    runtime,
                    parent_pid,
                    reason,
                    arp_socket=arp_socket,
                    socket_factory=socket_factory,
                    runner=runner,
                    nft_bin=nft_bin,
                    table_installed=nft_installed,
                    allow_missing_table=False,
                    tx_stopped_verified=True,
                    sleeper=sleeper,
                    extra_errors=errors,
                )
                for err in rec_errors:
                    if err not in errors:
                        errors.append(err)
                close_sockets([arp_socket] + reserved)
                if parent_monitor is not None:
                    parent_monitor.close()
        else:
            if errors:
                atomic_json(
                    runtime / 'recovery.json',
                    {
                        'time': utc(),
                        'parent': int(parent_pid),
                        'run_token': str(state.get('run_token', '')),
                        'reason': reason,
                        'errors': errors,
                        'arp_frames_sent': 0,
                        'peer_arp_table_verified': False,
                        'note': 'Aborted before nft install or ARP redirection.',
                    },
                )
            close_sockets([arp_socket] + reserved)
            if parent_monitor is not None:
                parent_monitor.close()

    return 1 if errors else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-file', type=Path, required=True)
    parser.add_argument('--parent', type=int, required=True)
    parser.add_argument('--runtime', type=Path)
    args = parser.parse_args(argv)
    return run_guardian(args.state_file, args.parent, runtime=args.runtime)


if __name__ == '__main__':
    sys.exit(main())
