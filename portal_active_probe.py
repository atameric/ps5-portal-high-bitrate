#!/usr/bin/env python3
"""One bounded, hypothesis-driven Portal LaunchSpec byte mutation.
Candidate offsets from static Sony templates, NOT verified Portal plaintext.
0x04 would change leading ASCII '2' to '6' if request is 25000 at that position.
Raw Ethernet forwarding only for the two authorized local devices; no scanning.
"""
import argparse, base64, collections, datetime, json, math, os, signal, socket, struct, subprocess, sys, tempfile, time
from pathlib import Path
from scapy.all import conf
import portal_capture as network
from protocol import fields
from protocol import readvar
from portal_egress_witness import Witness

PREFIX=b'{"sessionId":"sessionId4321","streamResolutions":[{"resolution":{"width":1920,"height":1080},"maxFps":60,"score":10}],"network":{"bwKbpsSent":'
OFFSET=334
PATCH_DELTA=bytes([4])
CONFIRM_TARGET=50000000
PROFILE_LABEL='65mbps'
PROFILES = {'65': (b'\x04', 50_000_000),
            '100': (bytes.fromhex('03501b0005'), 80_000_000),
            '200': (bytes.fromhex('00501b0005'), 160_000_000)}


def set_profile(profile):
    global OFFSET, PATCH_DELTA, CONFIRM_TARGET, PROFILE_LABEL
    OFFSET = 334
    PATCH_DELTA, CONFIRM_TARGET = PROFILES[profile]
    PROFILE_LABEL = profile + 'mbps_experimental'


class PreflightError(RuntimeError):
    """An attempt could not start; no network mappings were changed."""


class RelayWindow:
    """Bound connection and confirmation time, including independent recovery."""
    WARMUP_SECONDS = 5
    RECOVERY_MARGIN = 15

    def __init__(self, start, connect_timeout=35, confirmation_timeout=0):
        if not 1 <= connect_timeout <= 120 or not 0 <= confirmation_timeout <= 30:
            raise ValueError('Connection timeout must be 1-120s; confirmation timeout 0-30s')
        self.ready_at = start + self.WARMUP_SECONDS
        self.connect_deadline = self.ready_at + connect_timeout
        self.deadline = self.connect_deadline
        self.confirmation_timeout = confirmation_timeout
        self.connected = False
        self.watchdog_seconds = (self.WARMUP_SECONDS + connect_timeout
                                 + confirmation_timeout + self.RECOVERY_MARGIN)

    def startup(self, now):
        if not self.connected:
            self.connected = True
            if self.confirmation_timeout:
                self.deadline = min(now + self.confirmation_timeout,
                                    self.connect_deadline + self.confirmation_timeout)

    def phase(self, now):
        if now < self.ready_at:
            return 'preparing'
        return 'confirming' if self.connected else 'waiting'

    def remaining(self, now):
        deadline = self.ready_at if now < self.ready_at else self.deadline
        return max(0, math.ceil(deadline - now))

def mutate(data):
    if len(data)<32 or data[0]!=0 or data[13]!=0 or data[14] not in (0,1): return data,False
    if data[5:9]!=b'\0'*4 or data[21:26]!=b'\0'*5 or data[26:29]!=b'\x08\0\x12': return data,False
    if len(data)!=int.from_bytes(data[15:17],'big')+13:return data,False
    try:
        _,pos=readvar(data,29)
        tag,pos=readvar(data,pos); version,pos=readvar(data,pos)
        if tag!=8 or version!=20:return data,False
        while pos<len(data):
            tag,pos=readvar(data,pos)
            if tag&7!=2:return data,False
            size,pos=readvar(data,pos)
            if tag>>3==3:
                # Recorded Portal shape. Abort mutation for any other layout.
                if size!=2296:return data,False
                lo=OFFSET//3*3; a=pos+lo//3*4
                end=((OFFSET+len(PATCH_DELTA)+2)//3)*3
                b=pos+end//3*4
                if b>len(data):return data,False
                raw=bytearray(base64.b64decode(data[a:b],validate=True))
                for i,delta in enumerate(PATCH_DELTA):raw[OFFSET-lo+i]^=delta
                return data[:a]+base64.b64encode(raw)+data[b:],True
            pos+=size
    except (ValueError,IndexError): pass
    return data,False


def checksum(b):
    if len(b)%2:b+=b'\0'
    n=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while n>>16:n=(n&65535)+(n>>16)
    return (~n)&65535


def transform(frame,state,active=False):
    """Return outbound Ethernet bytes, observed UDP bytes/direction, mutation flag."""
    own=bytes.fromhex(state['own_mac'].replace(':',''))
    if len(frame)<34 or frame[:6]!=own or frame[12:14]!=b'\x08\0':return None
    ip=frame[14:]; ihl=(ip[0]&15)*4; total=int.from_bytes(ip[2:4],'big')
    if ip[0]>>4!=4 or ihl<20 or total<ihl or len(ip)<total:return None
    src,dst=socket.inet_ntoa(ip[12:16]),socket.inet_ntoa(ip[16:20])
    if (src,dst)==(network.PORTAL,network.PS5): dest=state['ps5_mac'];direction='out'
    elif (src,dst)==(network.PS5,network.PORTAL): dest=state['portal_mac'];direction='in'
    else:return None
    payload=None;changed=False
    if ip[9]==17 and not int.from_bytes(ip[6:8],'big')&0x3fff and total>=ihl+8:
        udp=ip[ihl:total]; sport,dport,n,_=struct.unpack('!HHHH',udp[:8])
        if 8<=n<=len(udp) and 9296 in (sport,dport):
            payload=udp[8:n]
            if active and direction=='out':
                new,changed=mutate(payload)
                if changed:
                    udp=udp[:6]+b'\0\0'+new
                    pseudo=ip[12:20]+b'\0\x11'+struct.pack('!H',len(udp))
                    cs=checksum(pseudo+udp) or 65535
                    udp=udp[:6]+struct.pack('!H',cs)+udp[8:]
                    ip=ip[:ihl]+udp
    outbound=bytes.fromhex(dest.replace(':',''))+own+frame[12:14]+ip
    return outbound,payload,direction,changed


def observe(data,events):
    if len(data)<28 or data[0]&15 or data[13]!=0 or data[14]!=1 or data[25]!=0:return
    try:
        f=fields(data[26:]);kind=f.get(1)
        if kind==1:
            q=fields(f[3]); events.append({'type':'BANG','version':q.get(1),'key_accepted':q.get(3),'version_accepted':q.get(4)})
        elif kind==13:events.append({'type':'STREAMINFO'})
        elif kind==16:events.append({'type':'CONNECTIONQUALITY','target_bitrate_raw':fields(f[17]).get(1)})
        elif kind==8:events.append({'type':'DISCONNECT'})
    except (ValueError,TypeError,KeyError):pass


class TargetConfirmation:
    """Only confirm quality reports belonging to a newly modified session."""
    def __init__(self):
        self.armed=False;self.accepted=False;self.streaming=False;self.samples=0

    def modified(self):
        self.armed=True;self.accepted=False;self.streaming=False;self.samples=0

    def observe(self,event):
        if event['type']=='DISCONNECT':
            self.__init__()
        elif event['type']=='BANG':
            self.accepted=self.armed and event.get('key_accepted')==1 and event.get('version_accepted')==1
            self.streaming=False;self.samples=0
        elif event['type']=='STREAMINFO' and self.accepted:
            self.streaming=True
        elif event['type']=='CONNECTIONQUALITY' and self.accepted and self.streaming:
            self.samples=self.samples+1 if event.get('target_bitrate_raw',0)>=CONFIRM_TARGET else 0

    @property
    def ready(self):
        return self.samples>=3


def run(active, finish_on_high_target=False, *, connect_timeout=35,
        confirmation_timeout=0, progress=None, config=None):
    """Run the existing relay; an optional callback receives structured UI events."""
    def notify(kind, message=None, **details):
        if progress is not None:
            keep_running = progress(dict(type=kind, **details))
            if keep_running is False and kind not in ('restoring', 'stopping'):
                raise KeyboardInterrupt
            return keep_running
        if message:
            print(message, flush=True)
        return True

    timing = RelayWindow(0, connect_timeout, confirmation_timeout)
    if os.geteuid() != 0:
        raise RuntimeError('Use local Terminal launcher with sudo')
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    notify('checking')
    try:
        network.configure(config)
        state = network.preflight()
        if state['sysctl']['net.inet.ip.forwarding'] != '0':
            raise RuntimeError('Forwarding already active; stop before any changes')
    except Exception as exc:
        raise PreflightError(str(exc)) from exc
    lock = Path('/var/run/portal-lab-capture.lock')
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise PreflightError('Another attempt or recovery is active. Wait for it to finish.') from None
    os.close(fd)
    folder = network.ROOT / 'experiments' / (
        'portal-' + ('patch-' if active else 'baseline-')
        + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    saved = rx = tx = watcher = witness = None
    altered = completed = False
    errors, events, seen = [], [], set()
    counts, rates = collections.Counter(), collections.Counter()
    confirmation = TargetConfirmation()
    run_error = None
    last_target = None
    old_handlers = {sig: signal.getsignal(sig)
                    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    old_umask = os.umask(0o077)

    def interrupted(sig, frame):
        raise KeyboardInterrupt

    for sig in old_handlers:
        signal.signal(sig, interrupted)
    try:
        folder.mkdir(mode=0o700, parents=True)
        saved = Path(tempfile.mkdtemp(prefix='portal-lab-restore-', dir='/var/tmp')) / 'state.json'
        saved.write_text(json.dumps(state))
        filt = (f'ether dst {state["own_mac"]} and ip '
                f'and host {network.PS5} and host {network.PORTAL}')
        rx = conf.L2listen(iface=network.IFACE, filter=filt)
        tx = conf.L2socket(iface=network.IFACE)
        witness = Witness(folder, state, network.IFACE, network.PS5, network.PORTAL)
        watchdog_seconds = timing.watchdog_seconds if active else 55
        watcher = subprocess.Popen(
            [sys.executable, str(network.ROOT / 'portal_capture.py'),
             '--watchdog', str(saved), '--watchdog-seconds', str(watchdog_seconds)],
            start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        altered = True
        network.syswrite('net.inet.ip.redirect', '0')
        # Forwarding remains OFF. Only the configured pair is relayed.
        start = time.monotonic()
        window = RelayWindow(start, connect_timeout if active else 15,
                             confirmation_timeout if active else 0)
        next_arp = next_progress = start
        ready_announced = early_session_warned = False
        notify('preparing', 'Preparing network path; keep Portal disconnected.')
        while time.monotonic() < window.deadline:
            now = time.monotonic()
            if watcher.poll() is not None:
                raise RuntimeError('Recovery watchdog exited unexpectedly')
            if now >= next_arp:
                for packet in network.frames(state):
                    tx.send(packet)
                next_arp = now + 1
            if not ready_announced and now >= window.ready_at:
                ready_announced = True
                notify('ready', ('EXPERIMENT' if active else 'BASELINE')
                       + f' READY: connect Portal to PS5 now. At most {window.remaining(now)} seconds remaining.',
                       seconds=connect_timeout if active else 15)
            if now >= next_progress:
                keep_running = notify(
                    'tick', phase=window.phase(now), seconds=window.remaining(now),
                    counts=dict(counts), modified=len(seen), accepted=confirmation.accepted,
                    streaming=confirmation.streaming, samples=confirmation.samples,
                    target_bitrate=last_target)
                if keep_running is False:
                    raise KeyboardInterrupt
                next_progress = now + .1
            if not rx.select([rx], remain=.05):
                continue
            _, frame, stamp = rx.recv_raw()
            if not frame:
                continue
            result = transform(frame, state, active)
            if result is None:
                continue
            outbound, data, direction, changed = result
            tx.send(outbound)
            counts['forwarded_' + direction] += 1
            if changed:
                witness.expect(outbound)
                counts['mutated_packets_including_retransmits'] += 1
                if data[17:21] not in seen:
                    confirmation.modified()
                    last_target = None
                    window.startup(now)
                seen.add(data[17:21])
                if counts['mutated_packets_including_retransmits'] == 1:
                    notify('modified', 'Startup packet modified; waiting for PS5 response.')
            if data is not None and direction == 'in':
                rates[int(now - start)] += len(data)
                observed = []
                observe(data, observed)
                events.extend(observed)
                for event in observed:
                    confirmation.observe(event)
                    if event['type'] == 'CONNECTIONQUALITY' and confirmation.streaming:
                        last_target = event.get('target_bitrate_raw')
                    if event['type'] == 'DISCONNECT':
                        last_target = None
                    notify('observed', event=event, accepted=confirmation.accepted,
                           streaming=confirmation.streaming, samples=confirmation.samples,
                           target_bitrate=last_target)
                    if (active and not seen and not early_session_warned
                            and event['type'] == 'CONNECTIONQUALITY'):
                        early_session_warned = True
                        notify('reconnect', 'Stream detected without modified startup. Disconnect Portal and reconnect.')
                if active and finish_on_high_target and confirmation.ready:
                    notify('confirmed', 'PS5 reported high target bitrate. Restoring direct connection.')
                    break
        completed = True
    except KeyboardInterrupt:
        run_error = 'Cancelled by user'
        notify('stopping', 'Stopping; restoring original network state.')
    except Exception as exc:
        run_error = f'{type(exc).__name__}: {exc}'
    finally:
        for sig in old_handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            # UI cancellation must never interrupt cleanup.
            try:
                notify('restoring')
            except (Exception, KeyboardInterrupt):
                pass
            if altered:
                try:
                    errors.extend(network.restore(state))
                except Exception as exc:
                    errors.append('Network restore: ' + str(exc))
            if witness:
                try:
                    witness.stop()
                except Exception as exc:
                    errors.append('Capture stop: ' + str(exc))
            for sock in (rx, tx):
                if sock:
                    try:
                        sock.close()
                    except Exception as exc:
                        errors.append('Relay close: ' + str(exc))
            sysctl_after = {}
            for key in network.KEYS:
                try:
                    sysctl_after[key] = network.sysread(key)
                    if sysctl_after[key] != state['sysctl'][key]:
                        errors.append(key + ': original value was not restored')
                except Exception as exc:
                    errors.append('Read restored state: ' + str(exc))
            if watcher and not errors:
                try:
                    watcher.terminate()
                    watcher.wait(timeout=3)
                except Exception as exc:
                    errors.append('Watchdog stop: ' + str(exc))
            if not errors:
                lock.unlink(missing_ok=True)
            try:
                witness_report = witness.report() if witness else None
            except Exception as exc:
                witness_report = {'all_expected_observed': False, 'read_error': type(exc).__name__}
            report = {
                'mode': 'candidate_byte_probe' if active else 'baseline',
                'completed': completed, 'run_error': run_error,
                'candidate_plaintext_offset': OFFSET if active else None,
                'candidate_is_verified_portal_plaintext': False,
                'counts': dict(counts), 'unique_mutated_sequences': len(seen),
                'ps5_messages': events, 'high_target_confirmed': confirmation.ready,
                'udp_9296_mbps_by_second': {str(k): round(v * 8 / 1e6, 3)
                                           for k, v in sorted(rates.items())},
                'restoration_errors': errors,
                'sysctl_after': sysctl_after,
                'egress_witness': witness_report,
                'limits': ['Candidate offset is a static template hypothesis, not decrypted Portal data.',
                           'Target bitrate is a console report, not a pure video throughput measure.',
                           'User-space relay latency/loss is not independently measured.'],
                'xor_mask': PATCH_DELTA[0] if active and len(PATCH_DELTA) == 1 else None,
                'xor_bytes_hex': PATCH_DELTA.hex() if active else None,
                'profile': PROFILE_LABEL, 'directory': str(folder),
                'watchdog_state': str(saved) if saved else None,
                'watchdog_seconds': watchdog_seconds if watcher else None,
                'connect_timeout_seconds': connect_timeout if active else 15,
                'confirmation_timeout_seconds': confirmation_timeout if active else 0,
            }
            try:
                for artifact in folder.iterdir():
                    os.chown(artifact, uid, gid)
                report_path = folder / 'report.json'
                report_path.write_text(json.dumps(report, indent=2) + '\n')
                os.chown(report_path, uid, gid)
                os.chown(folder, uid, gid)
                # The original root-owned parent prevented users reading their reports.
                os.chown(folder.parent, uid, gid)
            except Exception as exc:
                report['report_write_error'] = f'{type(exc).__name__}: {exc}'
            if progress is None:
                print(json.dumps(report, indent=2))
                print('Report:', folder / 'report.json', flush=True)
        finally:
            os.umask(old_umask)
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)

    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=('65','100','200'),default='65')
    parser.add_argument('--connect-timeout', type=int, default=35,
                        help='Seconds to connect after READY (1-120; default 35)')
    args=parser.parse_args()
    if not 1 <= args.connect_timeout <= 120:
        parser.error('--connect-timeout must be between 1 and 120 seconds')
    set_profile(args.profile)
    report=run(True,finish_on_high_target=True,connect_timeout=args.connect_timeout)
    if report['restoration_errors']:
        print('RESTORATION FAILED. See recovery instructions in README.');return 2
    if report.get('run_error'):
        print('STOPPED: '+report['run_error']);return 1
    if not report['unique_mutated_sequences']:
        print('NOT APPLIED: no matching fresh handshake. Disconnect and retry after READY.');return 1
    if not report['high_target_confirmed']:
        print(f'UNCONFIRMED: mutation sent, but three consecutive targets >= {CONFIRM_TARGET/1e6:g} Mbps were not observed. This does not mean the session failed.');return 1
    print('Target confirmed. This is not a measurement of actual video bitrate.');return 0

if __name__=='__main__': sys.exit(main())
