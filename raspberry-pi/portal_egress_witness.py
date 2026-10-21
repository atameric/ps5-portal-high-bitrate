"""Independent, bounded tcpdump witness for locally transmitted probe packets."""
import hashlib
import signal
import subprocess
import time
from scapy.all import IP, Ether, PcapReader

def ip_digest(frame):
    size = int.from_bytes(frame[16:18], 'big')
    return hashlib.sha256(frame[14:14 + size]).hexdigest()

class Witness:
    def __init__(self, folder, state, iface, ps5, portal):
        self.path = folder / 'egress-private.pcap'
        self.log_path = folder / 'egress-capture.log'
        self.own = state['own_mac'].lower()
        self.expected = set()
        self.log = self.log_path.open('wb')
        filt = (f'ether src {self.own} and ip and host {ps5} and host {portal} '
                'and udp port 9296 and (udp[8] & 15 = 0)')
        self.process = subprocess.Popen(
            ['/usr/sbin/tcpdump', '-i', iface, '-n', '-s', '0', '-U',
             '-c', '10000', '-w', str(self.path), filt],
            stdout=subprocess.DEVNULL, stderr=self.log)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.stop()
                raise RuntimeError('Independent capture failed before network changes')
            if b'listening on' in self.log_path.read_bytes():
                return
            time.sleep(.05)
        self.stop()
        raise RuntimeError('Independent capture did not become ready; no network changes')

    def expect(self, frame):
        self.expected.add(ip_digest(frame))

    def stop(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.log.close()

    def report(self):
        found = set()
        count = 0
        error = None
        try:
            with PcapReader(str(self.path)) as packets:
                for packet in packets:
                    if Ether in packet and IP in packet and packet[Ether].src.lower() == self.own:
                        count += 1
                        raw = bytes(packet[IP])[:packet[IP].len]
                        found.add(hashlib.sha256(raw).hexdigest())
        except Exception as exc:
            error = type(exc).__name__
        return {'expected_unique_modified_packets': len(self.expected),
                'matched_unique_modified_packets': len(found & self.expected),
                'captured_egress_packets': count, 'read_error': error,
                'all_expected_observed': bool(self.expected) and not error and self.expected <= found,
                'limit': 'Mac interface observation proves local egress, not delivery to PS5.'}
