"""Same-interface IPv4/TCP/UDP header NAT and bounded flow pool for Linux relay.

Source provenance:
- Preserves and imports `parse`, `replace_checksum`, `rewrite`, and `checksum`
  from root `header_nat.py` (exact copy of `reference-macos/header_nat.py`,
  using `checksum` from `portal_active_probe.py` at base commit 97880a2).
- Copies `PORTS`, `Flows`, `capture_filters`, and `packet_direction` behavior
  from `reference-macos/portal_nat_auto.py`.
"""
import scapy.config

scapy.config.conf.load_layers = ['l2', 'inet']

from header_nat import checksum, parse, replace_checksum, rewrite

PORTS = tuple(range(58001, 58065))
FLOW_EXPIRY_SECONDS = 60
QUARANTINE_SECONDS = 30
FRAGMENT_TTL_SECONDS = 5
FRAGMENT_CACHE_LIMIT = 512

__all__ = [
    'PORTS',
    'FLOW_EXPIRY_SECONDS',
    'QUARANTINE_SECONDS',
    'FRAGMENT_TTL_SECONDS',
    'FRAGMENT_CACHE_LIMIT',
    'Flows',
    'capture_filters',
    'checksum',
    'packet_direction',
    'parse',
    'replace_checksum',
    'rewrite',
]


def capture_filters(state):
    """Share one capture socket when both directions use Ethernet."""
    own_mac = state['own_mac']
    up_mac = state.get('up_mac', own_mac)
    up_ip = state.get('up_ip', state.get('own_ip'))
    downstream = state['config']['interface']
    up_interface = state.get('up_interface', downstream)
    out = (f'ether dst {own_mac} and ether src {state["portal_mac"]} and ip '
           f'and src host {state["config"]["portal_ip"]} and dst host {state["config"]["ps5_ip"]}')
    incoming = (f'ether dst {up_mac} and ether src {state["ps5_mac"]} and ip '
                f'and src host {state["config"]["ps5_ip"]} and dst host {up_ip}')
    if downstream == up_interface:
        return {downstream: f'({out}) or ({incoming})'}
    return {downstream: out, up_interface: incoming}


def packet_direction(frame, info, state, interface):
    """Check both peer identities; adapter alone cannot select direction."""
    if info is None or len(frame) < 34:
        return None
    downstream = state['config']['interface']
    up_interface = state.get('up_interface', downstream)
    own_mac = bytes.fromhex(state['own_mac'].replace(':', ''))
    up_mac = bytes.fromhex(state.get('up_mac', state['own_mac']).replace(':', ''))
    portal_mac = bytes.fromhex(state['portal_mac'].replace(':', ''))
    ps5_mac = bytes.fromhex(state['ps5_mac'].replace(':', ''))
    up_ip = state.get('up_ip', state.get('own_ip'))
    if (interface == downstream and
            frame[:6] == own_mac and
            frame[6:12] == portal_mac and
            info['src'] == state['config']['portal_ip'] and info['dst'] == state['config']['ps5_ip']):
        return 'out'
    if (interface == up_interface and
            frame[:6] == up_mac and
            frame[6:12] == ps5_mac and
            info['src'] == state['config']['ps5_ip'] and info['dst'] == up_ip):
        return 'in'
    return None


class Flows:
    """A bounded NAT port pool, with stale-session response isolation."""

    def __init__(self):
        self.up = {}
        self.down = {}
        self.quarantine = {}
        self.fragments = {}

    def retire(self, key, now):
        flow = self.up.pop(key)
        self.down.pop((flow['protocol'], flow['port']), None)
        self.quarantine[(flow['protocol'], flow['port'])] = now + QUARANTINE_SECONDS
        self.fragments = {k: v for k, v in self.fragments.items() if v[0] is not flow}

    def remember_fragment(self, key, flow, now):
        if key not in self.fragments and len(self.fragments) >= FRAGMENT_CACHE_LIMIT:
            self.fragments.pop(next(iter(self.fragments)))
        self.fragments[key] = (flow, now + FRAGMENT_TTL_SECONDS)

    def expire(self, now):
        for key, flow in list(self.up.items()):
            if now - flow['last'] > FLOW_EXPIRY_SECONDS:
                self.retire(key, now)
        self.quarantine = {key: end for key, end in self.quarantine.items() if end > now}
        self.fragments = {key: value for key, value in self.fragments.items() if value[1] > now}

    def outgoing(self, info, now):
        if info is None or info.get('protocol') not in (6, 17):
            return None
        fragment_key = ('out', info['protocol'], info['id'])
        if info['offset']:
            cached = self.fragments.get(fragment_key)
            flow = cached[0] if cached and cached[1] > now else None
            if flow is not None:
                flow['last'] = now
            return flow
        if info.get('sport', 0) <= 0 or info.get('dport', 0) <= 0:
            return None
        key = (info['protocol'], info['sport'], info['dport'])
        flow = self.up.get(key)
        if flow and info.get('syn') and flow.get('syn') not in (None, info['seq']):
            self.retire(key, now)
            flow = None
        if flow is None:
            port = next((port for port in PORTS if (key[0], port) not in self.down
                         and (key[0], port) not in self.quarantine), None)
            if port is None:
                return None
            flow = {'protocol': key[0], 'sport': key[1], 'dport': key[2], 'port': port,
                    'last': now, 'syn': info.get('seq') if info.get('syn') else None}
            self.up[key] = flow
            self.down[(key[0], port)] = flow
        flow['last'] = now
        if info['more']:
            self.remember_fragment(fragment_key, flow, now)
        return flow

    def incoming(self, info, now):
        if info is None or info.get('protocol') not in (6, 17):
            return None
        fragment_key = ('in', info['protocol'], info['id'])
        if info['offset']:
            cached = self.fragments.get(fragment_key)
            flow = cached[0] if cached and cached[1] > now else None
        else:
            if info.get('sport', 0) <= 0 or info.get('dport', 0) <= 0:
                return None
            flow = self.down.get((info['protocol'], info['dport']))
            if flow and info['sport'] != flow['dport']:
                return None
            if flow and info['more']:
                self.remember_fragment(fragment_key, flow, now)
        if flow:
            flow['last'] = now
        return flow
