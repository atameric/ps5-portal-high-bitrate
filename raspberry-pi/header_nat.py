"""IPv4 header NAT for the enrolled pair; encrypted transport bytes stay opaque."""
import socket
import struct
from portal_active_probe import checksum


def parse(frame):
    if len(frame) < 34 or frame[12:14] != b'\x08\0':
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], 'big')
    if ip[0] >> 4 != 4 or ihl < 20 or total < ihl or len(ip) < total:
        return None
    fragment = int.from_bytes(ip[6:8], 'big')
    info = {'ihl': ihl, 'total': total, 'protocol': ip[9],
            'src': socket.inet_ntoa(ip[12:16]), 'dst': socket.inet_ntoa(ip[16:20]),
            'id': int.from_bytes(ip[4:6], 'big'), 'offset': fragment & 8191,
            'more': bool(fragment & 8192)}
    if info['protocol'] in (6, 17) and not info['offset']:
        needed = 20 if info['protocol'] == 6 else 8
        if total < ihl + needed:
            return None
        info['sport'], info['dport'] = struct.unpack('!HH', ip[ihl:ihl+4])
        if info['protocol'] == 6:
            info['syn'] = bool(ip[ihl+13] & 2)
            info['seq'] = ip[ihl+4:ihl+8]
    return info


def replace_checksum(value, old, new):
    """RFC 1624 one's-complement update, including fragmented transport headers."""
    result = (~value) & 65535
    for before, after in zip(struct.unpack('!%dH' % (len(old)//2), old),
                             struct.unpack('!%dH' % (len(new)//2), new)):
        result += ((~before) & 65535) + after
    while result >> 16:
        result = (result & 65535) + (result >> 16)
    return (~result) & 65535


def rewrite(frame, source, destination, source_mac, destination_mac, sport=None, dport=None):
    info = parse(frame)
    if info is None:
        return None
    ip = bytearray(frame[14:14+info['total']]); ihl = info['ihl']
    old = bytes(ip[12:20]); new = socket.inet_aton(source) + socket.inet_aton(destination)
    ip[12:20] = new
    if not info['offset'] and info['protocol'] in (6, 17):
        old += bytes(ip[ihl:ihl+4])
        ports = struct.pack('!HH', info['sport'] if sport is None else sport,
                            info['dport'] if dport is None else dport)
        new += ports; ip[ihl:ihl+4] = ports
        position = ihl + (16 if info['protocol'] == 6 else 6)
        value = int.from_bytes(ip[position:position+2], 'big')
        if info['protocol'] == 6 or value:
            updated = replace_checksum(value, old, new)
            if info['protocol'] == 17 and not updated:
                updated = 65535
            ip[position:position+2] = struct.pack('!H', updated)
    ip[10:12] = b'\0\0'; ip[10:12] = struct.pack('!H', checksum(bytes(ip[:ihl])))
    return (bytes.fromhex(destination_mac.replace(':','')) +
            bytes.fromhex(source_mac.replace(':','')) + b'\x08\0' + ip)
