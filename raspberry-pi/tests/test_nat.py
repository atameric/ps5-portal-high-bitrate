"""Unit tests for `nat.py` and `header_nat.py` (NAT, checksums, flows, fragments)."""
from pathlib import Path
import socket
import struct
import sys
import unittest

ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from nat import (
    FLOW_EXPIRY_SECONDS,
    FRAGMENT_CACHE_LIMIT,
    FRAGMENT_TTL_SECONDS,
    PORTS,
    QUARANTINE_SECONDS,
    Flows,
    capture_filters,
    checksum,
    packet_direction,
    parse,
    replace_checksum,
    rewrite,
)

# RFC 5737 TEST-NET-1 documentation IPs & RFC 7042 documentation unicast MACs
PS5_IP = '192.0.2.10'
PORTAL_IP = '192.0.2.20'
PI_IP = '192.0.2.30'

PS5_MAC = '00:00:5e:00:53:10'
PORTAL_MAC = '00:00:5e:00:53:20'
PI_MAC = '00:00:5e:00:53:30'


def mac_bytes(mac):
    return bytes.fromhex(mac.replace(':', ''))


def ones_complement_sum(data):
    if len(data) % 2:
        data = data + b'\x00'
    acc = 0
    for (word,) in struct.iter_unpack('!H', data):
        acc += word
        acc = (acc & 0xFFFF) + (acc >> 16)
    acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def build_ipv4_header(
    src_ip,
    dst_ip,
    protocol,
    payload_len,
    *,
    ip_id=0x1234,
    flags_offset=0,
    ttl=64,
    options=b'',
):
    if len(options) % 4 != 0:
        raise ValueError('IPv4 options must be 32-bit aligned')
    ihl_words = 5 + (len(options) // 4)
    total_len = ihl_words * 4 + payload_len
    ver_ihl = (4 << 4) | ihl_words
    header_wo_csum = (
        struct.pack(
            '!BBHHHBBH4s4s',
            ver_ihl,
            0,
            total_len,
            ip_id,
            flags_offset,
            ttl,
            protocol,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        + options
    )
    hdr_csum = ones_complement_sum(header_wo_csum)
    return header_wo_csum[:10] + struct.pack('!H', hdr_csum) + header_wo_csum[12:]


def build_udp_frame(
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    sport,
    dport,
    payload,
    *,
    ip_id=0x2222,
    ip_options=b'',
    zero_checksum=False,
    force_checksum=None,
    outer_padding=b'',
):
    udp_len = 8 + len(payload)
    if zero_checksum:
        udp_csum = 0
    elif force_checksum is not None:
        udp_csum = force_checksum
    else:
        pseudo = (
            socket.inet_aton(src_ip)
            + socket.inet_aton(dst_ip)
            + struct.pack('!BBH', 0, 17, udp_len)
        )
        udp_wo_csum = struct.pack('!HHHH', sport, dport, udp_len, 0) + payload
        udp_csum = ones_complement_sum(pseudo + udp_wo_csum) or 0xFFFF
    udp_segment = struct.pack('!HHHH', sport, dport, udp_len, udp_csum) + payload
    ip_hdr = build_ipv4_header(
        src_ip,
        dst_ip,
        17,
        len(udp_segment),
        ip_id=ip_id,
        options=ip_options,
    )
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b'\x08\x00' + ip_hdr + udp_segment + outer_padding


def build_tcp_frame(
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    sport,
    dport,
    *,
    seq=1000,
    ack=0,
    flags=0x02,
    window=65535,
    tcp_options=b'',
    payload=b'',
    ip_id=0x3333,
    ip_options=b'',
    outer_padding=b'',
):
    if len(tcp_options) % 4 != 0:
        raise ValueError('TCP options must be 32-bit aligned')
    data_offset = (20 + len(tcp_options)) // 4
    offset_res = data_offset << 4
    tcp_wo_csum = (
        struct.pack(
            '!HHIIBBHHH',
            sport,
            dport,
            seq,
            ack,
            offset_res,
            flags,
            window,
            0,
            0,
        )
        + tcp_options
        + payload
    )
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, 6, len(tcp_wo_csum))
    )
    tcp_csum = ones_complement_sum(pseudo + tcp_wo_csum)
    tcp_segment = tcp_wo_csum[:16] + struct.pack('!H', tcp_csum) + tcp_wo_csum[18:]
    ip_hdr = build_ipv4_header(
        src_ip,
        dst_ip,
        6,
        len(tcp_segment),
        ip_id=ip_id,
        options=ip_options,
    )
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b'\x08\x00' + ip_hdr + tcp_segment + outer_padding


def fragment_ip_payload(
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    protocol,
    full_l4_bytes,
    chunk_sizes,
    *,
    ip_id=0x4444,
):
    """Split an L4 segment into IPv4 fragments (chunk_sizes except last must be multiples of 8)."""
    frames = []
    pos = 0
    total = len(full_l4_bytes)
    for idx, size in enumerate(chunk_sizes):
        piece = full_l4_bytes[pos : pos + size]
        more = (pos + len(piece)) < total
        if more and (len(piece) % 8 != 0):
            raise ValueError('Non-final fragment length must be a multiple of 8 bytes')
        offset_units = pos // 8
        flags_offset = (0x2000 if more else 0) | offset_units
        ip_hdr = build_ipv4_header(
            src_ip,
            dst_ip,
            protocol,
            len(piece),
            ip_id=ip_id,
            flags_offset=flags_offset,
        )
        frames.append(mac_bytes(dst_mac) + mac_bytes(src_mac) + b'\x08\x00' + ip_hdr + piece)
        pos += len(piece)
    return frames


def verify_frame_checksums(test_case, frame, expect_zero_udp_csum=False):
    info = parse(frame)
    test_case.assertIsNotNone(info)
    ip = frame[14 : 14 + info['total']]
    ihl = info['ihl']
    # Independent IPv4 header checksum verification
    test_case.assertEqual(ones_complement_sum(ip[:ihl]), 0)
    if not info['offset'] and not info['more'] and info['protocol'] in (6, 17):
        l4 = ip[ihl:]
        if info['protocol'] == 17:
            udp_csum = int.from_bytes(l4[6:8], 'big')
            if expect_zero_udp_csum:
                test_case.assertEqual(udp_csum, 0)
                return
            test_case.assertNotEqual(udp_csum, 0)
        pseudo = ip[12:20] + struct.pack('!BBH', 0, info['protocol'], len(l4))
        test_case.assertEqual(ones_complement_sum(pseudo + l4), 0)


class TestNatAndFlows(unittest.TestCase):
    def setUp(self):
        self.state = {
            'config': {
                'interface': 'eth0',
                'ps5_ip': PS5_IP,
                'portal_ip': PORTAL_IP,
            },
            'own_mac': PI_MAC,
            'own_ip': PI_IP,
            'up_interface': 'eth0',
            'up_mac': PI_MAC,
            'up_ip': PI_IP,
            'ps5_mac': PS5_MAC,
            'portal_mac': PORTAL_MAC,
        }

    def test_frame_sizes_54_59_60_66_1500_and_outer_padding(self):
        # 54-byte TCP ACK (14 eth + 20 ip + 20 tcp)
        f54 = build_tcp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 49152, 9295, flags=0x10, payload=b''
        )
        self.assertEqual(len(f54), 54)

        # 59-byte UDP frame (14 eth + 20 ip + 8 udp + 17 payload)
        f59 = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50000, 9296, b'A' * 17
        )
        self.assertEqual(len(f59), 59)

        # 60-byte UDP frame (14 eth + 20 ip + 8 udp + 18 payload)
        f60 = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50001, 9296, b'B' * 18
        )
        self.assertEqual(len(f60), 60)

        # 60-byte padded Ethernet frame carrying 54-byte TCP packet (6 bytes trailer padding)
        f54_padded60 = build_tcp_frame(
            PORTAL_MAC,
            PI_MAC,
            PORTAL_IP,
            PS5_IP,
            49153,
            9295,
            flags=0x02,
            payload=b'',
            outer_padding=b'\x00' * 6,
        )
        self.assertEqual(len(f54_padded60), 60)

        # 66-byte TCP SYN with 12B TCP options
        tcp_opts = b'\x02\x04\x05\xb4\x04\x02\x01\x03\x03\x07\x01\x01'
        f66 = build_tcp_frame(
            PORTAL_MAC,
            PI_MAC,
            PORTAL_IP,
            PS5_IP,
            49154,
            9295,
            flags=0x02,
            tcp_options=tcp_opts,
        )
        self.assertEqual(len(f66), 66)

        # 1500-byte Ethernet frame (14 eth + 20 ip + 8 udp + 1458 payload)
        payload_1458 = bytes(range(256)) * 5 + bytes(range(178))
        f1500 = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 50002, 9297, payload_1458
        )
        self.assertEqual(len(f1500), 1500)

        for idx, frame in enumerate((f54, f59, f60, f54_padded60, f66, f1500)):
            orig_info = parse(frame)
            nat_port = PORTS[idx]
            out_frame = rewrite(
                frame, PI_IP, PS5_IP, PI_MAC, PS5_MAC, sport=nat_port
            )
            self.assertIsNotNone(out_frame)
            verify_frame_checksums(self, out_frame)
            out_info = parse(out_frame)
            # Outer Ethernet padding stripped; IP total length unchanged
            self.assertEqual(len(out_frame), 14 + orig_info['total'])
            self.assertEqual(out_info['total'], orig_info['total'])
            self.assertEqual(out_info['src'], PI_IP)
            self.assertEqual(out_info['dst'], PS5_IP)
            self.assertEqual(out_info['sport'], nat_port)
            self.assertEqual(out_info['dport'], orig_info['dport'])
            # Non-NAT bytes (e.g. TCP options, seq/ack, encrypted payload) preserved identically
            l4_hdr_end = 14 + orig_info['ihl'] + (20 if orig_info['protocol'] == 6 else 8)
            self.assertEqual(out_frame[l4_hdr_end:], frame[l4_hdr_end : 14 + orig_info['total']])

    def test_ipv4_options_and_udp_zero_or_ffff_checksum(self):
        # IPv4 header with 8 bytes of options (ihl = 28)
        ip_opts = b'\x01\x01\x01\x01\x94\x04\x00\x00'
        payload = b'opaque-encrypted-payload-bytes'
        frame_opts = build_udp_frame(
            PORTAL_MAC,
            PI_MAC,
            PORTAL_IP,
            PS5_IP,
            51000,
            9296,
            payload,
            ip_options=ip_opts,
        )
        info = parse(frame_opts)
        self.assertEqual(info['ihl'], 28)
        rewritten = rewrite(frame_opts, PI_IP, PS5_IP, PI_MAC, PS5_MAC, sport=58001)
        verify_frame_checksums(self, rewritten)
        # Options preserved identically
        self.assertEqual(rewritten[34:42], ip_opts)
        self.assertEqual(rewritten[50:], payload)

        # UDP zero checksum must remain 0x0000 after rewrite
        frame_zero_csum = build_udp_frame(
            PORTAL_MAC,
            PI_MAC,
            PORTAL_IP,
            PS5_IP,
            51001,
            9296,
            payload,
            zero_checksum=True,
        )
        rewritten_zero = rewrite(
            frame_zero_csum, PI_IP, PS5_IP, PI_MAC, PS5_MAC, sport=58002
        )
        verify_frame_checksums(self, rewritten_zero, expect_zero_udp_csum=True)

        # RFC 1624 replace_checksum folding to 0 becomes 65535 for UDP in rewrite
        old_bytes = socket.inet_aton(PORTAL_IP) + socket.inet_aton(PS5_IP) + struct.pack('!HH', 51002, 9296)
        new_bytes = socket.inet_aton(PI_IP) + socket.inet_aton(PS5_IP) + struct.pack('!HH', 58003, 9296)
        # Construct a synthetic checksum value that folds to 0 after replacement
        crafted_old_csum = replace_checksum(0xFFFF, new_bytes, old_bytes)
        frame_ffff = build_udp_frame(
            PORTAL_MAC,
            PI_MAC,
            PORTAL_IP,
            PS5_IP,
            51002,
            9296,
            b'\x12\x34',
            force_checksum=crafted_old_csum,
        )
        rewritten_ffff = rewrite(
            frame_ffff, PI_IP, PS5_IP, PI_MAC, PS5_MAC, sport=58003
        )
        udp_csum_after = int.from_bytes(rewritten_ffff[40:42], 'big')
        self.assertEqual(udp_csum_after, 0xFFFF)

    def test_tcp_syn_synack_psh_and_new_syn_quarantine(self):
        flows = Flows()
        now = 100.0

        # 1. Outbound TCP SYN (seq=1111)
        syn1 = build_tcp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 52000, 9295, seq=1111, flags=0x02
        )
        info_syn1 = parse(syn1)
        self.assertEqual(packet_direction(syn1, info_syn1, self.state, 'eth0'), 'out')
        flow1 = flows.outgoing(info_syn1, now)
        self.assertIsNotNone(flow1)
        self.assertEqual(flow1['port'], 58001)
        syn1_nat = rewrite(syn1, PI_IP, PS5_IP, PI_MAC, PS5_MAC, sport=flow1['port'])
        verify_frame_checksums(self, syn1_nat)

        # Retransmitted SYN with same seq=1111 keeps same NAT port 58001
        flow1_re = flows.outgoing(info_syn1, now + 0.5)
        self.assertEqual(flow1_re['port'], 58001)

        # 2. Inbound SYN-ACK from PS5 to Pi:58001
        synack = build_tcp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9295, 58001, seq=2222, ack=1112, flags=0x12
        )
        info_sa = parse(synack)
        self.assertEqual(packet_direction(synack, info_sa, self.state, 'eth0'), 'in')
        in_flow = flows.incoming(info_sa, now + 1.0)
        self.assertIs(in_flow, flow1)
        synack_nat = rewrite(
            synack, PS5_IP, PORTAL_IP, PI_MAC, PORTAL_MAC, dport=in_flow['sport']
        )
        verify_frame_checksums(self, synack_nat)
        self.assertEqual(parse(synack_nat)['dport'], 52000)

        # 3. Outbound PSH-ACK keeps same port 58001
        psh = build_tcp_frame(
            PORTAL_MAC,
            PI_MAC,
            PORTAL_IP,
            PS5_IP,
            52000,
            9295,
            seq=1112,
            ack=2223,
            flags=0x18,
            payload=b'control-channel-ciphertext',
        )
        info_psh = parse(psh)
        flow_psh = flows.outgoing(info_psh, now + 2.0)
        self.assertEqual(flow_psh['port'], 58001)

        # 4. New TCP SYN on same tuple (52000, 9295) with new seq=9999 retires 58001 into quarantine
        syn2 = build_tcp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 52000, 9295, seq=9999, flags=0x02
        )
        flow2 = flows.outgoing(parse(syn2), now + 3.0)
        self.assertIsNotNone(flow2)
        self.assertEqual(flow2['port'], 58002)
        self.assertIn((6, 58001), flows.quarantine)
        # Stale response to quarantined port 58001 is rejected
        self.assertIsNone(flows.incoming(info_sa, now + 3.5))

    def test_udp_init_to_big_port_stability_and_pool_exhaustion_expiry(self):
        flows = Flows()
        now = 200.0

        # Outbound UDP INIT -> port 58001
        init_pkt = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 53000, 9296, b'INIT_HANDSHAKE_BYTES'
        )
        f_init = flows.outgoing(parse(init_pkt), now)
        self.assertEqual(f_init['port'], 58001)

        # Inbound UDP response on 58001
        resp_pkt = build_udp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9296, 58001, b'INIT_ACK_BYTES'
        )
        f_resp = flows.incoming(parse(resp_pkt), now + 0.1)
        self.assertIs(f_resp, f_init)

        # Outbound UDP BIG (same tuple 53000 -> 9296) MUST keep exact same port 58001
        big_pkt = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 53000, 9296, b'BIG_LAUNCHSPEC_PAYLOAD' * 20
        )
        f_big = flows.outgoing(parse(big_pkt), now + 0.2)
        self.assertEqual(f_big['port'], 58001)

        # Fill remaining 63 UDP ports (total 64 ports: 58001..58064)
        for i in range(1, len(PORTS)):
            pkt = build_udp_frame(
                PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 53000 + i, 9296, b'x'
            )
            allocated = flows.outgoing(parse(pkt), now + 1.0)
            self.assertIsNotNone(allocated)
            self.assertEqual(allocated['port'], PORTS[i])

        # 65th UDP flow finds pool full -> returns None
        overflow = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 54000, 9296, b'overflow'
        )
        self.assertIsNone(flows.outgoing(parse(overflow), now + 1.5))

        # TCP pool is separate from UDP pool and still has all 64 ports available
        tcp_pkt = build_tcp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 54000, 9295, flags=0x02
        )
        self.assertEqual(flows.outgoing(parse(tcp_pkt), now + 1.5)['port'], 58001)

        # Advance past 60s expiry -> flows move to 30s quarantine
        t_expired = now + 1.5 + FLOW_EXPIRY_SECONDS + 0.5
        flows.expire(t_expired)
        self.assertEqual(len(flows.up), 0)
        self.assertEqual(len(flows.quarantine), 65)
        # Still blocked during 30s quarantine
        self.assertIsNone(flows.outgoing(parse(overflow), t_expired + 1.0))

        # Advance past 30s quarantine -> ports available again
        t_released = t_expired + QUARANTINE_SECONDS + 0.5
        flows.expire(t_released)
        self.assertEqual(len(flows.quarantine), 0)
        reallocated = flows.outgoing(parse(overflow), t_released)
        self.assertIsNotNone(reallocated)
        self.assertEqual(reallocated['port'], 58001)

    def test_fragments_first_subsequent_missing_expiry_limit_and_reassembly(self):
        flows = Flows()
        now = 500.0
        payload = bytes((i * 7) & 0xFF for i in range(600))
        udp_len = 8 + len(payload)
        pseudo = (
            socket.inet_aton(PORTAL_IP)
            + socket.inet_aton(PS5_IP)
            + struct.pack('!BBH', 0, 17, udp_len)
        )
        udp_wo_csum = struct.pack('!HHHH', 55000, 9297, udp_len, 0) + payload
        udp_csum = ones_complement_sum(pseudo + udp_wo_csum) or 0xFFFF
        full_udp = struct.pack('!HHHH', 55000, 9297, udp_len, udp_csum) + payload

        frags = fragment_ip_payload(
            PORTAL_MAC,
            PI_MAC,
            PORTAL_IP,
            PS5_IP,
            17,
            full_udp,
            [200, 200, len(full_udp) - 400],
            ip_id=0x7777,
        )
        self.assertEqual(len(frags), 3)

        # Missing first fragment: sending frag[1] before frag[0] must be dropped
        self.assertIsNone(flows.outgoing(parse(frags[1]), now))

        # Process frag[0], frag[1], frag[2] in order and reassemble rewritten fragments
        rewritten_frags = []
        for frag in frags:
            info = parse(frag)
            flow = flows.outgoing(info, now)
            self.assertIsNotNone(flow)
            self.assertEqual(flow['port'], 58001)
            rw = rewrite(frag, PI_IP, PS5_IP, PI_MAC, PS5_MAC, sport=flow['port'])
            verify_frame_checksums(self, rw)
            rewritten_frags.append(rw)

        # Reassemble rewritten IP payload and verify end-to-end UDP checksum and payload
        reassembled = bytearray()
        for rw in rewritten_frags:
            r_info = parse(rw)
            ip_part = rw[14 : 14 + r_info['total']]
            reassembled.extend(ip_part[r_info['ihl'] :])
        self.assertEqual(len(reassembled), len(full_udp))
        self.assertEqual(bytes(reassembled[8:]), payload)
        nat_pseudo = (
            socket.inet_aton(PI_IP)
            + socket.inet_aton(PS5_IP)
            + struct.pack('!BBH', 0, 17, len(reassembled))
        )
        self.assertEqual(ones_complement_sum(nat_pseudo + reassembled), 0)

        # Fragment cache TTL expiry after 5 seconds
        flows.expire(now + FRAGMENT_TTL_SECONDS + 0.1)
        self.assertIsNone(flows.outgoing(parse(frags[1]), now + FRAGMENT_TTL_SECONDS + 0.1))

        # Fragment cache bounded at 512 entries
        for ip_id in range(1, FRAGMENT_CACHE_LIMIT + 20):
            f_list = fragment_ip_payload(
                PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 17, full_udp, [200, len(full_udp) - 200], ip_id=ip_id
            )
            self.assertIsNotNone(flows.outgoing(parse(f_list[0]), now + 10.0))
        self.assertEqual(len(flows.fragments), FRAGMENT_CACHE_LIMIT)
        self.assertNotIn(('out', 17, 1), flows.fragments)

    def test_inbound_fragments_reassembly_and_retire_eviction(self):
        flows = Flows()
        now = 600.0
        # Establish outbound mapping 55100 -> 9296 allocated at port 58001
        init_out = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 55100, 9296, b'init'
        )
        flow = flows.outgoing(parse(init_out), now)
        self.assertEqual(flow['port'], 58001)

        # Build fragmented inbound UDP packet from PS5:9296 -> Pi:58001
        payload = bytes((i * 13) & 0xFF for i in range(500))
        udp_len = 8 + len(payload)
        pseudo_in = (
            socket.inet_aton(PS5_IP)
            + socket.inet_aton(PI_IP)
            + struct.pack('!BBH', 0, 17, udp_len)
        )
        udp_wo_csum = struct.pack('!HHHH', 9296, 58001, udp_len, 0) + payload
        udp_csum = ones_complement_sum(pseudo_in + udp_wo_csum) or 0xFFFF
        full_udp_in = struct.pack('!HHHH', 9296, 58001, udp_len, udp_csum) + payload

        in_frags = fragment_ip_payload(
            PS5_MAC,
            PI_MAC,
            PS5_IP,
            PI_IP,
            17,
            full_udp_in,
            [160, 160, len(full_udp_in) - 320],
            ip_id=0x8888,
        )

        # Non-first inbound fragment before first fragment must be dropped
        self.assertIsNone(flows.incoming(parse(in_frags[1]), now + 0.1))

        rewritten_in = []
        for frag in in_frags:
            in_flow = flows.incoming(parse(frag), now + 0.2)
            self.assertIs(in_flow, flow)
            rw = rewrite(
                frag, PS5_IP, PORTAL_IP, PI_MAC, PORTAL_MAC, dport=in_flow['sport']
            )
            verify_frame_checksums(self, rw)
            rewritten_in.append(rw)

        reassembled = bytearray()
        for rw in rewritten_in:
            r_info = parse(rw)
            ip_part = rw[14 : 14 + r_info['total']]
            reassembled.extend(ip_part[r_info['ihl'] :])
        self.assertEqual(bytes(reassembled[8:]), payload)
        nat_pseudo_in = (
            socket.inet_aton(PS5_IP)
            + socket.inet_aton(PORTAL_IP)
            + struct.pack('!BBH', 0, 17, len(reassembled))
        )
        self.assertEqual(ones_complement_sum(nat_pseudo_in + reassembled), 0)

        # Retiring the flow immediately removes its cached fragments
        self.assertIn(('in', 17, 0x8888), flows.fragments)
        flows.retire((17, 55100, 9296), now + 0.5)
        self.assertNotIn(('in', 17, 0x8888), flows.fragments)

    def test_packet_direction_and_malformed_rejections(self):
        filters = capture_filters(self.state)
        self.assertIn('eth0', filters)

        valid_out = build_udp_frame(
            PORTAL_MAC, PI_MAC, PORTAL_IP, PS5_IP, 56000, 9296, b'hello'
        )
        self.assertEqual(
            packet_direction(valid_out, parse(valid_out), self.state, 'eth0'), 'out'
        )

        # Wrong interface rejected
        self.assertIsNone(
            packet_direction(valid_out, parse(valid_out), self.state, 'eth1')
        )

        # Own transmitted packet (src_mac == PI_MAC) rejected
        own_tx = build_udp_frame(
            PI_MAC, PS5_MAC, PI_IP, PS5_IP, 58001, 9296, b'hello'
        )
        self.assertIsNone(
            packet_direction(own_tx, parse(own_tx), self.state, 'eth0')
        )

        # Spoofed MAC with Portal IP rejected
        wrong_mac = build_udp_frame(
            PS5_MAC, PI_MAC, PORTAL_IP, PS5_IP, 56000, 9296, b'hello'
        )
        self.assertIsNone(
            packet_direction(wrong_mac, parse(wrong_mac), self.state, 'eth0')
        )

        # Unrelated incoming destination port or wrong source port rejected by Flows
        flows = Flows()
        flows.outgoing(parse(valid_out), 10.0)
        unmapped_in = build_udp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9296, 58055, b'unmapped'
        )
        self.assertIsNone(flows.incoming(parse(unmapped_in), 10.1))
        wrong_sport_in = build_udp_frame(
            PS5_MAC, PI_MAC, PS5_IP, PI_IP, 9999, 58001, b'wrong-sport'
        )
        self.assertIsNone(flows.incoming(parse(wrong_sport_in), 10.1))

        # Malformed frames rejected by parse()
        self.assertIsNone(parse(b'short'))
        self.assertIsNone(parse(b'\x00' * 12 + b'\x86\xdd' + b'\x00' * 40))  # IPv6
        truncated_ip = valid_out[:25]
        self.assertIsNone(parse(truncated_ip))


if __name__ == '__main__':
    unittest.main()
