#!/usr/bin/env python3
"""Isolated network acceptance test and optional measured 256-byte benchmark."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import signal
import struct
import math
import socket
import subprocess as sp
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve()


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!' + str(len(data) // 2) + 'H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def trap_payload(size=5000):
    # Real BER-encoded SNMPv2c Trap-PDU; only the test transmitter knows SNMP.
    def tlv(tag, data):
        length = len(data)
        encoded = bytes([length]) if length < 128 else b'\x82' + struct.pack('!H', length)
        return bytes([tag]) + encoded + data
    oid = lambda value: tlv(6, bytes.fromhex(value))
    varbind = lambda name, value: tlv(0x30, oid(name) + value)
    variables = varbind('2b06010201010300', tlv(0x43, b'\x01'))
    variables += varbind('2b060106030101040100', oid('2b0601060301010501'))
    variables += varbind('2b06010201010100', tlv(4, b'n-udptee fragmented SNMP trap '.ljust(size, b'x')))
    pdu = tlv(0xa7, tlv(2, b'\x01') + tlv(2, b'\x00') + tlv(2, b'\x00') + tlv(0x30, variables))
    return tlv(0x30, tlv(2, b'\x01') + tlv(4, b'public') + pdu)


def inject_fragments(encoded, identification, arrangement, port):
    payload = base64.b64decode(encoded)
    source = socket.inet_aton('10.10.0.2')
    destination = socket.inet_aton('10.10.0.1')
    udp = struct.pack('!HHHH', 40000, int(port), len(payload) + 8, 0) + payload
    pseudo = source + destination + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
    chunk = 1176
    packets = []
    def packet(offset, data, more, ident):
        flags = offset // 8 | (0x2000 if more else 0)
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(data), ident, flags, 64, 17, 0, source, destination)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        return header + data
    for offset in range(0, len(udp), chunk):
        data = udp[offset:offset + chunk]
        packets.append(packet(offset, data, offset + len(data) < len(udp), int(identification)))
    if arrangement == 'reverse-duplicate':
        packets.reverse()
        packets.insert(1, packets[0])
    elif arrangement == 'missing':
        del packets[1]
    elif arrangement == 'overlap':
        conflict = bytes([udp[8] ^ 255]) + udp[9:8 + chunk]
        packets.insert(1, packet(8, conflict, True, int(identification)))
    elif arrangement == 'flood':
        packets = [packet(0, udp[:chunk], True, int(identification) + i) for i in range(100)]
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    for p in packets:
        s.sendto(p, ('10.10.0.1', 0))


def verify_fragment_pcap(path, payload, mtu, source_ip):
    data = path.read_bytes()
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    assert data[:4] in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'], 'invalid PCAP'
    offset = 24
    pieces = []
    ids = set()
    src = dst = None
    while offset < len(data):
        _, _, captured, wire = struct.unpack_from(endian + 'IIII', data, offset)
        frame = data[offset + 16:offset + 16 + captured]
        assert captured == wire
        ip = frame[14:]
        ihl = (ip[0] & 15) * 4
        total, ident, flags = struct.unpack_from('!HHH', ip, 2)
        assert total <= mtu and checksum(ip[:ihl]) == 0, 'MTU/header checksum'
        assert not flags & 0x4000, 'DF set on fragment'
        assert socket.inet_ntoa(ip[12:16]) == source_ip
        src, dst = ip[12:16], ip[16:20]
        ids.add(ident)
        pieces.append(((flags & 0x1fff) * 8, bool(flags & 0x2000), ip[ihl:total]))
        offset += 16 + captured
    assert len(ids) == 1 and next(iter(ids)) != 0
    pieces.sort()
    udp = b''
    for i, (start, more, part) in enumerate(pieces):
        assert start == len(udp) and more == (i < len(pieces) - 1)
        assert not more or len(part) % 8 == 0
        udp += part
    assert udp[8:] == payload and struct.unpack_from('!H', udp, 4)[0] == len(udp)
    assert checksum(src + dst + struct.pack('!BBH', 0, 17, len(udp)) + udp) == 0, 'UDP checksum'
    if source_ip == '10.10.0.2':
        assert struct.unpack_from('!H', udp)[0] == 40000


def helper():
    mode = sys.argv[1]
    if mode == 'receive':
        ip, port, path = sys.argv[2:]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.bind((ip, int(port)))
        Path(path + '.ready').touch()
        with open(path, 'a', buffering=1) as out:
            while True:
                payload, origin = s.recvfrom(65535)
                out.write(json.dumps({'payload': base64.b64encode(payload).decode(), 'source': origin}) + '\n')
    elif mode == 'send':
        destination, port, encoded, count, interval = sys.argv[2:]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('10.10.0.2', 40000))
        # Keep the injected datagram unfragmented; output route MTU is tested separately.
        s.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_MTU_DISCOVER, IP_PMTUDISC_DO
        p = base64.b64decode(encoded)
        for _ in range(int(count)):
            s.sendto(p, (destination, int(port)))
            if float(interval):
                time.sleep(float(interval))
    elif mode == 'send-fragments':
        inject_fragments(*sys.argv[2:])
    elif mode == 'http':
        with urllib.request.urlopen(sys.argv[2], timeout=2) as r:
            print(r.read().decode(), end='')
    elif mode == 'tcp':
        s = socket.socket()
        s.settimeout(.2)
        try:
            s.connect(('10.10.0.1', 162))
        except OSError:
            pass
    else:
        raise ValueError(mode)


def wait(predicate, description, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.03)
    raise AssertionError('timeout: ' + description)


class Lab:
    def __init__(self, binary, out):
        self.binary = str(Path(binary).resolve())
        self.out = out
        self.prefix = 'nut' + str(os.getpid())
        self.names = {k: self.prefix + k for k in ['wire', 'source', 'rep', 'a', 'b']}
        self.processes = []
        self.created = []
        self.daemon = None

    def cmd(self, *args, **kwargs):
        r = sp.run(list(args), text=True, capture_output=True, **kwargs)
        if r.returncode:
            raise RuntimeError(f'{args}: exit={r.returncode} stderr={r.stderr}')
        return r.stdout

    def ns(self, key, *args):
        return self.cmd('ip', 'netns', 'exec', self.names[key], *args)

    def popen(self, key, *args, **kwargs):
        p = sp.Popen(['ip', 'netns', 'exec', self.names[key], *args], **kwargs)
        self.processes.append(p)
        return p

    def setup(self):
        for name in self.names.values():
            self.cmd('ip', 'netns', 'add', name)
            self.created.append(name)
        self.ns('wire', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
        self.ns('wire', 'ip', 'link', 'set', 'br0', 'up')
        for key, ip in [('source', '2'), ('rep', '1'), ('a', '20'), ('b', '21')]:
            # veth creation takes place inside a laboratory namespace.
            dev = key + '0'
            peer = 'w' + key
            self.ns('wire', 'ip', 'link', 'add', peer, 'type', 'veth', 'peer', 'name', dev)
            self.ns('wire', 'ip', 'link', 'set', dev, 'netns', self.names[key])
            self.ns('wire', 'ip', 'link', 'set', peer, 'master', 'br0')
            self.ns('wire', 'ip', 'link', 'set', peer, 'up')
            self.ns(key, 'ip', 'link', 'set', 'lo', 'up')
            self.ns(key, 'ip', 'addr', 'add', '10.10.0.' + ip + '/24', 'dev', dev)
            self.ns(key, 'ip', 'link', 'set', dev, 'up')
            # Only laboratory namespaces are touched; both all and interface matter.
            self.ns(key, 'sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=0')
            self.ns(key, 'sysctl', '-qw', 'net.ipv4.conf.' + dev + '.rp_filter=0')
        for key, ip in [('rep', '1'), ('a', '20'), ('b', '21')]:
            path = self.out / (key + '.jsonl')
            path.write_text('')
            Path(str(path) + '.ready').unlink(missing_ok=True)
            self.popen(key, sys.executable, str(HERE), 'receive', '10.10.0.' + ip, '162', str(path), stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            wait(lambda: Path(str(path) + '.ready').exists(), key + ' listener')

    def rows(self, key):
        p = self.out / (key + '.jsonl')
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def start(self, mode, b_port=162, reassembly=False, fragmentation="drop"):
        label = mode if b_port == 162 else mode + '-port-rewrite'
        if reassembly or fragmentation == 'auto':
            label += '-reassembly-' + str(reassembly).lower() + '-' + fragmentation
        conf = self.out / (label + '.yaml')
        conf.write_text('''version: 1
capture:
  interface: rep0
  bpf: "ip and udp"
replication:
  mode: MODE
  queue_size_per_target: 128
rules:
  - name: traps
    match:
      source_cidrs: ["0.0.0.0/0"]
      destination_cidrs: ["0.0.0.0/0"]
      destination_ports: [162]
    targets:
      - {name: a, ip: 10.10.0.20, port: 162}
      - {name: b, ip: 10.10.0.21, port: 162}
metrics:
  listen: "127.0.0.1:19109"
'''.replace('MODE', mode).replace('name: b, ip: 10.10.0.21, port: 162', 'name: b, ip: 10.10.0.21, port: ' + str(b_port))
          .replace('  mode: ' + mode, '  mode: ' + mode + '\n  fragmentation: ' + fragmentation)
          .replace('  bpf: "ip and udp"', '  bpf: "ip proto 17"\n  snaplen: 262144')
          + ('reassembly:\n  enabled: true\n  timeout_seconds: 1\n  max_datagrams: 64\n  max_bytes: 65535\n  max_fragments_per_datagram: 128\n' if reassembly else ''))
        log = open(self.out / (label + '.log'), 'w')
        self.daemon = self.popen('rep', self.binary, 'run', '-c', str(conf), stdout=log, stderr=log)
        def ready():
            if self.daemon.poll() is not None:
                raise AssertionError('daemon exited: ' + (self.out / (label + '.log')).read_text())
            try:
                return self.ns('rep', sys.executable, str(HERE), 'http', 'http://127.0.0.1:19109/healthz') == 'ok\n'
            except RuntimeError:
                return False
        wait(ready, 'healthz')
        log.close()

    def metrics(self):
        text = self.ns('rep', sys.executable, str(HERE), 'http', 'http://127.0.0.1:19109/metrics')
        (self.out / 'metrics.txt').write_text(text)
        return text

    def metric(self, name, **labels):
        total = 0
        for line in self.metrics().splitlines():
            if line.startswith('n_udptee_' + name + '{') or line.startswith('n_udptee_' + name + ' '):
                if all(f'{k}="{v}"' in line for k, v in labels.items()):
                    total += float(line.rsplit(' ', 1)[1])
        return total

    def send(self, payload, count=1, port=162, interval=0):
        self.ns('source', sys.executable, str(HERE), 'send', '10.10.0.1', str(port), base64.b64encode(payload).decode(), str(count), str(interval))

    def assert_delivery(self, payload, mode):
        before = {k: len(self.rows(k)) for k in ['rep', 'a', 'b']}
        self.send(payload)
        wait(lambda: all(len(self.rows(k)) >= before[k] + 1 for k in before), 'one copy per receiver')
        time.sleep(.15)
        for k in before:
            rows = self.rows(k)
            assert len(rows) == before[k] + 1, (k, 'duplicate deliveries', len(rows), before)
            row = rows[-1]
            assert base64.b64decode(row['payload']) == payload, (k, 'payload mismatch')
            if k == 'rep' or mode == 'raw_ipv4':
                assert row['source'] == ['10.10.0.2', 40000], row
            else:
                assert row['source'][0] == '10.10.0.1', row

    def stop(self):
        if self.daemon is None:
            return
        start = time.monotonic()
        self.daemon.send_signal(signal.SIGTERM)
        code = self.daemon.wait(timeout=6)
        assert code == 0, ('SIGTERM exit', code)
        assert time.monotonic() - start < 5.5
        self.daemon = None

    def functional(self, mode):
        self.start(mode)
        capture_dir = tempfile.TemporaryDirectory(prefix='n-udptee-capture-')
        capture_path = Path(capture_dir.name) / 'capture.pcap'
        capture = self.popen('b', 'tcpdump', '-c', '3', '-U', '-nn', '-i', 'b0', '-w', str(capture_path), 'udp', stdout=sp.DEVNULL, stderr=sp.PIPE)
        time.sleep(.2)
        if capture.poll() is not None:
            raise AssertionError('tcpdump exited: ' + capture.stderr.read().decode())
        for p in [b'one trap\x00\xff\x80', b'', bytes(range(256))]:
            self.assert_delivery(p, mode)
        before = {k: len(self.rows(k)) for k in ['a', 'b']}
        self.send(b'not matched', port=163)
        self.ns('source', sys.executable, str(HERE), 'tcp')
        time.sleep(.2)
        assert all(len(self.rows(k)) == before[k] for k in before), 'unmatched copied'
        # Outputs leave the SAME captured interface, match the broad BPF and port.
        # A stable counter therefore verifies ingress-only capture prevents loops.
        matched = self.metric('packets_matched_total')
        time.sleep(.2)
        assert self.metric('packets_matched_total') == matched == 3, 'replication loop'
        self.ns('a', 'ip', 'link', 'set', 'a0', 'down')
        n = len(self.rows('b'))
        self.send(b'A down, B live')
        wait(lambda: len(self.rows('b')) == n + 1, 'B delivery with A down')
        self.ns('a', 'ip', 'link', 'set', 'a0', 'up')
        self.ns('rep', 'ip', 'route', 'add', 'unreachable', '10.10.0.20/32')
        n = len(self.rows('b'))
        self.send(b'route error')
        wait(lambda: len(self.rows('b')) == n + 1, 'B delivery with A route error')
        assert self.metric('replicas_send_errors_total', target='a') >= 1
        self.ns('rep', 'ip', 'route', 'del', 'unreachable', '10.10.0.20/32')
        if mode == 'raw_ipv4':
            self.ns('rep', 'ip', 'route', 'add', '10.10.0.20/32', 'dev', 'rep0', 'mtu', '1200')
            n = len(self.rows('b'))
            a_before = len(self.rows('a'))
            self.send(b'M' * 1300)
            wait(lambda: len(self.rows('b')) == n + 1, 'MTU preserves other target')
            assert base64.b64decode(self.rows('b')[-1]['payload']) == b'M' * 1300
            assert len(self.rows('a')) == a_before, 'oversize packet delivered'
            assert self.metric('replicas_send_errors_total', target='a', reason='mtu') >= 1
            self.ns('rep', 'ip', 'route', 'del', '10.10.0.20/32')
        # A bounded sustained burst exercises capture and the bounded fan-out.
        rss_before = self.rss()
        self.send(b'B' * 256, count=3000, interval=.0001)
        time.sleep(.3)
        rss_after = self.rss()
        assert rss_after - rss_before < 96 * 1024 * 1024, ('unexpected memory growth', rss_before, rss_after)
        assert self.daemon.poll() is None
        self.metrics()
        assert capture.wait(timeout=3) == 0, 'tcpdump capture failed'
        capture_diagnostics = capture.stderr.read().decode()
        decoded = self.cmd('tcpdump', '-nn', '-vvv', '-r', str(capture_path))
        (self.out / (mode + '.pcap')).write_bytes(capture_path.read_bytes())
        (self.out / (mode + '-capture.log')).write_text(capture_diagnostics)
        capture_dir.cleanup()
        (self.out / (mode + '-tcpdump.txt')).write_text(decoded)
        if mode == 'raw_ipv4':
            assert '[udp sum ok]' in decoded and 'bad udp cksum' not in decoded, 'invalid raw UDP checksum'
            assert '10.10.0.2.40000 > 10.10.0.21.162' in decoded
        self.stop()
        print('PASS', mode, 'original + two targets, payload/source, ingress, errors, burst, shutdown', flush=True)

    def port_rewrite(self):
        path = self.out / 'alternate.jsonl'
        path.write_text('')
        Path(str(path) + '.ready').unlink(missing_ok=True)
        self.popen('b', sys.executable, str(HERE), 'receive', '10.10.0.21', '1162', str(path), stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        wait(lambda: Path(str(path) + '.ready').exists(), 'alternate port listener')
        self.start('raw_ipv4', b_port=1162)
        before = len(self.rows('rep'))
        self.send(b'rewritten destination port')
        wait(lambda: len(self.rows('alternate')) == 1, 'rewritten port delivery')
        wait(lambda: len(self.rows('rep')) == before + 1, 'original on unchanged port')
        row = self.rows('alternate')[0]
        assert row['source'] == ['10.10.0.2', 40000]
        assert base64.b64decode(row['payload']) == b'rewritten destination port'
        self.stop()
        print('PASS raw_ipv4 destination port rewrite', flush=True)

    def send_fragments(self, payload, identification, arrangement='ordered', port=162):
        self.ns('source', sys.executable, str(HERE), 'send-fragments', base64.b64encode(payload).decode(), str(identification), arrangement, str(port))

    def check_fragment_delivery(self, payload, identification, mode, arrangement='ordered'):
        before = {key: len(self.rows(key)) for key in ['rep', 'a', 'b']}
        self.send_fragments(payload, identification, arrangement)
        wait(lambda: all(len(self.rows(key)) == before[key] + 1 for key in before), 'fragmented datagram delivery')
        time.sleep(.1)
        for key in before:
            rows = self.rows(key)
            assert len(rows) == before[key] + 1, ('fragment duplicated', key)
            assert base64.b64decode(rows[-1]['payload']) == payload
            expected = '10.10.0.2' if key == 'rep' or mode == 'raw_ipv4' else '10.10.0.1'
            assert rows[-1]['source'][0] == expected
            if expected == '10.10.0.2':
                assert rows[-1]['source'][1] == 40000

    def fragmentation_defaults(self):
        payload = trap_payload()
        self.start('raw_ipv4')
        before = {key: len(self.rows(key)) for key in ['rep', 'a', 'b']}
        self.send_fragments(payload, 100)
        wait(lambda: len(self.rows('rep')) == before['rep'] + 1, 'original fragmented default')
        time.sleep(.15)
        assert all(len(self.rows(key)) == before[key] for key in ['a', 'b'])
        assert self.metric('packets_dropped_total', reason='fragment') >= 1
        self.stop()
        self.start('raw_ipv4', reassembly=True)
        before = {key: len(self.rows(key)) for key in ['rep', 'a', 'b']}
        self.send_fragments(payload, 101)
        wait(lambda: self.metric('replicas_send_errors_total', reason='mtu') == 2, 'reassembly without output fragmentation')
        assert self.metric('reassembly_events_total', event='completed') == 1
        assert all(len(self.rows(key)) == before[key] for key in ['a', 'b'])
        assert len(self.rows('rep')) == before['rep'] + 1
        self.stop()
        print('PASS fragmented defaults and independent reassembly option', flush=True)

    def fragmented(self, mode):
        self.ns('rep', 'ip', 'route', 'add', '10.10.0.20/32', 'dev', 'rep0', 'mtu', '1200')
        self.ns('rep', 'ip', 'route', 'add', '10.10.0.21/32', 'dev', 'rep0', 'mtu', '1400')
        try:
            if mode == 'raw_ipv4':
                self.start(mode, fragmentation='auto')
                self.assert_delivery(b'fits with auto', mode)
                assert self.metric('raw_fragmentation_attempts_total') == 0
                self.assert_delivery(b'fragment-output-only' * 70, mode)
                assert self.metric('raw_fragmentation_attempts_total', target='a') == 1
                self.stop()
            self.start(mode, reassembly=True, fragmentation='auto')
            payload = trap_payload()
            capture_dir = tempfile.TemporaryDirectory(prefix='n-udptee-fragments-')
            recorders = []
            for key, mtu in [('a', 1200), ('b', 1400)]:
                path = Path(capture_dir.name) / (key + '.pcap')
                count = math.ceil((len(payload) + 8) / ((mtu - 20) // 8 * 8))
                p = self.popen(key, 'tcpdump', '-c', str(count), '-U', '-nn', '-i', key + '0', '-w', str(path), 'ip proto 17', stdout=sp.DEVNULL, stderr=sp.PIPE)
                recorders.append((p, path, key, mtu))
            time.sleep(.2)
            self.check_fragment_delivery(payload, 200, mode, 'reverse-duplicate')
            for p, path, key, mtu in recorders:
                assert p.wait(timeout=3) == 0, p.stderr.read().decode()
                verify_fragment_pcap(path, payload, mtu, '10.10.0.2' if mode == 'raw_ipv4' else '10.10.0.1')
                (self.out / (mode + '-fragments-' + key + '.pcap')).write_bytes(path.read_bytes())
                decoded = self.cmd('tcpdump', '-nn', '-vvv', '-r', str(path))
                (self.out / (mode + '-fragments-' + key + '.txt')).write_text(decoded)
            capture_dir.cleanup()
            self.check_fragment_delivery(bytes(range(256)) * 20, 201, mode)
            self.check_fragment_delivery(b'Z' * 65507, 204, mode)
            assert self.metric('reassembly_events_total', event='completed') == 3
            assert self.metric('reassembly_events_total', event='duplicate') >= 1
            assert self.metric('packets_matched_total') == 3
            before = {key: len(self.rows(key)) for key in ['rep', 'a', 'b']}
            self.send_fragments(payload, 202, 'missing')
            wait(lambda: self.metric('reassembly_events_total', event='timeout') >= 1, 'idle reassembly timeout')
            assert all(len(self.rows(key)) == before[key] for key in before), 'partial datagram emitted'
            self.send_fragments(payload, 203, 'overlap')
            wait(lambda: self.metric('reassembly_events_total', event='overlap') >= 1, 'overlap rejection')
            assert all(len(self.rows(key)) == before[key] for key in ['a', 'b'])
            self.send_fragments(payload, 205, port=163)
            time.sleep(.1)
            assert all(len(self.rows(key)) == before[key] for key in ['a', 'b']), 'unmatched port copied'
            rss = self.rss()
            self.send_fragments(payload, 500, 'flood')
            assert self.metric('reassembly_events_total', event='capacity') > 0
            assert self.metric('reassembly_events_total', event='byte_limit') > 0
            assert self.metric('reassembly_buffered_bytes') <= 65535
            assert self.metric('reassembly_contexts') <= 64
            wait(lambda: self.metric('reassembly_contexts') == 0, 'bounded context expiry')
            assert self.metric('reassembly_active_datagrams') == 0 and self.metric('reassembly_buffered_bytes') == 0
            assert self.rss() - rss < 32 * 1024 * 1024
            matched = self.metric('packets_matched_total')
            time.sleep(.1)
            assert self.metric('packets_matched_total') == matched == 3, 'fragment replication loop'
            assert self.ns('rep', sys.executable, str(HERE), 'http', 'http://127.0.0.1:19109/healthz') == 'ok\n'
            # Fragmented jobs still preserve isolation when one route fails.
            self.ns('rep', 'ip', 'route', 'del', '10.10.0.20/32')
            self.ns('rep', 'ip', 'route', 'add', 'unreachable', '10.10.0.20/32')
            n = len(self.rows('b'))
            self.send_fragments(payload, 700)
            wait(lambda: len(self.rows('b')) == n + 1, 'fragmented B delivery while A fails')
            assert self.metric('replicas_send_errors_total', target='a') >= 1
            self.ns('rep', 'ip', 'route', 'del', 'unreachable', '10.10.0.20/32')
            self.send_fragments(payload, 701, 'missing')
            wait(lambda: self.metric('reassembly_active_datagrams') >= 1, 'pending datagram before shutdown')
            self.metrics()
            self.stop()
            print('PASS', mode, 'fragmented SNMP trap/binary/max payload, independent MTUs/checksums, out-of-order/duplicate, missing/overlap, bounds, failure isolation and shutdown', flush=True)
        finally:
            self.ns('rep', 'ip', 'route', 'del', '10.10.0.21/32')

    def rss(self):
        for line in Path('/proc/' + str(self.daemon.pid) + '/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) * 1024
        raise AssertionError('RSS unavailable')

    def benchmark(self, count):
        self.start('raw_ipv4')
        def ticks():
            f = Path('/proc/' + str(self.daemon.pid) + '/stat').read_text().split()
            return int(f[13]) + int(f[14])
        # Resolve neighbors and take a sampled libpcap baseline before measuring.
        self.send(b'W' * 256)
        wait(lambda: len(self.rows('b')) >= 1, 'benchmark warmup')
        time.sleep(1.1)
        before = self.metrics()
        start_ticks = ticks()
        start = time.monotonic()
        self.send(b'X' * 256, count=count)
        # Include drain time so measured send throughput does not omit queued work.
        time.sleep(1.1)
        duration = time.monotonic() - start
        cpu = (ticks() - start_ticks) / os.sysconf('SC_CLK_TCK')
        text = self.metrics()
        def sum_metric(name):
            prefix = 'n_udptee_' + name + '{'
            values = [float(x.rsplit(' ', 1)[1]) for x in text.splitlines() if x.startswith(prefix)]
            baseline = [float(x.rsplit(' ', 1)[1]) for x in before.splitlines() if x.startswith(prefix)]
            if name == 'pcap_kernel_drops_total' and not values:
                return None
            return sum(values) - sum(baseline)
        result = {'payload_bytes': 256, 'targets': 2, 'injected': count, 'wall_seconds': duration,
                  'captured': sum_metric('capture_packets_total'), 'send_success': sum_metric('replicas_send_success_total'),
                  'capture_pps': sum_metric('capture_packets_total') / duration,
                  'send_pps': sum_metric('replicas_send_success_total') / duration,
                  'cpu_seconds': cpu, 'cpu_percent_one_core': cpu / duration * 100,
                  'rss_bytes': self.rss(), 'kernel_drops': sum_metric('pcap_kernel_drops_total'),
                  'queue_drops': sum_metric('replicas_queue_dropped_total'), 'uname': os.uname()[:],
                  'note': 'Laboratory includes Python generators/listeners, bridge/veth, namespace entry and drain wait; no guaranteed throughput.'}
        (self.out / 'benchmark.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2), flush=True)
        self.stop()

    def close(self):
        for p in reversed(self.processes):
            if p.poll() is None:
                try:
                    p.terminate()
                except PermissionError as error:
                    print('cleanup signal denied:', error, file=sys.stderr)
                    continue
                try:
                    p.wait(timeout=2)
                except sp.TimeoutExpired:
                    p.kill()
                    p.wait()
        for name in reversed(self.created):
            sp.run(['ip', 'netns', 'del', name], capture_output=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binary', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--benchmark', type=int, default=0)
    a = p.parse_args()
    out = Path(a.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    lab = Lab(a.binary, out)
    try:
        lab.setup()
        if a.benchmark:
            lab.benchmark(a.benchmark)
        else:
            lab.functional('raw_ipv4')
            lab.functional('udp_socket')
            lab.port_rewrite()
            lab.fragmentation_defaults()
            lab.fragmented('raw_ipv4')
            lab.fragmented('udp_socket')
    finally:
        lab.close()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ['receive', 'send', 'send-fragments', 'http', 'tcp']:
        helper()
    else:
        main()
