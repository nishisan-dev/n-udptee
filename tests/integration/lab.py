#!/usr/bin/env python3
"""Isolated network acceptance test and optional measured 256-byte benchmark."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess as sp
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve()


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

    def start(self, mode, b_port=162):
        label = mode if b_port == 162 else mode + '-port-rewrite'
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
'''.replace('MODE', mode).replace('name: b, ip: 10.10.0.21, port: 162', 'name: b, ip: 10.10.0.21, port: ' + str(b_port)))
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
    finally:
        lab.close()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ['receive', 'send', 'http', 'tcp']:
        helper()
    else:
        main()
