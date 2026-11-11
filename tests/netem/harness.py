#!/usr/bin/env python3
"""Sequential, namespace-isolated QUIC/TCP buffer measurements. Python stdlib only."""
import argparse
import concurrent.futures
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import statistics
import struct
import subprocess as sp
import sys
import threading
import time

PROFILES = {
    'clean': [], 'loss1': ['loss', '1%'], 'loss5': ['loss', '5%'],
    'delay100': ['delay', '100ms', '30ms'],
    'g3': ['delay', '200ms', 'loss', '2%'],
    'burst': ['loss', '5%', '25%'], 'outage': [], 'rebind': [],
}
DIAGNOSTIC_PROFILES = {
    'delay100-fixed': ['delay', '100ms'],
    'delay100-jitter': ['delay', '100ms', '30ms'],
    'delay100-jitter-ordered': ['delay', '70ms', 'slot', '1ms', '60ms'],
    'relay-only': [],
}
BUFFERS = [76800, 212992, 1048576, 4194304]
BLOCK = bytes(range(256)) * 256
SIZES = {'A': 50_000_000, 'B': 65536, 'C': 65536, 'warm': 1024}

def digest(size):
    h = hashlib.sha256()
    while size:
        n = min(size, len(BLOCK))
        h.update(BLOCK[:n])
        size -= n
    return h.hexdigest()

def command(*args, check=True):
    return sp.run(list(map(str, args)), check=check, capture_output=True, text=True)

def ns(name, *args, check=True):
    return command('ip', 'netns', 'exec', name, *args, check=check)

def http_server(root):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            workload = self.path.strip('/')
            size = SIZES[workload]
            self.send_response(200)
            self.send_header('Content-Length', str(size))
            self.end_headers()
            try:
                first = min(1024, size)
                self.wfile.write(BLOCK[:first])
                size -= first
                if workload != 'warm' and (root / 'impair').exists():
                    (root / 'started').touch()
                    deadline = time.monotonic() + 10
                    while not (root / 'blocked').exists():
                        if time.monotonic() > deadline:
                            raise RuntimeError('Outage trigger was not acknowledged')
                        time.sleep(.01)
                offset = first
                while size:
                    n = min(size, len(BLOCK) - offset)
                    self.wfile.write(BLOCK[offset:offset+n])
                    size -= n
                    offset = 0
            except (BrokenPipeError, ConnectionResetError):
                pass
    http.server.ThreadingHTTPServer(('127.0.0.1', 18080), Handler).serve_forever()

def request(workload, timeout):
    start = time.monotonic()
    with socket.create_connection(('127.0.0.1', 1080), timeout=timeout) as sock:
        sock.settimeout(timeout)
        def exact(n):
            data = b''
            while len(data) < n:
                part = sock.recv(n-len(data))
                if not part:
                    raise RuntimeError('SOCKS connection closed')
                data += part
            return data
        sock.sendall(b'\x05\x01\x00')
        if exact(2) != b'\x05\x00':
            raise RuntimeError('SOCKS authentication failed')
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', 18080))
        header = exact(4)
        if header[1] != 0:
            raise RuntimeError(f'SOCKS CONNECT failed: {header!r}')
        exact({1: 4, 4: 16}.get(header[3], 0) if header[3] != 3 else exact(1)[0])
        exact(2)
        sock.sendall(f'GET /{workload} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
        response = http.client.HTTPResponse(sock)
        response.begin()
        h = hashlib.sha256()
        total = 0
        while True:
            data = response.read(65536)
            if not data:
                break
            total += len(data)
            h.update(data)
        if response.status != 200 or total != SIZES[workload] or h.hexdigest() != digest(total):
            raise RuntimeError('HTTP length/status/SHA256 mismatch')
    return time.monotonic() - start

def worker(workload, timeout):
    start = time.monotonic()
    if workload == 'C':
        time.sleep(5)
    active = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        values = list(pool.map(lambda _: request(workload, timeout), range(20 if workload == 'B' else 1)))
    elapsed = time.monotonic() - active
    ordered = sorted(values)
    return dict(duration_s=elapsed, wall_s=time.monotonic()-start,
                throughput_mbps=SIZES[workload]*len(values)*8/elapsed/1e6,
                p50_s=statistics.median(values), p95_s=ordered[max(0, int(len(values)*.95+.999)-1)],
                success=True, sha256_ok=True)

def relay(root, server_address):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((server_address, 4433))
    def upstream():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('127.0.0.1', 0))
        print(f'upstream_port={s.getsockname()[1]}', flush=True)
        return s
    current = upstream()
    stale = []
    peer = None
    switched = False
    while True:
        if (root / 'rebind').exists() and not switched:
            stale.append(current)
            current = upstream()
            switched = True
        ready, _, _ = select.select([listener, current] + stale, [], [], .02)
        for sock in ready:
            data, addr = sock.recvfrom(65535)
            if sock is listener:
                peer = addr
                current.sendto(data, ('127.0.0.1', 4434))
            elif sock is current and peer:
                listener.sendto(data, peer)

def buffer_log(text, recv, send):
    m = re.search(r'buffers requested recv=(\d+) send=(\d+) actual recv=(\d+) send=(\d+)', text)
    if not m or tuple(map(int, m.groups()[:2])) != (recv, send):
        raise RuntimeError('Missing or incorrect UDP buffer log')
    return dict(zip(('requested_recv', 'requested_send', 'actual_recv', 'actual_send'), map(int, m.groups())))

def probe_receive(root):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4194304)
    sock.bind(('', 19000))
    sock.settimeout(3)
    (root / 'probe-ready').touch()
    samples = []
    while True:
        try:
            data = sock.recv(2048)
        except socket.timeout:
            break
        seq, sent = struct.unpack('!Id', data[:12])
        samples.append((seq, time.monotonic()-sent))
    highest = -1
    reordered = 0
    for seq, _ in samples:
        reordered += seq < highest
        highest = max(highest, seq)
    delays = [delay*1000 for _, delay in samples]
    if not delays:
        raise RuntimeError('UDP probe received no packets')
    print(json.dumps(dict(received=len(samples), sent=5000, reordered=reordered,
                         reorder_fraction=reordered/len(samples),
                         delay_ms=dict(min=min(delays), max=max(delays), median=statistics.median(delays),
                                       spread=max(delays)-min(delays)))), flush=True)


def probe_send(address, spacing_s=0.001):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)
    t0 = time.monotonic()
    for seq in range(5000):
        target = t0 + seq * spacing_s
        diff = target - time.monotonic()
        if diff > 0.001:
            time.sleep(diff - 0.0005)
        while time.monotonic() < target:
            pass
        sock.sendto(struct.pack('!Id', seq, time.monotonic()) + bytes(1188), (address, 19000))
    time.sleep(0.05)
    sock.close()


def socket_buffers(name, pid, recv, send):
    output = ns(name, 'ss', '-u', '-a', '-n', '-m', '-p').stdout
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if f'pid={pid},' in line:
            match = re.search(r'skmem:\(r\d+,rb(\d+),t\d+,tb(\d+)', '\n'.join(lines[index:index+2]))
            if match:
                actual_recv, actual_send = (int(v)//2 for v in match.groups())
                return dict(requested_recv=recv, requested_send=send, actual_recv=actual_recv,
                            actual_send=actual_send, verification='ss skmem; Linux doubled values divided by two')
    raise RuntimeError(f'Cannot verify UDP buffers using ss for PID {pid}: {output}')


def quic_process_env(base_env, args, log_dir, label, mode):
    """Env for one trojan process. QUIC cells set CC and, if requested, a per-role stats path."""
    env = dict(base_env)
    env.pop('TROJAN_QUIC_STATS', None)
    env.pop('TROJAN_QUIC_CC', None)
    if mode != 'quic':
        return env
    env['TROJAN_QUIC_CC'] = args.quic_cc
    if args.quic_stats:
        env['TROJAN_QUIC_STATS'] = str(Path(log_dir) / f'{label}.quic_stats.csv')
    else:
        env.pop('TROJAN_QUIC_STATS', None)
    return env


def cpu_snapshot(pid):
    """Process totals retain exited threads; per-thread maxima cover surviving threads."""
    def ticks(path):
        fields = path.read_text().rsplit(') ', 1)[1].split()
        return int(fields[11]) + int(fields[12])
    proc = Path(f'/proc/{pid}')
    threads = {}
    for task in (proc / 'task').iterdir():
        try:
            threads[task.name] = ticks(task / 'stat')
        except (FileNotFoundError, ProcessLookupError):
            pass
    return dict(total=ticks(proc / 'stat'), threads=threads)


def cpu_delta(before, after):
    hz = os.sysconf('SC_CLK_TCK')
    return dict(total_s=max(0, after['total'] - before['total']) / hz,
                max_thread_s=max((max(0, value - before['threads'].get(tid, 0))
                                  for tid, value in after['threads'].items()), default=0) / hz)


def perf_command(args, root, pid):
    host = args.perf_host_output / root.name
    if args.perf_kind == 'trace':
        return ['chroot', '/host', '/usr/bin/perf', 'trace', '-S', '--summary-mode', 'total', '-p', str(pid),
                '-o', str(host / 'perf.trace')]
    argv = ['chroot', '/host', '/usr/bin/perf', 'stat' if args.perf_kind == 'stat' else 'record',
            '-p', str(pid), '--delay=-1', f'--control=fifo:{host}/perf.control,{host}/perf.ack']
    if args.perf_kind == 'stat':
        events = 'task-clock,context-switches,cpu-migrations,page-faults'
        argv += ['-e', events, '-o', str(host / 'perf.stat')]
    elif args.perf_kind == 'syscalls':
        # perf trace -s lacks FIFO acknowledgements; paired raw events retain return bytes.
        argv += ['-e', 'raw_syscalls:sys_enter,raw_syscalls:sys_exit', '-o', str(host / 'perf.data')]
    else:
        argv += ['-F', '999', '-g', '--call-graph', 'fp', '-o', str(host / 'perf.data')]
    return argv


class Profiler:
    """One host perf, ready after FIFO acknowledgement or trace event attachment."""
    def __init__(self, args, root, pid):
        self.trace = args is not None and args.perf_kind == 'trace'
        self.process = None
        self.fds = []
        self.handles = []
        self.argv = perf_command(args, root, pid)
        (root / 'perf.command.json').write_text(json.dumps(self.argv, indent=2))
        try:
            for name in (() if self.trace else ('perf.control', 'perf.ack')):
                path = root / name
                os.mkfifo(path, 0o600)
                self.fds.append(os.open(path, os.O_RDWR | os.O_NONBLOCK))
            self.handles = [(root / f'perf.{name}').open('w') for name in ('stdout', 'stderr')]
            self.process = sp.Popen(self.argv, stdout=self.handles[0], stderr=self.handles[1])
            (root / 'perf.pid').write_text(str(self.process.pid) + '\n')
            if self.trace:
                self.wait_trace_ready()
            else:
                self.control('enable')
        except Exception:
            self.close()
            raise

    def wait_trace_ready(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f'perf trace exited before attachment: {self.process.returncode}; see perf.stderr')
            try:
                attached = any('perf_event' in os.readlink(fd)
                               for fd in Path(f'/host/proc/{self.process.pid}/fd').iterdir())
            except (FileNotFoundError, ProcessLookupError):
                attached = False
            if attached and self.process.poll() is None:
                return
            time.sleep(.05)
        raise RuntimeError('perf trace attachment timed out; see perf.stderr')

    def control(self, action):
        os.write(self.fds[0], (action + '\n').encode())
        deadline = time.monotonic() + 15
        reply = b''
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f'perf exited before {action} acknowledgement: {self.process.returncode}; see perf.stderr')
            if select.select([self.fds[1]], [], [], .05)[0]:
                reply += os.read(self.fds[1], 4096)
                if b'\n' in reply:
                    if reply.rstrip(b'\x00') != b'ack\n':
                        raise RuntimeError(f'Unexpected perf acknowledgement: {reply!r}')
                    return
        raise RuntimeError(f'perf {action} acknowledgement timed out; see perf.stderr')

    def finish(self):
        try:
            if not self.trace:
                self.control('disable')
        finally:
            self.close()
        if self.process.returncode not in (0, -signal.SIGINT):
            raise RuntimeError(f'perf failed: {self.process.returncode}; see perf.stderr')

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=15)
            except sp.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        for fd in self.fds:
            os.close(fd)
        self.fds.clear()
        for handle in self.handles:
            handle.close()
        self.handles.clear()


def aggregate(rows):
    groups = {}
    for row in rows:
        key = (row['profile'], row['workload'], row['mode'], row['recv_buffer'], row['send_buffer'],
               row.get('quic_cc', 'bbr'), row.get('quic_stats', False), row.get('netem_before_handshake', False), row.get('perf_role'), row.get('perf_kind', 'record'))
        groups.setdefault(key, []).append(row)
    output = []
    for key, group in groups.items():
        good = [r for r in group if r['success']]
        item = dict(zip(('profile', 'workload', 'mode', 'recv_buffer', 'send_buffer', 'quic_cc', 'quic_stats', 'netem_before_handshake', 'perf_role', 'perf_kind'), key))
        item.update(runs=len(group), failures=len(group)-len(good), eagain=sum(r['eagain'] for r in group))
        for metric in ('duration_s', 'throughput_mbps'):
            values = [r[metric] for r in good]
            item[metric] = dict(median=statistics.median(values), min=min(values), max=max(values)) if values else None
        output.append(item)
    return output

def make_config(args, label, profile, mode, recv, send):
    config_dir = args.source / 'tests/LinuxFullTest/config'
    config = json.loads((config_dir / f'quic_{label}_config.json').read_text())
    config['log_level'] = args.log_level
    config['local_addr'] = '127.0.0.1' if label == 'client' else '0.0.0.0'
    config['local_port'] = 1080 if label == 'client' else (4434 if profile in ('rebind', 'relay-only') and mode == 'quic' else 4433)
    config['remote_addr'] = str(args.link_network.network_address + 2) if label == 'client' else '127.0.0.1'
    config['remote_port'] = 4433 if label == 'client' else 18080
    for key in ('cert', 'key'):
        if key in config['ssl']:
            config['ssl'][key] = str(config_dir / Path(config['ssl'][key]).name)
    config['quic'].update(enabled=mode == 'quic', recv_buffer_size=recv, send_buffer_size=send)
    config['experimental']['pipeline_num'] = 0
    return config


def link_network(value):
    try:
        network = ipaddress.IPv4Network(value)
        if network.prefixlen > 30:
            raise ValueError('Link network needs two usable addresses')
        return network
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def run_cell(args, profile, workload, mode, recv, send, repeat, index):
    root = args.output_dir / f'{index:04d}_{profile}_{workload}_{mode}_{recv}_{send}_r{repeat}'
    root.mkdir()
    names = ['nb-client', 'nb-server']
    processes = []
    handles = []
    metrics = {}
    stop = threading.Event()
    errors = []
    row = dict(profile=profile, workload=workload, mode=mode, recv_buffer=recv, send_buffer=send,
               repeat=repeat, log_level=args.log_level, link_network=str(args.link_network),
               quic_cc=args.quic_cc, quic_stats=args.quic_stats,
               netem_before_handshake=args.netem_before_handshake,
               perf_role=args.perf_role, perf_kind=args.perf_kind,
               logs=str(root), success=False, sha256_ok=False)
    def launch(name, label, argv, env=None):
        handle = (root / f'{label}.log').open('w')
        handles.append(handle)
        # ip netns exec replaces itself via execvp, so this env reaches trojan.
        argv = ['ip', 'netns', 'exec', name, *map(str, argv)]
        (root / f'{label}.command.json').write_text(json.dumps(argv, indent=2))
        p = sp.Popen(argv, stdout=handle, stderr=handle, env=env)
        processes.append((label, p))
        return p
    def monitor():
        ticks = os.sysconf('SC_CLK_TCK')
        while not stop.wait(.02):
            for label, p in processes[:]:
                if label not in ('client', 'server'):
                    continue
                try:
                    stat = Path(f'/proc/{p.pid}/stat').read_text().split(') ', 1)[1].split()
                    status = Path(f'/proc/{p.pid}/status').read_text()
                    rss = int(re.search(r'VmHWM:\s+(\d+)', status)[1])*1024
                    metrics[label] = dict(cpu_s=(int(stat[11])+int(stat[12]))/ticks, peak_rss_bytes=rss)
                except (FileNotFoundError, ProcessLookupError, TypeError):
                    pass
    def qdisc(loss=None):
        for name in names:
            if profile == 'g3' and loss is None:
                ns(name, 'tc', 'qdisc', 'replace', 'dev', 'eth0', 'root', 'handle', '1:', 'tbf', 'rate', '1mbit', 'burst', '16kb', 'latency', '500ms')
                ns(name, 'tc', 'qdisc', 'replace', 'dev', 'eth0', 'parent', '1:1', 'handle', '10:', 'netem', *PROFILES[profile])
            else:
                ns(name, 'tc', 'qdisc', 'replace', 'dev', 'eth0', 'root', 'handle', '1:', 'netem', *((PROFILES | DIAGNOSTIC_PROFILES)[profile] if loss is None else ['loss', loss]))
    def outage():
        try:
            deadline = time.monotonic()+args.timeout+10
            while not (root / 'started').exists():
                if stop.wait(.01):
                    return
                if time.monotonic() > deadline:
                    raise RuntimeError('No workload progress for outage trigger')
            qdisc('100%')
            (root / 'blocked').touch()
            row['outage_started_monotonic'] = time.monotonic()
            if stop.wait(10):
                raise RuntimeError('Workload ended before outage restored')
            if profile in ('rebind', 'relay-only') and mode == 'quic':
                (root / 'rebind').touch()
                # Wait for relay to acknowledge its newly bound upstream port.
                deadline = time.monotonic()+3
                while (root / 'relay.log').read_text().count('upstream_port=') < 2:
                    if time.monotonic() > deadline:
                        raise RuntimeError('Relay did not rebind')
                    time.sleep(.01)
            qdisc()
            row['outage_restored_monotonic'] = time.monotonic()
        except Exception as exc:
            errors.append(str(exc))
    monitor_thread = threading.Thread(target=monitor)
    event_thread = None
    profiler = None
    sample_stop = threading.Event()
    sampler = None
    try:
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                try:
                    comm = (proc / 'comm').read_text().strip()
                    cmd = (proc / 'cmdline').read_bytes()
                    if comm == 'trojan' or (b'harness.py\x00--internal\x00relay' in cmd):
                        raise RuntimeError(f'Leftover process {proc.name}: {comm}')
                except (FileNotFoundError, ProcessLookupError):
                    pass
        if command('ip', 'netns', 'list').stdout.strip():
            raise RuntimeError('Unexpected existing network namespaces')
        for name in names:
            command('ip', 'netns', 'add', name)
        command('ip', 'link', 'add', 'nb-c', 'type', 'veth', 'peer', 'name', 'nb-s')
        addresses = [f'{args.link_network.network_address + n}/{args.link_network.prefixlen}' for n in (1, 2)]
        for name, dev, addr in zip(names, ('nb-c', 'nb-s'), addresses):
            command('ip', 'link', 'set', dev, 'netns', name)
            ns(name, 'ip', 'link', 'set', dev, 'name', 'eth0')
            ns(name, 'ip', 'addr', 'add', addr, 'dev', 'eth0')
            ns(name, 'ip', 'link', 'set', 'eth0', 'up')
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        c_mac = ns(names[0], 'cat', '/sys/class/net/eth0/address').stdout.strip()
        s_mac = ns(names[1], 'cat', '/sys/class/net/eth0/address').stdout.strip()
        ns(names[0], 'ip', 'neigh', 'add', str(args.link_network.network_address + 2), 'lladdr', s_mac, 'dev', 'eth0', 'nud', 'permanent')
        ns(names[1], 'ip', 'neigh', 'add', str(args.link_network.network_address + 1), 'lladdr', c_mac, 'dev', 'eth0', 'nud', 'permanent')
        # Only write per-netns sysctls. Verify parent values remain unchanged.
        keys = ('net.core.rmem_max', 'net.core.wmem_max')
        parent = {key: command('sysctl', '-n', key, check=False).stdout.strip() for key in keys}
        row['sysctls'] = {}
        for name in names:
            row['sysctls'][name] = {}
            for key, value in zip(keys, (recv, send)):
                path = '/proc/sys/' + key.replace('.', '/')
                parent_inode = os.stat(path).st_ino if os.path.exists(path) else None
                result = ns(name, 'stat', '-c', '%i', path, check=False)
                isolated = result.returncode == 0 and int(result.stdout) != parent_inode
                attempt = ns(name, 'sysctl', '-w', f'{key}={max(value, 4194304)}', check=False) if isolated else None
                row['sysctls'][name][key] = dict(isolated=isolated, set_ok=attempt is not None and attempt.returncode == 0,
                                                               value=ns(name, 'sysctl', '-n', key, check=False).stdout.strip())
        if any(command('sysctl', '-n', key, check=False).stdout.strip() != value for key, value in parent.items()):
            raise RuntimeError('Parent sysctl changed unexpectedly')
        for label in ('client', 'server'):
            config = make_config(args, label, profile, mode, recv, send)
            (root / f'{label}.json').write_text(json.dumps(config, indent=2))
        launch(names[1], 'http', [sys.executable, __file__, '--internal', 'http', str(root)])
        if profile in ('rebind', 'relay-only') and mode == 'quic':
            launch(names[1], 'relay', [sys.executable, __file__, '--internal', 'relay', str(root), str(args.link_network.network_address + 2)])
        if args.netem_before_handshake:
            qdisc()
        launch(names[1], 'server', [args.binary, '-c', root / 'server.json'],
               quic_process_env(os.environ, args, root, 'server', mode))
        launch(names[0], 'client', [args.binary, '-c', root / 'client.json'],
               quic_process_env(os.environ, args, root, 'client', mode))
        monitor_thread.start()
        deadline = time.monotonic()+15
        while True:
            if any(p.poll() is not None for _, p in processes):
                raise RuntimeError('Service exited during startup')
            result = ns(names[0], sys.executable, __file__, '--internal', 'request', 'warm', '3', check=False)
            if result.returncode == 0:
                break
            if time.monotonic() > deadline:
                raise RuntimeError('Handshake failed: ' + result.stderr[-1000:])
            time.sleep(.05)
        if mode == 'quic':
            if args.log_level <= 1:
                row['buffers'] = {label: buffer_log((root / f'{label}.log').read_text(), recv, send) for label in ('client', 'server')}
            else:
                row['buffers'] = {label: socket_buffers(name, p.pid, recv, send)
                                  for label, p in processes if label in ('client', 'server')
                                  for name in [names[0] if label == 'client' else names[1]]}
            print(json.dumps(dict(cell=root.name, buffers=row['buffers'])), flush=True)
        else:
            row['buffers'] = None
        if not args.netem_before_handshake:
            qdisc()
        if profile.startswith('delay100-'):
            receiver = launch(names[1], 'probe', [sys.executable, __file__, '--internal', 'probe-receive', str(root)])
            deadline = time.monotonic()+5
            while not (root / 'probe-ready').exists():
                if receiver.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('UDP probe receiver failed to start')
                time.sleep(.01)
            ns(names[0], sys.executable, __file__, '--internal', 'probe-send', str(args.link_network.network_address+2), str(args.probe_spacing))
            receiver.wait(timeout=10)
            row['reordering_probe'] = json.loads((root / 'probe.log').read_text())
            if row['reordering_probe']['received'] != 5000:
                raise RuntimeError('UDP probe lost packets')
            if profile.endswith('ordered') and row['reordering_probe']['reordered']:
                raise RuntimeError('Ordered jitter probe detected reordering')
        row['qdisc_before'] = {name: ns(name, 'tc', '-s', 'qdisc', 'show', 'dev', 'eth0').stdout for name in names}
        endpoints = {label: p for label, p in processes if label in ('client', 'server')}
        row['endpoint_pids'] = {label: p.pid for label, p in endpoints.items()}
        sample_stop = threading.Event()
        def sample_threads():
            if not sample_stop.wait(4):
                server = next(p for label, p in processes if label == 'server')
                result = ns(names[1], 'top', '-H', '-b', '-d', '.5', '-n', '2', '-p', str(server.pid), check=False)
                (root / 'server-threads.log').write_text(result.stdout + result.stderr)
        sampler = None
        if not args.perf_role and args.log_level == 5 and profile == 'clean' and mode == 'quic':
            import shutil
            if shutil.which('top'):
                sampler = threading.Thread(target=sample_threads)
                sampler.start()
        if profile in ('outage', 'rebind'):
            (root / 'impair').touch()
            event_thread = threading.Thread(target=outage)
            event_thread.start()
        baseline_cpu = {label: cpu_snapshot(p.pid) for label, p in endpoints.items()}
        if args.perf_role:
            target = endpoints[args.perf_role]
            profiler = Profiler(args, root, target.pid)
            row['perf_pid'] = profiler.process.pid
            row['perf_target_pid'] = target.pid
            row['perf_command'] = profiler.argv
        measured_start = time.monotonic()
        row['transfer_started_monotonic'] = measured_start
        row['transfer_started_unix_ns'] = time.time_ns()
        worker_argv = ['ip', 'netns', 'exec', names[0], sys.executable, __file__, '--internal', 'worker', workload, str(args.timeout)]
        (root / 'workload.command.json').write_text(json.dumps(worker_argv, indent=2))
        try:
            result = sp.run(worker_argv, text=True, capture_output=True, timeout=args.timeout)
        except sp.TimeoutExpired as exc:
            result = sp.CompletedProcess(exc.cmd, 124, '', f'Hard workload deadline exceeded: {args.timeout}s')
        row['transfer_finished_monotonic'] = time.monotonic()
        row['transfer_finished_unix_ns'] = time.time_ns()
        row['attempt_duration_s'] = row['transfer_finished_monotonic'] - measured_start
        (root / 'workload.stdout').write_text(result.stdout)
        (root / 'workload.stderr').write_text(result.stderr)
        if result.returncode:
            row['error'] = result.stderr[-2000:]
        else:
            row.update(json.loads(result.stdout))
        row['transfer_cpu'] = {label: cpu_delta(baseline_cpu[label], cpu_snapshot(p.pid))
                               for label, p in endpoints.items()}
        row['transfer_cpu_s'] = {label: value['total_s'] for label, value in row['transfer_cpu'].items()}
        if profiler:
            profiler.finish()
            profiler = None
        sample_stop.set()
        if sampler:
            sampler.join()
        row['qdisc_after'] = {name: ns(name, 'tc', '-s', 'qdisc', 'show', 'dev', 'eth0').stdout for name in names}
    except Exception as exc:
        row['error'] = str(exc)
        row['fatal'] = True
    finally:
        if profiler:
            profiler.close()
        sample_stop.set()
        if sampler:
            sampler.join()
        stop.set()
        if event_thread:
            event_thread.join()
        if monitor_thread.ident:
            monitor_thread.join()
        for _, p in reversed(processes):
            p.terminate()
        for _, p in processes:
            try:
                p.wait(timeout=5)
            except sp.TimeoutExpired:
                p.kill()
                p.wait()
        for handle in handles:
            handle.close()
        for name in names:
            command('ip', 'netns', 'del', name, check=False)
    if errors:
        row.update(success=False, error='; '.join(errors), fatal=True)
    row['process_metrics'] = metrics
    duration = row.get('duration_s', row.get('attempt_duration_s', 0))
    row['cpu_share'] = {label: value/duration for label, value in row.get('transfer_cpu_s', {}).items()} if duration else {}
    texts = {label: (root / f'{label}.log').read_text(errors='replace') if (root / f'{label}.log').exists() else '' for label in ('client', 'server')}
    text = '\n'.join(texts.values())
    row['eagain'] = len(re.findall(r'send_packet[^\n]*failed: Try again', text))
    row['events'] = {term: sum(term.lower() in line.lower() for line in text.splitlines()) for term in ('connection recovery', 'handshake timeout', 'ERR_IDLE_CLOSE')}
    row['log_lines'] = {label: len(value.splitlines()) for label, value in texts.items()}
    row['all_log_indicators'] = {term: text.count(term) for term in ('send_stream_data_impl: loop break', 'UnackedBuf retry')} if args.log_level == 0 else None
    row['loss_log_lines'] = [line for line in text.splitlines() if re.search(r'\b(?:lost|retransmit\w*)\b', line, re.I)] if args.log_level == 1 else None
    row['quic_packets_sent'] = None  # No per-packet aggregate counter at this log level.
    def sent_bytes(output):
        return int(re.search(r'Sent (\d+) bytes', output)[1])
    if row.get('qdisc_after'):
        row['server_wire_bytes'] = sent_bytes(row['qdisc_after'][names[1]]) - sent_bytes(row['qdisc_before'][names[1]])
        row['payload_amplification'] = row['server_wire_bytes']/SIZES[workload] if workload == 'A' else None
    row['wire_packets'] = {name: sum(map(int, re.findall(r'Sent \d+ bytes (\d+) pkt', output.split('qdisc netem')[-1])))
                           for name, output in row.get('qdisc_after', {}).items()}
    with (args.output_dir / 'results.jsonl').open('a') as f:
        f.write(json.dumps(row)+'\n')
    print(json.dumps(row), flush=True)
    if row.get('fatal'):
        raise RuntimeError(f'Fatal cell {root}: {row.get("error")}')
    return row

def run_probe_only(args):
    profile = args.profile
    if profile not in (PROFILES | DIAGNOSTIC_PROFILES):
        raise SystemExit(f'Unknown profile for --probe-only: {profile}')
    import tempfile
    temp_dir = None
    if args.output_dir:
        args.output_dir = args.output_dir.resolve()
        if args.output_dir.is_relative_to(args.source.resolve()):
            raise SystemExit('Output directory must be outside source tree')
        args.output_dir.mkdir(parents=True, exist_ok=True)
        root = args.output_dir
    else:
        temp_dir = tempfile.TemporaryDirectory()
        root = Path(temp_dir.name)
    names = ['nb-client', 'nb-server']
    receiver = None
    try:
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                try:
                    comm = (proc / 'comm').read_text().strip()
                    cmd = (proc / 'cmdline').read_bytes()
                    if comm == 'trojan' or (b'harness.py\x00--internal\x00relay' in cmd):
                        raise RuntimeError(f'Leftover process {proc.name}: {comm}')
                except (FileNotFoundError, ProcessLookupError):
                    pass
        if command('ip', 'netns', 'list').stdout.strip():
            raise RuntimeError('Unexpected existing network namespaces')
        for name in names:
            command('ip', 'netns', 'add', name)
        command('ip', 'link', 'add', 'nb-c', 'type', 'veth', 'peer', 'name', 'nb-s')
        addresses = [f'{args.link_network.network_address + n}/{args.link_network.prefixlen}' for n in (1, 2)]
        for name, dev, addr in zip(names, ('nb-c', 'nb-s'), addresses):
            command('ip', 'link', 'set', dev, 'netns', name)
            ns(name, 'ip', 'link', 'set', dev, 'name', 'eth0')
            ns(name, 'ip', 'addr', 'add', addr, 'dev', 'eth0')
            ns(name, 'ip', 'link', 'set', 'eth0', 'up')
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        c_mac = ns(names[0], 'cat', '/sys/class/net/eth0/address').stdout.strip()
        s_mac = ns(names[1], 'cat', '/sys/class/net/eth0/address').stdout.strip()
        ns(names[0], 'ip', 'neigh', 'add', str(args.link_network.network_address + 2), 'lladdr', s_mac, 'dev', 'eth0', 'nud', 'permanent')
        ns(names[1], 'ip', 'neigh', 'add', str(args.link_network.network_address + 1), 'lladdr', c_mac, 'dev', 'eth0', 'nud', 'permanent')

        for name in names:
            if profile == 'g3':
                ns(name, 'tc', 'qdisc', 'replace', 'dev', 'eth0', 'root', 'handle', '1:', 'tbf', 'rate', '1mbit', 'burst', '16kb', 'latency', '500ms')
                ns(name, 'tc', 'qdisc', 'replace', 'dev', 'eth0', 'parent', '1:1', 'handle', '10:', 'netem', *PROFILES[profile])
            else:
                tc_args = (PROFILES | DIAGNOSTIC_PROFILES)[profile]
                ns(name, 'tc', 'qdisc', 'replace', 'dev', 'eth0', 'root', 'handle', '1:', 'netem', *tc_args)

        log_path = root / 'probe.log'
        with log_path.open('w') as log_file:
            receiver = sp.Popen(['ip', 'netns', 'exec', names[1], sys.executable, __file__, '--internal', 'probe-receive', str(root)],
                                stdout=log_file, stderr=sp.STDOUT)
            deadline = time.monotonic() + 5
            while not (root / 'probe-ready').exists():
                if receiver.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('UDP probe receiver failed to start')
                time.sleep(0.01)
            ns(names[0], sys.executable, __file__, '--internal', 'probe-send', str(args.link_network.network_address + 2), str(args.probe_spacing))
            receiver.wait(timeout=10)
        probe_data = json.loads(log_path.read_text())
        print(json.dumps(probe_data, indent=2), flush=True)
        if probe_data['received'] != 5000:
            raise RuntimeError('UDP probe lost packets')
        if profile.endswith('ordered') and probe_data['reordered']:
            raise RuntimeError('Ordered jitter probe detected reordering')
        return probe_data
    finally:
        if receiver and receiver.poll() is None:
            receiver.terminate()
            try:
                receiver.wait(timeout=2)
            except sp.TimeoutExpired:
                receiver.kill()
                receiver.wait()
        for name in names:
            command('ip', 'netns', 'del', name, check=False)
        if temp_dir:
            temp_dir.cleanup()


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile', choices=[*PROFILES, *DIAGNOSTIC_PROFILES, 'all'], default='all')
    p.add_argument('--buffer-size', type=int, choices=BUFFERS)
    p.add_argument('--recv-buffer', type=int)
    p.add_argument('--send-buffer', type=int)
    p.add_argument('--workload', choices=['A', 'B', 'C', 'all'], default='all')
    p.add_argument('--mode', choices=['quic', 'tcp', 'all'], default='all')
    p.add_argument('--repeat', type=int, default=3)
    p.add_argument('--slow-repeats', type=int, default=None)
    p.add_argument('--output-dir', type=Path)
    p.add_argument('--source', type=Path, default=Path('/work'))
    p.add_argument('--binary', type=Path, default=Path('/work/build/trojan'))
    p.add_argument('--log-level', type=int, choices=range(6), default=1,
                   help='Trojan log level: 0=ALL, 1=INFO (default), through 5=OFF; ss verifies buffers above INFO')
    p.add_argument('--link-network', type=link_network, default=link_network('10.88.0.0/24'),
                   help='Isolated IPv4 veth subnet; first two usable addresses are client/server')
    p.add_argument('--timeout', type=float, default=900)
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--probe-only', action='store_true',
                   help='Build namespaces, apply profile, run probe, print JSON, and clean up without running trojan')
    p.add_argument('--probe-spacing', type=float, default=0.001,
                   help='UDP probe spacing in seconds (default: 0.001)')
    p.set_defaults(quic_cc_explicit=False)
    p.add_argument('--quic-cc', choices=['bbr', 'cubic', 'reno'], default='bbr', action=QuicCcAction,
                   help='QUIC congestion control for both endpoints (TROJAN_QUIC_CC)')
    p.add_argument('--netem-before-handshake', action='store_true',
                   help='Apply profile qdisc before starting endpoints, not after warm-up')
    p.add_argument('--perf-role', choices=['server', 'client'], default=None,
                   help='Attach host perf to one endpoint after warm-up and probes')
    p.add_argument('--perf-kind', choices=['record', 'stat', 'syscalls', 'trace'], default='record')
    p.add_argument('--perf-host-output', type=Path,
                   help='Absolute host path corresponding to --output-dir; cell paths append root.name')
    p.add_argument('--quic-stats', action='store_true',
                   help='Write per-endpoint TROJAN_QUIC_STATS CSV into the cell log directory')
    return p

def plan(args):
    cells = []
    for profile in PROFILES if args.profile == 'all' else [args.profile]:
        repeats = args.slow_repeats if profile in ('g3', 'outage', 'rebind') and args.slow_repeats else args.repeat
        for workload in 'ABC' if args.workload == 'all' else args.workload:
            for mode in ('quic', 'tcp') if args.mode == 'all' else [args.mode]:
                if mode == 'tcp' and workload == 'C':
                    continue
                for buffer in ([args.buffer_size] if args.buffer_size else BUFFERS) if mode == 'quic' else [76800]:
                    for repeat in range(1, repeats+1):
                        cells.append((profile, workload, mode, args.recv_buffer or buffer, args.send_buffer or buffer, repeat))
    return cells

def require_quic_diagnostics(args):
    if (args.quic_stats or args.quic_cc_explicit) and b'quic stats: compiled in' not in args.binary.read_bytes():
        raise SystemExit('Binary lacks QUIC diagnostics; rebuild with -DTROJAN_QUIC_STATS=ON')


class QuicCcAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        namespace.quic_cc_explicit = True


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--internal':
        action = sys.argv[2]
        if action == 'probe-receive':
            return probe_receive(Path(sys.argv[3]))
        if action == 'probe-send':
            spacing = float(sys.argv[4]) if len(sys.argv) > 4 else 0.001
            return probe_send(sys.argv[3], spacing)
        if action == 'http':
            return http_server(Path(sys.argv[3]))
        if action == 'relay':
            return relay(Path(sys.argv[3]), sys.argv[4])
        value = request(sys.argv[3], float(sys.argv[4])) if action == 'request' else worker(sys.argv[3], float(sys.argv[4]))
        print(json.dumps(value))
        return
    args = parser().parse_args()
    if args.perf_role:
        if args.perf_host_output is None or not args.perf_host_output.is_absolute() or '..' in args.perf_host_output.parts:
            raise SystemExit('--perf-role requires an absolute --perf-host-output without ..')
        if args.quic_stats:
            raise SystemExit('Profiling measurements require QUIC stats OFF; omit --quic-stats')
        if args.probe_only:
            raise SystemExit('--perf-role cannot be used with --probe-only')
    if args.probe_only:
        if os.geteuid() != 0:
            raise SystemExit('Run inside a privileged container as root')
        for tool in ('ip', 'tc'):
            import shutil
            if not shutil.which(tool):
                raise SystemExit(f'Missing prerequisite: {tool}')
        if args.profile == 'all':
            raise SystemExit('--probe-only requires a specific --profile, not all')
        run_probe_only(args)
        return
    if not args.output_dir:
        raise SystemExit('the following arguments are required: --output-dir')
    if args.repeat < 1 or (args.slow_repeats is not None and args.slow_repeats < 1) or any(v is not None and v <= 0 for v in (args.recv_buffer, args.send_buffer, args.timeout)):
        raise SystemExit('Repeat counts, buffers and timeout must be positive')
    cells = plan(args)
    if args.dry_run:
        print(json.dumps(dict(cells=len(cells), plan=cells), indent=2))
        return
    args.output_dir = args.output_dir.resolve()
    if args.output_dir.is_relative_to(args.source.resolve()):
        raise SystemExit('Output directory must be outside source tree')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if (args.output_dir / 'results.jsonl').exists():
        raise SystemExit('Refusing to overwrite existing results; use a fresh output directory')
    if os.geteuid() != 0:
        raise SystemExit('Run inside a privileged container as root')
    for tool in ('ip', 'tc', 'sysctl', 'stat'):
        import shutil
        if not shutil.which(tool):
            raise SystemExit(f'Missing prerequisite: {tool}')
    if args.log_level > 1:
        import shutil
        if not shutil.which('ss'):
            raise SystemExit('Missing prerequisite: ss (buffer verification with logging disabled)')
    if not args.binary.is_file():
        raise SystemExit(f'Missing binary: {args.binary}')
    require_quic_diagnostics(args)
    rows = []
    for index, cell in enumerate(cells):
        rows.append(run_cell(args, *cell, index))
        (args.output_dir / 'aggregate.json').write_text(json.dumps(aggregate(rows), indent=2))
    if any(not row['success'] for row in rows):
        raise SystemExit('Measurement failures recorded; inspect results.jsonl and retained logs')

if __name__ == '__main__':
    main()
