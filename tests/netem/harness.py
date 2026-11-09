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

def aggregate(rows):
    groups = {}
    for row in rows:
        key = (row['profile'], row['workload'], row['mode'], row['recv_buffer'], row['send_buffer'])
        groups.setdefault(key, []).append(row)
    output = []
    for key, group in groups.items():
        good = [r for r in group if r['success']]
        item = dict(zip(('profile', 'workload', 'mode', 'recv_buffer', 'send_buffer'), key))
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
    config['local_port'] = 1080 if label == 'client' else (4434 if profile == 'rebind' and mode == 'quic' else 4433)
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
               logs=str(root), success=False, sha256_ok=False)
    def launch(name, label, argv):
        handle = (root / f'{label}.log').open('w')
        handles.append(handle)
        p = sp.Popen(['ip', 'netns', 'exec', name, *map(str, argv)], stdout=handle, stderr=handle)
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
                ns(name, 'tc', 'qdisc', 'replace', 'dev', 'eth0', 'root', 'netem', *(PROFILES[profile] if loss is None else ['loss', loss]))
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
            if profile == 'rebind' and mode == 'quic':
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
        if profile == 'rebind' and mode == 'quic':
            launch(names[1], 'relay', [sys.executable, __file__, '--internal', 'relay', str(root), str(args.link_network.network_address + 2)])
        launch(names[1], 'server', [args.binary, '-c', root / 'server.json'])
        launch(names[0], 'client', [args.binary, '-c', root / 'client.json'])
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
            row['buffers'] = {label: buffer_log((root / f'{label}.log').read_text(), recv, send) for label in ('client', 'server')}
            print(json.dumps(dict(cell=root.name, buffers=row['buffers'])), flush=True)
        else:
            row['buffers'] = None
        qdisc()
        row['qdisc_before'] = {name: ns(name, 'tc', '-s', 'qdisc', 'show', 'dev', 'eth0').stdout for name in names}
        if profile in ('outage', 'rebind'):
            (root / 'impair').touch()
            event_thread = threading.Thread(target=outage)
            event_thread.start()
        measured_start = time.monotonic()
        try:
            result = sp.run(['ip', 'netns', 'exec', names[0], sys.executable, __file__, '--internal', 'worker', workload, str(args.timeout)],
                            text=True, capture_output=True, timeout=args.timeout)
        except sp.TimeoutExpired as exc:
            result = sp.CompletedProcess(exc.cmd, 124, '', f'Hard workload deadline exceeded: {args.timeout}s')
        row['attempt_duration_s'] = time.monotonic() - measured_start
        (root / 'workload.stdout').write_text(result.stdout)
        (root / 'workload.stderr').write_text(result.stderr)
        if result.returncode:
            row['error'] = result.stderr[-2000:]
        else:
            row.update(json.loads(result.stdout))
        row['qdisc_after'] = {name: ns(name, 'tc', '-s', 'qdisc', 'show', 'dev', 'eth0').stdout for name in names}
    except Exception as exc:
        row['error'] = str(exc)
        row['fatal'] = True
    finally:
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
    texts = {label: (root / f'{label}.log').read_text(errors='replace') if (root / f'{label}.log').exists() else '' for label in ('client', 'server')}
    text = '\n'.join(texts.values())
    row['eagain'] = len(re.findall(r'send_packet[^\n]*failed: Try again', text))
    row['events'] = {term: sum(term.lower() in line.lower() for line in text.splitlines()) for term in ('connection recovery', 'handshake timeout', 'ERR_IDLE_CLOSE')}
    row['quic_packets_sent'] = None  # No per-packet aggregate counter at this log level.
    row['wire_packets'] = {name: sum(map(int, re.findall(r'Sent \d+ bytes (\d+) pkt', output.split('qdisc netem')[-1])))
                           for name, output in row.get('qdisc_after', {}).items()}
    with (args.output_dir / 'results.jsonl').open('a') as f:
        f.write(json.dumps(row)+'\n')
    print(json.dumps(row), flush=True)
    if row.get('fatal'):
        raise RuntimeError(f'Fatal cell {root}: {row.get("error")}')
    return row

def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile', choices=[*PROFILES, 'all'], default='all')
    p.add_argument('--buffer-size', type=int, choices=BUFFERS)
    p.add_argument('--recv-buffer', type=int)
    p.add_argument('--send-buffer', type=int)
    p.add_argument('--workload', choices=['A', 'B', 'C', 'all'], default='all')
    p.add_argument('--mode', choices=['quic', 'tcp', 'all'], default='all')
    p.add_argument('--repeat', type=int, default=3)
    p.add_argument('--slow-repeats', type=int, default=None)
    p.add_argument('--output-dir', type=Path, required=True)
    p.add_argument('--source', type=Path, default=Path('/work'))
    p.add_argument('--binary', type=Path, default=Path('/work/build/trojan'))
    p.add_argument('--log-level', type=int, choices=range(6), default=1,
                   help='Trojan log level: 0=ALL, 1=INFO (default), through 5=OFF; levels above INFO may omit required buffer logs')
    p.add_argument('--link-network', type=link_network, default=link_network('10.88.0.0/24'),
                   help='Isolated IPv4 veth subnet; first two usable addresses are client/server')
    p.add_argument('--timeout', type=float, default=900)
    p.add_argument('--dry-run', action='store_true')
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

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--internal':
        action = sys.argv[2]
        if action == 'http':
            return http_server(Path(sys.argv[3]))
        if action == 'relay':
            return relay(Path(sys.argv[3]), sys.argv[4])
        value = request(sys.argv[3], float(sys.argv[4])) if action == 'request' else worker(sys.argv[3], float(sys.argv[4]))
        print(json.dumps(value))
        return
    args = parser().parse_args()
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
    if not args.binary.is_file():
        raise SystemExit(f'Missing binary: {args.binary}')
    rows = []
    for index, cell in enumerate(cells):
        rows.append(run_cell(args, *cell, index))
        (args.output_dir / 'aggregate.json').write_text(json.dumps(aggregate(rows), indent=2))
    if any(not row['success'] for row in rows):
        raise SystemExit('Measurement failures recorded; inspect results.jsonl and retained logs')

if __name__ == '__main__':
    main()
