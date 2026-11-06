#!/usr/bin/env python3
"""Real TLS padding regressions. Pass BINARY or set S2_BINARY; never skip in CI.

Temporary artifacts are cleaned up; set S2_LOG_DIR to retain output instead.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

BINARY = sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else os.environ.get('S2_BINARY')
if not BINARY:
    candidates = [Path(__file__).resolve().parents[1] / 'build/trojan']
    if os.environ.get('PIPELINE_WORKSPACE'):
        candidates.append(Path(os.environ['PIPELINE_WORKSPACE']) / 'LinuxBinary/trojan')
    BINARY = next((str(path) for path in candidates if path.is_file()), None)
if not BINARY and ('TF_BUILD' in os.environ or 'CI' in os.environ):
    sys.exit('S2 padding: binary missing; pass BINARY, set S2_BINARY, or build build/trojan')

PASSWORD = 's2-integration-test'
PASSWORD_HASH = hashlib.sha224(PASSWORD.encode()).hexdigest().encode()
TIMEOUT = 10


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError('connection closed before expected bytes')
        result.extend(chunk)
    return bytes(result)


def frame(kind, payload=b''):
    return struct.pack('!BH', kind, len(payload)) + payload


def address(port):
    return b'\x01\x7f\x00\x00\x01' + struct.pack('!H', port)


def request(command, port):
    return PASSWORD_HASH + b'\r\n' + bytes([command]) + address(port) + b'\r\n'


class Peer:
    """Bound local fixture; close sockets before joining every worker."""
    def __init__(self, handler, context=None):
        self.handler = handler
        self.context = context
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.sockets = set()
        self.workers = []
        self.errors = []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(.2)
        self.thread = threading.Thread(target=self.accept, name='s2-listener')
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                sock, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.stopped.is_set():
                    self.errors.append(sys.exc_info()[1])
                return
            sock.settimeout(TIMEOUT)
            with self.lock:
                self.sockets.add(sock)
            worker = threading.Thread(target=self.serve, args=(sock,), name='s2-peer')
            self.workers.append(worker)
            worker.start()

    def serve(self, sock):
        try:
            if self.context:
                # Track the SSLSocket before handshake so shutdown can interrupt it.
                wrapped = self.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
                with self.lock:
                    self.sockets.discard(sock)
                    self.sockets.add(wrapped)
                sock = wrapped
                sock.do_handshake()
            self.handler(sock)
        except (ConnectionError, EOFError, ssl.SSLError):
            pass  # Peers may abort TLS or close with an in-flight echo.
        except Exception as exc:
            if not self.stopped.is_set():
                self.errors.append(exc)
        finally:
            with self.lock:
                self.sockets.discard(sock)
            sock.close()

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(TIMEOUT)
        with self.lock:
            for sock in self.sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        for worker in self.workers:
            worker.join(TIMEOUT)
        if self.thread.is_alive() or any(worker.is_alive() for worker in self.workers):
            raise AssertionError('fixture thread failed to stop')
        if self.errors:
            raise AssertionError(f'fixture failures: {self.errors}')


def echo(sock):
    while True:
        data = sock.recv(65536)
        if not data:
            return
        sock.sendall(data)


class Process:
    def __init__(self, work, name, config):
        self.ready = threading.Event()
        path = work / (name + '.json')
        path.write_text(json.dumps(config, indent=2))
        self.log = (work / (name + '.log')).open('wb')
        self.proc = subprocess.Popen([str(Path(BINARY).resolve()), '-c', str(path)],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.reader = threading.Thread(target=self.capture, name='s2-log')
        self.reader.start()
        if not self.ready.wait(TIMEOUT):
            self.close()
            raise AssertionError(f'binary readiness timeout; evidence: {work}')
        if self.proc.poll() is not None:
            self.close()
            raise AssertionError(f'binary exited during startup; evidence: {work}')

    def capture(self):
        for line in self.proc.stdout:
            self.log.write(line)
            self.log.flush()
            if b'service (' in line and b') started at ' in line:
                self.ready.set()

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(TIMEOUT)
        self.reader.join(TIMEOUT)
        self.proc.stdout.close()
        self.log.close()
        if self.reader.is_alive():
            raise AssertionError('binary log reader failed to stop')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class PaddingReader:
    def __init__(self, sock):
        self.sock = sock
        self.ended = False
        self.data_bytes = 0
        self.pending = bytearray()

    def read(self, size):
        while len(self.pending) < size:
            if self.ended:
                self.pending.extend(exact(self.sock, size - len(self.pending)))
                break
            # Read headers byte by byte; never assume TLS record or recv boundaries.
            kind, length = struct.unpack('!BH', b''.join(exact(self.sock, 1) for _ in range(3)))
            if kind > 2 or length > 1447 or (kind == 2 and length):
                raise AssertionError(f'invalid response frame: {kind}/{length}')
            payload = exact(self.sock, length)
            if kind == 0:
                self.data_bytes += length
                self.pending.extend(payload)
            elif kind == 2:
                self.ended = True
        result = bytes(self.pending[:size])
        del self.pending[:size]
        return result


@unittest.skipUnless(BINARY, 'pass BINARY or set S2_BINARY')
class PaddingIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output = os.environ.get('S2_LOG_DIR')
        if output:
            Path(output).mkdir(parents=True, exist_ok=True)
            cls.work = Path(tempfile.mkdtemp(prefix='s2-padding-', dir=output))
        else:
            work = tempfile.TemporaryDirectory(prefix='s2-padding-')
            cls.addClassCleanup(work.cleanup)
            cls.work = Path(work.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(cls.work / 'key.pem'), '-out', str(cls.work / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def config(self, mode, port, remote_port):
        return {'run_type': mode, 'local_addr': '127.0.0.1', 'local_port': port,
                'remote_addr': '127.0.0.1', 'remote_port': remote_port,
                'password': [PASSWORD], 'log_level': 0,
                'ssl': {'cert': str(self.work / 'cert.pem'), 'key': str(self.work / 'key.pem'),
                        'verify': False, 'verify_hostname': False, 'sni': 'localhost',
                        'alpn': ['http/1.1']}, 'experimental': {'pipeline_num': 0}}

    def server(self, name, budget=None, flush_limit=None):
        target = Peer(echo)
        self.addCleanup(target.close)
        port = free_port()
        cfg = self.config('server', port, 1)
        if budget is not None:
            cfg['ssl']['padding_bytes'] = budget
        if flush_limit is not None:
            cfg['ssl']['padding_flushes'] = flush_limit
        proc = Process(self.work, name, cfg)
        self.addCleanup(proc.close)
        return port, target.port

    def tls(self, port):
        sock = socket.create_connection(('127.0.0.1', port), TIMEOUT)
        self.addCleanup(sock.close)
        ctx = ssl._create_unverified_context()
        ctx.set_alpn_protocols(['http/1.1'])
        tls = ctx.wrap_socket(sock, server_hostname='localhost')
        self.addCleanup(tls.close)
        return tls

    def test_server_split_frames_end_and_default_budget(self):
        port, target = self.server('server-default', flush_limit=0)
        with self.tls(port) as tls:
            header = request(5, target)
            for part in (header[:1], header[1:57], header[57:60], header[60:]):
                tls.sendall(part)
            reader = PaddingReader(tls)
            first = frame(0, b'partial payload')
            # Exercise partial frame header, partial payload, PAD, then another DATA.
            for part in (first[:1], first[1:2], first[2:5], first[5:]):
                tls.sendall(part)
            self.assertEqual(reader.read(15), b'partial payload')
            raw = bytes(range(256)) * 80
            tls.sendall(frame(1, b'ignored padding') + frame(0, b'next') + frame(2) + raw)
            self.assertEqual(reader.read(4 + len(raw)), b'next' + raw)
            self.assertTrue(reader.ended)
            self.assertEqual(reader.data_bytes, 16384)
            tls.sendall(b'raw after END\x02\x00\x00')
            self.assertEqual(reader.read(16), b'raw after END\x02\x00\x00')

    def test_server_zero_budget(self):
        port, target = self.server('server-zero', 0)
        with self.tls(port) as tls:
            tls.sendall(request(5, target) + frame(0, b'zero budget') + frame(2) + b'raw')
            self.assertEqual(exact(tls, 3), frame(2))
            self.assertEqual(exact(tls, 14), b'zero budgetraw')
            tls.sendall(b'still raw')
            self.assertEqual(exact(tls, 9), b'still raw')

    def test_server_legacy_command(self):
        port, target = self.server('server-legacy')
        with self.tls(port) as tls:
            payload = b'legacy\x00\x00\x04data\x02\x00\x00'
            tls.sendall(request(1, target) + payload)
            self.assertEqual(exact(tls, len(payload)), payload)

    def test_server_rejects_malformed_frames(self):
        port, target = self.server('server-malformed')
        for bad in (b'\x03\x00\x00', b'\xff\x00\x00', b'\x00\x05\xa8',
                    b'\x01\xff\xff', b'\x02\x00\x01x'):
            with self.subTest(frame=bad.hex()), self.tls(port) as tls:
                tls.sendall(request(5, target) + bad)
                try:
                    self.assertEqual(tls.recv(1), b'')
                except (ConnectionResetError, ssl.SSLError):
                    pass

    def test_client_large_upload_before_response(self):
        payload = bytes(range(256)) * 320  # 81920 bytes; response waits for entire upload.
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'
        received = threading.Event()

        def target(sock):
            self.assertEqual(exact(sock, len(payload)), payload)
            received.set()
            sock.sendall(response)

        peer = Peer(target)
        self.addCleanup(peer.close)
        server_port = free_port()
        server = Process(self.work, 'server-large-upload', self.config('server', server_port, 1))
        self.addCleanup(server.close)
        port = free_port()
        client = Process(self.work, 'client-large-upload', self.config('client', port, server_port))
        self.addCleanup(lambda: client.close() if not client.log.closed else None)
        with socket.create_connection(('127.0.0.1', port), TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            sock.sendall(b'\x05\x01\x00')
            self.assertEqual(exact(sock, 2), b'\x05\x00')
            sock.sendall(b'\x05\x01\x00' + address(peer.port))
            self.assertEqual(exact(sock, 3), b'\x05\x00\x00')
            atyp = exact(sock, 1)[0]
            if atyp == 1:
                exact(sock, 6)
            elif atyp == 4:
                exact(sock, 18)
            elif atyp == 3:
                exact(sock, exact(sock, 1)[0] + 2)
            else:
                self.fail(f'unknown SOCKS reply ATYP: {atyp}')
            sock.sendall(payload)
            self.assertEqual(exact(sock, len(response)), response)
        self.assertTrue(received.is_set())
        client.close()
        self.assertEqual((self.work / 'client-large-upload.log').read_text().count('S2 replay cap reached'), 1)

    def test_client_legacy_retry_and_memo(self):
        self.check_client_legacy_retry_and_memo(False)

    def test_client_upload_retry_preserves_payload(self):
        self.check_client_legacy_retry_and_memo(True)

    def check_client_legacy_retry_and_memo(self, upload):
        upload_payload = bytes(range(256)) * 192  # 49152 bytes, below replay cap.
        commands = []
        lock = threading.Lock()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.work / 'cert.pem', self.work / 'key.pem')
        ctx.set_alpn_protocols(['http/1.1'])

        def legacy(sock):
            self.assertEqual(exact(sock, 58), PASSWORD_HASH + b'\r\n')
            command, atyp = exact(sock, 2)
            with lock:
                commands.append(command)
            if atyp == 1:
                exact(sock, 6)
            elif atyp == 4:
                exact(sock, 18)
            elif atyp == 3:
                exact(sock, exact(sock, 1)[0] + 2)
            else:
                raise AssertionError(f'unknown ATYP: {atyp}')
            self.assertEqual(exact(sock, 2), b'\r\n')
            if command == 5:
                if upload:
                    self.assertEqual(PaddingReader(sock).read(len(upload_payload)), upload_payload)
                sock.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                return
            self.assertEqual(command, 1)
            if upload:
                self.assertEqual(exact(sock, len(upload_payload)), upload_payload)
                sock.sendall(upload_payload)
            else:
                echo(sock)

        peer = Peer(legacy, ctx)
        self.addCleanup(peer.close)
        port = free_port()
        # Leave ssl.padding absent: default-on must attempt command 5.
        name = 'client-upload-retry' if upload else 'client-legacy-retry'
        proc = Process(self.work, name, self.config('client', port, peer.port))
        self.addCleanup(proc.close)
        for index in range(2):
            with socket.create_connection(('127.0.0.1', port), TIMEOUT) as sock:
                sock.settimeout(TIMEOUT)
                sock.sendall(b'\x05\x01\x00')
                self.assertEqual(exact(sock, 2), b'\x05\x00')
                sock.sendall(b'\x05\x01\x00' + address(23456))
                self.assertEqual(exact(sock, 3), b'\x05\x00\x00')
                atyp = exact(sock, 1)[0]
                if atyp == 1:
                    exact(sock, 6)
                elif atyp == 4:
                    exact(sock, 18)
                elif atyp == 3:
                    exact(sock, exact(sock, 1)[0] + 2)
                else:
                    self.fail(f'unknown SOCKS reply ATYP: {atyp}')
                payload = upload_payload if upload else f'connection {index}: retry preserves original payload'.encode()
                sock.sendall(payload)
                self.assertEqual(exact(sock, len(payload)), payload)
            with lock:
                self.assertEqual(commands, [5, 1] if index == 0 else [5, 1, 1])


if __name__ == '__main__':
    if not BINARY:
        print('SKIP S2 padding: pass BINARY, set S2_BINARY, or build build/trojan')
    unittest.main()
