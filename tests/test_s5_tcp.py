#!/usr/bin/env python3
"""Exercise real TCP accept paths. Pass BINARY or set S5_BINARY; otherwise skip."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = sys.argv.pop(1) if len(sys.argv) > 1 else os.environ.get('S5_BINARY')
if not BINARY:
    candidates = [Path(__file__).resolve().parents[1] / 'build/trojan']
    if os.environ.get('PIPELINE_WORKSPACE'):
        candidates.append(Path(os.environ['PIPELINE_WORKSPACE']) / 'LinuxBinary/trojan')
    BINARY = next((str(path) for path in candidates if path.is_file()), None)
if not BINARY and ('TF_BUILD' in os.environ or 'CI' in os.environ):
    sys.exit('S5 TCP: binary missing; pass BINARY, set S5_BINARY, or build build/trojan')


@unittest.skipUnless(BINARY, 'pass BINARY or set S5_BINARY')
class TcpHandshakeRegression(unittest.TestCase):
    def test_accept_paths(self):
        output = Path(os.environ.get('S5_LOG_DIR', tempfile.gettempdir()))
        output.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='s5-tcp-', dir=output))
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(work / 'key.pem'), '-out', str(work / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        failures = []
        for pipeline in (0, 1):
            for mode in ('default', 'empty', 'file', 'disabled'):
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0))
                    port = probe.getsockname()[1]
                override = work / 'response.txt'
                override.write_bytes(b'HTTP/1.1 418 Teapot\r\nContent-Length: 0\r\n\r\n')
                cfg = {'run_type': 'server', 'local_addr': '127.0.0.1', 'local_port': port,
                       'remote_addr': '127.0.0.1', 'remote_port': 1, 'password': ['s5-test'],
                       'log_level': 0, 'ssl': {'cert': str(work / 'cert.pem'), 'key': str(work / 'key.pem'),
                       'alpn': ['h2', 'http/1.1'], 'handshake_timeout': 0 if mode == 'disabled' else 1},
                       'experimental': {'pipeline_num': pipeline}}
                if mode == 'empty':
                    cfg['ssl']['plain_http_server'] = ''
                if mode == 'file':
                    cfg['ssl']['plain_http_response'] = str(override)
                path = work / f'{pipeline}-{mode}.json'
                path.write_text(json.dumps(cfg))
                with (work / f'{pipeline}-{mode}.log').open('wb') as log:
                    proc = subprocess.Popen([str(Path(BINARY).resolve()), '-c', str(path)], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        self.assertIsNone(proc.poll(), str(work))
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                self.fail('server readiness timeout: ' + str(work))
                            time.sleep(.02)

                    def raw(parts, timeout=3):
                        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as sock:
                            sock.settimeout(timeout)
                            for part in parts:
                                sock.sendall(part)
                            result = b''
                            while True:
                                chunk = sock.recv(4096)
                                if not chunk:
                                    return result
                                result += chunk

                    with self.subTest(pipeline=pipeline, mode=mode):
                        if mode == 'disabled':
                            with socket.create_connection(('127.0.0.1', port), timeout=2) as sock:
                                sock.settimeout(1.3)
                                with self.assertRaises(socket.timeout):
                                    sock.recv(1)
                            continue
                        started = time.monotonic()
                        self.assertEqual(raw([]), b'')
                        self.assertGreater(time.monotonic() - started, .7)
                        for garbage in (b'\xaa' * 50, b'\x16\x02\x00\x00\x05hello', b'\x16\x03\x01\xff\xff' + b'x' * 50):
                            self.assertEqual(raw([garbage]), b'')
                        response = raw([b'G', b'ET / HTTP/1.1\r\nHost: localhost\r\n\r\n'])
                        if mode == 'file':
                            self.assertEqual(response, override.read_bytes())
                        else:
                            headers, body = response.split(b'\r\n\r\n', 1)
                            self.assertTrue(headers.startswith(b'HTTP/1.1 400 Bad Request\r\n'))
                            self.assertIn(b'Content-Type: text/html', headers)
                            self.assertIn(b'Date: ', headers)
                            self.assertIn(b'Content-Length: ' + str(len(body)).encode(), headers)
                            self.assertIn(b'<center>The plain HTTP request was sent to HTTPS port</center>\r\n', body)
                            self.assertEqual(b'Server: nginx' in headers, mode != 'empty')
                            self.assertTrue(body.endswith(b'</body>\r\n</html>\r\n'))
                        for offered, expected in ((['h2'], 'h2'), (['http/1.1'], 'http/1.1'), (['unknown'], None)):
                            ctx = ssl._create_unverified_context()
                            ctx.set_alpn_protocols(offered)
                            with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
                                if expected:
                                    with ctx.wrap_socket(sock, server_hostname='unknown.example') as tls:
                                        self.assertEqual(tls.selected_alpn_protocol(), expected)
                                        if pipeline and mode == 'default' and expected == 'h2':
                                            tls.settimeout(5)
                                            self.assertEqual(tls.recv(1), b'', 'pipeline authentication deadline missing')
                                else:
                                    with self.assertRaisesRegex(ssl.SSLError, 'NO_APPLICATION_PROTOCOL'):
                                        ctx.wrap_socket(sock, server_hostname='localhost')
                except Exception as exc:
                    failures.append(f'{pipeline}/{mode}: {exc}')
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
        self.assertFalse(failures, '\n'.join(failures) + '\nEvidence: ' + str(work))


if __name__ == '__main__':
    if not BINARY:
        print('SKIP S5 TCP: pass BINARY, set S5_BINARY, or build build/trojan')
    unittest.main()
