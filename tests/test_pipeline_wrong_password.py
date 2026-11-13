#!/usr/bin/env python3
"""Pipeline wrong-password handoff must move the accepted socket at most once."""
import json
import os
from pathlib import Path
import signal
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
    sys.exit('pipeline wrong-password: binary missing; pass BINARY, set S5_BINARY, or build build/trojan')

MOVE_LOG = 'std::move data to ServerSession'
# Longer than Config::MAX_PASSWORD_LENGTH (EVP_MAX_MD_SIZE << 1) and not a password prefix.
TOO_LONG = b'Z' * 160
WRONG_PP = b'00' * 28 + b'\r\nPP'


@unittest.skipUnless(BINARY, 'pass BINARY or set S5_BINARY')
class PipelineWrongPassword(unittest.TestCase):
    def setUp(self):
        self.output = Path(os.environ.get('S5_LOG_DIR', tempfile.gettempdir()))
        self.output.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix='pipe-wp-', dir=self.output))
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
             '-keyout', str(self.work / 'key.pem'), '-out', str(self.work / 'cert.pem'),
             '-days', '1', '-subj', '/CN=localhost'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.proc = None
        self.log = None

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.kill(self.proc.pid, signal.SIGCONT)
            except OSError:
                pass
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.log is not None and not self.log.closed:
            self.log.close()

    def _start(self, name):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        cfg = {
            'run_type': 'server', 'local_addr': '127.0.0.1', 'local_port': port,
            'remote_addr': '127.0.0.1', 'remote_port': 1, 'password': ['pipe-wp'],
            'log_level': 0,
            'ssl': {
                'cert': str(self.work / 'cert.pem'), 'key': str(self.work / 'key.pem'),
                'alpn': ['h2', 'http/1.1'], 'handshake_timeout': 0,
            },
            'experimental': {'pipeline_num': 1},
        }
        path = self.work / f'{name}.json'
        path.write_text(json.dumps(cfg))
        log_path = self.work / f'{name}.log'
        self.log = log_path.open('wb')
        self.proc = subprocess.Popen(
            [str(Path(BINARY).resolve()), '-c', str(path)], stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while True:
            self.assertIsNone(self.proc.poll(), self._evidence(name))
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    return port, log_path
            except OSError:
                if time.monotonic() >= deadline:
                    self.fail('server readiness timeout: ' + self._evidence(name))
                time.sleep(0.02)

    def _tls(self, port):
        ctx = ssl._create_unverified_context()
        ctx.set_alpn_protocols(['http/1.1'])
        raw = socket.create_connection(('127.0.0.1', port), timeout=3)
        tls = ctx.wrap_socket(raw, server_hostname='localhost')
        tls.settimeout(2)
        return tls

    def _evidence(self, name):
        path = self.work / f'{name}.log'
        text = path.read_text(errors='replace') if path.exists() else ''
        return f'{path}\n{text[-4000:]}'

    def _assert_once(self, name, log_path):
        self.assertIsNone(self.proc.poll(), self._evidence(name))
        text = log_path.read_text(errors='replace')
        self.assertNotIn('AddressSanitizer', text, self._evidence(name))
        self.assertNotIn('runtime error:', text, self._evidence(name))
        self.assertNotIn('Error: signal', text, self._evidence(name))
        self.assertEqual(text.count(MOVE_LOG), 1, self._evidence(name))

    def _send(self, port, parts, close=False):
        tls = self._tls(port)
        try:
            for part in parts:
                tls.sendall(part)
                time.sleep(0.05)
            if close:
                try:
                    tls.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        finally:
            tls.close()

    def _same_turn(self, name, payload):
        # Handshake arms a 3s gc timer and a read. Freeze the process so the
        # payload and the timer expiry are both ready before either handler runs.
        # epoll reports the socket first; the read moves the socket and destroy()
        # cannot abort the already-queued timer completion.
        port, log_path = self._start(name)
        tls = self._tls(port)
        try:
            # Wait until the handshake handler has armed the gc timer and blocked.
            # Stopping earlier lets the read complete before the timer is queued.
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                self.assertIsNone(self.proc.poll(), self._evidence(name))
                if Path(f'/proc/{self.proc.pid}/wchan').read_text().strip() == 'ep_poll':
                    break
                time.sleep(0.01)
            else:
                self.fail('server did not block in epoll_wait: ' + self._evidence(name))
            os.kill(self.proc.pid, signal.SIGSTOP)
            tls.sendall(payload)
            time.sleep(3.3)
            os.kill(self.proc.pid, signal.SIGCONT)
            time.sleep(0.4)
        finally:
            try:
                os.kill(self.proc.pid, signal.SIGCONT)
            except OSError:
                pass
            try:
                tls.close()
            except OSError:
                pass
        self._assert_once(name, log_path)

    def test_timer_same_turn_nonprefix(self):
        self._same_turn('timer-nonprefix', b'ZZ')

    def test_timer_same_turn_too_long(self):
        self._same_turn('timer-toolong', TOO_LONG)

    def test_timer_same_turn_wrong_password(self):
        self._same_turn('timer-wrong', WRONG_PP)

    def test_immediate_branches(self):
        cases = (
            ('nonprefix', [b'ZZ'], False),
            ('toolong', [TOO_LONG], False),
            ('wrong-pp', [WRONG_PP], False),
            ('split', [b'0', b'ZZ'], False),
            ('close-after', [b'ZZ'], True),
        )
        for name, parts, close in cases:
            with self.subTest(name=name):
                port, log_path = self._start(name)
                self._send(port, parts, close=close)
                time.sleep(0.3)
                self._assert_once(name, log_path)
                self.proc.terminate()
                self.proc.wait(timeout=3)
                self.proc = None
                self.log.close()
                self.log = None


if __name__ == '__main__':
    if not BINARY:
        print('SKIP pipeline wrong-password: pass BINARY, set S5_BINARY, or build build/trojan')
    unittest.main()
