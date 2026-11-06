#!/usr/bin/env python3
"""Local QUIC Initial recovery regression; no root or third-party Python modules.

Usage: python3 tests/test_quic_initial_loss.py --binary /absolute/path/to/trojan \
    --output-dir /tmp/opencode/quic-initial-results

Runs native (none) and chrome clients against unchanged server configuration.
The 5% case uses deterministic bidirectional UDP datagram loss, NOT tc netem.
This is extra regression coverage, not a replacement for task-level netem runs.
Without --binary, run pure helper self-checks and skip live integration.
Artifacts contain only disposable fixture configuration, public certificate,
logs and metadata; never supply production credentials. Private key is temporary
and removed on exit. Every invocation creates a unique retained result directory.
"""

import argparse
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = bytes(range(256)) * 4096
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
HANDSHAKE = "QuicConnection: handshake completed"


def drop_packet(mode, direction, count):
    return ((mode == "loss5" and count % 20 == 0) or
            (mode == "first_reply" and direction == "server" and count == 1))


def is_initial(data):
    # These fixtures use QUIC v1; version negotiation is not an Initial.
    return (len(data) >= 6 and data[0] & 0xf0 == 0xc0 and
            data[1:5] == b"\x00\x00\x00\x01")


class Relay:
    """One client per case, separate sockets preserve server/client direction."""

    def __init__(self, server_port, mode):
        self.mode = mode
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.back.bind(("127.0.0.1", 0))
        self.back.connect(("127.0.0.1", server_port))
        self.port = self.front.getsockname()[1]
        self.stop = threading.Event()
        self.error = None
        self.stats = {d: {"received": 0, "dropped": 0, "initials": 0,
                          "initials_dropped": 0} for d in ("client", "server")}
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        client = None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.front, selectors.EVENT_READ, "client")
                selector.register(self.back, selectors.EVENT_READ, "server")
                while not self.stop.is_set():
                    for key, _ in selector.select(timeout=0.1):
                        data, address = key.fileobj.recvfrom(65535)
                        direction = key.data
                        if direction == "client":
                            if client is not None and address != client:
                                raise RuntimeError("unexpected second relay client")
                            client = address
                        stats = self.stats[direction]
                        stats["received"] += 1
                        initial = is_initial(data)
                        stats["initials"] += int(initial)
                        if drop_packet(self.mode, direction, stats["received"]):
                            stats["dropped"] += 1
                            stats["initials_dropped"] += int(initial)
                            continue
                        if direction == "client":
                            self.back.send(data)
                        elif client is not None:
                            self.front.sendto(data, client)
        except Exception as error:
            self.error = repr(error)

    def close(self):
        self.stop.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=2)
        self.front.close()
        self.back.close()
        if self.thread.is_alive():
            raise RuntimeError("relay failed to stop")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def free_port():
    # Reserve TCP and check UDP together; subprocess bind still has a small race.
    with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(("127.0.0.1", 0))
        port = tcp.getsockname()[1]
        udp.bind(("127.0.0.1", port))
        return port


def wait_until(predicate, deadline, processes):
    wake = threading.Event()
    while True:
        if predicate():
            return
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"trojan exited early: {process.returncode}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("readiness/handshake deadline exceeded")
        wake.wait(min(0.05, remaining))


def has_log(path, text):
    return text in path.read_text(encoding="utf-8", errors="replace")


def socks_ready(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
            return True
    except OSError:
        return False


def receive(sock, size, deadline):
    result = bytearray()
    while len(result) < size:
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        if time.monotonic() >= deadline:
            raise TimeoutError("SOCKS deadline exceeded")
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("truncated SOCKS reply")
        result.extend(chunk)
    return bytes(result)


def transfer(proxy_port, http_port, deadline):
    with socket.create_connection(("127.0.0.1", proxy_port),
                                  timeout=max(0.001, deadline - time.monotonic())) as sock:
        sock.sendall(b"\x05\x01\x00")
        if receive(sock, 2, deadline) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication failed")
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", http_port))
        reply = receive(sock, 4, deadline)
        if reply[:3] != b"\x05\x00\x00":
            raise RuntimeError(f"SOCKS CONNECT failed: {reply.hex()}")
        if reply[3] == 1:
            receive(sock, 6, deadline)
        elif reply[3] == 4:
            receive(sock, 18, deadline)
        elif reply[3] == 3:
            receive(sock, receive(sock, 1, deadline)[0] + 2, deadline)
        else:
            raise RuntimeError("invalid SOCKS address type")
        sock.sendall(b"GET /payload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        with http.client.HTTPResponse(sock) as response:
            response.begin()
            if response.status != 200 or response.getheader("Content-Length") != str(len(PAYLOAD)):
                raise RuntimeError("unexpected HTTP status or length")
            digest = hashlib.sha256()
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("HTTP transfer deadline exceeded")
                sock.settimeout(remaining)
                chunk = response.read1(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > len(PAYLOAD):
                    raise RuntimeError("oversized HTTP body")
                digest.update(chunk)
    if size != len(PAYLOAD) or digest.hexdigest() != DIGEST:
        raise RuntimeError(f"payload mismatch: bytes={size}, sha256={digest.hexdigest()}")
    return {"bytes": size, "sha256": digest.hexdigest()}


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/payload":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *_args):
        pass


def run_case(binary, directory, profile, mode, cert, key, http_port, timeout):
    directory.mkdir()
    processes = []
    relay = None
    result = {"profile": profile, "mode": mode, "loss_backend": "deterministic UDP relay, NOT tc netem",
              "status": "failed"}
    try:
        with contextlib.ExitStack() as stack:
            server_port = free_port()
            relay = Relay(server_port, mode)
            stack.callback(relay.close)
            relay.thread.start()
            proxy_port = free_port()
            configs = {}
            for role, template in (("server", "quic_server_config.json"),
                                   ("client", "quic_client_config.json")):
                config = json.loads((ROOT / "tests/LinuxFullTest/config" / template).read_text())
                config["local_port"] = server_port if role == "server" else proxy_port
                config["remote_port"] = http_port if role == "server" else relay.port
                config["password"] = ["public-quic-initial-loss-test-fixture"]
                config["ssl"]["cert"] = str(cert)
                config["quic"]["debug_disable_tcp"] = True
                config["tcp"]["reuse_port"] = False
                if role == "server":
                    config["ssl"]["key"] = str(key)
                    config["ssl"].pop("key_password", None)
                else:
                    config["ssl"]["fingerprint"] = profile
                    config["ssl"]["sni"] = "localhost"
                    config["target_port"] = http_port
                path = directory / f"{role}.json"
                write_json(path, config)
                configs[role] = path
            deadline = time.monotonic() + timeout
            for role in ("server", "client"):
                log_path = directory / f"{role}.log"
                log = stack.enter_context(log_path.open("wb"))
                process = subprocess.Popen([str(binary), "-c", str(configs[role])],
                                           cwd=directory, stdout=log, stderr=subprocess.STDOUT)
                processes.append(process)
                if role == "server":
                    wait_until(lambda: has_log(log_path, "QuicServerEndpoint: listening on UDP"),
                               deadline, processes)
            wait_until(lambda: socks_ready(proxy_port), deadline, processes)
            result.update(transfer(proxy_port, http_port, deadline))
            for role in ("client", "server"):
                wait_until(lambda role=role: has_log(directory / f"{role}.log", HANDSHAKE),
                           deadline, processes)
            if relay.error:
                raise RuntimeError(f"relay error: {relay.error}")
            if mode == "loss5" and any(s["dropped"] == 0 for s in relay.stats.values()):
                raise RuntimeError("5% loss not exercised in both directions")
            if mode == "first_reply":
                if relay.stats["server"]["initials_dropped"] != 1:
                    raise RuntimeError("first server reply was not a QUIC v1 Initial")
                # Chrome's first flight already has two client Initial packets;
                # require a second server Initial after dropping its first reply.
                if relay.stats["server"]["initials"] < 2:
                    raise RuntimeError("no repeated server Initial observed after forced drop")
            result["handshake_evidence"] = {role: HANDSHAKE for role in ("client", "server")}
            result["status"] = "passed"
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        # Reap before returning, including startup/transfer failures.
        for process in processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if relay is not None:
            result["relay"] = relay.stats
            result["relay_error"] = relay.error
        write_json(directory / "result.json", result)


def self_check():
    for direction in ("client", "server"):
        assert sum(drop_packet("loss5", direction, n) for n in range(1, 1001)) == 50
        assert not any(drop_packet("normal", direction, n) for n in range(1, 41))
    assert drop_packet("first_reply", "server", 1)
    assert not drop_packet("first_reply", "server", 2)
    assert not drop_packet("first_reply", "client", 1)
    assert is_initial(b"\xc0\x00\x00\x00\x01\x00")
    assert not is_initial(b"\xe0\x00\x00\x00\x01\x00")
    assert not is_initial(b"\xc0\x00\x00\x00\x00\x00")
    assert not is_initial(b"")
    assert len(PAYLOAD) == 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=60, help="deadline per case, seconds")
    args = parser.parse_args()
    self_check()
    if args.binary is None:
        print("PASS helper self-checks; SKIP live QUIC integration (supply --binary and --output-dir)")
        return
    if not args.binary.is_absolute() or not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        parser.error("--binary must be an absolute executable file path")
    if args.output_dir is None:
        parser.error("--output-dir is required with --binary")
    output = args.output_dir.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("--output-dir must be outside repository")
    if not 0 < args.timeout <= 600:
        parser.error("--timeout must be greater than zero and at most 600 seconds")
    openssl = shutil.which("openssl")
    if openssl is None:
        parser.error("openssl CLI required for disposable local certificate")
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="quic-initial-", dir=output))
    print(f"Artifacts: {run}", flush=True)
    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
    target.daemon_threads = True
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    try:
        # Private fixture key never becomes a retained artifact.
        with tempfile.TemporaryDirectory(prefix="quic-fixture-key-", dir=output) as secrets:
            key = Path(secrets) / "key.pem"
            cert = run / "certificate.pem"
            with (run / "certificate.log").open("wb") as log:
                subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                "-keyout", str(key), "-out", str(cert), "-days", "1",
                                "-subj", "/CN=localhost"], stdout=log, stderr=subprocess.STDOUT,
                               check=True, timeout=30)
            for profile in ("none", "chrome"):
                for mode in ("normal", "loss5", "first_reply"):
                    run_case(args.binary.resolve(), run / f"{profile}-{mode}", profile, mode,
                             cert, key, target.server_port, args.timeout)
                    print(f"PASS {profile}/{mode}: 1 MiB SHA256 + client/server QUIC handshake", flush=True)
    finally:
        target.shutdown()
        target.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
