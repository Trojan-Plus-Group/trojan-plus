#!/usr/bin/env python3
"""Real-binary QUIC shutdown regression. Usage: test_quic_shutdown_close.py [BINARY]."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/LinuxFullTest/config"


def wait_for(predicate, timeout, message):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        threading.Event().wait(0.01)
    raise AssertionError(message)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise AssertionError("SOCKS connection closed")
        data += chunk
    return data


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("S5_BINARY")
    candidates = [ROOT / "build/trojan"]
    if os.environ.get("PIPELINE_WORKSPACE"):
        candidates.append(Path(os.environ["PIPELINE_WORKSPACE"]) / "LinuxBinary/trojan")
    if not binary:
        binary = next((str(path) for path in candidates if path.is_file()), None)
    if not binary:
        if "TF_BUILD" in os.environ or "CI" in os.environ:
            sys.exit("QUIC shutdown: binary missing")
        print("SKIP QUIC shutdown: binary missing")
        return
    binary = str(Path(binary).resolve())
    output = Path(os.environ.get("S5_LOG_DIR", Path(tempfile.gettempdir()) / "tp-s5"))
    output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="quic-shutdown-", dir=output))
    print(f"QUIC shutdown evidence: {work}", flush=True)

    for stopped in ("server", "client"):
        server_port, client_port = free_port(), free_port()
        while client_port == server_port:
            client_port = free_port()
        with socket.socket() as target:
            target.bind(("127.0.0.1", 0))
            target.listen()
            target.settimeout(10)
            target_port = target.getsockname()[1]
            processes = {}
            logs = {}
            stream = upstream = None
            try:
                for role in ("server", "client"):
                    config = json.loads((FIXTURE / f"quic_{role}_config.json").read_text())
                    config["local_port"] = server_port if role == "server" else client_port
                    config["remote_port"] = target_port if role == "server" else server_port
                    config["ssl"]["cert"] = str(FIXTURE / "server.crt")
                    if role == "server":
                        config["ssl"]["key"] = str(FIXTURE / "server.key")
                    path = work / f"{stopped}-{role}.json"
                    path.write_text(json.dumps(config))
                    logs[role] = work / f"{stopped}-{role}.log"
                    with logs[role].open("wb") as log:
                        processes[role] = subprocess.Popen([binary, "-c", str(path)], stdout=log, stderr=log)
                    if role == "server":
                        wait_for(lambda: "QuicServerEndpoint: listening on UDP" in logs[role].read_text(errors="replace"),
                                 10, f"server not ready: {work}")
                for role in processes:
                    wait_for(lambda: "QuicConnection: handshake completed" in logs[role].read_text(errors="replace"),
                             15, f"{role} handshake missing: {work}")
                stream = socket.create_connection(("127.0.0.1", client_port), timeout=5)
                stream.settimeout(10)
                stream.sendall(b"\x05\x01\x00")
                assert recv_exact(stream, 2) == b"\x05\x00"
                stream.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
                response = recv_exact(stream, 4)
                assert response[:2] == b"\x05\x00", response
                lengths = {1: 4, 4: 16}
                address_len = recv_exact(stream, 1)[0] if response[3] == 3 else lengths[response[3]]
                recv_exact(stream, address_len + 2)
                upstream, _ = target.accept()
                stream.sendall(b"active")
                upstream.settimeout(5)
                assert recv_exact(upstream, 6) == b"active"
                peer = "client" if stopped == "server" else "server"
                offset = logs[peer].stat().st_size
                processes[stopped].terminate()
                wait_for(lambda: "QuicConnection: closing connection" in
                         logs[peer].read_text(errors="replace")[offset:],
                         2, f"{peer} did not observe {stopped} close in 2s: {work}")
                assert processes[stopped].wait(timeout=5) == 0
            finally:
                if stream:
                    stream.close()
                if upstream:
                    upstream.close()
                for proc in processes.values():
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
    print("QUIC shutdown close passed")


if __name__ == "__main__":
    main()
