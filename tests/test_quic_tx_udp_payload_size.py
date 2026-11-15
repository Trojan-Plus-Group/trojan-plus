#!/usr/bin/env python3
"""Wire check for quic.tx_udp_payload_size with the real binary.

Usage: python3 tests/test_quic_tx_udp_payload_size.py [--binary /absolute/path/to/trojan]
Without --binary: $S5_BINARY, then build/trojan; missing binary fails under CI/TF_BUILD, else SKIP.

Server and client talk through a localhost UDP relay that records every datagram
size per direction; one proxied 1 MiB download follows. Reuses the relay-style
helpers of test_quic_initial_loss.py. Uses the disposable LinuxFullTest cert/key.
Logs are kept in a temp dir only when a case fails.
"""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_quic_initial_loss as base  # noqa: E402

ROOT = base.ROOT
CONFIG = ROOT / "tests/LinuxFullTest/config"

class SizeRelay(base.Relay):
    """base.Relay topology; forwards everything and records datagram sizes."""

    def __init__(self, server_port):
        super().__init__(server_port, "normal")
        self.sizes = {"client": [], "server": []}

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
                        self.sizes[direction].append(len(data))
                        if direction == "client":
                            client = address
                            self.back.send(data)
                        elif client is not None:
                            self.front.sendto(data, client)
        except Exception as error:
            self.error = repr(error)

def run_case(binary, root, name, fingerprint, size, http_port, timeout):
    directory = root / name
    directory.mkdir()
    processes = []
    relay = None
    with contextlib.ExitStack() as stack:
        try:
            server_port = base.free_port()
            relay = SizeRelay(server_port)
            stack.callback(relay.close)
            relay.thread.start()
            proxy_port = base.free_port()
            configs = {}
            for role in ("server", "client"):
                config = json.loads((CONFIG / f"quic_{role}_config.json").read_text())
                config["local_port"] = server_port if role == "server" else proxy_port
                config["remote_port"] = http_port if role == "server" else relay.port
                config["password"] = ["public-quic-tx-size-test-fixture"]
                config["ssl"]["cert"] = str(CONFIG / "server.crt")
                config["quic"]["debug_disable_tcp"] = True
                config["tcp"]["reuse_port"] = False
                if size is not None:
                    config["quic"]["tx_udp_payload_size"] = size
                if role == "server":
                    config["ssl"]["key"] = str(CONFIG / "server.key")
                else:
                    config["ssl"]["fingerprint"] = fingerprint
                    config["ssl"]["sni"] = "localhost"
                    config["target_port"] = http_port
                configs[role] = directory / f"{role}.json"
                base.write_json(configs[role], config)
            deadline = time.monotonic() + timeout
            for role in ("server", "client"):
                log_path = directory / f"{role}.log"
                log = stack.enter_context(log_path.open("wb"))
                processes.append(subprocess.Popen([str(binary), "-c", str(configs[role])],
                                                  cwd=directory, stdout=log, stderr=subprocess.STDOUT))
                if role == "server":
                    # TCP accept is not readiness; wait for the UDP listener log line.
                    base.wait_until(lambda: base.has_log(log_path, "QuicServerEndpoint: listening on UDP"),
                                    deadline, processes)
            base.wait_until(lambda: base.socks_ready(proxy_port), deadline, processes)
            base.transfer(proxy_port, http_port, deadline)
            if relay.error:
                raise RuntimeError(f"relay error: {relay.error}")
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    return relay.sizes

def check(name, sizes, client_max, server_max, first):
    c, s = sizes["client"], sizes["server"]
    assert c and s, f"{name}: no datagrams recorded"
    summary = f"{name}: client->server n={len(c)} max={max(c)} first={c[0]}; server->client n={len(s)} max={max(s)}"
    print(summary, flush=True)
    assert max(c) == client_max, f"{name}: client max {max(c)} != {client_max}"
    assert c[0] == first, f"{name}: first client datagram {c[0]} != {first}"
    if server_max is not None:
        assert max(s) == server_max, f"{name}: server max {max(s)} != {server_max}"

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path,
                        help="default: $S5_BINARY, then build/trojan, then $PIPELINE_WORKSPACE/LinuxBinary/trojan")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if args.binary is None:
        # Same lookup as test_s5_quic.py so the argument-less CI loop over tests/test_*.py works.
        found = os.environ.get("S5_BINARY")
        if not found:
            candidates = [ROOT / "build/trojan"]
            if os.environ.get("PIPELINE_WORKSPACE"):
                candidates.append(Path(os.environ["PIPELINE_WORKSPACE"]) / "LinuxBinary/trojan")
            found = next((str(path) for path in candidates if path.is_file()), None)
        if not found:
            if "TF_BUILD" in os.environ or "CI" in os.environ:
                sys.exit("QUIC tx_udp_payload_size: binary missing; pass --binary, set S5_BINARY, or build build/trojan")
            print("SKIP QUIC tx_udp_payload_size: pass --binary, set S5_BINARY, or build build/trojan")
            return
        args.binary = Path(found).resolve()
    if not args.binary.is_absolute() or not os.access(args.binary, os.X_OK):
        parser.error("binary must be an absolute executable file path")
    root = Path(tempfile.mkdtemp(prefix="quic-tx-size-"))
    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), base.Target)
    target.daemon_threads = True
    threading.Thread(target=target.serve_forever, daemon=True).start()
    try:
        port = target.server_port
        # (name, fingerprint, key, expected client max, expected server max, first client datagram)
        for name, fp, size, cmax, smax, first in (
            ("chrome-unset", "chrome", None, 1250, None, 1250),
            ("chrome-1200", "chrome", 1200, 1200, 1200, 1200),
            ("none-1200", "none", 1200, 1200, 1200, 1200),
            ("chrome-1400", "chrome", 1400, 1400, 1400, 1400),
            ("none-1400", "none", 1400, 1400, 1400, 1400),
            ("none-1452", "none", 1452, 1452, 1452, 1452),
        ):
            sizes = run_case(args.binary, root, name, fp, size, port, args.timeout)
            check(name, sizes, cmax, smax, first)
    except BaseException:
        print(f"FAIL; logs kept in {root}", flush=True)
        raise
    finally:
        target.shutdown()
        target.server_close()
    shutil.rmtree(root)
    print("PASS quic.tx_udp_payload_size wire sizes (chrome unset=1250, pinned 1200/1400/1452)")

if __name__ == "__main__":
    main()
