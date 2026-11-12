#!/usr/bin/env python3
"""Exercise QUIC client/server shutdown under ASan, LSan and UBSan.

Usage: python3 tests/test_quic_shutdown_leaks.py --binary /absolute/path/to/trojan
Build trojan with address/undefined sanitizers and leak detection enabled first.
Without --binary, skip live integration. Requires openssl and no Python packages.
Logs and disposable fixture certificate are retained in a unique temporary directory;
the private key is removed on exit. Both endpoints run with UDP GSO off and on.
"""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time

from test_quic_initial_loss import (HANDSHAKE, ROOT, Target, free_port, has_log,
                                    socks_ready, transfer, wait_until)

SANITIZER_ERROR = re.compile(
    r"AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|"
    r"runtime error:|SUMMARY: .*Sanitizer", re.IGNORECASE)


def run_case(binary, directory, cert, key, target_port, gso, timeout):
    directory.mkdir()
    processes = {}
    server_port, proxy_port = free_port(), free_port()
    while proxy_port == server_port:
        proxy_port = free_port()
    env = os.environ.copy()
    # Append required settings so they override conflicting inherited options.
    for name, options in (("ASAN_OPTIONS", "detect_leaks=1:halt_on_error=1:exitcode=86"),
                          ("LSAN_OPTIONS", "exitcode=86"),
                          ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1:exitcode=86")):
        env[name] = env.get(name, "") + ":" + options
    with contextlib.ExitStack() as stack:
        try:
            for role in ("server", "client"):
                config = json.loads((ROOT / "tests/LinuxFullTest/config" /
                                     f"quic_{role}_config.json").read_text())
                config["local_port"] = server_port if role == "server" else proxy_port
                config["remote_port"] = target_port if role == "server" else server_port
                config["password"] = ["public-quic-shutdown-test-fixture"]
                config["ssl"]["cert"] = str(cert)
                config["quic"]["debug_disable_tcp"] = True
                config["quic"]["udp_gso"] = gso
                config["tcp"]["reuse_port"] = False
                if role == "server":
                    config["ssl"]["key"] = str(key)
                    config["ssl"].pop("key_password", None)
                else:
                    config["ssl"]["sni"] = "localhost"
                    config["target_port"] = target_port
                path = directory / f"{role}.json"
                path.write_text(json.dumps(config, indent=2) + "\n")
                log = stack.enter_context((directory / f"{role}.log").open("wb"))
                processes[role] = subprocess.Popen([str(binary), "-c", str(path)],
                                                   cwd=directory, env=env, stdout=log,
                                                   stderr=subprocess.STDOUT)
                if role == "server":
                    wait_until(lambda: has_log(directory / "server.log",
                                               "QuicServerEndpoint: listening on UDP"),
                               time.monotonic() + timeout, processes.values())
            deadline = time.monotonic() + timeout
            wait_until(lambda: socks_ready(proxy_port), deadline, processes.values())
            transfer(proxy_port, target_port, deadline)
            for role in ("client", "server"):
                wait_until(lambda: has_log(directory / f"{role}.log", HANDSHAKE),
                           deadline, processes.values())
        finally:
            # SIGTERM invokes trojan's normal stop path; never hide timeout or crash.
            errors = []
            for role in ("client", "server"):
                process = processes.get(role)
                if process is None:
                    continue
                if process.poll() is None:
                    process.terminate()
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    errors.append(f"{role}: shutdown timeout")
                    continue
                if code != 0:
                    errors.append(f"{role}: exit code {code}")
            for role in processes:
                text = (directory / f"{role}.log").read_text(errors="replace")
                if SANITIZER_ERROR.search(text):
                    errors.append(f"{role}: sanitizer diagnostic in {role}.log")
            if errors:
                raise RuntimeError("; ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    assert SANITIZER_ERROR.search("ERROR: LeakSanitizer: detected memory leaks")
    assert SANITIZER_ERROR.search("file.cpp:1: runtime error: overflow")
    assert not SANITIZER_ERROR.search("normal shutdown")
    if args.binary is None:
        print("SKIP: supply --binary pointing to sanitizer-built trojan")
        return
    if not args.binary.is_absolute() or not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        parser.error("--binary must be an absolute executable file path")
    if not 0 < args.timeout <= 600:
        parser.error("--timeout must be greater than zero and at most 600 seconds")
    openssl = shutil.which("openssl")
    if not openssl:
        parser.error("openssl CLI required for disposable local certificate")
    directory = Path(tempfile.mkdtemp(prefix="quic-shutdown-leaks-"))
    print(f"Artifacts: {directory}", flush=True)
    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
    target.daemon_threads = True
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="quic-shutdown-key-") as secrets:
            key, cert = Path(secrets) / "key.pem", directory / "certificate.pem"
            with (directory / "certificate.log").open("wb") as log:
                subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                "-keyout", str(key), "-out", str(cert), "-days", "1",
                                "-subj", "/CN=localhost"], stdout=log, stderr=subprocess.STDOUT,
                               check=True, timeout=30)
            for gso in (False, True):
                run_case(args.binary, directory / f"gso-{int(gso)}", cert, key,
                         target.server_port, gso, args.timeout)
                print(f"PASS UDP GSO {'on' if gso else 'off'}: transfer and shutdown", flush=True)
    finally:
        target.shutdown()
        target.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
