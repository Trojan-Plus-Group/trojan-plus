#!/usr/bin/env python3
"""Capture three fresh core ClientHellos per transport on loopback.

Usage: python3 tests/check_chrome_profile_capture.py --binary build/trojan
Requires dumpcap capture permission and tshark with tls.handshake.ja4 support.
Initial-flight check only: sink never authenticates or completes TLS/QUIC.
Artifacts retained under /tmp/opencode; no keylogs or real passwords.
"""
import argparse
import contextlib
import json
from pathlib import Path
import queue
import shlex
import socket
import subprocess
import tempfile
import threading
import time


@contextlib.contextmanager
def process(command, log):
    proc = subprocess.Popen(command, stdout=log, stderr=log)
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fields(capture, display_filter, names, port, quic):
    command = ["tshark", "-r", str(capture), "-d",
               ("udp.port==%d,quic" if quic else "tcp.port==%d,tls") % port,
               "-Y", display_filter, "-T", "fields", "-E", "occurrence=a"]
    for name in names:
        command += ["-e", name]
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=15)
    return [line.split("\t") for line in result.stdout.splitlines()]


def integers(value):
    return [int(item, 16) if item.startswith("0x") else int(item)
            for item in value.split(",") if item]


def grease(value):
    return value & 0x0f0f == 0x0a0a and value >> 8 == value & 0xff


def inspect(capture, port, quic):
    names = ["tls.handshake.ja4", "tls.handshake.extension.type", "tls.handshake.ciphersuite"]
    rows = fields(capture, "tls.handshake.type == 1", names, port, quic)
    assert rows, "No decoded ClientHello in " + str(capture)
    ja4, extensions, ciphers = rows[0]
    if quic:
        assert ja4 == "u13d0312h3_55b375c5d22e_178839b6cec1", ja4
    else:
        assert ja4.startswith("t13d1517h2_8daaf6152771_"), ja4
    extension_ids = integers(extensions)
    assert {17613, 27} <= set(extension_ids), extension_ids
    cipher_ids = integers(ciphers)
    assert any(map(grease, extension_ids)) == (not quic), extension_ids
    assert any(map(grease, cipher_ids)) == (not quic), cipher_ids
    if quic:
        packets = fields(capture, "quic.long.packet_type == 0 && udp.dstport == %d" % port,
                         ["quic.dcil", "quic.scil", "udp.length"], port, True)
        assert packets, "No QUIC Initial"
        for dcid, scid, length in packets:
            assert set(integers(dcid)) == {8}, dcid
            assert set(integers(scid)) == {0}, scid
            assert int(length) == 1258, length  # Eight-byte UDP header; payload is 1250.
    return extension_ids, [value for value in cipher_ids if grease(value)]


def capture_one(binary, output, quic, index, capture_command):
    label = ("quic" if quic else "tcp") + "-" + str(index)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if quic else socket.SOCK_STREAM) as sink:
        sink.bind(("127.0.0.1", 0))
        if not quic:
            sink.listen(8)
        port = sink.getsockname()[1]
        local = free_port()
        config = {"run_type": "forward", "local_addr": "127.0.0.1", "local_port": local,
                  "remote_addr": "127.0.0.1", "remote_port": port,
                  "target_addr": "127.0.0.1", "target_port": 80,
                  "password": ["local-capture-test-only"], "log_level": 0,
                  "ssl": {"fingerprint": "chrome", "verify": False, "sni": "capture.invalid",
                          "reuse_session": False},
                  "tcp": {"fast_open": False, "reuse_port": False},
                  "quic": {"enabled": quic, "alpn_token": "h3"}}
        path = output / (label + ".json")
        path.write_text(json.dumps(config))
        pcap = output / (label + ".pcapng")
        with (output / (label + "-dumpcap.log")).open("w") as capture_log, pcap.open("xb") as packets:
            capture = subprocess.Popen([*capture_command, "-i", "lo", "-f",
                                        ("udp" if quic else "tcp") + " port " + str(port),
                                        "-w", "-", "-a", "duration:5"],
                                       stdout=packets, stderr=subprocess.PIPE, text=True)
            ready = queue.Queue()

            def monitor():
                for line in capture.stderr:
                    capture_log.write(line)
                    capture_log.flush()
                    if "Capturing on" in line:
                        ready.put(True)
                ready.put(False)

            thread = threading.Thread(target=monitor, daemon=True)
            thread.start()
            try:
                assert ready.get(timeout=5), "dumpcap failed before capture readiness"
                with (output / (label + ".log")).open("w") as log:
                    with process([str(binary), "-c", str(path)], log) as core:
                        deadline = time.monotonic() + 3
                        while True:
                            assert core.poll() is None, "core exited; inspect " + str(output)
                            try:
                                connection = socket.create_connection(("127.0.0.1", local), timeout=0.2)
                                break
                            except OSError:
                                assert time.monotonic() < deadline, "core listener timeout"
                                time.sleep(0.02)  # Bounded readiness polling only.
                        with connection:
                            connection.sendall(b"GET / HTTP/1.1\r\nHost: capture.invalid\r\n\r\n")
                            assert capture.wait(timeout=8) == 0, "dumpcap failed"
            finally:
                if capture.poll() is None:
                    capture.terminate()
                    capture.wait(timeout=5)
                thread.join(timeout=2)
                capture.stderr.close()
    return inspect(pcap, port, quic)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--dumpcap", default="dumpcap", help="Capture command, e.g. 'sudo -n dumpcap'")
    args = parser.parse_args()
    binary = args.binary.resolve()
    assert binary.is_file(), binary
    output = Path(tempfile.mkdtemp(prefix="chrome-capture-", dir="/tmp/opencode"))
    print("Evidence: " + str(output), flush=True)
    for quic in (False, True):
        samples = [capture_one(binary, output, quic, index, shlex.split(args.dumpcap)) for index in range(3)]
        assert len({tuple(order) for order, _ in samples}) > 1, "extension order did not vary"
        if not quic:
            # Two GREASE choices across three connections are possible; collision chance 1/256.
            assert len({tuple(ids) for _, ids in samples}) > 1, "TCP GREASE cipher did not vary"
        print("PASS " + ("QUIC" if quic else "TCP") + " three core ClientHellos", flush=True)


if __name__ == "__main__":
    main()
