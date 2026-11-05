#!/usr/bin/env python3
"""Real-binary S5 checks. Usage: test_s5_quic.py [BINARY], or S5_BINARY.

Requires aioquic. Artifacts use S5_LOG_DIR or tempfile.gettempdir()/tp-s5.
"""
import asyncio
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("S5_BINARY")
    if not binary:
        print("SKIP S5 QUIC: pass BINARY or set S5_BINARY")
        return
    from aioquic.asyncio.client import connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection

    binary = str(Path(binary).resolve())
    output = Path(os.environ.get("S5_LOG_DIR", Path(tempfile.gettempdir()) / "tp-s5"))
    output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="regression-", dir=output))
    fixture = ROOT / "tests/LinuxFullTest/config"
    config = json.loads((fixture / "quic_server_config.json").read_text())
    config["ssl"].update(cert=str(fixture / "server.crt"),
                          key=str(fixture / "server.key"), handshake_timeout=2)
    config["quic"]["alpn_token"] = "s5-custom"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    config["local_port"] = port
    path = work / "server.json"
    path.write_text(json.dumps(config))

    def start():
        log = (work / "server.log").open("ab")
        proc = subprocess.Popen([binary, "-c", str(path)], stdout=log, stderr=log)
        log.close()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert proc.poll() is None, f"server exited; evidence: {work}"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return proc
            except OSError:
                threading.Event().wait(0.02)
        stop(proc)
        raise AssertionError(f"server readiness timeout; evidence: {work}")

    def stop(proc):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    async def handshake(protocols, accepted):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=protocols,
                                server_name="localhost")
        cfg.verify_mode = 0
        try:
            async with connect("127.0.0.1", port, configuration=cfg) as client:
                assert accepted, f"unsupported ALPN accepted: {protocols}"
                assert client._quic.tls.alpn_negotiated in {"h3", "s5-custom"}
                cid = client._quic._peer_cid
                return bytes(cid.cid), cid.stateless_reset_token
        except (ConnectionError, asyncio.TimeoutError):
            assert not accepted, f"supported ALPN rejected: {protocols}"

    async def alpn_checks():
        await asyncio.wait_for(handshake(["h3"], True), 5)
        await asyncio.wait_for(handshake(["s5-custom"], True), 5)
        await asyncio.wait_for(handshake(["unrelated"], False), 5)
        return await asyncio.wait_for(handshake(["h3"], True), 5)

    def exchange(packet):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(0.4)
            udp.sendto(packet, ("127.0.0.1", port))
            try:
                return udp.recv(2048)
            except socket.timeout:
                return None

    def initial(size, first=0xc0, version=0xfaceb00c):
        dcid, scid = b"destination", b"source"
        packet = bytes([first]) + struct.pack("!I", version)
        packet += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        return packet.ljust(size, b"\0"), dcid, scid

    def handshake_deadline(proc):
        # Generate a valid Initial without running a client event loop: no ACKs,
        # Handshake packets, or retransmits can complete the server handshake.
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                                server_name="localhost")
        cfg.verify_mode = 0
        client = QuicConnection(configuration=cfg)
        log_path = work / "server.log"
        offset = log_path.stat().st_size
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            peer_port = udp.getsockname()[1]
            started = time.monotonic()
            client.connect(("127.0.0.1", port), now=started)
            packets = client.datagrams_to_send(now=started)
            assert packets and len(packets[0][0]) >= 1200
            udp.sendto(packets[0][0], ("127.0.0.1", port))
            # Keep socket open, but never receive or answer server packets.
            deadline = started + 6
            timeout_seen = False
            while time.monotonic() < deadline:
                assert proc.poll() is None, f"server exited; evidence: {work}"
                text = log_path.read_text(errors="replace")[offset:]
                timeout_seen |= "ERR_HANDSHAKE_TIMEOUT" in text
                closed = any("QuicConnection: closing connection" in line
                             and f":{peer_port}" in line for line in text.splitlines())
                if timeout_seen and closed:
                    elapsed = time.monotonic() - started
                    assert 1.5 <= elapsed < 6, f"unexpected handshake deadline: {elapsed:.3f}s"
                    return
                threading.Event().wait(0.02)
            raise AssertionError(f"2-second server handshake deadline did not close connection; evidence: {work}")

    def own_client():
        client_config = json.loads((fixture / "quic_client_config.json").read_text())
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            client_port = listener.getsockname()[1]
        client_config.update(local_port=client_port, remote_port=port)
        client_config["ssl"].update(cert=str(fixture / "server.crt"),
                                    fingerprint="chrome", handshake_timeout=2)
        client_config["quic"].update(alpn_token="s5-custom", debug_disable_tcp=True)
        client_path = work / "client.json"
        client_path.write_text(json.dumps(client_config))
        log_path = work / "client.log"
        with log_path.open("wb") as log:
            client = subprocess.Popen([binary, "-c", str(client_path)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                assert client.poll() is None, f"client exited; evidence: {work}"
                try:
                    sock = socket.create_connection(("127.0.0.1", client_port), timeout=0.2)
                    break
                except OSError:
                    threading.Event().wait(0.02)
            else:
                raise AssertionError("client readiness timeout")
            with sock:
                sock.sendall(b"\x05\x01\x00")
                assert sock.recv(2) == b"\x05\x00"
                sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", port))
                while time.monotonic() < deadline:
                    if "alpn=s5-custom" in log_path.read_text(errors="replace"):
                        return
                    assert client.poll() is None
                    threading.Event().wait(0.02)
                raise AssertionError(f"Chrome QUIC client did not negotiate custom ALPN; evidence: {work}")
        finally:
            stop(client)

    proc = start()
    try:
        handshake_deadline(proc)
        own_client()
        for packet in (b"\x20" + b"random UDP" * 10, b"\x00" * 100, b"\x40" * 19):
            assert exchange(packet) is None, "random/undersized packet triggered reset"
        packet, dcid, scid = initial(1200)
        response = exchange(packet)
        assert response and response[0] & 0x80
        assert response[1:5] == b"\0" * 4, "missing Version Negotiation"
        offset = 5
        assert response[offset] == len(scid)
        offset += 1
        assert response[offset:offset + len(scid)] == scid
        offset += len(scid)
        assert response[offset] == len(dcid)
        offset += 1
        assert response[offset:offset + len(dcid)] == dcid
        offset += len(dcid)
        assert 1 in struct.unpack("!" + "I" * ((len(response) - offset) // 4), response[offset:])
        for size, first, version in ((1199, 0xc0, 0xfaceb00c),
                                     (1200, 0xe0, 0xfaceb00c), (1200, 0xc0, 0)):
            assert exchange(initial(size, first, version)[0]) is None
        old_cid, token = asyncio.run(alpn_checks())
        assert len(old_cid) == 18 and token, "server SCID/reset token missing"
    finally:
        stop(proc)

    # Restart loses connection state, but configured secret preserves reset tokens.
    proc = start()
    try:
        packet = b"\x40" + old_cid + b"\0" * 80
        response = exchange(packet)
        assert response and 21 <= len(response) < len(packet)
        assert response[0] & 0xc0 == 0x40 and response[-16:] == token
        assert exchange(b"\x00" + packet[1:]) is None, "fixed-bit-zero reset"
    finally:
        stop(proc)
    print(f"S5 QUIC passed; evidence: {work}")


if __name__ == "__main__":
    main()
