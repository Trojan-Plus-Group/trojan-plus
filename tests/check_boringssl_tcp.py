#!/usr/bin/env python3
"""Local TCP TLS checks. Run: python3 tests/check_boringssl_tcp.py

Uses build-bssl/trojan, fixture certificate/key, ephemeral loopback ports only.
Covers encrypted keys, verification, policy, ALPN, reuse and fallback.
"""
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("TROJAN_BINARY", ROOT / "build-bssl/trojan"))
FIXTURES = ROOT / "tests/LinuxFullTest/config"
TIMEOUT = 3
HTTP = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nbssl-tcp"


def listener():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    sock.settimeout(TIMEOUT)
    return sock


def port():
    with listener() as sock:
        return sock.getsockname()[1]


def connect(number):
    return socket.create_connection(("127.0.0.1", number), TIMEOUT)


@contextlib.contextmanager
def running(tmp, config):
    name = str(time.monotonic_ns())
    path = tmp / (name + ".json")
    path.write_text(json.dumps(config))
    with (tmp / (name + ".log")).open("w+") as log:
        proc = subprocess.Popen([str(BINARY), "-c", str(path)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + TIMEOUT
            while True:
                if proc.poll() is not None:
                    log.seek(0)
                    raise AssertionError("trojan exited: " + log.read())
                try:
                    with connect(config["local_port"]):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("trojan startup timeout")
                    time.sleep(0.02)  # Bounded readiness polling, not synchronization delay.
            yield config["local_port"], log
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=TIMEOUT)


def context(version=None, alpn=None, curve=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version:
        ctx.minimum_version = ctx.maximum_version = version
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if curve:
        ctx.set_ecdh_curve(curve)
    return ctx


def tls(ctx, number, session=None):
    raw = connect(number)
    try:
        return ctx.wrap_socket(raw, server_hostname="yuchting", session=session)
    except BaseException:
        raw.close()
        raise


def receive(sock):
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except ConnectionResetError:
            break
        if not chunk:
            break
        data += chunk
    return data


def relay(sock, backend):
    sock.sendall(HTTP)
    deadline = time.monotonic() + TIMEOUT
    while True:
        upstream, _ = backend.accept()
        with upstream:
            upstream.settimeout(TIMEOUT)
            request = upstream.recv(4096)
            if request:
                assert request == HTTP, repr(request)
                upstream.sendall(RESPONSE)
                break
        assert time.monotonic() < deadline, "only readiness connections received"
    assert receive(sock) == RESPONSE


def main():
    assert BINARY.is_file(), BINARY
    failures = []

    def check(name, action):
        try:
            action()
            print("PASS " + name, flush=True)
        except Exception as error:
            failures.append(name)
            print("FAIL " + name + ": " + repr(error), flush=True)

    with tempfile.TemporaryDirectory(prefix="bssl-tcp-", dir="/tmp/opencode") as directory:
        tmp = Path(directory)
        encrypted = tmp / "encrypted.key"
        # Fixture passphrase only; never inspect unrelated credentials.
        subprocess.run(["openssl", "pkey", "-in", str(FIXTURES / "server.key"),
                        "-passin", "pass:123456", "-aes-256-cbc", "-passout",
                        "pass:tcp-check-only", "-out", str(encrypted)],
                       check=True, capture_output=True, timeout=TIMEOUT)
        with listener() as backend:
            base = json.loads((FIXTURES / "server_config.json").read_text())
            base.update(local_addr="127.0.0.1", local_port=port(),
                        remote_addr="127.0.0.1", remote_port=backend.getsockname()[1])
            base["ssl"].update(cert=str(FIXTURES / "server.crt"), key=str(encrypted),
                               key_password="tcp-check-only", curves="P-256",
                               cipher="ECDHE-RSA-AES128-GCM-SHA256",
                               cipher_tls13="TLS_AES_128_GCM_SHA256")
            base["tcp"].update(fast_open=False, reuse_port=False)
            with running(tmp, base) as (number, _):
                def negotiation(version, expected):
                    ctx = context(version, ["http/1.1", "h2"], "prime256v1")
                    ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
                    with tls(ctx, number) as sock:
                        assert sock.cipher()[0] == expected, sock.cipher()
                        assert sock.selected_alpn_protocol() == "h2"
                        relay(sock, backend)
                check("encrypted key callback; TLS1.2 cipher/P-256; server ALPN preference; TLS fallback",
                      lambda: negotiation(ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-GCM-SHA256"))
                check("TLS1.3 configured cipher/P-256", lambda: negotiation(
                    ssl.TLSVersion.TLSv1_3, "TLS_AES_128_GCM_SHA256"))

                def no_match():
                    with tls(context(alpn=["unmatched"]), number) as sock:
                        assert sock.selected_alpn_protocol() is None
                check("ALPN no match continues without selection", no_match)

                def wrong_curve():
                    try:
                        with tls(context(ssl.TLSVersion.TLSv1_2, curve="X25519"), number):
                            raise AssertionError("disjoint curves accepted")
                    except ssl.SSLError:
                        pass
                check("disjoint configured curve rejected", wrong_curve)

                def reuse():
                    ctx = context(ssl.TLSVersion.TLSv1_2)
                    with tls(ctx, number) as sock:
                        session = sock.session
                        assert session.has_ticket, "ticket missing"
                    with tls(ctx, number, session) as sock:
                        assert sock.session_reused, "ticket not resumed"
                check("TLS1.2 server ticket issuance and reuse", reuse)

                def reuse_tls13():
                    ctx = context(ssl.TLSVersion.TLSv1_3)
                    with tls(ctx, number) as sock:
                        assert not sock.session_reused
                        # TLS1.3 tickets arrive after the handshake; relay reads them too.
                        relay(sock, backend)
                        session = sock.session
                        assert session.has_ticket, "TLS1.3 post-handshake ticket missing"
                    with tls(ctx, number, session) as sock:
                        assert sock.session_reused, "TLS1.3 ticket not resumed"
                        relay(sock, backend)
                check("TLS1.3 server post-handshake ticket issuance and reuse", reuse_tls13)

                def client_verify(trust, hostname, success):
                    config = {"run_type": "forward", "local_addr": "127.0.0.1",
                              "local_port": port(), "remote_addr": "127.0.0.1",
                              "remote_port": number, "target_addr": "127.0.0.1",
                              "target_port": backend.getsockname()[1], "password": base["password"],
                              "log_level": 0, "ssl": {"verify": True, "verify_hostname": True,
                              "cert": str(trust), "sni": hostname, "alpn": ["http/1.1"]}}
                    with running(tmp, config) as (client_port, log):
                        with connect(client_port) as sock:
                            if success:
                                relay(sock, backend)
                            else:
                                sock.sendall(HTTP)
                                assert receive(sock) == b"", "verification failure leaked payload"
                                log.seek(0)
                                text = log.read().lower()
                                assert "certificate verify failed" in text.replace("_", " "), text
                check("client ALPN offer; trusted CA/hostname positive control", lambda: client_verify(
                    FIXTURES / "server.crt", "yuchting", True))
                check("client hostname verification failure", lambda: client_verify(
                    FIXTURES / "server.crt", "wrong.invalid", False))
                other_cert = tmp / "other.crt"
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                "-subj", "/CN=unrelated", "-days", "1", "-keyout",
                                str(tmp / "other.key"), "-out", str(other_cert)],
                               check=True, capture_output=True, timeout=10)
                check("client untrusted CA failure", lambda: client_verify(other_cert, "yuchting", False))

            def client_alpn():
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(str(FIXTURES / "server.crt"), str(encrypted),
                                    "tcp-check-only")
                ctx.set_alpn_protocols(["http/1.1", "h2"])
                with listener() as upstream:
                    config = {"run_type": "forward", "local_addr": "127.0.0.1",
                              "local_port": port(), "remote_addr": "127.0.0.1",
                              "remote_port": upstream.getsockname()[1],
                              "target_addr": "127.0.0.1", "target_port": 80,
                              "password": base["password"], "log_level": 0,
                              "ssl": {"verify": True, "verify_hostname": True,
                                      "cert": str(FIXTURES / "server.crt"),
                                      "sni": "yuchting", "alpn": ["h2"]}}
                    with running(tmp, config) as (client_port, _):
                        with connect(client_port) as client:
                            client.sendall(HTTP)
                            deadline = time.monotonic() + TIMEOUT
                            while True:
                                assert time.monotonic() < deadline, "client TLS connection missing"
                                raw, _ = upstream.accept()
                                with raw:
                                    raw.settimeout(TIMEOUT)
                                    try:
                                        peer = ctx.wrap_socket(raw, server_side=True)
                                    except (ssl.SSLError, ConnectionResetError):
                                        continue  # Readiness connection may close during handshake.
                                    with peer:
                                        request = b""
                                        while not request.endswith(HTTP):
                                            remaining = deadline - time.monotonic()
                                            assert remaining > 0, "client payload timeout"
                                            peer.settimeout(remaining)
                                            try:
                                                chunk = peer.recv(4096)
                                            except ConnectionResetError:
                                                break
                                            if not chunk:
                                                break
                                            request += chunk
                                            assert len(request) < 65536, "unexpected client payload"
                                        if not request.endswith(HTTP):
                                            continue  # Ignore forward listener readiness connection.
                                        assert peer.selected_alpn_protocol() == "h2", (
                                            peer.selected_alpn_protocol())
                                        peer.sendall(RESPONSE)
                                        break
                            assert receive(client) == RESPONSE
            check("client ALPN wire selection by stdlib TLS server", client_alpn)

            def invalid_policy(field, diagnostic):
                config = copy.deepcopy(base)
                config["local_port"] = port()
                config["ssl"][field] = "not-a-valid-tls-policy"
                path = tmp / ("invalid-" + field + ".json")
                path.write_text(json.dumps(config))
                result = subprocess.run([str(BINARY), "-c", str(path)],
                                        capture_output=True, text=True, timeout=TIMEOUT)
                output = result.stdout + result.stderr
                assert result.returncode != 0, "invalid " + field + " accepted"
                assert diagnostic in output, output
            check("invalid TLS1.2 cipher startup diagnostic", lambda: invalid_policy(
                "cipher", "Invalid TLS cipher list"))
            check("invalid curve startup diagnostic", lambda: invalid_policy(
                "curves", "Invalid TLS curve list"))

            disabled = copy.deepcopy(base)
            disabled["local_port"] = port()
            disabled["ssl"].update(reuse_session=False, session_ticket=False)
            with running(tmp, disabled) as (number, _):
                def no_reuse():
                    ctx = context(ssl.TLSVersion.TLSv1_2)
                    with tls(ctx, number) as sock:
                        session = sock.session
                        assert not session.has_ticket
                    with tls(ctx, number, session) as sock:
                        assert not sock.session_reused
                check("reuse disabled suppresses tickets/resumption", no_reuse)

            response_file = tmp / "plain.http"
            response_file.write_bytes(RESPONSE)
            plain = copy.deepcopy(base)
            plain["local_port"] = port()
            plain["ssl"]["plain_http_response"] = str(response_file)
            with running(tmp, plain) as (number, _):
                def plain_response():
                    with connect(number) as sock:
                        sock.sendall(HTTP)
                        actual = receive(sock)
                        assert actual == RESPONSE, "configured plain response: " + repr(actual)
                check("plain HTTP configured response", plain_response)
    print("GAPS: client-side resumption; session-ID-only cache", flush=True)
    if failures:
        raise SystemExit("Failed: " + ", ".join(failures))


if __name__ == "__main__":
    main()
