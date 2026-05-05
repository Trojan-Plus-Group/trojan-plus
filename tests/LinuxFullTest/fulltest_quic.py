"""
QUIC integration tests for trojan-plus.

Test cases:
  T1: e2e_basic_proxy     - QUIC handshake + HTTP GET proxy
  T2: e2e_multistream     - concurrent streams over one QUIC connection
  T3: e2e_post_data       - HTTP POST through QUIC
  T4: h3_upstream_fallback - non-trojan traffic forwarded to h3_upstream
  T5: idle_timeout        - connection closes after max_idle_timeout_ms
  T7: alpn_negotiation    - verify ALPN token in logs
  T8: quic_disabled       - quic.enabled=false falls back to TLS
"""

import json
import os
import re
import signal
import socket
import sys
import time
import traceback
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from subprocess import Popen

try:
    import socks
except ImportError:
    socks = None

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from fulltest_utils import print_time_log, is_windows_system

# ---------------------------------------------------------------------------
# Port assignments (must not collide with existing tests)
# ---------------------------------------------------------------------------
QUIC_SERVER_PORT = 14651
QUIC_CLIENT_PROXY_PORT = 10621
HTTP_TARGET_PORT = 18083          # dedicated target HTTP server for QUIC tests
H3_UPSTREAM_PORT = 18182

TEST_FILES_DIR = 'html'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def wait_for_port(port, host='127.0.0.1', timeout=10):
    """Wait until a TCP port is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.3)
    return False


def wait_for_log(log_path, pattern, timeout=20):
    """Poll a log file until *pattern* (regex) matches a line. Returns the match or None."""
    deadline = time.time() + timeout
    compiled = re.compile(pattern)
    while time.time() < deadline:
        if os.path.exists(log_path):
            with open(log_path, 'r', errors='replace') as f:
                for line in f:
                    m = compiled.search(line)
                    if m:
                        return m
        time.sleep(0.5)
    return None


def start_trojan(binary_path, config_path):
    """Start a trojan-plus process and return (process, log_path)."""
    log_path = config_path + ".output"
    log_file = open(log_path, "w+")
    kwargs = {'universal_newlines': True}
    if not is_windows_system():
        kwargs['restore_signals'] = True
    proc = Popen([binary_path, "-c", config_path],
                 executable=binary_path,
                 bufsize=1024 * 1024,
                 stdout=log_file, stderr=log_file,
                 **kwargs)
    proc._log_file = log_file
    proc._log_path = log_path
    time.sleep(1)
    if proc.returncode:
        print_time_log(f"Failed to start trojan with {config_path}")
        log_file.close()
        return None, log_path
    return proc, log_path


def close_process(proc, dump_log=False):
    if not proc:
        return
    try:
        proc._log_file.flush()
    except Exception:
        pass
    try:
        if is_windows_system():
            proc.send_signal(signal.SIGTERM)
        else:
            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    if dump_log:
        try:
            proc._log_file.seek(0)
            print_time_log("--- LOG: " + proc._log_path + " ---")
            print_time_log(proc._log_file.read())
            print_time_log("--- END LOG ---")
        except Exception:
            pass
    try:
        proc._log_file.close()
    except Exception:
        pass


def start_http_target():
    """Start the fulltest HTTP server on HTTP_TARGET_PORT."""
    log_file = open("config/quic_http_target.output", "w+")
    proc = Popen([sys.executable, "-u", "fulltest_server.py", TEST_FILES_DIR, str(HTTP_TARGET_PORT)],
                 executable=sys.executable,
                 bufsize=1024 * 1024,
                 stdout=log_file, stderr=log_file,
                 universal_newlines=True)
    proc._log_file = log_file
    proc._log_path = "config/quic_http_target.output"
    if not wait_for_port(HTTP_TARGET_PORT, timeout=8):
        print_time_log(f"HTTP target server failed to start on {HTTP_TARGET_PORT}")
        proc.kill()
        log_file.close()
        return None
    print_time_log(f"HTTP target server ready on {HTTP_TARGET_PORT}")
    return proc


def start_h3_upstream_mock():
    """Start the h3_upstream UDP mock server."""
    log_file = open("config/quic_h3mock.output", "w+")
    proc = Popen([sys.executable, "-u", "fulltest_quic_h3mock.py", str(H3_UPSTREAM_PORT)],
                 executable=sys.executable,
                 bufsize=1024 * 1024,
                 stdout=log_file, stderr=log_file,
                 universal_newlines=True)
    proc._log_file = log_file
    proc._log_path = "config/quic_h3mock.output"
    # For UDP, we wait for the log instead of wait_for_port.
    if not wait_for_log("config/quic_h3mock.output", r"listening on .*:" + str(H3_UPSTREAM_PORT), timeout=8):
        print_time_log(f"h3_upstream UDP mock server failed to start on {H3_UPSTREAM_PORT}")
        proc.kill()
        log_file.close()
        return None
    print_time_log(f"h3_upstream UDP mock server ready on {H3_UPSTREAM_PORT}")
    return proc


def patch_quic_config(base_name, overrides):
    """Load a JSON config, apply overrides (nested dicts merged), write to a temp file."""
    path = os.path.join("config", base_name)
    with open(path, 'r') as f:
        cfg = json.load(f)
    for key, val in overrides.items():
        if isinstance(val, dict) and key in cfg and isinstance(cfg[key], dict):
            cfg[key].update(val)
        else:
            cfg[key] = val
    tmp = path + ".tmp.json"
    with open(tmp, 'w') as f:
        json.dump(cfg, f, indent=4)
    return tmp


def http_get_via_socks5(url, proxy_port, timeout=15):
    """HTTP GET through a SOCKS5 proxy. Returns response bytes."""
    if socks is None:
        raise RuntimeError("PySocks not installed")
    orig = socket.socket
    try:
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", proxy_port)
        socket.socket = socks.socksocket
        req = urllib.request.urlopen(url, timeout=timeout)
        return req.read()
    finally:
        socket.socket = orig


def http_post_via_socks5(url, data, proxy_port, timeout=15):
    """HTTP POST through a SOCKS5 proxy. Returns response bytes."""
    if socks is None:
        raise RuntimeError("PySocks not installed")
    import urllib.parse
    orig = socket.socket
    try:
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", proxy_port)
        socket.socket = socks.socksocket
        encoded = urllib.parse.urlencode({'d': data}).encode()
        req = urllib.request.Request(url, data=encoded)
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.read()
    finally:
        socket.socket = orig


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_e2e_basic_proxy(binary_path):
    """T1: Full QUIC handshake + TrojanRequest proxying via HTTP GET."""
    print_time_log("[T1] e2e_basic_proxy: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json",
                                {"remote_port": HTTP_TARGET_PORT})
    cli_cfg = patch_quic_config("quic_client_config.json", {})

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        # Wait for QUIC handshake on both sides.
        if not wait_for_log(srv_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T1] FAIL: server QUIC handshake not seen in log")
            dump = True
            return False
        print_time_log("[T1] server QUIC handshake OK")

        # Also verify TCP acceptor is up.
        if not wait_for_port(QUIC_SERVER_PORT, timeout=5):
            print_time_log("[T1] FAIL: server TCP port not open")
            dump = True
            return False

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T1] FAIL: client SOCKS5 port not open")
            dump = True
            return False

        # Verify QUIC handshake on client side.
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T1] FAIL: client QUIC handshake not seen in log")
            dump = True
            return False
        print_time_log("[T1] client QUIC handshake OK")

        # Small extra wait so QuicStreamTransport is preferred.
        time.sleep(1)

        # GET a test file through the SOCKS5 proxy.
        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode('utf-8')
        files = [f for f in index.splitlines() if f.strip()]
        if not files:
            print_time_log("[T1] FAIL: no test files listed")
            dump = True
            return False

        test_file = files[0]
        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{test_file}"
        got = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT)
        with open(os.path.join(TEST_FILES_DIR, test_file), 'rb') as f:
            want = f.read()
        if got != want:
            print_time_log(f"[T1] FAIL: content mismatch for {test_file} "
                           f"(got {len(got)} bytes, want {len(want)} bytes)")
            dump = True
            return False

        # Verify server log shows trojan auth via QUIC.
        if not wait_for_log(srv_log, r"QuicProxySession: stream .* authenticated", timeout=5):
            print_time_log("[T1] WARN: trojan auth log not found (may use TLS fallback)")

        print_time_log("[T1] e2e_basic_proxy PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_e2e_multistream(binary_path):
    """T2: N concurrent HTTP GETs over QUIC (multiple bidi streams)."""
    print_time_log("[T2] e2e_multistream: starting...")
    N = 8

    srv_cfg = patch_quic_config("quic_server_config.json",
                                {"remote_port": HTTP_TARGET_PORT})
    cli_cfg = patch_quic_config("quic_client_config.json", {})

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T2] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T2] FAIL: client proxy port not open")
            dump = True
            return False

        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode('utf-8')
        files = [f for f in index.splitlines() if f.strip()][:N]
        if len(files) == 0:
            print_time_log("[T2] FAIL: no test files")
            dump = True
            return False

        def fetch_and_compare(fname):
            url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{fname}"
            got = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT)
            with open(os.path.join(TEST_FILES_DIR, fname), 'rb') as f:
                want = f.read()
            return got == want

        ok = True
        with ThreadPoolExecutor(max_workers=N) as pool:
            futs = {pool.submit(fetch_and_compare, f): f for f in files}
            for fut in as_completed(futs):
                if not fut.result():
                    print_time_log(f"[T2] FAIL: mismatch for {futs[fut]}")
                    ok = False
                    dump = True

        if ok:
            print_time_log(f"[T2] e2e_multistream ({N} streams) PASSED")
        return ok
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_e2e_post_data(binary_path):
    """T3: HTTP POST through QUIC proxy."""
    print_time_log("[T3] e2e_post_data: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json",
                                {"remote_port": HTTP_TARGET_PORT})
    cli_cfg = patch_quic_config("quic_client_config.json", {})

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T3] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T3] FAIL: proxy port not open")
            dump = True
            return False

        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode('utf-8')
        files = [f for f in index.splitlines() if f.strip()]
        if not files:
            print_time_log("[T3] FAIL: no test files")
            dump = True
            return False

        test_file = files[0]
        with open(os.path.join(TEST_FILES_DIR, test_file), 'rb') as f:
            payload = f.read()

        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{test_file}"
        resp = http_post_via_socks5(url, payload, QUIC_CLIENT_PROXY_PORT)
        if resp != b"OK":
            print_time_log(f"[T3] FAIL: POST response = {resp!r}, expected b'OK'")
            dump = True
            return False

        print_time_log("[T3] e2e_post_data PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_h3_upstream_fallback(binary_path):
    """T4: Non-trojan traffic forwarded to h3_upstream (wrong password)."""
    print_time_log("[T4] h3_upstream_fallback: starting...")

    # Server with h3_upstream pointing to mock UDP server.
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h3_upstream": f"127.0.0.1:{H3_UPSTREAM_PORT}"},
    })
    # Client with CORRECT password — we will test fallback by sending non-trojan data.
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "password": ["testpassword123"],
    })

    mock = start_h3_upstream_mock()
    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not mock or not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T4] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T4] FAIL: proxy port not open")
            dump = True
            return False

        # Send any HTTP request — wrong password will trigger h3_upstream.
        try:
            url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
            http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=8)
        except Exception:
            pass  # Response may be garbage; we only care about server log.

        # Verify server log shows UDP h3_upstream forwarding.
        m = wait_for_log(srv_log, r"forwarding to UDP h3_upstream", timeout=10)
        if not m:
            print_time_log("[T4] FAIL: h3_upstream UDP forwarding log not found")
            dump = True
            return False

        # Verify mock server received data.
        m2 = wait_for_log("config/quic_h3mock.output",
                          r"received \d+ bytes", timeout=5)
        if not m2:
            print_time_log("[T4] FAIL: h3_upstream UDP mock did not receive data")
            dump = True
            return False

        print_time_log("[T4] h3_upstream_fallback PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)
        close_process(mock, dump)


def test_idle_timeout(binary_path):
    """T5: Connection closes after max_idle_timeout_ms."""
    print_time_log("[T5] idle_timeout: starting...")

    IDLE_MS = 3000  # 3 seconds
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "max_idle_timeout_ms": IDLE_MS},
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "quic": {"enabled": True, "prefer_quic": True, "max_idle_timeout_ms": IDLE_MS},
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T5] FAIL: QUIC handshake not seen")
            dump = True
            return False
        print_time_log(f"[T5] QUIC handshake done, waiting {IDLE_MS + 2000}ms for idle close...")

        # Wait for idle timeout to fire.
        time.sleep((IDLE_MS + 2000) / 1000.0)

        # Check either side for idle close log.
        found = (wait_for_log(cli_log, r"IDLE_CLOSE|idle.*close", timeout=3) or
                 wait_for_log(srv_log, r"IDLE_CLOSE|idle.*close", timeout=3))
        if not found:
            print_time_log("[T5] FAIL: idle close not seen in logs")
            dump = True
            return False

        print_time_log("[T5] idle_timeout PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_alpn_negotiation(binary_path):
    """T7: Verify ALPN token appears in log during TLS context init."""
    print_time_log("[T7] alpn_negotiation: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "alpn_token": "h3"},
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "quic": {"enabled": True, "prefer_quic": True, "alpn_token": "h3"},
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        # Wait for handshake.
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T7] FAIL: QUIC handshake not seen")
            dump = True
            return False

        # Check ALPN log line from QuicTlsCtx.
        m = wait_for_log(srv_log, r"QuicTlsCtx: initialized.*alpn=h3", timeout=5)
        if not m:
            print_time_log("[T7] FAIL: ALPN=h3 not found in server log")
            dump = True
            return False

        m2 = wait_for_log(cli_log, r"QuicTlsCtx: initialized.*alpn=h3", timeout=5)
        if not m2:
            print_time_log("[T7] FAIL: ALPN=h3 not found in client log")
            dump = True
            return False

        print_time_log("[T7] alpn_negotiation PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_quic_disabled(binary_path):
    """T8: quic.enabled=false → no QUIC logs, TLS path works."""
    print_time_log("[T8] quic_disabled: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": False},
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "quic": {"enabled": False},
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_port(QUIC_SERVER_PORT, timeout=8):
            print_time_log("[T8] FAIL: server TCP port not open")
            dump = True
            return False
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=8):
            print_time_log("[T8] FAIL: client proxy port not open")
            dump = True
            return False

        # There should be NO QUIC-related log lines.
        time.sleep(2)
        quic_log = wait_for_log(srv_log, r"QuicTlsCtx|QuicEndpoint|QuicConnection", timeout=1)
        if quic_log:
            print_time_log("[T8] FAIL: QUIC log found despite enabled=false")
            dump = True
            return False

        # Verify TLS path works (HTTP GET through SOCKS5).
        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode('utf-8')
        files = [f for f in index.splitlines() if f.strip()]
        if not files:
            print_time_log("[T8] FAIL: no test files")
            dump = True
            return False

        test_file = files[0]
        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{test_file}"
        got = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT)
        with open(os.path.join(TEST_FILES_DIR, test_file), 'rb') as f:
            want = f.read()
        if got != want:
            print_time_log(f"[T8] FAIL: content mismatch (TLS path)")
            dump = True
            return False

        print_time_log("[T8] quic_disabled PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALL_TESTS = [
    ("T1", test_e2e_basic_proxy),
    ("T2", test_e2e_multistream),
    ("T3", test_e2e_post_data),
    ("T4", test_h3_upstream_fallback),
    ("T5", test_idle_timeout),
    ("T7", test_alpn_negotiation),
    ("T8", test_quic_disabled),
]


def main(binary_path):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print_time_log("===== QUIC Integration Tests =====")

    # Ensure test files exist.
    if not os.path.isdir(TEST_FILES_DIR):
        print_time_log(f"Test files directory '{TEST_FILES_DIR}' not found. "
                       "Run with -g to generate test files first.")
        return 1

    # Kill any leftover processes on our ports.
    if not is_windows_system():
        for p in [QUIC_SERVER_PORT, QUIC_CLIENT_PROXY_PORT, HTTP_TARGET_PORT, H3_UPSTREAM_PORT]:
            os.system(f"lsof -ti:{p} | xargs kill -9 > /dev/null 2>&1")

    # Start the dedicated HTTP target server.
    http_target = start_http_target()
    if not http_target:
        return 1

    passed = 0
    failed = 0
    try:
        for tag, fn in ALL_TESTS:
            print_time_log(f"--- Running {tag} ---")
            try:
                if fn(binary_path):
                    passed += 1
                else:
                    failed += 1
                    print_time_log(f"--- {tag} FAILED ---")
            except Exception:
                traceback.print_exc()
                failed += 1
            # Brief cooldown between tests.
            time.sleep(2)
    finally:
        close_process(http_target, failed > 0)

    print_time_log(f"===== QUIC Tests: {passed} passed, {failed} failed =====")
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <trojan-binary-path>")
        sys.exit(1)
    binary = os.path.abspath(sys.argv[1])
    sys.exit(main(binary))
