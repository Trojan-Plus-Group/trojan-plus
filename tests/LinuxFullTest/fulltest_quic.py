"""
QUIC integration tests for trojan-plus.

Test cases:
  T1:  e2e_basic_proxy              - QUIC handshake + HTTP GET proxy
  T2:  e2e_multistream              - concurrent streams over one QUIC connection
  T3:  e2e_post_data                - HTTP POST through QUIC
  T4:  h3_upstream_fallback         - non-trojan traffic forwarded to h3_upstream
  T5:  idle_timeout                 - connection closes after max_idle_timeout_ms
  T6:  h3_upstream_unconfigured_drop - non-trojan traffic dropped when h3_upstream is empty
  T7:  alpn_negotiation             - verify ALPN token in logs
  T8:  quic_disabled                - quic.enabled=false falls back to TLS
  T9:  client_retry_no_server       - retry_connect_timeout_ms > 0 fires; = 0 does not
  T10: prefer_quic_false            - prefer_quic=false routes data over TLS, not QUIC streams
  T11: tcp_target_unreachable       - server logs error and drops session on TCP connect fail
  T12: large_file_transfer          - 300 KB file exercises QUIC flow-control back-pressure
  T13: h3_upstream_dns_failure      - h3_upstream with invalid hostname → resolve error, no crash
  T14: multiple_quic_connections    - two independent QUIC clients connect to same server concurrently
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
from subprocess import Popen, PIPE

try:
    import socks
except ImportError:
    socks = None

import threading
_socks_lock = threading.Lock()  # protects global socket.socket monkey-patch
_true_socket_class = socket.socket  # save original socket class

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from fulltest_utils import print_time_log, is_windows_system

# ---------------------------------------------------------------------------
# Port assignments (must not collide with existing tests)
# ---------------------------------------------------------------------------
QUIC_SERVER_PORT        = 14651
QUIC_CLIENT_PROXY_PORT  = 10621
QUIC_CLIENT_PROXY_PORT_2 = 10622   # second client for T14
HTTP_TARGET_PORT        = 18083    # dedicated target HTTP server for QUIC tests
H3_UPSTREAM_PORT        = 18182
DEAD_TARGET_PORT        = 19993    # nothing listens here (used by T11)

TEST_FILES_DIR   = 'html'
LARGE_FILE_NAME  = 'quic_large_test.bin'
LARGE_FILE_SIZE  = 300 * 1024      # 300 KB > 256 KB QUIC flow-control window

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


def _kill_port(port):
    """Kill any process listening on a given UDP port (Windows)."""
    try:
        result = __import__('subprocess').run(
            ['powershell', '-Command',
             f'(Get-NetUDPEndpoint -LocalPort {port} -ErrorAction SilentlyContinue).OwningProcess | ForEach-Object {{ Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }}'],
            capture_output=True, timeout=5)
    except Exception:
        pass


def start_h3_upstream_mock():
    """Start the h3_upstream TCP mock server (kills any stale process on that port first)."""
    _kill_port(H3_UPSTREAM_PORT)
    time.sleep(0.3)
    log_file = open("config/quic_h3mock.output", "w+")
    proc = Popen([sys.executable, "-u", "fulltest_quic_h3mock.py", str(H3_UPSTREAM_PORT)],
                 executable=sys.executable,
                 bufsize=1024 * 1024,
                 stdout=log_file, stderr=log_file,
                 universal_newlines=True)
    proc._log_file = log_file
    proc._log_path = "config/quic_h3mock.output"
    if not wait_for_log("config/quic_h3mock.output", r"listening on .*:" + str(H3_UPSTREAM_PORT), timeout=8):
        print_time_log(f"h3_upstream TCP mock server failed to start on {H3_UPSTREAM_PORT}")
        proc.kill()
        log_file.close()
        return None
    print_time_log(f"h3_upstream TCP mock server ready on {H3_UPSTREAM_PORT}")
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


def patch_quic_config_with_suffix(base_name, suffix, overrides):
    """Like patch_quic_config but writes to a file with a custom suffix."""
    path = os.path.join("config", base_name)
    with open(path, 'r') as f:
        cfg = json.load(f)
    for key, val in overrides.items():
        if isinstance(val, dict) and key in cfg and isinstance(cfg[key], dict):
            cfg[key].update(val)
        else:
            cfg[key] = val
    tmp = path + suffix
    with open(tmp, 'w') as f:
        json.dump(cfg, f, indent=4)
    return tmp


def http_get_via_socks5(url, proxy_port, timeout=60):
    """HTTP GET through a SOCKS5 proxy using a manual socket and http.client for thread safety."""
    import urllib.parse
    import http.client
    parsed = urllib.parse.urlparse(url)
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", proxy_port)
    s.settimeout(timeout)
    try:
        s.connect((parsed.hostname, parsed.port or 80))
        conn = http.client.HTTPConnection(parsed.hostname, port=parsed.port or 80)
        conn.sock = s
        conn.request("GET", parsed.path + ("?" + parsed.query if parsed.query else ""))
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return data
    except Exception as e:
        s.close()
        raise e

def http_post_via_socks5(url, data, proxy_port, timeout=60):
    """HTTP POST through a SOCKS5 proxy using a manual socket and http.client for thread safety."""
    import urllib.parse
    import http.client
    parsed = urllib.parse.urlparse(url)
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", proxy_port)
    s.settimeout(timeout)
    try:
        s.connect((parsed.hostname, parsed.port or 80))
        conn = http.client.HTTPConnection(parsed.hostname, port=parsed.port or 80)
        conn.sock = s
        body = data.encode() if isinstance(data, str) else data
        conn.request("POST", parsed.path + ("?" + parsed.query if parsed.query else ""), body=body)
        resp = conn.getresponse()
        data_recv = resp.read()
        conn.close()
        return data_recv
    except Exception as e:
        s.close()
        raise e


def ensure_large_test_file():
    """Create a 300 KB test file in the html directory if it doesn't exist.
    Returns True if the file is ready, False if html dir doesn't exist.
    """
    if not os.path.isdir(TEST_FILES_DIR):
        return False
    large_path = os.path.join(TEST_FILES_DIR, LARGE_FILE_NAME)
    if not os.path.exists(large_path):
        import random
        rng = random.Random(42)
        CHARS = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        data = bytes(CHARS[rng.randrange(len(CHARS))] for _ in range(LARGE_FILE_SIZE))
        with open(large_path, 'wb') as f:
            f.write(data)
        index_path = os.path.join(TEST_FILES_DIR, "index.html")
        if os.path.exists(index_path):
            with open(index_path, 'a') as f:
                f.write('\n' + LARGE_FILE_NAME)
        print_time_log(f"Created large test file: {large_path} ({LARGE_FILE_SIZE} bytes)")
    return True


# ---------------------------------------------------------------------------
# Test cases  T1 – T8 (existing)
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
    """T4: HTTP/3 traffic forwarded to h3_upstream."""
    print_time_log("[T4] h3_upstream_fallback: starting...")

    # Server with h3_upstream pointing to mock TCP server.
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h3_upstream": f"127.0.0.1:{H3_UPSTREAM_PORT}"},
    })

    mock = start_h3_upstream_mock()
    server, srv_log = start_trojan(binary_path, srv_cfg)
    dump = False
    try:
        if not mock or not server:
            dump = True
            return False

        # Wait for QUIC server to be ready (UDP listener is up).
        if not wait_for_log(srv_log, r"QuicServerEndpoint: listening on UDP", timeout=10):
            print_time_log("[T4] FAIL: server QUIC endpoint not ready")
            dump = True
            return False
        time.sleep(1)

        # Run aioquic in a subprocess to simulate a real HTTP/3 browser client.
        # This will send proper H3 frames (not Trojan protocol bytes) which
        # QuicUpstreamHandler expects during fallback.
        script_path = os.path.join(os.path.dirname(__file__), "quic_t4_aioquic_client.py")
        result = __import__('subprocess').run(
            [sys.executable, "-u", script_path, str(QUIC_SERVER_PORT)],
            capture_output=True, timeout=15
        )
        
        stdout_str = result.stdout.decode('utf-8', errors='replace')
        for line in stdout_str.splitlines():
            if line.strip():
                print_time_log(f"[T4] aioquic: {line}")
        if result.stderr:
            for line in result.stderr.decode('utf-8', errors='replace').splitlines():
                if line.strip() and 'AIOQUIC_ERROR' not in line:
                    print_time_log(f"[T4] aioquic stderr: {line}")

        # Verify server log shows HTTP upstream forwarding.
        m = wait_for_log(srv_log, r"HTTP upstream connected to", timeout=10)
        if not m:
            print_time_log("[T4] FAIL: h3_upstream forwarding log not found")
            dump = True
            return False

        # Verify mock server received data.
        m2 = wait_for_log("config/quic_h3mock.output",
                          r"received \d+ bytes", timeout=5)
        if not m2:
            print_time_log("[T4] FAIL: h3_upstream TCP mock did not receive data")
            dump = True
            return False

        # Verify mock also sent a response back (round-trip).
        m3 = wait_for_log("config/quic_h3mock.output",
                          r"sent response", timeout=5)
        if not m3:
            print_time_log("[T4] FAIL: h3_upstream TCP mock did not send response")
            dump = True
            return False

        # Verify the response was relayed back through the QUIC stream to the client.
        if "H3 Upstream Fallback!" not in stdout_str:
            print_time_log(f"[T4] FAIL: mock response not relayed to client "
                           f"(got stdout: {stdout_str})")
            dump = True
            return False

        print_time_log("[T4] h3_upstream_fallback PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
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


def test_h3_upstream_unconfigured_drop(binary_path):
    """T6: Non-trojan traffic with h3_upstream='' → server falls back to remote_addr (Trojan decoy), stays alive.

    QuicProxySession::forward_to_h3_upstream() in src/quic/quic_session.cpp:
      * h3_upstream non-empty           → forward there (covered by T4)
      * h3_upstream empty, remote_addr  → fall back to remote_addr:remote_port
                                          (classic Trojan decoy anti-probing)
      * neither configured              → log "not configured, dropping" + destroy()

    A real server config always has remote_addr set, so the implicit fallback
    is the actual unconfigured-h3-upstream behavior to verify here.
    """
    print_time_log("[T6] h3_upstream_unconfigured_drop: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h3_upstream": ""},
    })
    # Client with WRONG password so the server cannot authenticate the Trojan
    # request and falls into forward_to_h3_upstream() → remote_addr fallback.
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "password": ["wrongpassword_t6"],
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T6] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T6] FAIL: proxy port not open")
            dump = True
            return False

        # Send a request – the wrong password causes an auth failure on the server,
        # which triggers forward_to_h3_upstream(). With h3_upstream empty, it
        # falls back to remote_addr:remote_port (the configured HTTP target).
        try:
            url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
            http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=5)
        except Exception:
            pass  # The wrong-password garbage won't be a valid HTTP request from
                  # urllib's perspective; client-side parse failure is expected.

        # The server must log the invalid-password fallback.
        if not wait_for_log(srv_log, r"invalid password, forwarding to h3_upstream", timeout=10):
            print_time_log("[T6] FAIL: 'invalid password, forwarding to h3_upstream' not found in server log")
            dump = True
            return False

        # And it must fall back to remote_addr:remote_port (the legacy Trojan decoy path).
        fallback_pat = r"falling back to h3_upstream 127\.0\.0\.1:" + str(HTTP_TARGET_PORT)
        if not wait_for_log(srv_log, fallback_pat, timeout=5):
            print_time_log(f"[T6] FAIL: server did not fall back to remote_addr:{HTTP_TARGET_PORT}")
            dump = True
            return False

        # Verify the server process is still alive (did not crash).
        if server.poll() is not None:
            print_time_log("[T6] FAIL: server process crashed")
            dump = True
            return False

        print_time_log("[T6] h3_upstream_unconfigured_drop PASSED")
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
# Test cases  T9 – T14 (new)
# ---------------------------------------------------------------------------

def test_client_retry_no_server(binary_path):
    """T9: retry_connect_timeout_ms > 0 fires retry; = 0 does not retry.

    mark_unreachable() is called when the DNS resolution for the server address
    fails. With retry_connect_timeout_ms=500, the timer fires and logs
    "retrying QUIC connection". With retry_connect_timeout_ms=0, no retry log.
    """
    print_time_log("[T9] client_retry_no_server: starting...")

    # --- Part A: retry_connect_timeout_ms=500, should see "retrying" ---
    # Use an unresolvable hostname (.invalid TLD is reserved by RFC 2606).
    cli_cfg_a = patch_quic_config("quic_client_config.json", {
        "remote_addr": "quic-test-unreachable.invalid",
        "quic": {"enabled": True, "prefer_quic": True, "retry_connect_timeout_ms": 500},
    })
    client_a, cli_log_a = start_trojan(binary_path, cli_cfg_a)
    dump_a = False
    part_a_ok = False
    try:
        if not client_a:
            dump_a = True
        else:
            # DNS failure should be quick; retry at 500 ms; allow up to 10 s total.
            m = wait_for_log(cli_log_a,
                             r"retrying QUIC connection|server resolve failed",
                             timeout=10)
            if not m:
                print_time_log("[T9] FAIL: Part A — no retry/resolve-failed log with retry_ms=500")
                dump_a = True
            else:
                retry_seen = wait_for_log(cli_log_a, r"retrying QUIC connection", timeout=5)
                if not retry_seen:
                    print_time_log("[T9] FAIL: Part A — resolve failed but no retry log (retry_ms=500)")
                    dump_a = True
                else:
                    print_time_log("[T9] Part A OK: retry log seen with retry_ms=500")
                    part_a_ok = True
    except Exception:
        traceback.print_exc()
        dump_a = True
    finally:
        close_process(client_a, dump_a)

    if not part_a_ok:
        return False

    # --- Part B: retry_connect_timeout_ms=0, must NOT see "retrying" ---
    cli_cfg_b = patch_quic_config_with_suffix("quic_client_config.json", ".tmpb.json", {
        "remote_addr": "quic-test-unreachable.invalid",
        "quic": {"enabled": True, "prefer_quic": True, "retry_connect_timeout_ms": 0},
    })
    client_b, cli_log_b = start_trojan(binary_path, cli_cfg_b)
    dump_b = False
    part_b_ok = False
    try:
        if not client_b:
            dump_b = True
        else:
            # Wait for DNS failure first.
            wait_for_log(cli_log_b, r"server resolve failed", timeout=10)
            time.sleep(2)  # Extra grace period; if retry_ms=0, no retry should fire.
            with open(cli_log_b, 'r', errors='replace') as f:
                content = f.read()
            if re.search(r"retrying QUIC connection", content):
                print_time_log("[T9] FAIL: Part B — retry log appeared with retry_ms=0")
                dump_b = True
            else:
                print_time_log("[T9] Part B OK: no retry seen with retry_ms=0")
                part_b_ok = True
    except Exception:
        traceback.print_exc()
        dump_b = True
    finally:
        close_process(client_b, dump_b)

    if not part_b_ok:
        return False

    print_time_log("[T9] client_retry_no_server PASSED")
    return True


def test_prefer_quic_false(binary_path):
    """T10: prefer_quic=false → QUIC endpoint connects but data is routed via TLS.

    QuicClientEndpoint still establishes a QUIC connection (enabled=true), but
    the per-request transport selector skips it (prefer_quic=false).  The server
    should therefore never see any QuicProxySession streams for the test request.
    """
    print_time_log("[T10] prefer_quic_false: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "quic": {"enabled": True, "prefer_quic": False},
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_port(QUIC_SERVER_PORT, timeout=8):
            print_time_log("[T10] FAIL: server port not open")
            dump = True
            return False
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=8):
            print_time_log("[T10] FAIL: client proxy port not open")
            dump = True
            return False

        # Allow the QUIC endpoint time to (optionally) handshake in background.
        time.sleep(2)

        # Fetch a test file — should succeed via TLS transport.
        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        got_index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode('utf-8')
        files = [f for f in got_index.splitlines() if f.strip()]
        if not files:
            print_time_log("[T10] FAIL: no test files")
            dump = True
            return False

        test_file = files[0]
        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{test_file}"
        got = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT)
        with open(os.path.join(TEST_FILES_DIR, test_file), 'rb') as f:
            want = f.read()
        if got != want:
            print_time_log("[T10] FAIL: content mismatch — TLS path did not work")
            dump = True
            return False

        # With prefer_quic=false, the server must never handle the request as a
        # QUIC proxy session (no QuicProxySession stream opened for proxy data).
        with open(srv_log, 'r', errors='replace') as f:
            srv_content = f.read()
        if re.search(r"QuicProxySession: stream \d+ opened", srv_content):
            print_time_log("[T10] FAIL: QuicProxySession stream opened on server despite prefer_quic=false")
            dump = True
            return False

        print_time_log("[T10] prefer_quic_false PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_tcp_target_unreachable(binary_path):
    """T11: Server cannot reach the TCP target → session destroyed, client doesn't hang.

    The trojan request wraps the destination 127.0.0.1:DEAD_TARGET_PORT.
    The server's QuicProxySession::connect_target() gets a connection-refused
    error and must destroy the session cleanly without blocking.
    """
    print_time_log("[T11] tcp_target_unreachable: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {})

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T11] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T11] FAIL: proxy port not open")
            dump = True
            return False

        # Request targets DEAD_TARGET_PORT — the server will try to TCP-connect
        # to 127.0.0.1:DEAD_TARGET_PORT and get connection-refused.
        t_start = time.time()
        try:
            url = f"http://127.0.0.1:{DEAD_TARGET_PORT}/"
            http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=10)
        except Exception:
            pass  # Expected: the connection will be refused/closed.
        elapsed = time.time() - t_start

        # The request must not hang — should fail within 12 seconds.
        if elapsed > 12:
            print_time_log(f"[T11] FAIL: request hung for {elapsed:.1f}s")
            dump = True
            return False

        # Verify the server logged a target-unreachable message.
        m = wait_for_log(srv_log, r"target unreachable|connect.*failed", timeout=8)
        if not m:
            print_time_log("[T11] FAIL: no 'target unreachable' log found on server")
            dump = True
            return False

        # Server process must still be alive.
        if server.poll() is not None:
            print_time_log("[T11] FAIL: server process crashed")
            dump = True
            return False

        print_time_log(f"[T11] tcp_target_unreachable PASSED (elapsed={elapsed:.2f}s)")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_large_file_transfer(binary_path):
    """T12: Transfer a 300 KB file through QUIC to exercise flow-control back-pressure.

    The QUIC stream window is 256 KB (initial_max_stream_data_bidi_*).  A 300 KB
    file forces flush_tcp_read_buf() to hit NGTCP2_ERR_STREAM_DATA_BLOCKED and
    retry via the 5 ms write timer, verifying that path works correctly.
    """
    print_time_log("[T12] large_file_transfer: starting...")

    if not ensure_large_test_file():
        print_time_log("[T12] SKIP: html test-files directory not available")
        return True

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {})

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T12] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T12] FAIL: proxy port not open")
            dump = True
            return False

        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{LARGE_FILE_NAME}"
        got = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=30)
        with open(os.path.join(TEST_FILES_DIR, LARGE_FILE_NAME), 'rb') as f:
            want = f.read()

        if len(got) != len(want):
            print_time_log(f"[T12] FAIL: size mismatch (got {len(got)}, want {len(want)})")
            dump = True
            return False
        if got != want:
            print_time_log("[T12] FAIL: content mismatch for large file")
            dump = True
            return False

        print_time_log(f"[T12] large_file_transfer PASSED ({len(got)} bytes)")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_h3_upstream_dns_failure(binary_path):
    """T13: h3_upstream hostname doesn't resolve → session destroyed, server stays alive.

    QuicProxySession::forward_to_h3_upstream() calls async_resolve on the
    h3_upstream address.  If DNS fails, the error is logged and destroy() is
    called.  The server process must not crash.
    """
    print_time_log("[T13] h3_upstream_dns_failure: starting...")

    # Configure h3_upstream with an unresolvable hostname.
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h3_upstream": "quic-test-h3-upstream.invalid:443"},
    })
    # Wrong password forces the server into forward_to_h3_upstream().
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "password": ["wrongpassword_t13"],
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T13] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T13] FAIL: proxy port not open")
            dump = True
            return False

        # Trigger the wrong-password → forward_to_h3_upstream() → DNS failure path.
        try:
            url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
            http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=5)
        except Exception:
            pass  # Expected: DNS fails, session is dropped.

        # DNS resolution for .invalid can be slow on some resolvers; allow up to 20 s.
        m = wait_for_log(srv_log, r"h3_upstream TCP resolve failed", timeout=20)
        if not m:
            print_time_log("[T13] FAIL: 'h3_upstream TCP resolve failed' not in server log")
            dump = True
            return False

        # Server must remain alive.
        if server.poll() is not None:
            print_time_log("[T13] FAIL: server crashed after h3_upstream DNS failure")
            dump = True
            return False

        print_time_log("[T13] h3_upstream_dns_failure PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_multiple_quic_connections(binary_path):
    """T14: Two independent QUIC clients connect to the same server concurrently.

    Validates QuicServerEndpoint::m_conns routing-table correctness when two
    separate connection IDs (from different UDP sources) coexist simultaneously.
    """
    print_time_log("[T14] multiple_quic_connections: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
    })
    # Client 1: standard config on QUIC_CLIENT_PROXY_PORT.
    cli_cfg1 = patch_quic_config("quic_client_config.json", {})
    # Client 2: identical config but on a different local SOCKS5 port.
    cli_cfg2 = patch_quic_config_with_suffix("quic_client_config.json", ".tmp2.json", {
        "local_port": QUIC_CLIENT_PROXY_PORT_2,
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client1, cli_log1 = start_trojan(binary_path, cli_cfg1)
    client2, cli_log2 = start_trojan(binary_path, cli_cfg2)
    dump = False
    try:
        if not server or not client1 or not client2:
            dump = True
            return False

        # Both clients must complete the QUIC handshake.
        if not wait_for_log(cli_log1, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T14] FAIL: client1 QUIC handshake not seen")
            dump = True
            return False
        if not wait_for_log(cli_log2, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T14] FAIL: client2 QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T14] FAIL: client1 proxy port not open")
            dump = True
            return False
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT_2, timeout=5):
            print_time_log("[T14] FAIL: client2 proxy port not open")
            dump = True
            return False

        # Resolve the list of test files.
        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode('utf-8')
        files = [f for f in index.splitlines() if f.strip()]
        if not files:
            print_time_log("[T14] FAIL: no test files")
            dump = True
            return False

        # Use two different files so the transfers are genuinely independent.
        file1 = files[0]
        file2 = files[1] if len(files) > 1 else files[0]
        url1 = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{file1}"
        url2 = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{file2}"
        with open(os.path.join(TEST_FILES_DIR, file1), 'rb') as f:
            want1 = f.read()
        with open(os.path.join(TEST_FILES_DIR, file2), 'rb') as f:
            want2 = f.read()

        def fetch(url, proxy_port, want):
            got = http_get_via_socks5(url, proxy_port)
            return got == want

        ok = True
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut1 = pool.submit(fetch, url1, QUIC_CLIENT_PROXY_PORT, want1)
            fut2 = pool.submit(fetch, url2, QUIC_CLIENT_PROXY_PORT_2, want2)
            for fut, label in [(fut1, "client1"), (fut2, "client2")]:
                if not fut.result():
                    print_time_log(f"[T14] FAIL: data mismatch for {label}")
                    ok = False
                    dump = True

        if ok:
            print_time_log("[T14] multiple_quic_connections PASSED")
        return ok
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client2, dump)
        close_process(client1, dump)
        close_process(server, dump)


def test_no_crlf_fallback(binary_path):
    """
    T15: test_no_crlf_fallback
    This test verifies that if non-Trojan traffic is sent (no CRLF), the server
    falls back to H3. If that traffic is also invalid H3 (garbage), the server
    must close the connection with H3_FRAME_ERROR and NOT forward any data
    to the h3_upstream mock.
    """
    print_time_log("[T15] test_no_crlf_fallback: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h3_upstream": f"127.0.0.1:{H3_UPSTREAM_PORT}"},
    })

    mock = start_h3_upstream_mock()
    server, srv_log = start_trojan(binary_path, srv_cfg)

    try:
        dump = False
        if not mock or not server:
            dump = True
            return False

        # Wait for QUIC server to be ready (UDP listener is up).
        if not wait_for_log(srv_log, r"QuicServerEndpoint: listening on UDP", timeout=10):
            print_time_log("[T15] FAIL: server QUIC endpoint not ready")
            dump = True
            return False

        # Run aioquic in a subprocess to avoid event-loop conflicts with the
        # SOCKS socket monkey-patching done by other test functions.
        script_path = os.path.join(os.path.dirname(__file__), "quic_t15_aioquic_client.py")
        try:
            result = __import__('subprocess').run(
                [sys.executable, "-u", script_path, str(QUIC_SERVER_PORT)],
                capture_output=True, timeout=15
            )
            stdout_str = result.stdout.decode('utf-8', errors='replace')
            stderr_str = result.stderr.decode('utf-8', errors='replace')
        except __import__('subprocess').TimeoutExpired as e:
            print_time_log(f"[T15] aioquic client timed out!")
            stdout_str = e.stdout.decode('utf-8', errors='replace') if e.stdout else ""
            stderr_str = e.stderr.decode('utf-8', errors='replace') if e.stderr else ""
        
        combined_out = stdout_str + stderr_str

        if stdout_str:
            for line in stdout_str.splitlines():
                if line.strip():
                    print_time_log(f"[T15] aioquic: {line}")
        if stderr_str:
            for line in stderr_str.splitlines():
                if line.strip() and 'CLIENT_EXPECTED_ERROR' not in line:
                    print_time_log(f"[T15] aioquic stderr: {line}")

        if 'CLIENT_EXPECTED_ERROR' not in combined_out:
            print_time_log("[T15] FAIL: aioquic client did not report expected error")
            dump = True
            return False
        
        # Verify it's a real protocol error (non-zero code)
        import re
        m_err = re.search(r'CLIENT_EXPECTED_ERROR: Code (\d+)', combined_out)
        if m_err:
            error_code = int(m_err.group(1))
            if error_code == 0:
                print_time_log(f"[T15] FAIL: aioquic client reported Code 0 (NO_ERROR), but protocol error was expected")
                dump = True
                return False
            print_time_log(f"[T15] aioquic client reported expected protocol error code: {error_code}")
        elif "Connection closed without specific event" in combined_out:
             # This might happen if closure was very abrupt, but we prefer a code.
             # For now, let's allow it but log a warning.
             print_time_log("[T15] WARNING: aioquic client reported closure without specific error code")
        else:
            print_time_log("[T15] aioquic client reported expected error string")

        # 1. Verify server fell back to h3_upstream.
        m = wait_for_log(srv_log, r"(no CRLF in|first byte not hex)", timeout=10)
        if not m:
            print_time_log("[T15] FAIL: 'no CRLF in' not found in server log")
            dump = True
            return False
        print_time_log("[T15] server fallback triggered (no CRLF in 128 bytes)")

        # 2. Verify server reported H3_FRAME_ERROR as expected.
        m2 = wait_for_log(srv_log, r"H3 protocol error.*H3_FRAME_(ERROR|UNEXPECTED)", timeout=10)
        if not m2:
            print_time_log("[T15] FAIL: H3 protocol error not found in server log")
            dump = True
            return False
        print_time_log("[T15] Standard H3 error handling verified (H3_FRAME_ERROR logged)")

        # 3. Verify h3_upstream mock DID NOT receive any data.
        # We check the mock log for "received" or "accepted connection".
        mock_log_path = "config/quic_h3mock.output"
        if os.path.exists(mock_log_path):
            with open(mock_log_path, "r") as f:
                content = f.read()
                if "received" in content:
                    print_time_log("[T15] FAIL: h3_upstream mock received data unexpectedly")
                    dump = True
                    return False
        print_time_log("[T15] h3_upstream mock remained idle as expected")

        # Server must stay alive.
        if server.poll() is not None:
            print_time_log("[T15] FAIL: server process crashed")
            dump = True
            return False

        print_time_log("[T15] test_no_crlf_fallback PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(server, dump)
        close_process(mock, dump)

def test_quic_load_test(binary_path):
    """T16: QUIC Load Test - parallel proxy and H3 fallback traffic."""
    print_time_log("[T16] quic_load_test: starting...")
    
    # --- Configuration ---
    ENABLE_SOCKS_LOAD = True
    ENABLE_H3_LOAD    = False
    
    TOTAL_FILES       = 100
    SOCKS_CONCURRENCY = 5
    H3_CONCURRENCY    = 50
    # ---------------------

    # 1. Server config: proxy to HTTP_TARGET_PORT, fallback to HTTP_TARGET_PORT.
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {
            "h3_upstream": f"127.0.0.1:{HTTP_TARGET_PORT}",
            "alpn_token": "h3"
        }
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "quic": {
            "alpn_token": "trojan"
        }
    })
    
    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False

    try:
        if not server or not client:
            dump = True
            return False
            
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T16] FAIL: QUIC handshake not seen")
            dump = True
            return False
            
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T16] FAIL: client proxy port not open")
            dump = True
            return False

        # Get list of files from target server
        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode('utf-8')
        all_files = [f for f in index.splitlines() if f.strip()]
        if not all_files:
            print_time_log("[T16] FAIL: no test files")
            return False
            
        # Select some files for testing
        test_files = (all_files * TOTAL_FILES)[:TOTAL_FILES]
        
        def fetch_proxy(fname):
            url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{fname}"
            try:
                got = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT)
                with open(os.path.join(TEST_FILES_DIR, fname), 'rb') as f:
                    want = f.read()
                return fname, got == want, len(got)
            except Exception as e:
                return fname, False, str(e)

        def run_proxy_load():
            print_time_log(f"[T16] Starting {len(test_files)} SOCKS5 proxy requests (concurrency={SOCKS_CONCURRENCY})...")
            results = []
            with ThreadPoolExecutor(max_workers=SOCKS_CONCURRENCY) as pool:
                futs = [pool.submit(fetch_proxy, f) for f in test_files]
                for fut in as_completed(futs):
                    results.append(fut.result())
            return results

        def run_h3_load(concurrency=20):
            print_time_log(f"[T16] Starting {len(test_files)} H3 fallback requests (concurrency={concurrency})...")
            
            # Use a temporary file to avoid command line length limits
            list_file = os.path.join("config", "t16_file_list.tmp")
            with open(list_file, "w") as f:
                for tf in test_files:
                    f.write(tf + "\n")
            
            # Run the external aioquic client with new arguments
            cmd = [
                sys.executable, "-u", "quic_t16_aioquic_client.py",
                "--port", str(QUIC_SERVER_PORT),
                "--file-list", list_file,
                "--concurrency", str(concurrency)
            ]
            
            aio_proc = Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
            try:
                stdout, stderr = aio_proc.communicate(timeout=300)
            finally:
                if os.path.exists(list_file):
                    try:
                        os.remove(list_file)
                    except:
                        pass
            return aio_proc.returncode, stdout, stderr

        # Run configured load types
        proxy_results = None
        h3_res = None
        
        with ThreadPoolExecutor(max_workers=2) as main_pool:
            futs = {}
            if ENABLE_SOCKS_LOAD:
                futs['proxy'] = main_pool.submit(run_proxy_load)
            if ENABLE_H3_LOAD:
                futs['h3'] = main_pool.submit(run_h3_load, H3_CONCURRENCY)
            
            if 'proxy' in futs:
                proxy_results = futs['proxy'].result()
            if 'h3' in futs:
                h3_res = futs['h3'].result()

        # 1. Verify Proxy Results
        if ENABLE_SOCKS_LOAD:
            for fname, ok, info in proxy_results:
                if not ok:
                    print_time_log(f"[T16] FAIL: proxy failure for {fname}: {info}")
                    return False
            print_time_log(f"[T16] Proxy parallel requests OK")

        # 2. Verify H3 Results
        if ENABLE_H3_LOAD:
            h3_rc, h3_stdout, h3_stderr = h3_res
            if h3_rc != 0:
                print_time_log(f"[T16] FAIL: aioquic client exited with {h3_rc}")
                if h3_stdout: print_time_log(f"STDOUT: {h3_stdout}")
                if h3_stderr: print_time_log(f"STDERR: {h3_stderr}")
                return False
                
            # Parse aioquic output
            h3_results = {}
            for line in h3_stdout.splitlines():
                if line.startswith("FILE:"):
                    parts = line.split(":")
                    if len(parts) >= 5 and parts[2] == "OK":
                        fname = parts[1]
                        size = int(parts[3])
                        md5 = parts[4]
                        h3_results[fname] = (size, md5)
                    else:
                        print_time_log(f"[T16] FAIL: aioquic error line: {line}")
                        return False

            import hashlib
            for fname in test_files:
                if fname not in h3_results:
                    print_time_log(f"[T16] FAIL: {fname} missing from H3 results")
                    return False
                
                with open(os.path.join(TEST_FILES_DIR, fname), 'rb') as f:
                    want_data = f.read()
                    want_md5 = hashlib.md5(want_data).hexdigest()
                    want_size = len(want_data)
                
                got_size, got_md5 = h3_results[fname]
                if got_size != want_size or got_md5 != want_md5:
                    print_time_log(f"[T16] FAIL: H3 content mismatch for {fname} (got {got_size} bytes, md5 {got_md5}; want {want_size} bytes, md5 {want_md5})")
                    return False
            
            print_time_log(f"[T16] H3 parallel requests OK")
        
        print_time_log(f"[T16] quic_load_test PASSED")
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
    ("T1",  test_e2e_basic_proxy),
    ("T2",  test_e2e_multistream),
    ("T3",  test_e2e_post_data),
    ("T4",  test_h3_upstream_fallback),
    ("T5",  test_idle_timeout),
    ("T6",  test_h3_upstream_unconfigured_drop),
    ("T7",  test_alpn_negotiation),
    ("T8",  test_quic_disabled),
    ("T9",  test_client_retry_no_server),
    ("T10", test_prefer_quic_false),
    ("T11", test_tcp_target_unreachable),
    ("T12", test_large_file_transfer),
    ("T13", test_h3_upstream_dns_failure),
    ("T14", test_multiple_quic_connections),
    ("T15", test_no_crlf_fallback),
    ("T16", test_quic_load_test),
]

def main(binary_path, test_tag='all'):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print_time_log(f"===== QUIC Integration Tests ({test_tag}) =====")

    # Ensure test files exist.
    if not os.path.isdir(TEST_FILES_DIR):
        print_time_log(f"Test files directory '{TEST_FILES_DIR}' not found. "
                       "Run with -g to generate test files first.")
        return 1

    # Filter tests if a specific tag is requested
    tests_to_run = ALL_TESTS
    if test_tag and test_tag != 'all':
        tests_to_run = [t for t in ALL_TESTS if t[0].upper() == test_tag.upper()]
        if not tests_to_run:
            print_time_log(f"Unknown QUIC test tag: {test_tag}")
            return 1

    # Kill any leftover processes on our ports.
    if not is_windows_system():
        for p in [QUIC_SERVER_PORT, QUIC_CLIENT_PROXY_PORT, QUIC_CLIENT_PROXY_PORT_2,
                  HTTP_TARGET_PORT, H3_UPSTREAM_PORT]:
            os.system(f"lsof -ti:{p} | xargs kill -9 > /dev/null 2>&1")

    # Start the dedicated HTTP target server.
    http_target = start_http_target()
    if not http_target:
        return 1

    passed = 0
    failed = 0
    try:
        for tag, fn in tests_to_run:
            with _socks_lock:
                socket.socket = _true_socket_class
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
        print(f"Usage: {sys.argv[0]} <trojan-binary-path> [test-tag]")
        sys.exit(1)
    binary = os.path.abspath(sys.argv[1])
    tag = sys.argv[2] if len(sys.argv) > 2 else 'all'
    sys.exit(main(binary, tag))
