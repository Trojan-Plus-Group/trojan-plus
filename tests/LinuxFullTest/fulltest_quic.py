"""
QUIC integration tests for trojan-plus.

Test cases:
  T1:  e2e_basic_proxy              - QUIC handshake + HTTP GET proxy
  T2:  e2e_multistream              - concurrent streams over one QUIC connection
  T3:  e2e_post_data                - HTTP POST through QUIC
  T4:  h1_upstream_fallback         - non-trojan traffic forwarded to h1_upstream
  T5:  idle_timeout                 - connection closes after max_idle_timeout_ms
  T6:  h1_upstream_unconfigured_drop - non-trojan traffic dropped when h1_upstream is empty
  T7:  alpn_negotiation             - verify ALPN token in logs
  T8:  quic_disabled                - quic.enabled=false falls back to TLS
  T9:  client_retry_no_server       - retry_connect_timeout_ms > 0 fires; = 0 does not
  T11: tcp_target_unreachable       - server logs error and drops session on TCP connect fail
  T12: large_file_transfer          - 300 KB file exercises QUIC flow-control back-pressure
  T13: h1_upstream_dns_failure      - h1_upstream with invalid hostname → resolve error, no crash
  T14: multiple_quic_connections    - two independent QUIC clients connect to same server concurrently
  T18: bidirectional_stream_close   - TCP and UDP proxy streams close cleanly via FIN (log-confirmed)
  T19: quic_ping_keepalive          - PING keep-alive prevents idle close (Part A: no ping→idle close; Part B: ping→no idle close, second request succeeds)
  T20: quic_only_ignores_pipeline    - client bypasses TCP pipeline in QUIC-only mode
  T21: quic_preferred_over_pipeline  - QUIC wins while TCP pipeline remains fallback
  T22: handshake_blackhole_recovery  - black-holed handshake times out, retries, and recovers
  T23: outage_idle_recovery          - proxy recovers within bound after outage exceeding server idle timeout
  T24: outage_download_flight_recovery - proxy request succeeds within bound after outage during active download
  T25: outage_server_forgot_client   - proxy recovers within bound after server forgets connection while client idle
  T26: healthy_idle_streams          - healthy idle streams survive fresh requests without connection recovery
  T27: healthy_paused_bulk_stream    - paused bulk response survives fresh requests without connection recovery
  T29: enabled_sni_verified_name     - verified hostname succeeds with expected wire SNI
  T30: wrong_hostname_rejected       - hostname verification rejects wrong names
  T31: chain_only_wrong_hostname     - chain-only verification accepts wrong names
"""

import atexit
import json
import os
import re
import signal
import socket
import sys
import time
import traceback
import urllib.request
from collections import Counter
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

from quic_relay import UdpRelay
from fulltest_utils import print_time_log, is_windows_system

try:
    import psutil
except ImportError:
    psutil = None

def get_process_memory(pid):
    """Get the RSS memory of a process in bytes."""
    if psutil is not None:
        try:
            process = psutil.Process(pid)
            return process.memory_info().rss
        except Exception:
            pass

    # Fallback 1: UNIX 'ps' command
    try:
        import subprocess
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)])
        rss_kb = int(out.strip())
        return rss_kb * 1024
    except Exception:
        pass

    # Fallback 2: Linux /proc/pid/statm
    try:
        with open(f"/proc/{pid}/statm", "r") as f:
            pages = int(f.read().split()[1])
            import resource
            page_size = resource.getpagesize()
            return pages * page_size
    except Exception:
        pass

    return 0

# ---------------------------------------------------------------------------
# Port assignments (must not collide with existing tests)
# ---------------------------------------------------------------------------
QUIC_SERVER_PORT        = 14651
QUIC_CLIENT_PROXY_PORT  = 10621
QUIC_CLIENT_PROXY_PORT_2 = 10622   # second client for T14
HTTP_TARGET_PORT        = 18083    # dedicated target HTTP server for QUIC tests
H1_STREAM_PORT        = 18182
DEAD_TARGET_PORT        = 19993    # nothing listens here (used by T11)
UDP_ECHO_PORT           = 19911    # local UDP echo server (used by T18)

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
        proc.wait()
        log_file.seek(0)
        print_time_log(log_file.read())
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


def start_h1_upstream_mock():
    """Start the h1_upstream TCP mock server (kills any stale process on that port first)."""
    _kill_port(H1_STREAM_PORT)
    time.sleep(0.3)
    log_file = open("config/quic_h1mock.output", "w+")
    proc = Popen([sys.executable, "-u", "fulltest_quic_h1mock.py", str(H1_STREAM_PORT)],
                 executable=sys.executable,
                 bufsize=1024 * 1024,
                 stdout=log_file, stderr=log_file,
                 universal_newlines=True)
    proc._log_file = log_file
    proc._log_path = "config/quic_h1mock.output"
    if not wait_for_log("config/quic_h1mock.output", r"listening on .*:" + str(H1_STREAM_PORT), timeout=8):
        print_time_log(f"h1_upstream TCP mock server failed to start on {H1_STREAM_PORT}")
        proc.kill()
        log_file.close()
        return None
    print_time_log(f"h1_upstream TCP mock server ready on {H1_STREAM_PORT}")
    return proc


TEMP_CONFIG_FILES = set()


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
    TEMP_CONFIG_FILES.add(tmp)
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
    TEMP_CONFIG_FILES.add(tmp)
    return tmp


def cleanup_temp_configs(*paths):
    """Delete specified temporary config files."""
    for p in paths:
        if p:
            try:
                if os.path.exists(p):
                    os.remove(p)
                TEMP_CONFIG_FILES.discard(p)
            except Exception:
                pass


def cleanup_all_temp_configs():
    """Delete all tracked temporary config files."""
    for p in list(TEMP_CONFIG_FILES):
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    TEMP_CONFIG_FILES.clear()


atexit.register(cleanup_all_temp_configs)


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
        resp = http_post_via_socks5(url, b"d=" + payload, QUIC_CLIENT_PROXY_PORT)
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


def test_h1_upstream_fallback(binary_path):
    """T4: HTTP/3 traffic forwarded to h1_upstream."""
    print_time_log("[T4] h1_upstream_fallback: starting...")

    # Server with h1_upstream pointing to mock TCP server.
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h1_upstream": f"127.0.0.1:{H1_STREAM_PORT}"},
    })

    mock = start_h1_upstream_mock()
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
            print_time_log("[T4] FAIL: h1_upstream forwarding log not found")
            dump = True
            return False

        # Verify mock server received data.
        m2 = wait_for_log("config/quic_h1mock.output",
                          r"received \d+ bytes", timeout=5)
        if not m2:
            print_time_log("[T4] FAIL: h1_upstream TCP mock did not receive data")
            dump = True
            return False

        # Verify mock also sent a response back (round-trip).
        m3 = wait_for_log("config/quic_h1mock.output",
                          r"sent response", timeout=5)
        if not m3:
            print_time_log("[T4] FAIL: h1_upstream TCP mock did not send response")
            dump = True
            return False

        # Verify the response was relayed back through the QUIC stream to the client.
        if "H1 Stream Fallback!" not in stdout_str:
            print_time_log(f"[T4] FAIL: mock response not relayed to client "
                           f"(got stdout: {stdout_str})")
            dump = True
            return False

        print_time_log("[T4] h1_upstream_fallback PASSED")
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

    IDLE_MS = 10000  # 10 seconds
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "max_idle_timeout_ms": IDLE_MS, "ping_interval_ms": 0},
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "quic": {"enabled": True, "max_idle_timeout_ms": IDLE_MS, "ping_interval_ms": 0},
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


def test_h1_upstream_unconfigured_drop(binary_path):
    """T6: Non-trojan traffic with h1_upstream='' → server falls back to remote_addr (Trojan decoy), stays alive.

    QuicProxySession::forward_to_h1_upstream() in src/quic/quic_session.cpp:
      * h1_upstream non-empty           → forward there (covered by T4)
      * h1_upstream empty, remote_addr  → fall back to remote_addr:remote_port
                                          (classic Trojan decoy anti-probing)
      * neither configured              → log "not configured, dropping" + destroy()

    A real server config always has remote_addr set, so the implicit fallback
    is the actual unconfigured-h3-upstream behavior to verify here.
    """
    print_time_log("[T6] h1_upstream_unconfigured_drop: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h1_upstream": ""},
    })
    # Client with WRONG password so the server cannot authenticate the Trojan
    # request and falls into forward_to_h1_upstream() → remote_addr fallback.
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
        # which triggers forward_to_h1_upstream(). With h1_upstream empty, it
        # falls back to remote_addr:remote_port (the configured HTTP target).
        try:
            url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
            http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=5)
        except Exception:
            pass  # The wrong-password garbage won't be a valid HTTP request from
                  # urllib's perspective; client-side parse failure is expected.

        # The server must log the invalid-password fallback.
        if not wait_for_log(srv_log, r"invalid password, forwarding to h1_upstream", timeout=10):
            print_time_log("[T6] FAIL: 'invalid password, forwarding to h1_upstream' not found in server log")
            dump = True
            return False

        # And it must fall back to remote_addr:remote_port (the legacy Trojan decoy path).
        fallback_pat = r"falling back to h1_upstream 127\.0\.0\.1:" + str(HTTP_TARGET_PORT)
        if not wait_for_log(srv_log, fallback_pat, timeout=5):
            print_time_log(f"[T6] FAIL: server did not fall back to remote_addr:{HTTP_TARGET_PORT}")
            dump = True
            return False

        # Verify the server process is still alive (did not crash).
        if server.poll() is not None:
            print_time_log("[T6] FAIL: server process crashed")
            dump = True
            return False

        print_time_log("[T6] h1_upstream_unconfigured_drop PASSED")
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
        "quic": {"enabled": True, "alpn_token": "h3"},
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

# Exceeds both the 63-byte DNS label and 253-byte hostname limits. Native
# getaddrinfo rejects this ASCII name locally, without querying public DNS.
_RESOLVER_FAILURE_HOST = "x" * 256


def test_client_retry_no_server(binary_path):
    """T9: retry_connect_timeout_ms > 0 fires retry; = 0 does not retry.

    mark_unreachable() is called when the DNS resolution for the server address
    fails. With retry_connect_timeout_ms=500, the timer fires and logs
    "retrying QUIC connection". With retry_connect_timeout_ms=0, no retry log.
    """
    print_time_log("[T9] client_retry_no_server: starting...")

    # --- Part A: retry_connect_timeout_ms=500, should see "retrying" ---
    # Force native resolver failure locally, independent of DNS configuration.
    cli_cfg_a = patch_quic_config("quic_client_config.json", {
        "remote_addr": _RESOLVER_FAILURE_HOST,
        "quic": {"enabled": True, "retry_connect_timeout_ms": 500},
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
        "remote_addr": _RESOLVER_FAILURE_HOST,
        "quic": {"enabled": True, "retry_connect_timeout_ms": 0},
    })
    client_b, cli_log_b = start_trojan(binary_path, cli_cfg_b)
    dump_b = False
    part_b_ok = False
    try:
        if not client_b:
            dump_b = True
        else:
            # Require the failure path before checking that retries stay disabled.
            if not wait_for_log(cli_log_b, r"server resolve failed", timeout=10):
                print_time_log("[T9] FAIL: Part B — no resolve-failed log with retry_ms=0")
                dump_b = True
                return False
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


def test_h1_upstream_dns_failure(binary_path):
    """T13: h1_upstream hostname doesn't resolve → session destroyed, server stays alive.

    QuicProxySession::forward_to_h1_upstream() calls async_resolve on the
    h1_upstream address.  If DNS fails, the error is logged and destroy() is
    called.  The server process must not crash.
    """
    print_time_log("[T13] h1_upstream_dns_failure: starting...")

    # Force native resolver failure locally, independent of DNS configuration.
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h1_upstream": f"{_RESOLVER_FAILURE_HOST}:443"},
    })
    # Wrong password forces the server into forward_to_h1_upstream().
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

        # Trigger the wrong-password → forward_to_h1_upstream() → DNS failure path.
        try:
            url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
            http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=5)
        except Exception:
            pass  # Expected: DNS fails, session is dropped.

        # The oversized ASCII name fails in the native resolver without DNS traffic.
        m = wait_for_log(srv_log, r"h1_upstream TCP resolve failed", timeout=20)
        if not m:
            print_time_log("[T13] FAIL: 'h1_upstream TCP resolve failed' not in server log")
            dump = True
            return False

        # Server must remain alive.
        if server.poll() is not None:
            print_time_log("[T13] FAIL: server crashed after h1_upstream DNS failure")
            dump = True
            return False

        print_time_log("[T13] h1_upstream_dns_failure PASSED")
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
    to the h1_upstream mock.
    """
    print_time_log("[T15] test_no_crlf_fallback: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h1_upstream": f"127.0.0.1:{H1_STREAM_PORT}"},
    })

    mock = start_h1_upstream_mock()
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

        # 1. Verify server fell back to h1_upstream.
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

        # 3. Verify h1_upstream mock DID NOT receive any data.
        # We check the mock log for "received" or "accepted connection".
        mock_log_path = "config/quic_h1mock.output"
        if os.path.exists(mock_log_path):
            with open(mock_log_path, "r") as f:
                content = f.read()
                if "received" in content:
                    print_time_log("[T15] FAIL: h1_upstream mock received data unexpectedly")
                    dump = True
                    return False
        print_time_log("[T15] h1_upstream mock remained idle as expected")

        # Server must stay alive.
        if server.poll() is not None:
            print_time_log("[T15] FAIL: server process crashed")
            dump = True
            return False

        print_time_log("[T15] test_no_crlf_fallback PASSED")
        return True

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

def _parse_h3_load_results(stdout: str, requested: list[str]) -> dict[str, list[tuple[int, str]]]:
    """Require one successful H3 result per request, including repeated paths."""
    results: dict[str, list[tuple[int, str]]] = {}
    for line in stdout.splitlines():
        if line.startswith(("H3_FILE_ERROR:", "AIOQUIC_ERROR:")):
            raise ValueError(line)
        if line.startswith("FILE:"):
            parts = line.split(":")
            if len(parts) != 5 or parts[2] != "OK":
                raise ValueError(f"Invalid H3 result: {line}")
            results.setdefault(parts[1], []).append((int(parts[3]), parts[4]))
    if Counter({name: len(items) for name, items in results.items()}) != Counter(requested):
        raise ValueError("H3 result counts do not match requests")
    return results


def _t16_sustained_growth(samples: list[int]) -> float:
    """Measure steady-state median pairwise RSS slope over its observed window.

    Discard three allocator/cache warm-up rounds. Median pairwise slope resists
    isolated RSS spikes and drops without selecting a favorable baseline.
    Live counters cover core objects, not BoringSSL's allocator. RSS includes TLS
    allocations and independently fails sustained growth above the configured limit;
    it cannot prove absence of small TLS leaks or distinguish allocator caching.
    """
    from statistics import median
    if len(samples) < 7 or any(value <= 0 for value in samples):
        raise ValueError("T16 requires at least seven valid per-round RSS samples")
    steady = samples[3:]
    slopes = [(steady[j] - steady[i]) / (j - i)
              for i in range(len(steady)) for j in range(i + 1, len(steady))]
    return median(slopes) * (len(steady) - 1) / median(steady)


def _wait_t16_quiescence(server, client, log_path: str, h3_connections: int,
                         timeout: float = 20.0) -> bool:
    """Wait for load sessions and H3 connections to die; keep Trojan connection."""
    deadline = time.monotonic() + timeout
    poll = threading.Event()
    while True:
        if server.poll() is not None or client.poll() is not None:
            return False
        with open(log_path, errors="replace") as log:
            text = log.read()
        created = text.count("QuicConnection: QuicConnection constructed for peer ")
        destroyed = text.count("QuicConnection: ~QuicConnection destructed for peer ")
        sessions = text.count("QuicProxySession: QuicProxySession constructed stream_id=")
        finished = text.count("QuicProxySession: QuicProxySession destructed stream_id=")
        if (destroyed >= h3_connections and created == destroyed + 1
                and sessions > 0 and sessions == finished):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print_time_log(f"[T16] Teardown timeout: connections={created - destroyed} "
                           f"(expected 1), H3 destroyed={destroyed}/{h3_connections}, "
                           f"sessions={sessions - finished}")
            return False
        poll.wait(min(0.1, remaining))


def _wait_t16_live_counters(process, log_path: str, offset: int,
                            timeout: float = 10.0,
                            idle_sessions: int | None = None) -> dict[str, int]:
    """Require a complete telemetry line written after the quiescence offset."""
    pattern = re.compile(rb"\[mem\] live objects=(\d+) bytes=(\d+) sessions=(\d+) "
                         rb"quic_connections=(\d+) quic_proxy_sessions=(\d+)\r?\n")
    deadline = time.monotonic() + timeout
    poll = threading.Event()
    while process.poll() is None:
        with open(log_path, "rb") as log:
            log.seek(offset)
            match = pattern.search(log.read())
        if match:
            sample = dict(zip(("objects", "bytes", "sessions", "quic_connections",
                               "quic_proxy_sessions"), map(int, match.groups())))
            if idle_sessions is None or (sample["sessions"] == idle_sessions
                    and sample["quic_connections"] == 0 and sample["quic_proxy_sessions"] == 0):
                return sample
            offset += match.end()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        poll.wait(min(0.1, remaining))
    raise ValueError(f"Missing fresh live-counter telemetry after offset {offset}: {log_path}")


def _t16_live_counter_errors(samples: list[dict[str, int]], *, peak_cap: bool = True) -> list[str]:
    """Check lifecycle consistency; only the client caps live-connection capacity."""
    if len(samples) != 10:
        return [f"Expected 10 live-counter samples, got {len(samples)}"]
    errors = []
    baseline = samples[0]
    for round_number, sample in enumerate(samples[1:], 2):
        for key in ("sessions", "quic_connections", "quic_proxy_sessions"):
            if sample[key] != baseline[key]:
                errors.append(f"{key}: baseline={baseline[key]} round{round_number}={sample[key]}")
    objects = [sample["objects"] for sample in samples]
    if peak_cap and max(objects) - objects[0] > 1000:
        errors.append(f"objects: baseline={objects[0]} peak={max(objects)} (overall allowance=1000)")
    return errors


def _t16_idle_counter_errors(baseline: dict[str, int], final: dict[str, int]) -> list[str]:
    """Compare server allocations only after all connection-owned pools are gone."""
    errors = []
    for key in ("quic_connections", "quic_proxy_sessions"):
        if baseline[key] != 0 or final[key] != 0:
            errors.append(f"{key}: idle baseline={baseline[key]} after_close={final[key]} (expected 0)")
    if final["sessions"] != baseline["sessions"]:
        errors.append(f"sessions: idle baseline={baseline['sessions']} after_close={final['sessions']}")
    if final["objects"] - baseline["objects"] > 32:
        errors.append(f"objects: idle baseline={baseline['objects']} after_close={final['objects']} "
                      "(idle allowance=32)")
    return errors


def test_quic_load_test(binary_path):
    """T16: QUIC Load Test - parallel proxy and H3 fallback traffic."""
    print_time_log("[T16] quic_load_test: starting...")
    
    # --- Configuration ---
    ENABLE_SOCKS_LOAD = True
    ENABLE_H3_LOAD    = True
    
    TOTAL_FILES       = 200
    SOCKS_CONCURRENCY = 30
    H3_CONCURRENCY    = 30

    CLIENT_MEMORY_GROW_THRESHOLD = 0.80
    SERVER_MEMORY_GROW_THRESHOLD = 0.80
    LOAD_RUNS         = 10
    # ---------------------

    # 1. Server config: proxy to HTTP_TARGET_PORT, fallback to HTTP_TARGET_PORT.
    srv_cfg = patch_quic_config("quic_server_config.json", {
        "log_live_counters": True,
        "remote_port": HTTP_TARGET_PORT,
        "quic": {
            "h1_upstream": f"127.0.0.1:{HTTP_TARGET_PORT}",
            "alpn_token": "h3"
        }
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "log_live_counters": True,
        "quic": {
            "alpn_token": "trojan"
        }
    })
    
    server, srv_log = start_trojan(binary_path, srv_cfg)
    client = None
    dump = False

    try:
        if not server:
            dump = True
            return False
        idle_baseline = _wait_t16_live_counters(server, srv_log, os.path.getsize(srv_log))
        if idle_baseline["quic_connections"] or idle_baseline["quic_proxy_sessions"]:
            raise ValueError(f"Server not idle before client startup: {idle_baseline}")
        print_time_log("[T16] Server idle baseline: " +
                       " ".join(f"{key}={value}" for key, value in idle_baseline.items()))
        client, cli_log = start_trojan(binary_path, cli_cfg)
        if not client:
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

        # Get initial memory usage
        init_srv_mem = get_process_memory(server.pid)
        init_cli_mem = get_process_memory(client.pid)
        print_time_log(f"[T16] Initial memory - Server PID {server.pid}: {init_srv_mem / 1024 / 1024:.2f} MB, Client PID {client.pid}: {init_cli_mem / 1024 / 1024:.2f} MB")
        srv_memory_samples = []
        cli_memory_samples = []
        live_samples = {"Server": [], "Client": []}

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
                success = (got == want)
                if not success:
                    print_time_log(f"[DEBUG] Content Mismatch for {fname}: got_len={len(got)} want_len={len(want)}")
                    print_time_log(f"[DEBUG] got prefix: {got[:100]}")
                    print_time_log(f"[DEBUG] want prefix: {want[:100]}")
                    print_time_log(f"[DEBUG] got suffix: {got[-100:]}")
                    print_time_log(f"[DEBUG] want suffix: {want[-100:]}")
                return fname, success, len(got)
            except Exception as e:
                return fname, False, str(e)

        def run_proxy_load(crash_event):
            print_time_log(f"[T16] Starting {len(test_files)} SOCKS5 proxy requests (concurrency={SOCKS_CONCURRENCY})...")
            results = []
            done = 0
            with ThreadPoolExecutor(max_workers=SOCKS_CONCURRENCY) as pool:
                futs = [pool.submit(fetch_proxy, f) for f in test_files]
                while any(not f.done() for f in futs):
                    if crash_event.is_set():
                        return [("CRASH", False, "Abort due to other component crash")]
                    if server.poll() is not None:
                        print_time_log("[T16] ERROR: Trojan Server CRASHED during SOCKS load!")
                        crash_event.set()
                        return [("CRASH", False, "Server Crashed")]
                    if client.poll() is not None:
                        print_time_log("[T16] ERROR: Trojan Client CRASHED during SOCKS load!")
                        crash_event.set()
                        return [("CRASH", False, "Client Crashed")]
                    time.sleep(0.5)
                
                for fut in futs:
                    results.append(fut.result())
                    done += 1
                    if done % 10 == 0 or done == len(test_files):
                        print_time_log(f"[T16] Proxy progress: {done}/{len(test_files)}")
            return results

        def run_h3_load(crash_event, concurrency=20, iteration=1):
            print_time_log(f"[T16] Starting {len(test_files)} H3 fallback requests (concurrency={concurrency})...")
            
            list_file = os.path.join("config", "t16_file_list.tmp")
            with open(list_file, "w") as f:
                for tf in test_files:
                    f.write(tf + "\n")
            
            cmd = [
                sys.executable, "-u", "quic_t16_aioquic_client.py",
                "--port", str(QUIC_SERVER_PORT),
                "--file-list", list_file,
                "--concurrency", str(concurrency)
            ]
            
            t16_log_path = os.path.join("config", "quic_t16_log.output")
            os.makedirs(os.path.dirname(t16_log_path), exist_ok=True)
            log_file = open(t16_log_path, "w")
            log_file.write(f"--- H3 Load run (iteration {iteration}) ---\n")
            log_file.flush()
            
            log_lock = threading.Lock()
            
            aio_proc = Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
            stdout_lines = []
            stderr_lines = []
            
            def reader_thread(pipe, lines_list, prefix=""):
                from datetime import datetime
                try:
                    for line in pipe:
                        line = line.strip()
                        if line:
                            lines_list.append(line)
                            with log_lock:
                                try:
                                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                                    log_file.write(f"[{ts}] [{prefix}] {line}\n")
                                    log_file.flush()
                                except: pass
                            if line.startswith("H3_PROGRESS:") or line.startswith("AIOQUIC_") or line.startswith("H3_EVENT:"):
                                print_time_log(f"[T16] {line}")
                            elif line.startswith("FILE:") and ":OK:" in line:
                                # Optional: could print per-file if needed, but summary is cleaner
                                pass
                except: pass

            t_out = threading.Thread(target=reader_thread, args=(aio_proc.stdout, stdout_lines, "STDOUT"))
            t_err = threading.Thread(target=reader_thread, args=(aio_proc.stderr, stderr_lines, "STDERR"))
            t_out.start()
            t_err.start()
            
            try:
                while aio_proc.poll() is None:
                    if crash_event.is_set():
                        aio_proc.kill()
                        return -1, "", "Abort due to other component crash"
                    if server.poll() is not None:
                        print_time_log("[T16] ERROR: Trojan Server CRASHED during H3 load!")
                        crash_event.set()
                        aio_proc.kill()
                        return -1, "", "Trojan Server Crashed"
                    if client.poll() is not None:
                        print_time_log("[T16] ERROR: Trojan Client CRASHED during H3 load!")
                        crash_event.set()
                        aio_proc.kill()
                        return -1, "", "Trojan Client Crashed"
                    time.sleep(0.5)
                
                t_out.join()
                t_err.join()
                stdout = "\n".join(stdout_lines)
                stderr = "\n".join(stderr_lines)
                return aio_proc.returncode, stdout, stderr
            except:
                aio_proc.kill()
                t_out.join()
                t_err.join()
                raise
            finally:
                if os.path.exists(list_file):
                    try:
                        os.remove(list_file)
                    except:
                        pass
                try:
                    log_file.close()
                except:
                    pass
            return aio_proc.returncode, stdout, stderr

        # Run configured load types
        for run_idx in range(LOAD_RUNS):
            print_time_log(f"[T16] Running load iteration {run_idx + 1}/{LOAD_RUNS}...")
            proxy_results = None
            h3_res = None
            
            crash_event = threading.Event()
            with ThreadPoolExecutor(max_workers=2) as main_pool:
                futs = {}
                if ENABLE_SOCKS_LOAD:
                    futs['proxy'] = main_pool.submit(run_proxy_load, crash_event)
                if ENABLE_H3_LOAD:
                    futs['h3'] = main_pool.submit(run_h3_load, crash_event, H3_CONCURRENCY, run_idx + 1)
                
                if 'proxy' in futs:
                    proxy_results = futs['proxy'].result()
                if 'h3' in futs:
                    h3_res = futs['h3'].result()

            # 1. Verify Proxy Results
            if ENABLE_SOCKS_LOAD:
                if proxy_results and proxy_results[0][0] == "CRASH":
                    dump = True
                    return False
                for fname, ok, info in proxy_results:
                    if not ok:
                        print_time_log(f"[T16] FAIL: proxy failure for {fname}: {info} (iteration {run_idx + 1})")
                        dump = True
                        return False
                print_time_log(f"[T16] Proxy parallel requests OK (iteration {run_idx + 1})")

            # 2. Verify H3 Results
            if ENABLE_H3_LOAD:
                h3_rc, h3_stdout, h3_stderr = h3_res
                if h3_rc != 0:
                    if h3_rc == -1:
                        dump = True
                    print_time_log(f"[T16] FAIL: aioquic client exited with {h3_rc} (iteration {run_idx + 1})")
                    if h3_stdout: print_time_log(f"STDOUT: {h3_stdout}")
                    if h3_stderr: print_time_log(f"STDERR: {h3_stderr}")
                    return False
                    
                try:
                    h3_results = _parse_h3_load_results(h3_stdout, test_files)
                except ValueError as e:
                    print_time_log(f"[T16] FAIL: {e} (iteration {run_idx + 1})")
                    return False

                import hashlib
                for fname in set(test_files):
                    with open(os.path.join(TEST_FILES_DIR, fname), 'rb') as f:
                        want_data = f.read()
                        want_md5 = hashlib.md5(want_data).hexdigest()
                        want_size = len(want_data)
                    
                    for got_size, got_md5 in h3_results[fname]:
                        if got_size != want_size or got_md5 != want_md5:
                            print_time_log(f"[T16] FAIL: H3 content mismatch for {fname} (got {got_size} bytes, md5 {got_md5}; want {want_size} bytes, md5 {want_md5}) (iteration {run_idx + 1})")
                            return False
                
                print_time_log(f"[T16] H3 parallel requests OK (iteration {run_idx + 1})")
            
            # Match baseline and final lifecycle state, not a CPU-dependent delay.
            if not _wait_t16_quiescence(server, client, srv_log,
                                        (run_idx + 1) if ENABLE_H3_LOAD else 0):
                print_time_log(f"[T16] FAIL: teardown incomplete (iteration {run_idx + 1})")
                dump = True
                return False
            # Capture both offsets now, before waiting for either process's next tick.
            offsets = {"Server": os.path.getsize(srv_log), "Client": os.path.getsize(cli_log)}
            print_time_log(f"[T16] Teardown complete (iteration {run_idx + 1})")
            for name, process, log_path in (("Server", server, srv_log),
                                             ("Client", client, cli_log)):
                sample = _wait_t16_live_counters(process, log_path, offsets[name])
                live_samples[name].append(sample)
                print_time_log(f"[T16] {name} live round {run_idx + 1}: " +
                               " ".join(f"{key}={value}" for key, value in sample.items()))
            srv_memory_samples.append(get_process_memory(server.pid))
            cli_memory_samples.append(get_process_memory(client.pid))
            print_time_log(f"[T16] RSS round {run_idx + 1}: "
                           f"server={srv_memory_samples[-1] / 1024 / 1024:.2f} MB "
                           f"client={cli_memory_samples[-1] / 1024 / 1024:.2f} MB")

        leak_detected = False
        for name, samples in live_samples.items():
            errors = _t16_live_counter_errors(samples, peak_cap=(name == "Client"))
            print_time_log(f"[T16] {name} allocator bytes round 1/10: "
                           f"{samples[0]['bytes']}/{samples[-1]['bytes']}")
            for error in errors:
                print_time_log(f"[T16] FAIL: {name} live-counter leak: {error}")
                leak_detected = True
        for name, samples, threshold in (
                ("Server", srv_memory_samples, SERVER_MEMORY_GROW_THRESHOLD),
                ("Client", cli_memory_samples, CLIENT_MEMORY_GROW_THRESHOLD)):
            ratio = _t16_sustained_growth(samples)
            print_time_log(f"[T16] {name} RSS series (MB): " +
                           ", ".join(f"{value / 1024 / 1024:.2f}" for value in samples))
            print_time_log(f"[T16] {name} sustained growth: {ratio * 100:.2f}% "
                           f"(rounds 4-10 slope over {LOAD_RUNS - 4} observed intervals)")
            if ratio > threshold:
                print_time_log(f"[T16] FAIL: {name} sustained RSS growth exceeds "
                               f"{threshold * 100:.1f}% (possible memory leak)")
                leak_detected = True

        # SIGINT closes QUIC gracefully on POSIX. Windows termination may not run
        # handlers, so also allow the configured 30s peer idle timeout plus margin.
        close_process(client)
        after_close = _wait_t16_live_counters(
            server, srv_log, os.path.getsize(srv_log), timeout=60.0,
            idle_sessions=idle_baseline["sessions"])
        print_time_log("[T16] Server after close: " +
                       " ".join(f"{key}={value}" for key, value in after_close.items()))
        for error in _t16_idle_counter_errors(idle_baseline, after_close):
            print_time_log(f"[T16] FAIL: Server idle-counter leak: {error}")
            leak_detected = True

        if leak_detected:
            if hasattr(signal, 'SIGINFO'):
                print_time_log("[T16] Leak detected. Sending SIGINFO to server and client to dump memory logs...")
                try:
                    server.send_signal(signal.SIGINFO)
                except Exception as e:
                    print_time_log(f"[T16] Failed to send SIGINFO to server: {e}")
                try:
                    client.send_signal(signal.SIGINFO)
                except Exception as e:
                    print_time_log(f"[T16] Failed to send SIGINFO to client: {e}")
                time.sleep(2)
            else:
                print_time_log("[T16] Leak detected. SIGINFO is not supported on this platform.")
            return False

        print_time_log(f"[T16] quic_load_test PASSED")
        return True
        
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_stateless_reset(binary_path):
    """T17: Client reconnects promptly after server restart."""
    print_time_log("[T17] stateless_reset: starting...")

    # Keep the reset token valid across restarts; forbid TCP fallback.
    quic_options = {
        "enabled": True,
        "debug_disable_tcp": True,
        "stateless_reset_secret": "fulltest-t17-reset-secret",
    }
    srv_cfg = patch_quic_config_with_suffix("quic_server_config.json", "T17.tmp.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": quic_options,
    })
    cli_cfg = patch_quic_config_with_suffix("quic_client_config.json", "T17.tmp.json", {
        "quic": {"enabled": True, "debug_disable_tcp": True},
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False

        # ── Step 1: establish connection and verify a file transfer succeeds ──
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T17] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)   # let QuicStreamTransport become preferred

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T17] FAIL: client proxy port not open")
            dump = True
            return False

        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode("utf-8")
        files = [f for f in index.splitlines() if f.strip()]
        if not files:
            print_time_log("[T17] FAIL: no test files listed")
            dump = True
            return False

        test_file = files[0]
        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{test_file}"
        got = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT)
        with open(os.path.join(TEST_FILES_DIR, test_file), "rb") as f:
            want = f.read()
        if got != want:
            print_time_log(f"[T17] FAIL: first request content mismatch ({len(got)} vs {len(want)} bytes)")
            dump = True
            return False
        print_time_log("[T17] Step 1 OK – first proxy request succeeded")

        # ── Step 2: kill server and restart it ──
        cli_restart_offset = _get_log_offset(cli_log)
        server.kill()  # Do not send a graceful QUIC CONNECTION_CLOSE.
        server.wait(timeout=5)
        close_process(server, False)
        server = None
        print_time_log("[T17] Server stopped – restarting with the same reset secret...")
        time.sleep(0.5)

        # Write a fresh config so the new output log is separate.
        srv_cfg2 = patch_quic_config_with_suffix("quic_server_config.json", "T17.svr2.tmp.json", {
            "remote_port": HTTP_TARGET_PORT,
            "quic": quic_options,
        })
        server, srv_log2 = start_trojan(binary_path, srv_cfg2)
        if not server:
            print_time_log("[T17] FAIL: server restart failed")
            dump = True
            return False

        if not wait_for_log(srv_log2, r"QuicServerEndpoint: listening on UDP", timeout=10):
            print_time_log("[T17] FAIL: restarted server not ready")
            dump = True
            return False
        print_time_log("[T17] Step 2 OK – server restarted")

        # A reset may already have triggered reconnect before this request.
        started = time.monotonic()
        try:
            got_stale = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=3)
            if got_stale != want:
                print_time_log("[T17] FAIL: restart request content mismatch")
                dump = True
                return False
            print_time_log("[T17] Step 3 OK – request succeeded after early reconnect")
        except Exception as e:
            elapsed = time.monotonic() - started
            if elapsed >= 3:
                print_time_log(f"[T17] FAIL: stale request hung for {elapsed:.2f}s")
                dump = True
                return False
            print_time_log(f"[T17] Step 3 OK – stale request failed in {elapsed:.2f}s: {type(e).__name__}")

        # Require reset detection, not an idle timeout or TCP fallback.
        if not _wait_for_log_after(cli_log, r"QuicConnection: stateless reset received",
                                   cli_restart_offset, timeout=3):
            print_time_log("[T17] FAIL: client did not detect stateless reset")
            dump = True
            return False
        if not wait_for_log(srv_log2, r"QuicServerEndpoint: sending Stateless Reset", timeout=3):
            print_time_log("[T17] FAIL: restarted server did not send stateless reset")
            dump = True
            return False

        # ── Step 4: automatic reconnect must make the next request succeed ──
        if not _wait_for_log_after(cli_log, r"QuicClientEndpoint: retrying QUIC connection|reconnect quic client!",
                                   cli_restart_offset, timeout=3):
            print_time_log("[T17] FAIL: client did not retry QUIC after server restart")
            dump = True
            return False
        if not wait_for_log(srv_log2, r"QuicConnection: handshake completed", timeout=3):
            print_time_log("[T17] FAIL: second QUIC handshake not seen")
            dump = True
            return False

        try:
            got2 = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=3)
        except Exception as e:
            print_time_log(f"[T17] FAIL: request after reconnect failed: {e}")
            dump = True
            return False
        if got2 != want:
            print_time_log(f"[T17] FAIL: request after reconnect returned wrong data: {got2}")
            dump = True
            return False

        print_time_log("[T17] Step 4 OK – request after reconnect succeeded")

        print_time_log("[T17] stateless_reset PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)




# ---------------------------------------------------------------------------
# T18 helpers
# ---------------------------------------------------------------------------

def _get_log_offset(log_path):
    """Return current byte size of log_path, or 0 if it doesn't exist."""
    try:
        return os.path.getsize(log_path)
    except OSError:
        return 0


def _wait_for_log_after(log_path, pattern, offset, timeout=10):
    """Return True if *pattern* appears in log_path after *offset* bytes within *timeout* s."""
    deadline = time.time() + timeout
    compiled = re.compile(pattern)
    while time.time() < deadline:
        if os.path.exists(log_path):
            with open(log_path, 'r', errors='replace') as f:
                f.seek(offset)
                for line in f:
                    if compiled.search(line):
                        return True
        time.sleep(0.3)
    return False


def _start_udp_echo_server(port):
    """Start UDP echo server; return (socket, stop_event, thread)."""
    import threading
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', port))
    s.settimeout(0.3)
    stop = threading.Event()

    def _run():
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(4096)
                s.sendto(data, addr)
            except socket.timeout:
                continue
            except OSError:
                if not stop.is_set():
                    raise
                break

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return s, stop, thread


def _socks5_udp_send(proxy_host, proxy_port, target_host, target_port, data, timeout=5):
    """Send one UDP datagram via SOCKS5 UDP-ASSOCIATE and return echoed bytes (or None).

    Closing the TCP control connection at the end signals the trojan client to
    send FIN on the associated QUIC stream, which is what T18-PartB relies on.
    """
    import struct

    ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl.settimeout(timeout)
    try:
        ctrl.connect((proxy_host, proxy_port))

        # No-auth handshake
        ctrl.sendall(b'\x05\x01\x00')
        r = ctrl.recv(2)
        if r != b'\x05\x00':
            raise Exception(f"SOCKS5 auth handshake: {r!r}")

        # UDP ASSOCIATE (client bind 0.0.0.0:0)
        ctrl.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        rep = b''
        while len(rep) < 10:
            chunk = ctrl.recv(10 - len(rep))
            if not chunk:
                break
            rep += chunk
        if len(rep) < 10 or rep[1] != 0x00:
            raise Exception(f"SOCKS5 UDP ASSOCIATE failed: {rep!r}")

        relay_ip = socket.inet_ntoa(rep[4:8])
        relay_port = struct.unpack('>H', rep[8:10])[0]
        if relay_ip == '0.0.0.0':
            relay_ip = proxy_host

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        try:
            # SOCKS5 UDP request header: RSV(2)+FRAG(1)+ATYP=IPv4(1)+DST.ADDR(4)+DST.PORT(2)
            hdr = b'\x00\x00\x00\x01' + socket.inet_aton(target_host) + struct.pack('>H', target_port)
            udp.sendto(hdr + data, (relay_ip, relay_port))
            try:
                raw, _ = udp.recvfrom(65535)
                return raw[10:]  # strip SOCKS5 UDP response header
            except socket.timeout:
                return None
        finally:
            udp.close()
    finally:
        ctrl.close()  # closing ctrl triggers FIN on the QUIC stream


# ---------------------------------------------------------------------------
# Test case  T18
# ---------------------------------------------------------------------------

def test_bidirectional_stream_close(binary_path):
    """T18: TCP and UDP proxy streams both close cleanly after their sessions end.

    Part A – TCP close:
      HTTP GET through QUIC proxy.  After the response the HTTP server closes
      the upstream TCP socket.  QuicProxySession::destroy() runs and logs
      "stream X closed".  Also exercises cb_stream_close::extend_max_streams_bidi.

    Part B – UDP close:
      A local UDP echo server is started.  One datagram is sent via SOCKS5
      UDP-ASSOCIATE through the QUIC proxy; then the SOCKS5 TCP control socket
      is closed.  This causes the trojan client to send FIN on the QUIC stream.
      The server sets m_udp_fin_received=true; once the UDP send queue drains
      destroy() is called and "stream X closed" is logged.
    """
    print_time_log("[T18] bidirectional_stream_close: starting...")

    srv_cfg = patch_quic_config("quic_server_config.json",
                                {"remote_port": HTTP_TARGET_PORT})
    cli_cfg = patch_quic_config("quic_client_config.json", {})

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    udp_echo_sock = None
    udp_stop = None
    udp_thread = None
    try:
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T18] FAIL: QUIC handshake not seen")
            dump = True
            return False
        time.sleep(1)

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T18] FAIL: client proxy port not open")
            dump = True
            return False

        # ── Part A: TCP stream close ─────────────────────────────────────────
        print_time_log("[T18] Part A: TCP proxy stream close")
        log_offset_a = _get_log_offset(srv_log)

        url_base = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        index = http_get_via_socks5(url_base, QUIC_CLIENT_PROXY_PORT).decode('utf-8')
        files = [f for f in index.splitlines() if f.strip()]
        if not files:
            print_time_log("[T18] FAIL Part A: no test files")
            dump = True
            return False

        test_file = files[0]
        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/{test_file}"
        got = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT)
        with open(os.path.join(TEST_FILES_DIR, test_file), 'rb') as f:
            want = f.read()
        if got != want:
            print_time_log("[T18] FAIL Part A: content mismatch")
            dump = True
            return False

        if not _wait_for_log_after(srv_log, r"QuicProxySession: stream \d+ closed",
                                   log_offset_a, timeout=8):
            print_time_log("[T18] FAIL Part A: 'stream X closed' not seen after TCP session")
            dump = True
            return False
        print_time_log("[T18] Part A PASSED: TCP stream closed cleanly")

        # ── Part B: UDP stream close via m_udp_fin_received ──────────────────
        print_time_log("[T18] Part B: UDP proxy stream close")
        udp_echo_sock, udp_stop, udp_thread = _start_udp_echo_server(UDP_ECHO_PORT)
        log_offset_b = _get_log_offset(srv_log)

        echo = _socks5_udp_send("127.0.0.1", QUIC_CLIENT_PROXY_PORT,
                                "127.0.0.1", UDP_ECHO_PORT,
                                b"t18-udp-ping", timeout=5)
        print_time_log(f"[T18] UDP echo response: {echo!r}")
        # echo may be None on timeout (UDP is best-effort); closing ctrl is what matters.

        if not _wait_for_log_after(srv_log, r"QuicProxySession: stream \d+ closed",
                                   log_offset_b, timeout=10):
            print_time_log("[T18] FAIL Part B: 'stream X closed' not seen after UDP FIN")
            dump = True
            return False
        print_time_log("[T18] Part B PASSED: UDP stream closed via m_udp_fin_received path")

        print_time_log("[T18] bidirectional_stream_close PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        if udp_stop:
            udp_stop.set()
        if udp_thread:
            udp_thread.join()  # recvfrom wakes within the socket's 0.3s timeout.
        if udp_echo_sock:
            try:
                udp_echo_sock.close()
            except Exception:
                pass
        close_process(client, dump)
        close_process(server, dump)


def test_quic_ping_keepalive(binary_path):
    """T19: PING keep-alive prevents idle close.

    Part A: ping_interval_ms=0 (disabled). After one request, connection goes idle.
            Idle close log must appear within idle_timeout + 2s.
    Part B: ping_interval_ms = idle_timeout/2. Same wait. No idle close log.
            Second request at the end must succeed.
    """
    print_time_log("[T19] quic_ping_keepalive: starting...")
    if socks is None:
        print_time_log("[T19] SKIP: PySocks not available")
        return True

    IDLE_MS = 10000   # 10s idle timeout for both sides
    WAIT_S  = 12      # wait > IDLE_MS to ensure timeout fires if no PING

    # ---- Part A: no PING ----
    print_time_log("[T19-A] ping disabled, expect idle close after request...")
    srv_cfg_a = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "max_idle_timeout_ms": IDLE_MS, "ping_interval_ms": 0},
    })
    cli_cfg_a = patch_quic_config_with_suffix("quic_client_config.json", ".a.tmp.json", {
        "quic": {"enabled": True,
                 "max_idle_timeout_ms": IDLE_MS, "ping_interval_ms": 0},
    })
    server_a, srv_log_a = start_trojan(binary_path, srv_cfg_a)
    client_a, cli_log_a = start_trojan(binary_path, cli_cfg_a)
    dump_a = False
    try:
        if not server_a or not client_a:
            dump_a = True
            return False
        if not wait_for_log(cli_log_a, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T19-A] FAIL: QUIC handshake not seen")
            dump_a = True
            return False
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T19-A] FAIL: proxy port not open")
            dump_a = True
            return False
        # Send one request to mark connection active, then let it go idle.
        try:
            http_get_via_socks5(f"http://127.0.0.1:{HTTP_TARGET_PORT}/", QUIC_CLIENT_PROXY_PORT, timeout=10)
        except Exception:
            pass
        print_time_log(f"[T19-A] request done, waiting {WAIT_S}s for idle close...")
        time.sleep(WAIT_S)
        # Idle close must appear in at least one side's log.
        found_a = (wait_for_log(cli_log_a, r"IDLE_CLOSE|idle.*close", timeout=3) or
                   wait_for_log(srv_log_a, r"IDLE_CLOSE|idle.*close", timeout=3))
        if not found_a:
            print_time_log("[T19-A] FAIL: idle close not seen — connection may have stayed alive without PING")
            dump_a = True
            return False
        print_time_log("[T19-A] idle close confirmed OK")
    except Exception:
        traceback.print_exc()
        dump_a = True
        return False
    finally:
        close_process(client_a, dump_a)
        close_process(server_a, dump_a)

    time.sleep(1)

    # ---- Part B: PING enabled (interval = IDLE_MS/2) ----
    PING_MS = IDLE_MS // 2   # 5s
    print_time_log(f"[T19-B] ping_interval_ms={PING_MS}, expect NO idle close after same wait...")
    srv_cfg_b = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "max_idle_timeout_ms": IDLE_MS, "ping_interval_ms": PING_MS},
    })
    cli_cfg_b = patch_quic_config_with_suffix("quic_client_config.json", ".b.tmp.json", {
        "quic": {"enabled": True,
                 "max_idle_timeout_ms": IDLE_MS, "ping_interval_ms": PING_MS},
    })
    server_b, srv_log_b = start_trojan(binary_path, srv_cfg_b)
    client_b, cli_log_b = start_trojan(binary_path, cli_cfg_b)
    dump_b = False
    try:
        if not server_b or not client_b:
            dump_b = True
            return False
        if not wait_for_log(cli_log_b, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T19-B] FAIL: QUIC handshake not seen")
            dump_b = True
            return False
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T19-B] FAIL: proxy port not open")
            dump_b = True
            return False
        # First request.
        try:
            http_get_via_socks5(f"http://127.0.0.1:{HTTP_TARGET_PORT}/", QUIC_CLIENT_PROXY_PORT, timeout=10)
        except Exception:
            pass
        print_time_log(f"[T19-B] first request done, waiting {WAIT_S}s (PING fires every {PING_MS}ms)...")
        time.sleep(WAIT_S)
        # Must NOT have idle close.
        idle_found = (wait_for_log(cli_log_b, r"IDLE_CLOSE|idle.*close", timeout=1) or
                      wait_for_log(srv_log_b, r"IDLE_CLOSE|idle.*close", timeout=1))
        if idle_found:
            print_time_log("[T19-B] FAIL: idle close seen even with PING enabled")
            dump_b = True
            return False
        # Second request must succeed on the still-alive connection.
        try:
            resp = http_get_via_socks5(f"http://127.0.0.1:{HTTP_TARGET_PORT}/", QUIC_CLIENT_PROXY_PORT, timeout=10)
        except Exception as e:
            print_time_log(f"[T19-B] FAIL: second request failed: {e}")
            dump_b = True
            return False
        if not resp:
            print_time_log("[T19-B] FAIL: second request returned empty response")
            dump_b = True
            return False
        print_time_log("[T19-B] second request succeeded, no idle close — PING keep-alive works!")
        print_time_log("[T19] quic_ping_keepalive PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump_b = True
        return False
    finally:
        close_process(client_b, dump_b)
        close_process(server_b, dump_b)


def test_quic_only_ignores_pipeline(binary_path):
    """T20: Client bypasses TCP pipeline when debug_disable_tcp is enabled."""
    print_time_log("[T20] quic_only_ignores_pipeline: starting...")
    if socks is None:
        print_time_log("[T20] SKIP: PySocks not available")
        return True

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "debug_disable_tcp": True},
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "experimental": {"pipeline_num": 10},
        "quic": {"enabled": True, "debug_disable_tcp": True},
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T20] FAIL: client QUIC handshake not seen")
            dump = True
            return False
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T20] FAIL: client SOCKS5 port not open")
            dump = True
            return False

        response = http_get_via_socks5(
            f"http://127.0.0.1:{HTTP_TARGET_PORT}/", QUIC_CLIENT_PROXY_PORT, timeout=10)
        if not response:
            print_time_log("[T20] FAIL: request returned empty response")
            dump = True
            return False

        print_time_log("[T20] quic_only_ignores_pipeline PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_quic_preferred_over_pipeline(binary_path):
    """T21: QUIC handles the session while TCP pipeline remains available as fallback."""
    print_time_log("[T21] quic_preferred_over_pipeline: starting...")
    if socks is None:
        print_time_log("[T21] SKIP: PySocks not available")
        return True

    srv_cfg = patch_quic_config("quic_server_config.json", {
        "remote_port": HTTP_TARGET_PORT,
        "experimental": {"pipeline_num": 2},
        "quic": {"enabled": True, "debug_disable_tcp": False},
    })
    cli_cfg = patch_quic_config("quic_client_config.json", {
        "experimental": {"pipeline_num": 2},
        "quic": {"enabled": True, "debug_disable_tcp": False},
    })

    server, srv_log = start_trojan(binary_path, srv_cfg)
    client, cli_log = start_trojan(binary_path, cli_cfg)
    dump = False
    try:
        if not server or not client:
            dump = True
            return False
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T21] FAIL: client QUIC handshake not seen")
            dump = True
            return False
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T21] FAIL: client SOCKS5 port not open")
            dump = True
            return False

        response = http_get_via_socks5(
            f"http://127.0.0.1:{HTTP_TARGET_PORT}/", QUIC_CLIENT_PROXY_PORT, timeout=10)
        if not response:
            print_time_log("[T21] FAIL: request returned empty response")
            dump = True
            return False
        if not wait_for_log(srv_log, r"QuicProxySession: stream .* authenticated", timeout=5):
            print_time_log("[T21] FAIL: request did not use QUIC")
            dump = True
            return False
        if wait_for_log(cli_log, r"pipeline \d+ start session_id: \d+", timeout=1):
            print_time_log("[T21] FAIL: session bound to TCP pipeline while QUIC was available")
            dump = True
            return False

        print_time_log("[T21] quic_preferred_over_pipeline PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)


def test_handshake_blackhole_recovery(binary_path):
    """T22: A black-holed handshake times out, retries, and recovers."""
    print_time_log("[T22] handshake_blackhole_recovery: starting...")
    if socks is None:
        print_time_log("[T22] SKIP: PySocks not available")
        return True

    srv_cfg = patch_quic_config_with_suffix("quic_server_config.json", ".T22.srv.tmp.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "h1_upstream": ""},
    })
    cli_cfg = patch_quic_config_with_suffix("quic_client_config.json", ".T22.cli.tmp.json", {
        "tcp": {"connect_time_out": 3},
        "quic": {"enabled": True, "retry_connect_timeout_ms": 500},
    })

    blackhole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blackhole.bind(("127.0.0.1", QUIC_SERVER_PORT))
    client, cli_log = start_trojan(binary_path, cli_cfg)
    server = None
    dump = False
    try:
        if not client:
            dump = True
            return False
        # Keep the UDP sink bound until timeout: an early server could accept a
        # retransmitted Initial and complete the first attempt at its deadline.
        if not wait_for_log(cli_log, r"QuicClientEndpoint: handshake timeout", timeout=8):
            print_time_log("[T22] FAIL: black-holed handshake did not time out")
            dump = True
            return False
        blackhole.close()
        blackhole = None
        server, srv_log = start_trojan(binary_path, srv_cfg)
        if not server:
            dump = True
            return False
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=10):
            print_time_log("[T22] FAIL: QUIC did not recover after handshake timeout")
            dump = True
            return False
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T22] FAIL: client SOCKS5 port not open")
            dump = True
            return False

        response = http_get_via_socks5(
            f"http://127.0.0.1:{HTTP_TARGET_PORT}/", QUIC_CLIENT_PROXY_PORT, timeout=15)
        if not response or not wait_for_log(srv_log, r"QuicProxySession: stream .* authenticated", timeout=5):
            print_time_log("[T22] FAIL: request after recovery did not use QUIC")
            dump = True
            return False

        print_time_log("[T22] handshake_blackhole_recovery PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        if blackhole is not None:
            blackhole.close()
        close_process(client, dump)
        close_process(server, dump)
        cleanup_temp_configs(srv_cfg, cli_cfg)


def test_outage_idle_recovery(binary_path):
    """T23: First request after network outage longer than server idle timeout must succeed within bound."""
    print_time_log("[T23] outage_idle_recovery: starting...")
    if socks is None:
        if "TF_BUILD" in os.environ or "CI" in os.environ:
            print_time_log("[T23] FAIL: PySocks is required under CI")
            return False
        print_time_log("[T23] SKIP: PySocks not available")
        return True

    srv_cfg = patch_quic_config_with_suffix("quic_server_config.json", ".T23.srv.tmp.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "max_idle_timeout_ms": 2000, "ping_interval_ms": 1000, "debug_disable_tcp": True},
    })

    relay = None
    server = None
    client = None
    dump = False
    try:
        server, srv_log = start_trojan(binary_path, srv_cfg)
        relay = UdpRelay(0, "127.0.0.1", QUIC_SERVER_PORT)
        cli_cfg = patch_quic_config_with_suffix("quic_client_config.json", ".T23.cli.tmp.json", {
            "remote_port": relay.listen_port,
            "quic": {"enabled": True, "max_idle_timeout_ms": 2000, "ping_interval_ms": 1000, "debug_disable_tcp": True},
        })
        client, cli_log = start_trojan(binary_path, cli_cfg)
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T23] FAIL: initial client QUIC handshake not seen")
            dump = True
            return False

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T23] FAIL: client SOCKS5 port not open")
            dump = True
            return False

        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        baseline = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=5)
        if not baseline:
            print_time_log("[T23] FAIL: baseline request returned empty response")
            dump = True
            return False

        # Outage: pause relay so client cannot reach server.
        # Outage of 3s exceeds the 2s server idle timeout and 2s stale_after threshold.
        print_time_log("[T23] Outage started (relay paused for 3s > 2s idle timeout)...")
        relay.pause()
        time.sleep(3.0)

        # Server drops/restarts during outage (with default config, generates new random reset secret)
        print_time_log("[T23] Server drops/restarts during outage...")
        server.kill()
        server.wait(timeout=5)
        close_process(server, False)
        server = None
        time.sleep(0.5)

        server, srv_log2 = start_trojan(binary_path, srv_cfg)
        if not server:
            dump = True
            return False
        time.sleep(0.5)

        # Resume relay (network restored)
        print_time_log("[T23] Outage ended (relay resumed)...")
        t_resume = time.monotonic()
        relay.resume(rebind=False)

        # Assert: first request after recovery must succeed within 10s bound
        try:
            res = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=10)
            elapsed = time.monotonic() - t_resume
            if not res:
                print_time_log(f"[T23] FAIL: request after recovery returned empty response ({elapsed:.2f}s)")
                dump = True
                return False
            if elapsed > 10.0:
                print_time_log(f"[T23] FAIL: request after recovery took too long ({elapsed:.2f}s > 10s)")
                dump = True
                return False
            print_time_log(f"[T23] Request after recovery succeeded in {elapsed:.2f}s")
        except Exception as e:
            elapsed = time.monotonic() - t_resume
            print_time_log(f"[T23] FAIL: request stalled/failed after {elapsed:.2f}s: {e}")
            dump = True
            return False

        print_time_log("[T23] outage_idle_recovery PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        if relay is not None:
            relay.stop()
        close_process(client, dump)
        close_process(server, dump)
        cleanup_temp_configs(srv_cfg, cli_cfg if 'cli_cfg' in locals() else None)


def test_outage_download_flight_recovery(binary_path):
    """T24: Next request after outage during in-flight download must succeed within bound."""
    print_time_log("[T24] outage_download_flight_recovery: starting...")
    if socks is None:
        if "TF_BUILD" in os.environ or "CI" in os.environ:
            print_time_log("[T24] FAIL: PySocks is required under CI")
            return False
        print_time_log("[T24] SKIP: PySocks not available")
        return True

    srv_cfg = patch_quic_config_with_suffix("quic_server_config.json", ".T24.srv.tmp.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "max_idle_timeout_ms": 30000, "debug_disable_tcp": True},
    })

    relay = None
    server = None
    client = None
    dump = False
    try:
        server, srv_log = start_trojan(binary_path, srv_cfg)
        relay = UdpRelay(0, "127.0.0.1", QUIC_SERVER_PORT)
        cli_cfg = patch_quic_config_with_suffix("quic_client_config.json", ".T24.cli.tmp.json", {
            "remote_port": relay.listen_port,
            "quic": {"enabled": True, "max_idle_timeout_ms": 30000, "debug_disable_tcp": True},
        })
        client, cli_log = start_trojan(binary_path, cli_cfg)
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T24] FAIL: initial client QUIC handshake not seen")
            dump = True
            return False

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T24] FAIL: client SOCKS5 port not open")
            dump = True
            return False

        # Ensure 20 MB flight test file exists
        flight_file = os.path.join(TEST_FILES_DIR, "quic_flight_20m.bin")
        if not os.path.exists(flight_file) or os.path.getsize(flight_file) != 20 * 1024 * 1024:
            with open(flight_file, "wb") as f:
                f.write(b'X' * (20 * 1024 * 1024))

        # Launch large transfer in flight
        large_url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/quic_flight_20m.bin"
        dl_started = threading.Event()

        def in_flight_dl():
            try:
                import urllib.parse
                u = urllib.parse.urlparse(large_url)
                s = socks.socksocket()
                s.set_proxy(socks.SOCKS5, "127.0.0.1", QUIC_CLIENT_PROXY_PORT)
                s.settimeout(30)
                s.connect((u.hostname, u.port or 80))
                s.sendall(f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\nConnection: close\r\n\r\n".encode())
                dl_started.set()
                while True:
                    data = s.recv(65536)
                    if not data:
                        break
                s.close()
            except Exception:
                pass

        dl_t = threading.Thread(target=in_flight_dl, daemon=True)
        dl_t.start()
        if not dl_started.wait(timeout=5.0):
            print_time_log("[T24] FAIL: in-flight download request failed to start")
            dump = True
            return False
        time.sleep(0.1)

        # Outage during transfer
        print_time_log("[T24] Pausing relay for 12s (simulating outage while transfer in flight)...")
        relay.pause()
        time.sleep(12.0)

        # Resume relay
        print_time_log("[T24] Resuming relay...")
        t_resume = time.monotonic()
        relay.resume(rebind=False)

        # Bound: the fixed client recovers in ~1.5 s; master took 6.3-9.5 s (new
        # streams wait behind PTO backoff on the stale connection). 4.0 s keeps
        # ~2.5x margin for slow CI agents while still failing the old behavior.
        small_url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        try:
            res = http_get_via_socks5(small_url, QUIC_CLIENT_PROXY_PORT, timeout=10)
            elapsed = time.monotonic() - t_resume
            if not res:
                print_time_log(f"[T24] FAIL: request returned empty response ({elapsed:.2f}s)")
                dump = True
                return False
            if elapsed > 4.0:
                print_time_log(f"[T24] FAIL: request stalled by in-flight transfer PTO backoff ({elapsed:.2f}s > 4.0s)")
                dump = True
                return False
            print_time_log(f"[T24] Request completed in {elapsed:.2f}s")
        except Exception as e:
            elapsed = time.monotonic() - t_resume
            print_time_log(f"[T24] FAIL: request failed after {elapsed:.2f}s: {e}")
            dump = True
            return False

        print_time_log("[T24] outage_download_flight_recovery PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        if relay is not None:
            relay.stop()
        close_process(client, dump)
        close_process(server, dump)
        cleanup_temp_configs(srv_cfg, cli_cfg if 'cli_cfg' in locals() else None)


def test_outage_server_forgot_client(binary_path):
    """T25: Request after server idle-close while client clock paused/desynced must recover within bound."""
    print_time_log("[T25] outage_server_forgot_client: starting...")
    if socks is None:
        if "TF_BUILD" in os.environ or "CI" in os.environ:
            print_time_log("[T25] FAIL: PySocks is required under CI")
            return False
        print_time_log("[T25] SKIP: PySocks not available")
        return True

    reset_secret = "t25-reset-secret"
    srv_cfg = patch_quic_config_with_suffix("quic_server_config.json", ".T25.srv.tmp.json", {
        "remote_port": HTTP_TARGET_PORT,
        "quic": {"enabled": True, "max_idle_timeout_ms": 2000, "ping_interval_ms": 1000, "debug_disable_tcp": True, "stateless_reset_secret": reset_secret},
    })

    relay = None
    server = None
    client = None
    dump = False
    try:
        server, srv_log = start_trojan(binary_path, srv_cfg)
        relay = UdpRelay(0, "127.0.0.1", QUIC_SERVER_PORT)
        cli_cfg = patch_quic_config_with_suffix("quic_client_config.json", ".T25.cli.tmp.json", {
            "remote_port": relay.listen_port,
            "quic": {"enabled": True, "max_idle_timeout_ms": 2000, "ping_interval_ms": 1000, "debug_disable_tcp": True},
        })
        client, cli_log = start_trojan(binary_path, cli_cfg)
        if not server or not client:
            dump = True
            return False

        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            print_time_log("[T25] FAIL: initial client QUIC handshake not seen")
            dump = True
            return False

        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            print_time_log("[T25] FAIL: client SOCKS5 port not open")
            dump = True
            return False

        url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
        baseline = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=5)
        if not baseline:
            print_time_log("[T25] FAIL: baseline request returned empty response")
            dump = True
            return False

        # Outage: pause relay so no pings reach server for 3s (> 2s idle timeout)
        print_time_log("[T25] Outage started (relay paused for 3s)...")
        relay.pause()
        time.sleep(3.0)

        # Server drops connection (restarting with same reset secret simulates server forgetting client)
        print_time_log("[T25] Server forgets client connection...")
        server.kill()
        server.wait(timeout=5)
        close_process(server, False)
        server = None
        time.sleep(0.5)

        server, srv_log2 = start_trojan(binary_path, srv_cfg)
        if not server:
            dump = True
            return False
        time.sleep(0.5)

        # Resume relay (network back)
        print_time_log("[T25] Outage ended (relay resumed)...")
        t_resume = time.monotonic()
        relay.resume(rebind=False)

        # Assert: the first request through proxy after recovery must succeed within 10s
        try:
            res = http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=10)
            elapsed = time.monotonic() - t_resume
            if not res:
                print_time_log(f"[T25] FAIL: first request after recovery returned empty response ({elapsed:.2f}s)")
                dump = True
                return False
            if elapsed > 10.0:
                print_time_log(f"[T25] FAIL: first request after recovery took too long ({elapsed:.2f}s > 10s)")
                dump = True
                return False
            print_time_log(f"[T25] First request succeeded in {elapsed:.2f}s")
        except Exception as e:
            elapsed = time.monotonic() - t_resume
            print_time_log(f"[T25] FAIL: first request after recovery failed after {elapsed:.2f}s: {e}")
            dump = True
            return False

        print_time_log("[T25] outage_server_forgot_client PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        if relay is not None:
            relay.stop()
        close_process(client, dump)
        close_process(server, dump)
        cleanup_temp_configs(srv_cfg, cli_cfg if 'cli_cfg' in locals() else None)


def test_healthy_idle_streams(binary_path):
    """T26: Idle stream handlers must not turn healthy receive gaps into outages."""
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    print_time_log("[T26] healthy_idle_streams: starting...")
    if socks is None:
        print_time_log("[T26] FAIL: PySocks is required")
        return False

    body = b"t26-healthy-idle-stream\n"
    target_sockets: list[socket.socket] = []
    target_lock = threading.Lock()
    stop = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()

        def log_message(self, format: str, *args) -> None:
            pass

    class Target(ThreadingHTTPServer):
        def get_request(self):
            conn, addr = super().get_request()
            # No HTTP keepalive expiry during the ~30s regression window.
            # No heartbeat traffic: idle sockets stay silent until reused.
            conn.settimeout(120)
            with target_lock:
                target_sockets.append(conn)
            return conn, addr

    target = Target(("127.0.0.1", 0), Handler)
    target_thread = threading.Thread(target=target.serve_forever,
                                     kwargs={"poll_interval": 0.05})
    server = client = relay = None
    srv_cfg = cli_cfg = None
    idle_connections: list[http.client.HTTPConnection] = []
    dump = False

    def open_connection() -> http.client.HTTPConnection:
        sock = socks.socksocket()
        try:
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", QUIC_CLIENT_PROXY_PORT)
            sock.settimeout(5)
            sock.connect(target.server_address)
            conn = http.client.HTTPConnection("127.0.0.1", target.server_port, timeout=5)
            conn.sock = sock
            return conn
        except Exception:
            sock.close()
            raise

    def request(conn: http.client.HTTPConnection) -> None:
        original_socket = conn.sock
        conn.request("GET", "/t26")
        response = conn.getresponse()
        if response.status != 200 or response.read() != body:
            raise AssertionError("T26: incorrect HTTP response")
        if response.will_close or conn.sock is not original_socket:
            raise AssertionError("T26: original keepalive socket was not preserved")

    def assert_no_recovery() -> None:
        with open(cli_log, errors="replace") as log:
            recoveries = [line.rstrip() for line in log if "connection recovery" in line.lower()]
        if recoveries:
            raise AssertionError(f"T26: unexpected connection recovery: {recoveries}")
        if client.poll() is not None or server.poll() is not None:
            raise AssertionError("T26: proxy process exited")

    def wait_for_quiet() -> None:
        # Observe both directions, including delayed ACKs and stream-close packets.
        # Never pause/drop relay traffic: this is healthy silence, not an outage.
        deadline = time.monotonic() + 12
        quiet_since = time.monotonic()
        previous = None
        while time.monotonic() < deadline:
            with relay.lock:
                counts = (relay.pkt_to_server, relay.pkt_to_client)
            now = time.monotonic()
            if counts != previous:
                previous = counts
                quiet_since = now
            elif now - quiet_since >= 3.75:
                return
            assert_no_recovery()
            stop.wait(0.05)
        raise AssertionError("T26: no packet-free 3.75s interval within 12s")

    try:
        target_thread.start()
        quic = {"enabled": True, "debug_disable_tcp": True,
                "max_idle_timeout_ms": 60000, "ping_interval_ms": 60000,
                "retry_connect_timeout_ms": 1000}
        srv_cfg = patch_quic_config_with_suffix("quic_server_config.json", ".T26.srv.tmp.json", {
            "remote_port": target.server_port, "quic": quic,
        })
        server, _ = start_trojan(binary_path, srv_cfg)
        relay = UdpRelay(0, "127.0.0.1", QUIC_SERVER_PORT)
        cli_cfg = patch_quic_config_with_suffix("quic_client_config.json", ".T26.cli.tmp.json", {
            "remote_port": relay.listen_port, "quic": quic,
        })
        client, cli_log = start_trojan(binary_path, cli_cfg)
        if not server or not client:
            raise AssertionError("T26: proxy startup failed")
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            raise AssertionError("T26: initial QUIC handshake not seen")
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            raise AssertionError("T26: SOCKS5 port not open")

        for _ in range(4):
            conn = open_connection()
            idle_connections.append(conn)
            request(conn)

        # Eight verified quiet gaps provide at least 30s of healthy idle time.
        # Keep original streams open and silent throughout all fresh requests.
        for round_index in range(8):
            wait_for_quiet()
            conn = open_connection()
            try:
                request(conn)
            finally:
                conn.close()
            assert_no_recovery()
            print_time_log(f"[T26] Fresh request {round_index + 1}/8 passed after packet-free gap")

        for conn in idle_connections:
            request(conn)
        assert_no_recovery()
        print_time_log("[T26] healthy_idle_streams PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        stop.set()
        for conn in idle_connections:
            conn.close()
        close_process(client, dump)
        close_process(server, dump)
        # close_process may kill after its bounded wait; always reap children.
        for proc in (client, server):
            if proc is not None:
                proc.wait(timeout=5)
        if relay is not None:
            relay.stop()
        if target_thread.ident is not None:
            target.shutdown()
            target_thread.join(timeout=5)
        with target_lock:
            for sock in target_sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        target.server_close()
        cleanup_temp_configs(srv_cfg, cli_cfg)


def test_healthy_paused_bulk_stream(binary_path):
    """T27: A healthy paused bulk response must not trigger connection recovery."""
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    print_time_log("[T27] healthy_paused_bulk_stream: starting...")
    if socks is None:
        print_time_log("[T27] FAIL: PySocks is required")
        return False

    burst = bytes(range(256)) * 4096
    tail = b"t27-resumed-without-reconnect\n" * 4096
    fresh_body = b"t27-fresh-stream\n"
    paused = threading.Event()
    resume = threading.Event()
    stop = threading.Event()
    target_lock = threading.Lock()
    target_sockets: list[socket.socket] = []
    fixture_errors: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            bulk = self.path == "/bulk"
            self.send_response(200)
            self.send_header("Content-Length", str(len(burst) + len(tail) if bulk else len(fresh_body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if not bulk:
                self.wfile.write(fresh_body)
                self.wfile.flush()
                return
            try:
                # Leave response unfinished, with no FIN or heartbeat during pause.
                self.wfile.write(burst)
                self.wfile.flush()
                paused.set()
                if not resume.wait(25):
                    fixture_errors.append("bulk resume event timed out")
                    return
                if stop.is_set():
                    return
                self.wfile.write(tail)
                self.wfile.flush()
            except OSError as exc:
                if not stop.is_set():
                    fixture_errors.append(str(exc))

        def log_message(self, format: str, *args) -> None:
            pass

    class Target(ThreadingHTTPServer):
        def get_request(self):
            conn, addr = super().get_request()
            conn.settimeout(40)
            with target_lock:
                target_sockets.append(conn)
            return conn, addr

    target = Target(("127.0.0.1", 0), Handler)
    target_thread = threading.Thread(target=target.serve_forever,
                                     kwargs={"poll_interval": 0.05})
    server = client = relay = None
    srv_cfg = cli_cfg = None
    original = response = None
    dump = False

    def open_connection() -> http.client.HTTPConnection:
        sock = socks.socksocket()
        try:
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", QUIC_CLIENT_PROXY_PORT)
            sock.settimeout(8)
            sock.connect(target.server_address)
            conn = http.client.HTTPConnection("127.0.0.1", target.server_port, timeout=8)
            conn.sock = sock
            return conn
        except Exception:
            sock.close()
            raise

    def assert_no_recovery() -> None:
        with open(cli_log, errors="replace") as log:
            recoveries = [line.rstrip() for line in log if "connection recovery" in line.lower()]
        if recoveries:
            raise AssertionError(f"T27: unexpected connection recovery: {recoveries}")
        if client.poll() is not None or server.poll() is not None:
            raise AssertionError("T27: proxy process exited")
        if fixture_errors:
            raise AssertionError(f"T27: fixture failed: {fixture_errors}")

    def request(conn: http.client.HTTPConnection) -> None:
        sock = conn.sock
        conn.request("GET", "/fresh")
        reply = conn.getresponse()
        if reply.status != 200 or reply.read() != fresh_body:
            raise AssertionError("T27: incorrect fresh response")
        if reply.will_close or conn.sock is not sock:
            raise AssertionError("T27: keepalive socket changed")

    try:
        target_thread.start()
        quic = {"enabled": True, "debug_disable_tcp": True,
                "max_idle_timeout_ms": 60000, "ping_interval_ms": 60000,
                "retry_connect_timeout_ms": 1000}
        srv_cfg = patch_quic_config_with_suffix("quic_server_config.json", ".T27.srv.tmp.json", {
            "remote_port": target.server_port, "quic": quic,
        })
        server, _ = start_trojan(binary_path, srv_cfg)
        relay = UdpRelay(0, "127.0.0.1", QUIC_SERVER_PORT)
        cli_cfg = patch_quic_config_with_suffix("quic_client_config.json", ".T27.cli.tmp.json", {
            "remote_port": relay.listen_port, "quic": quic,
        })
        client, cli_log = start_trojan(binary_path, cli_cfg)
        if not server or not client:
            raise AssertionError("T27: proxy startup failed")
        if not wait_for_log(cli_log, r"QuicConnection: handshake completed", timeout=15):
            raise AssertionError("T27: initial QUIC handshake not seen")
        if not wait_for_port(QUIC_CLIENT_PROXY_PORT, timeout=5):
            raise AssertionError("T27: SOCKS5 port not open")

        original = open_connection()
        original_socket = original.sock
        original.request("GET", "/bulk")
        response = original.getresponse()
        if response.status != 200 or response.read(len(burst)) != burst:
            raise AssertionError("T27: incorrect initial 1 MiB burst")
        if not paused.wait(2):
            raise AssertionError("T27: fixture did not enter pause")
        pause_observed = time.monotonic()

        # Observe both relay directions without dropping or delaying any packets.
        # The bulk stream stays unfinished while fresh SOCKS opens test liveness.
        deadline = time.monotonic() + 12
        quiet_since = time.monotonic()
        previous = None
        while time.monotonic() < deadline:
            with relay.lock:
                counts = (relay.pkt_to_server, relay.pkt_to_client)
            now = time.monotonic()
            if counts != previous:
                previous = counts
                quiet_since = now
            elif now - quiet_since >= 3.75:
                break
            assert_no_recovery()
            stop.wait(0.05)
        else:
            raise AssertionError("T27: no packet-free 3.75s interval within 12s")

        for _ in range(2):
            if resume.is_set() or response.isclosed():
                raise AssertionError("T27: bulk stream ended before fresh request")
            conn = open_connection()
            try:
                request(conn)
            finally:
                conn.close()
            assert_no_recovery()

        # Release only after fresh requests and assertions, never before 5s.
        remaining = pause_observed + 5 - time.monotonic()
        if remaining > 0:
            stop.wait(remaining)
        assert_no_recovery()
        resume.set()
        if response.read() != tail:
            raise AssertionError("T27: resumed response bytes differ")
        if response.will_close or original.sock is not original_socket:
            raise AssertionError("T27: original bulk socket was not preserved")
        request(original)
        assert_no_recovery()
        print_time_log("[T27] healthy_paused_bulk_stream PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        stop.set()
        resume.set()
        if response is not None:
            response.close()
        if original is not None:
            original.close()
        close_process(client, dump)
        close_process(server, dump)
        for proc in (client, server):
            if proc is not None:
                proc.wait(timeout=5)
        if relay is not None:
            relay.stop()
        if target_thread.ident is not None:
            target.shutdown()
            target_thread.join(timeout=5)
        with target_lock:
            for sock in target_sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        target.server_close()
        cleanup_temp_configs(srv_cfg, cli_cfg)


def _initial_server_name(datagrams):
    """Decrypt captured client Initials and reassemble a complete ClientHello."""
    from aioquic.buffer import Buffer
    from aioquic.quic.crypto import CryptoPair
    from aioquic.quic.packet import QuicPacketType, pull_ack_frame, pull_quic_header
    from aioquic.tls import pull_client_hello

    streams = {}
    for datagram in datagrams:
        buf = Buffer(data=datagram)
        while not buf.eof():
            start = buf.tell()
            header = pull_quic_header(buf, host_cid_length=0)
            end = start + header.packet_length
            encrypted_offset = buf.tell() - start
            buf.seek(end)
            if header.packet_type != QuicPacketType.INITIAL:
                continue
            key = (header.version, header.destination_cid)
            if key not in streams:
                crypto = CryptoPair()
                crypto.setup_initial(header.destination_cid, is_client=False, version=header.version)
                streams[key] = (crypto, {}, 0)
            crypto, fragments, expected = streams[key]
            _, payload, number = crypto.decrypt_packet(
                datagram[start:end], encrypted_offset, expected)
            streams[key] = (crypto, fragments, max(expected, number + 1))
            frames = Buffer(data=payload)
            while not frames.eof():
                frame_type = frames.pull_uint_var()
                if frame_type in (0, 1):  # PADDING, PING
                    continue
                if frame_type in (2, 3):  # ACK, ACK_ECN
                    pull_ack_frame(frames)
                    if frame_type == 3:
                        for _ in range(3):
                            frames.pull_uint_var()
                elif frame_type == 6:  # CRYPTO
                    offset = frames.pull_uint_var()
                    data = frames.pull_bytes(frames.pull_uint_var())
                    for index, value in enumerate(data, offset):
                        if index in fragments and fragments[index] != value:
                            raise AssertionError("conflicting Initial CRYPTO retransmission")
                        fragments[index] = value
                else:
                    raise AssertionError(f"unexpected client Initial frame {frame_type}")
                if all(index in fragments for index in range(4)):
                    size = 4 + int.from_bytes(bytes(fragments[i] for i in range(1, 4)), "big")
                    if all(index in fragments for index in range(size)):
                        hello = bytes(fragments[i] for i in range(size))
                        return pull_client_hello(Buffer(data=hello)).server_name
    raise AssertionError("no complete wire ClientHello captured")


class _InitialCaptureRelay(UdpRelay):
    """Existing relay with bounded client-datagram capture, no traffic changes."""

    def __init__(self):
        self.datagrams = []
        super().__init__(0, "127.0.0.1", QUIC_SERVER_PORT)

    def _run(self):
        relay = self
        original = self.ls

        class CaptureSocket:
            def __getattr__(self, name):
                return getattr(original, name)

            def recvfrom(self, size):
                data, addr = original.recvfrom(size)
                if len(relay.datagrams) < 256:
                    relay.datagrams.append(data)
                return data, addr

        self.ls = CaptureSocket()
        super()._run()


def _test_sni_verification(binary_path, tag, verify_hostname, hostname):
    """Use trusted fixture certificate; force QUIC and disable session resumption."""
    server = client = relay = None
    srv_cfg = cli_cfg = None
    import tempfile
    import subprocess
    cert_dir = tempfile.TemporaryDirectory(prefix="quic-sni-")
    dump = False
    print_time_log(f"[{tag}] verify_hostname={verify_hostname}, name={hostname}")
    try:
        # Missing wire decoder must fail, never silently skip required coverage.
        from aioquic.quic.crypto import CryptoPair

        cert = os.path.join(cert_dir.name, "server.crt")
        key = os.path.join(cert_dir.name, "server.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "2",
                        "-subj", "/CN=trojan.test", "-addext", "subjectAltName=DNS:trojan.test"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        quic = {"enabled": True, "debug_disable_tcp": True,
                "retry_connect_timeout_ms": 0}
        srv_cfg = patch_quic_config_with_suffix("quic_server_config.json", f".{tag}.srv.tmp.json", {
            "remote_port": HTTP_TARGET_PORT, "quic": quic,
            "ssl": {"cert": cert, "key": key},
        })
        server, srv_log = start_trojan(binary_path, srv_cfg)
        if not server or server.poll() is not None:
            raise AssertionError("server startup failed")
        relay = _InitialCaptureRelay()
        cli_cfg = patch_quic_config_with_suffix("quic_client_config.json", f".{tag}.cli.tmp.json", {
            "remote_port": relay.listen_port, "quic": quic,
            "ssl": {"verify": True, "verify_hostname": verify_hostname,
                    "cert": cert, "sni": hostname,
                    "reuse_session": False,
                    "session_ticket": False},
        })
        client, cli_log = start_trojan(binary_path, cli_cfg)
        if not client:
            raise AssertionError("client startup failed")
        should_succeed = not verify_hostname or hostname == "trojan.test"
        deadline = time.monotonic() + 12
        completed = False
        rejected = False
        while time.monotonic() < deadline:
            with open(cli_log, errors="replace") as log:
                text = log.read()
            completed = "QuicConnection: handshake completed" in text
            rejected = bool(re.search(r"ngtcp2_conn_read_pkt:.*(?:ERR_CRYPTO|crypto)", text, re.I))
            if completed or rejected or client.poll() is not None:
                break
            threading.Event().wait(0.05)
        # Decode before asserting handshake outcome: no log-only SNI assertions.
        wire_name = _initial_server_name(list(relay.datagrams))
        if wire_name != hostname:
            raise AssertionError(f"wire SNI {wire_name!r}, expected {hostname!r}")
        if should_succeed:
            if not completed or client.poll() is not None:
                raise AssertionError("verified QUIC handshake did not succeed")
            if not wait_for_log(srv_log, r"QuicConnection: handshake completed", timeout=5):
                raise AssertionError("server handshake did not complete")
            url = f"http://127.0.0.1:{HTTP_TARGET_PORT}/"
            if http_get_via_socks5(url, QUIC_CLIENT_PROXY_PORT, timeout=10) != urllib.request.urlopen(url, timeout=10).read():
                raise AssertionError("proxied response differs from local target")
        else:
            if completed:
                raise AssertionError("wrong hostname accepted with verify_hostname=true")
            if not rejected:
                raise AssertionError("no explicit TLS crypto rejection; timeout/exit is not proof")
        print_time_log(f"[{tag}] SNI/verification case PASSED")
        return True
    except Exception:
        traceback.print_exc()
        dump = True
        return False
    finally:
        close_process(client, dump)
        close_process(server, dump)
        if relay is not None:
            relay.stop()
        cleanup_temp_configs(srv_cfg, cli_cfg)
        cert_dir.cleanup()


def test_enabled_sni_verified_name(binary_path):
    """T29: SNI carries the verified fixture hostname on wire."""
    return _test_sni_verification(binary_path, "T29", True, "trojan.test")


def test_wrong_hostname_rejected(binary_path):
    """T30: Wrong certificate hostname must fail verification."""
    return _test_sni_verification(binary_path, "T30", True, "wrong.invalid")


def test_chain_only_wrong_hostname(binary_path):
    """T31: Chain verification alone must not enforce certificate hostname."""
    return _test_sni_verification(binary_path, "T31", False, "wrong.invalid")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALL_TESTS = [
    ("T1",  test_e2e_basic_proxy),
    ("T2",  test_e2e_multistream),
    ("T3",  test_e2e_post_data),
    ("T4",  test_h1_upstream_fallback),
    ("T5",  test_idle_timeout),
    ("T6",  test_h1_upstream_unconfigured_drop),
    ("T7",  test_alpn_negotiation),
    ("T8",  test_quic_disabled),
    ("T9",  test_client_retry_no_server),
    ("T11", test_tcp_target_unreachable),
    ("T12", test_large_file_transfer),
    ("T13", test_h1_upstream_dns_failure),
    ("T14", test_multiple_quic_connections),
    ("T15", test_no_crlf_fallback),
    ("T16", test_quic_load_test),
    ("T17", test_stateless_reset),
    ("T18", test_bidirectional_stream_close),
    ("T19", test_quic_ping_keepalive),
    ("T20", test_quic_only_ignores_pipeline),
    ("T21", test_quic_preferred_over_pipeline),
    ("T22", test_handshake_blackhole_recovery),
    ("T23", test_outage_idle_recovery),
    ("T24", test_outage_download_flight_recovery),
    ("T25", test_outage_server_forgot_client),
    ("T26", test_healthy_idle_streams),
    ("T27", test_healthy_paused_bulk_stream),
    ("T29", test_enabled_sni_verified_name),
    ("T30", test_wrong_hostname_rejected),
    ("T31", test_chain_only_wrong_hostname),
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
                  HTTP_TARGET_PORT, H1_STREAM_PORT]:
            os.system(f"lsof -ti:{p} | xargs kill -9 > /dev/null 2>&1")

    # Start the dedicated HTTP target server.
    http_target = start_http_target()
    if not http_target:
        return 1

    passed_tests = []
    failed_tests = []
    try:
        for tag, fn in tests_to_run:
            with _socks_lock:
                socket.socket = _true_socket_class
            print_time_log(f"--- Running {tag} ---")
            try:
                if fn(binary_path):
                    passed_tests.append(tag)
                else:
                    failed_tests.append(tag)
                    print_time_log(f"--- {tag} FAILED ---")
            except Exception:
                traceback.print_exc()
                failed_tests.append(tag)
            # Brief cooldown between tests.
            time.sleep(2)
    finally:
        close_process(http_target, len(failed_tests) > 0)

    passed = len(passed_tests)
    failed = len(failed_tests)
    passed_str = f" ({' '.join(passed_tests)})" if passed_tests else ""
    failed_str = f" ({' '.join(failed_tests)})" if failed_tests else ""
    print_time_log(f"===== QUIC Tests: {passed} passed{passed_str}, {failed} failed{failed_str} =====")
    return 0 if failed == 0 else 1

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <trojan-binary-path> [test-tag]")
        sys.exit(1)
    binary = os.path.abspath(sys.argv[1])
    tag = sys.argv[2] if len(sys.argv) > 2 else 'all'
    sys.exit(main(binary, tag))
