'''
 This file is part of the Trojan Plus project.
 Trojan is an unidentifiable mechanism that helps you bypass GFW.
 Trojan Plus is derived from original trojan project and writing
 for more experimental features.
 Copyright (C) 2020 The Trojan Plus Group Authors.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

 IPv6 coverage for the Linux full test.

    python3 fulltest_main.py /path/to/trojan -6

 The default IPv4 run (-n / -f / -t / -d / -q) is unchanged. -6 may be
 combined with those flags; the IPv6 suite runs after they finish.

 NAT without an ip6tables rule is skipped unless
 --ipv6-include-expected-fail is set. When executed it must match
 IP6T_SO_ORIGINAL_DST failed and a 0-byte probe. A different outcome,
 including an unexpected pass, fails the suite.

 TUN IPv6 is a real TCP+UDP case. It runs when root and /dev/net/tun
 are available and skips cleanly otherwise, including on the default
 -6 run.

 Real IPv6 REDIRECT and TPROXY transfers are opt-in via --ipv6-nat.
 They need sudo -n, a network namespace, and ip6tables, and SKIP when
 that environment is missing. See fulltest_ipv6_nat.py and
 IPV6_BASELINE.md. The default -6 run still skips them.

 PySocks refuses IPv6 destinations (socks.py connect raises
 "PySocks doesn't support IPv6"), so client-mode cases speak SOCKS5
 directly. That is what lets the suite send ATYP 4 and ATYP 3 exactly.

 The suite exit status is non-zero when an in-scope IPv6 case fails,
 when TUN IPv6 runs and fails, or when the executed no-rule NAT probe
 does not match its expected-fail signature. See IPV6_BASELINE.md.
'''

import atexit
import ipaddress
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

import fulltest_client
import fulltest_fallback
import fulltest_gen_content
import fulltest_udp_proto
from fulltest_utils import print_time_log

TEST_ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(TEST_ROOT, "config")

CONTENT_DIR = "html_ipv6"
CONTENT_PORT = 18080
# Dual-stack and the IPv4 hostname reference talk to this port. It is the
# only content listener with IPV6_V6ONLY=0. Pure IPv6 cases use CONTENT_PORT
# with IPV6_V6ONLY=1, so a silent fall back to 127.0.0.1 cannot succeed.
DUAL_CONTENT_PORT = 18081
SOCKS_PORT = 10620
SERVER_PORT = 4650
BALANCE_PORT = 4651
NAT_PORT = 20621
TIMEOUT = 8

IPV6_LOOPBACK = "::1"
IPV4_LOOPBACK = "127.0.0.1"
IPV6_ANY = "::"
HOSTNAME_V6 = "trojanplus-ipv6.test"
HOSTNAME_V4 = "trojanplus-ipv4.test"
HOSTNAME_DUAL = "trojanplus-dual.test"
HOSTS_PATH = "/etc/hosts"
HOSTS_MARKER = "trojan-plus-ipv6-fulltest"

# FAIL fails the suite. SKIP and EXPECTED-FAIL do not.
RESULTS = []
_original_hosts_bytes = None
_hosts_guards_installed = False
_content_procs = []
RESOLVED_TO_RE = re.compile(r"resolved to (\S+)")


def is_ipv6_host(host):
    return ":" in host


def connect_addr(host, port):
    if is_ipv6_host(host):
        return (host, port, 0, 0)
    return (host, port)


def open_tcp(host, port, timeout=TIMEOUT):
    family = socket.AF_INET6 if is_ipv6_host(host) else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(connect_addr(host, port))
    return sock


def port_open(host, port):
    try:
        sock = open_tcp(host, port, timeout=0.4)
        sock.close()
        return True
    except OSError:
        return False


def recvn(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("short read, got %d of %d" % (len(data), count))
        data += chunk
    return data


def pack_socks_addr(host, port):
    """Encode a SOCKS5 address. IPv6 literals use ATYP 4, names use ATYP 3."""
    try:
        raw = socket.inet_pton(socket.AF_INET, host)
        return b"\x01" + raw + struct.pack("!H", port)
    except OSError:
        pass
    try:
        raw = socket.inet_pton(socket.AF_INET6, host)
        return b"\x04" + raw + struct.pack("!H", port)
    except OSError:
        pass
    encoded = host.encode("idna")
    if len(encoded) > 255:
        raise ValueError("hostname too long")
    return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port)


def read_socks_addr(sock):
    atyp = recvn(sock, 1)
    if atyp == b"\x01":
        addr = socket.inet_ntoa(recvn(sock, 4))
    elif atyp == b"\x04":
        addr = socket.inet_ntop(socket.AF_INET6, recvn(sock, 16))
    elif atyp == b"\x03":
        length = recvn(sock, 1)[0]
        addr = recvn(sock, length).decode("idna")
    else:
        raise RuntimeError("SOCKS reply has unknown ATYP %r" % atyp)
    port = struct.unpack("!H", recvn(sock, 2))[0]
    return atyp, addr, port


def socks5_connect(proxy_host, proxy_port, dest_host, dest_port, command=b"\x01"):
    """Open a SOCKS5 session. command \\x01 is CONNECT, \\x03 is UDP ASSOCIATE."""
    sock = open_tcp(proxy_host, proxy_port)
    sock.sendall(b"\x05\x01\x00")
    greet = recvn(sock, 2)
    if greet != b"\x05\x00":
        sock.close()
        raise RuntimeError("SOCKS5 greeting rejected: %r" % greet)
    request_addr = pack_socks_addr(dest_host, dest_port)
    sock.sendall(b"\x05" + command + b"\x00" + request_addr)
    head = recvn(sock, 3)
    if head[0:1] != b"\x05":
        sock.close()
        raise RuntimeError("SOCKS5 reply is not version 5: %r" % head)
    if head[1:2] != b"\x00":
        # Drain the bound address so the failure reason includes it.
        try:
            read_socks_addr(sock)
        except Exception:
            pass
        sock.close()
        raise RuntimeError("SOCKS5 command failed, REP=%s" % head[1:2].hex())
    atyp, bnd_addr, bnd_port = read_socks_addr(sock)
    return sock, atyp, bnd_addr, bnd_port, request_addr


def http_exchange(sock, request):
    sock.sendall(request)
    data = b""
    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        raise RuntimeError("HTTP response has no header: %r" % data[:200])
    status = head.split(b"\r\n", 1)[0]
    if b" 200 " not in status and not status.endswith(b" 200"):
        raise RuntimeError("HTTP status %r body %r" % (status, body[:120]))
    return body


def load_json(name):
    with open(os.path.join(CONFIG_DIR, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(name, obj):
    path = os.path.join(CONFIG_DIR, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=4)
        handle.write("\n")
    return name


def tune_timeouts(cfg):
    cfg["log_level"] = 0
    cfg["udp_timeout"] = 8
    tcp = cfg.setdefault("tcp", {})
    tcp["connect_time_out"] = 5
    if "dns" in cfg:
        # Built-in DNS is part of the later TUN PR, not this suite.
        cfg["dns"]["enabled"] = False
    if "route" in cfg:
        cfg["route"]["enabled"] = False
    return cfg


def write_configs():
    server = tune_timeouts(load_json("server_config.json"))
    server["run_type"] = "server"
    server["local_addr"] = IPV6_ANY
    server["local_port"] = SERVER_PORT
    server["tcp"]["prefer_ipv4"] = True
    save_json("ipv6_server.json", server)

    server_pipe = tune_timeouts(load_json("server_config_pipeline.json"))
    server_pipe["local_addr"] = IPV6_ANY
    server_pipe["local_port"] = SERVER_PORT
    server_pipe["tcp"]["prefer_ipv4"] = True
    save_json("ipv6_server_pipeline.json", server_pipe)

    server_balance = tune_timeouts(load_json("server_config_pipeline_balance.json"))
    server_balance["local_addr"] = IPV6_ANY
    server_balance["local_port"] = BALANCE_PORT
    server_balance["tcp"]["prefer_ipv4"] = True
    save_json("ipv6_server_pipeline_balance.json", server_balance)

    server_v4 = tune_timeouts(load_json("server_config.json"))
    server_v4["local_addr"] = "0.0.0.0"
    server_v4["local_port"] = SERVER_PORT
    server_v4["tcp"]["prefer_ipv4"] = True
    save_json("ipv6_server_v4ref.json", server_v4)

    server_v6only = tune_timeouts(load_json("server_config.json"))
    server_v6only["local_addr"] = IPV6_ANY
    server_v6only["local_port"] = SERVER_PORT
    server_v6only["tcp"]["prefer_ipv4"] = True
    server_v6only["tcp"]["ipv6_only"] = True
    save_json("ipv6_server_v6only.json", server_v6only)

    # Omit tcp.prefer_ipv4 so the case exercises the code default (false).
    server_default = tune_timeouts(load_json("server_config.json"))
    server_default["local_addr"] = IPV6_ANY
    server_default["local_port"] = SERVER_PORT
    server_default["tcp"].pop("prefer_ipv4", None)
    save_json("ipv6_server_resolver_default.json", server_default)

    def client(pipeline, local_addr, remote_addr, remote_port, target_addr, run_type, target_port=CONTENT_PORT):
        cfg = tune_timeouts(load_json("client_config_pipeline.json" if pipeline else "client_config.json"))
        cfg["run_type"] = run_type
        cfg["local_addr"] = local_addr
        cfg["local_port"] = SOCKS_PORT
        cfg["remote_addr"] = remote_addr
        cfg["remote_port"] = remote_port
        cfg["target_addr"] = target_addr
        cfg["target_port"] = target_port
        if pipeline:
            cfg["experimental"]["pipeline_num"] = 10
            cfg["experimental"]["pipeline_ack_window"] = 10
        return cfg

    save_json("ipv6_client.json", client(
        False, IPV6_LOOPBACK, IPV6_LOOPBACK, SERVER_PORT, IPV6_LOOPBACK, "client"))
    save_json("ipv6_forward.json", client(
        False, IPV6_LOOPBACK, IPV6_LOOPBACK, SERVER_PORT, IPV6_LOOPBACK, "forward"))
    save_json("ipv6_client_v4_to_dual.json", client(
        False, IPV4_LOOPBACK, IPV4_LOOPBACK, SERVER_PORT, IPV4_LOOPBACK, "client",
        target_port=DUAL_CONTENT_PORT))
    save_json("ipv6_client_v4ref.json", client(
        False, IPV4_LOOPBACK, IPV4_LOOPBACK, SERVER_PORT, IPV4_LOOPBACK, "client",
        target_port=DUAL_CONTENT_PORT))

    balance = client(True, IPV6_LOOPBACK, IPV6_LOOPBACK, BALANCE_PORT, IPV6_LOOPBACK, "client")
    balance["experimental"].pop("pipeline_loadbalance_configs", None)
    save_json("ipv6_client_pipeline_balance.json", balance)

    pipe = client(True, IPV6_LOOPBACK, IPV6_LOOPBACK, SERVER_PORT, IPV6_LOOPBACK, "client")
    pipe["experimental"]["pipeline_loadbalance_configs"] = ["config/ipv6_client_pipeline_balance.json"]
    save_json("ipv6_client_pipeline.json", pipe)

    fwd_balance = client(True, IPV6_LOOPBACK, IPV6_LOOPBACK, BALANCE_PORT, IPV6_LOOPBACK, "forward")
    fwd_balance["experimental"].pop("pipeline_loadbalance_configs", None)
    save_json("ipv6_forward_pipeline_balance.json", fwd_balance)

    fwd_pipe = client(True, IPV6_LOOPBACK, IPV6_LOOPBACK, SERVER_PORT, IPV6_LOOPBACK, "forward")
    fwd_pipe["experimental"]["pipeline_loadbalance_configs"] = ["config/ipv6_forward_pipeline_balance.json"]
    save_json("ipv6_forward_pipeline.json", fwd_pipe)

    fallback = tune_timeouts(load_json("fallback_server_config.json"))
    fallback["local_addr"] = IPV6_ANY
    fallback["remote_addr"] = IPV6_LOOPBACK
    fallback["tcp"]["prefer_ipv4"] = True
    save_json("ipv6_fallback_server.json", fallback)

    nat = tune_timeouts(load_json("client_config.json"))
    nat["run_type"] = "nat"
    nat["local_addr"] = IPV6_LOOPBACK
    nat["local_port"] = NAT_PORT
    nat["remote_addr"] = IPV6_LOOPBACK
    nat["remote_port"] = SERVER_PORT
    # use_tproxy stays false. Turning it on without an ip6tables TPROXY rule makes
    # getsockname() return the listen address, and NATSession then forwards to
    # itself (observed: "forwarding to [::1]:20621 via [::1]:4650").
    nat["tcp"]["use_tproxy"] = False
    nat["password"] = ["88888888"]
    save_json("ipv6_nat.json", nat)

    tun = tune_timeouts(load_json("client_config.json"))
    tun["run_type"] = "client_tun"
    tun["remote_addr"] = "fd00:1::1"
    tun["remote_port"] = 24650
    tun["tun"]["tun_name"] = "tunipv6"
    tun["tun"]["net_ip"] = ""
    tun["tun"]["net_mask"] = ""
    tun["tun"]["net_ipv6"] = "fd00::2"
    tun["tun"]["net_ipv6_prefix"] = 64
    tun["tun"]["redirect_local"] = False
    tun["quic"] = {"enabled": False}
    if "dns" in tun:
        tun["dns"]["enabled"] = False
    if "route" in tun:
        tun["route"]["enabled"] = True
        tun["route"]["proxy_type"] = 0
    save_json("ipv6_tun.json", tun)


def excerpt(text):
    if not text:
        return ""
    keys = (
        "error", "fatal", "cannot", "fail", "exception", "bad ",
        "resolved to", "requested connection", "requested udp",
        "trojan plus service", "what():", "terminate", "ipv6",
        "original_dst", "transparent", "tun",
    )
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    picked = [ln for ln in lines if any(key in ln.lower() for key in keys)]
    if not picked:
        picked = lines[-12:]
    return " | ".join(picked[-12:])[:1800]


class ProcGroup:
    def __init__(self, binary):
        self.binary = binary
        self.procs = []

    def start(self, config_name, use_sudo=False):
        log_path = os.path.join(CONFIG_DIR, config_name + ".output")
        log_file = open(log_path, "w+", encoding="utf-8", errors="replace")
        cmd = [self.binary, "-c", os.path.join(CONFIG_DIR, config_name)]
        if use_sudo and os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        proc = subprocess.Popen(
            cmd, stdout=log_file, stderr=log_file, cwd=TEST_ROOT, universal_newlines=True)
        proc.log_file = log_file
        proc.log_path = log_path
        self.procs.append(proc)
        return proc

    def _signal(self, proc, sig):
        if proc.poll() is not None:
            return
        if proc.args and proc.args[0] == "sudo":
            subprocess.run(["sudo", "-n", "kill", "-%d" % sig, str(proc.pid)], check=False)
        else:
            try:
                proc.send_signal(sig)
            except ProcessLookupError:
                pass

    def stop(self):
        # Stop first so stdio is flushed, then read the logs.
        for proc in reversed(self.procs):
            self._signal(proc, signal.SIGINT)
        for proc in reversed(self.procs):
            if proc.poll() is None:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._signal(proc, signal.SIGKILL)
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
        chunks = []
        for proc in self.procs:
            try:
                proc.log_file.flush()
                proc.log_file.seek(0)
                chunks.append(proc.log_file.read())
                proc.log_file.close()
            except Exception:
                pass
        self.procs = []
        return "\n".join(chunks)


def wait_until(predicate, proc, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        if predicate():
            return True
        time.sleep(0.15)
    return predicate()


def content_files():
    index_path = os.path.join(TEST_ROOT, CONTENT_DIR, "index.html")
    with open(index_path, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def read_content(name):
    with open(os.path.join(TEST_ROOT, CONTENT_DIR, name), "rb") as handle:
        return handle.read()


def start_content_server(port, ipv6_v6only):
    log_path = os.path.join(CONFIG_DIR, "ipv6_content_%d.output" % port)
    log_file = open(log_path, "w+", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [sys.executable, "-u", "fulltest_server.py", CONTENT_DIR, str(port), IPV6_ANY,
         "1" if ipv6_v6only else "0"],
        stdout=log_file, stderr=log_file, cwd=TEST_ROOT, universal_newlines=True)
    proc.log_file = log_file
    _content_procs.append(proc)
    ok_v6 = wait_until(lambda: port_open(IPV6_LOOPBACK, port), proc)
    if ipv6_v6only:
        ok_v4 = port_open(IPV4_LOOPBACK, port)
    else:
        ok_v4 = wait_until(lambda: port_open(IPV4_LOOPBACK, port), proc, timeout=3)
    if not ok_v6 or (ipv6_v6only and ok_v4) or (not ipv6_v6only and not ok_v4):
        log_file.flush()
        log_file.seek(0)
        detail = log_file.read()
        stop_content_server(proc)
        raise RuntimeError(
            "content server on %d v6only=%s accepted ::1=%s 127.0.0.1=%s (%s)"
            % (port, ipv6_v6only, ok_v6, ok_v4, excerpt(detail) or "no log"))
    return proc


def start_content_servers():
    fulltest_gen_content.gen_files(os.path.join(TEST_ROOT, CONTENT_DIR), 2, 1500)
    pure = start_content_server(CONTENT_PORT, True)
    try:
        dual = start_content_server(DUAL_CONTENT_PORT, False)
    except Exception:
        stop_content_server(pure)
        raise
    return [pure, dual]


def stop_content_server(proc):
    if not proc:
        return
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    try:
        proc.log_file.close()
    except Exception:
        pass


def require_pair(group, server_cfg, client_cfg, server_host, client_host, balance_cfg=None, use_sudo=False):
    server = group.start(server_cfg, use_sudo=use_sudo)
    if not wait_until(lambda: port_open(server_host, SERVER_PORT), server):
        raise RuntimeError("server did not listen on %s:%d" % (server_host, SERVER_PORT))
    if balance_cfg:
        balance = group.start(balance_cfg, use_sudo=use_sudo)
        if not wait_until(lambda: port_open(server_host, BALANCE_PORT), balance):
            raise RuntimeError("balance server did not listen on %s:%d" % (server_host, BALANCE_PORT))
    client = group.start(client_cfg, use_sudo=use_sudo)
    if not wait_until(lambda: port_open(client_host, SOCKS_PORT), client):
        raise RuntimeError("client did not listen on %s:%d" % (client_host, SOCKS_PORT))
    return client


def assert_socks_tcp_bind(proxy_host, atyp, bnd_addr, bnd_port):
    """The TCP CONNECT reply must carry the accepted socket's local endpoint."""
    if bnd_port != SOCKS_PORT:
        raise RuntimeError(
            "SOCKS TCP bind port is %s, expected listener %s (addr %s atyp %r)"
            % (bnd_port, SOCKS_PORT, bnd_addr, atyp))
    if is_ipv6_host(proxy_host):
        if atyp != b"\x04" or not is_ipv6_loopback(bnd_addr):
            raise RuntimeError(
                "SOCKS TCP bind reply ATYP %r %s:%s, expected ATYP 4 [::1]:%s"
                % (atyp, bnd_addr, bnd_port, SOCKS_PORT))
    elif atyp != b"\x01" or bnd_addr != IPV4_LOOPBACK:
        raise RuntimeError(
            "SOCKS TCP bind reply ATYP %r %s:%s, expected ATYP 1 %s:%s"
            % (atyp, bnd_addr, bnd_port, IPV4_LOOPBACK, SOCKS_PORT))


def require_socks_atyp(request_addr, expect_atyp):
    actual = request_addr[0]
    if expect_atyp is not None and actual != expect_atyp:
        raise RuntimeError("SOCKS request ATYP was %d, expected %d" % (actual, expect_atyp))
    return actual


def tcp_get_post(proxy_host, dest_host, dest_port, expect_atyp=None):
    name = content_files()[0]
    expected = read_content(name)
    sock, atyp, bnd_addr, bnd_port, request_addr = socks5_connect(
        proxy_host, SOCKS_PORT, dest_host, dest_port, b"\x01")
    try:
        atyp_n = require_socks_atyp(request_addr, expect_atyp)
        assert_socks_tcp_bind(proxy_host, atyp, bnd_addr, bnd_port)
        body = http_exchange(sock, (
            "GET /%s HTTP/1.1\r\nHost: ipv6-fulltest\r\nConnection: close\r\n\r\n" % name
        ).encode("ascii"))
        if body != expected:
            raise RuntimeError("GET body mismatch (%d vs %d)" % (len(body), len(expected)))
    finally:
        sock.close()

    payload = b"d=" + expected
    sock, post_atyp, post_bnd_addr, post_bnd_port, post_addr = socks5_connect(
        proxy_host, SOCKS_PORT, dest_host, dest_port, b"\x01")
    try:
        require_socks_atyp(post_addr, expect_atyp)
        assert_socks_tcp_bind(proxy_host, post_atyp, post_bnd_addr, post_bnd_port)
        header = (
            "POST /%s HTTP/1.1\r\nHost: ipv6-fulltest\r\nContent-Length: %d\r\n"
            "Connection: close\r\n\r\n" % (name, len(payload))
        ).encode("ascii")
        body = http_exchange(sock, header + payload)
        if body != b"OK":
            raise RuntimeError("POST body %r" % body[:80])
    finally:
        sock.close()
    return "request ATYP %d, SOCKS bind ATYP %s %s:%s" % (atyp_n, atyp.hex(), bnd_addr, bnd_port)


def udp_associate_transfer(proxy_host, dest_host, dest_port):
    name = content_files()[0]
    expected = read_content(name)
    ctrl, atyp, bnd_addr, bnd_port, request_addr = socks5_connect(
        proxy_host, SOCKS_PORT, "::", 0, b"\x03")
    try:
        if request_addr[0] != 4:
            raise RuntimeError("UDP ASSOCIATE request was not ATYP 4")
        if atyp != b"\x04" or not is_ipv6_loopback(bnd_addr) or bnd_port == 0:
            raise RuntimeError(
                "UDP ASSOCIATE bind reply ATYP %r %s:%s, expected ATYP 4 [::1]:<ephemeral>"
                % (atyp, bnd_addr, bnd_port))
        relay_host = bnd_addr
        family = socket.AF_INET6 if is_ipv6_host(relay_host) else socket.AF_INET
        udp = socket.socket(family, socket.SOCK_DGRAM)
        udp.settimeout(TIMEOUT)
        query = ("file=%s&len=%d&m=GET\r\n" % (name, len(expected))).encode("ascii")
        packed_dest = pack_socks_addr(dest_host, dest_port)
        if packed_dest[0] != 4:
            raise RuntimeError("UDP destination ATYP was %d, expected 4" % packed_dest[0])
        header = b"\x00\x00\x00" + packed_dest
        udp.sendto(header + query, connect_addr(relay_host, bnd_port))
        chunks = []
        got = 0
        while got < len(expected):
            packet, _ = udp.recvfrom(fulltest_udp_proto.UDP_SEND_PACKET_LENGTH + 64)
            if len(packet) < 4 or packet[0:3] != b"\x00\x00\x00":
                raise RuntimeError("UDP relay packet missing RSV/FRAG: %r" % packet[:16])
            # Parse and drop the SOCKS address, keep the test payload.
            payload = strip_socks_udp(packet)
            got += len(payload) - fulltest_udp_proto.UDP_INDEX_HEADER_SIZE
            chunks.append(payload)
        data = fulltest_udp_proto.compose_udp_file_data(chunks)
        if data != expected:
            raise RuntimeError("UDP GET mismatch (%d vs %d)" % (len(data), len(expected)))
        return "UDP ASSOCIATE ATYP 4 via %s:%d, %d bytes" % (relay_host, bnd_port, len(data))
    finally:
        ctrl.close()


def strip_socks_udp(packet):
    atyp = packet[3:4]
    if atyp == b"\x01":
        offset = 4 + 4 + 2
    elif atyp == b"\x04":
        offset = 4 + 16 + 2
    elif atyp == b"\x03":
        offset = 5 + packet[4] + 2
    else:
        raise RuntimeError("UDP relay ATYP %r" % atyp)
    return packet[offset:]


def run_forward(binary, server_cfg, client_cfg, balance_cfg, tcp, udp):
    group = ProcGroup(binary)
    old_retry = fulltest_client.UDP_RETRY_MAX_COUNT
    old_timeout = fulltest_client.RECV_DATA_TIMEOUT
    fulltest_client.UDP_RETRY_MAX_COUNT = 2
    fulltest_client.RECV_DATA_TIMEOUT = TIMEOUT
    status, reason = "FAIL", "forward transfer failed"
    try:
        require_pair(group, server_cfg, client_cfg, IPV6_LOOPBACK, IPV6_LOOPBACK, balance_cfg)
        ok = fulltest_client.start_query(
            IPV6_LOOPBACK, 0, SOCKS_PORT, CONTENT_DIR,
            tcp=tcp, udp=udp, file_list=content_files())
        if ok:
            status, reason = "PASS", "forward %s via [::1]:%d" % ("TCP" if tcp else "UDP", SOCKS_PORT)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    finally:
        fulltest_client.UDP_RETRY_MAX_COUNT = old_retry
        fulltest_client.RECV_DATA_TIMEOUT = old_timeout
        text = group.stop()
    if status == "PASS":
        try:
            assert_resolved_ipv6_loopback(text)
            if "atyp 4" not in text:
                raise RuntimeError("forward server log has no atyp 4")
            if "atyp 1" in text or "atyp 3" in text:
                raise RuntimeError("forward literal was not encoded as ATYP 4")
            if "IPV6_V6ONLY=0" not in text:
                raise RuntimeError("forward listener did not log IPV6_V6ONLY=0")
        except Exception as exc:
            status, reason = "FAIL", str(exc)
    if status != "PASS":
        reason = "%s | %s" % (reason, excerpt(text))
    return status, reason


def read_hosts_bytes():
    try:
        with open(HOSTS_PATH, "rb") as handle:
            return handle.read()
    except PermissionError:
        proc = subprocess.run(["sudo", "-n", "cat", HOSTS_PATH], capture_output=True)
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError("cannot read /etc/hosts (%d): %s" % (proc.returncode, detail))
        return proc.stdout


def _run_checked(cmd, action):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError("%s failed (%d): %s" % (action, proc.returncode, detail))
    return proc


def atomic_replace_hosts(data):
    """Replace /etc/hosts by writing a temp file and renaming it into place.

    A crash during the write leaves the previous file intact. sudo is used
    only when the current user cannot create a file in /etc. Every privileged
    command's exit code is checked.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    local_fd, local_path = tempfile.mkstemp(prefix="trojan-hosts-", dir="/tmp")
    etc_tmp = None
    remote_tmp = "/etc/.hosts-trojan-plus-%d.tmp" % os.getpid()
    try:
        with os.fdopen(local_fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            fd, etc_tmp = tempfile.mkstemp(prefix=".hosts-trojan-plus-", dir="/etc")
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(etc_tmp, 0o644)
            os.replace(etc_tmp, HOSTS_PATH)
            etc_tmp = None
        except PermissionError:
            if etc_tmp and os.path.exists(etc_tmp):
                try:
                    os.unlink(etc_tmp)
                except OSError:
                    pass
            etc_tmp = None
            _run_checked(["sudo", "-n", "cp", local_path, remote_tmp], "copy hosts temp")
            try:
                _run_checked(["sudo", "-n", "chmod", "644", remote_tmp], "chmod hosts temp")
                _run_checked(["sudo", "-n", "mv", "-f", remote_tmp, HOSTS_PATH], "rename hosts temp")
            except Exception:
                subprocess.run(["sudo", "-n", "rm", "-f", remote_tmp], check=False)
                raise
        readback = read_hosts_bytes()
        if readback != data:
            raise RuntimeError("/etc/hosts contents do not match the bytes just written")
    finally:
        if os.path.exists(local_path):
            os.unlink(local_path)


def install_hosts():
    global _original_hosts_bytes
    original = read_hosts_bytes()
    _original_hosts_bytes = original
    text = original.decode("utf-8")
    lines = [ln for ln in text.splitlines(keepends=True) if HOSTS_MARKER not in ln]
    if lines and not lines[-1].endswith("\n"):
        lines[-1] = lines[-1] + "\n"
    lines.append("::1 %s # %s\n" % (HOSTNAME_V6, HOSTS_MARKER))
    lines.append("127.0.0.1 %s # %s\n" % (HOSTNAME_V4, HOSTS_MARKER))
    lines.append("127.0.0.1 %s # %s\n" % (HOSTNAME_DUAL, HOSTS_MARKER))
    lines.append("::1 %s # %s\n" % (HOSTNAME_DUAL, HOSTS_MARKER))
    atomic_replace_hosts("".join(lines).encode("utf-8"))
    readback = read_hosts_bytes().decode("utf-8")
    if (HOSTNAME_V6 not in readback or HOSTNAME_V4 not in readback or HOSTNAME_DUAL not in readback
            or HOSTS_MARKER not in readback):
        raise RuntimeError("hosts update did not persist")


def remove_hosts():
    """Put back the exact bytes captured before install_hosts."""
    if _original_hosts_bytes is None:
        return
    current = read_hosts_bytes()
    if current == _original_hosts_bytes:
        return
    atomic_replace_hosts(_original_hosts_bytes)
    if read_hosts_bytes() != _original_hosts_bytes:
        raise RuntimeError("/etc/hosts was not restored to the original bytes")


def _restore_hosts_on_signal(signum, _frame):
    sys.stderr.write("restoring /etc/hosts after signal %s\n" % signum)
    sys.stderr.flush()
    try:
        remove_hosts()
    except Exception as exc:
        sys.stderr.write("failed to restore /etc/hosts after signal %s: %s\n" % (signum, exc))
        sys.stderr.flush()
    raise SystemExit(128 + signum)


def _restore_hosts_atexit():
    try:
        remove_hosts()
    except Exception as exc:
        sys.stderr.write("atexit failed to restore /etc/hosts: %s\n" % exc)
        sys.stderr.flush()


def install_hosts_guards():
    global _hosts_guards_installed
    if _hosts_guards_installed:
        return
    _hosts_guards_installed = True
    atexit.register(_restore_hosts_atexit)
    signal.signal(signal.SIGINT, _restore_hosts_on_signal)
    signal.signal(signal.SIGTERM, _restore_hosts_on_signal)


def is_ipv6_loopback(addr):
    try:
        parsed = ipaddress.ip_address(addr.strip("[]"))
    except ValueError:
        return False
    if not isinstance(parsed, ipaddress.IPv6Address):
        return False
    if parsed.ipv4_mapped is not None:
        return False
    return parsed == ipaddress.ip_address("::1")


def assert_resolved_ipv6_loopback(log_text):
    """Fail when a pure-IPv6 flow does not stay on ::1.

    IPv6 endpoints in these paths are logged as [::1]:port. The uncompressed
    form produced by the old SOCKS parser is a failure. An IPv4 address,
    including an IPv4-mapped one, fails the case.
    """
    text = log_text or ""
    if "127.0.0.1" in text or "::ffff:" in text:
        raise RuntimeError("pure IPv6 log contains an IPv4 peer")
    if "0000:0000:0000:0000:0000:0000:0000:0001" in text:
        raise RuntimeError("IPv6 address was logged uncompressed")
    if "[::1]:" not in text:
        raise RuntimeError("IPv6 endpoint was not logged as [::1]:port")
    resolved = RESOLVED_TO_RE.findall(text)
    bad = [addr for addr in resolved if not is_ipv6_loopback(addr)]
    if bad:
        raise RuntimeError("traffic resolved to non-::1 address(es): %s" % ", ".join(bad))
    if any(is_ipv6_loopback(addr) for addr in resolved):
        return
    if re.search(r"(?:to|from|via) \[::1\]:", text):
        return
    raise RuntimeError("log has no ::1 peer (no 'resolved to ::1' and no [IPv6] destination)")


def record(case_id, status, reason, expected=False):
    RESULTS.append({
        "case": case_id,
        "status": status,
        "reason": reason,
        "expected": expected,
    })
    print_time_log("[%s] %s %s" % (status, case_id, reason.split(" | ")[0][:300]))


def run_recorded(case_id, func, expected=False):
    try:
        status, reason = func()
    except Exception as exc:
        status = "FAIL"
        reason = "%s: %s" % (type(exc).__name__, exc)
        trace = traceback.format_exc(limit=4)
        reason = reason + " | " + " ".join(trace.splitlines()[-4:])
    record(case_id, status, reason, expected=expected)


def finish_group(group, status, reason, require_ipv6_loopback=False, require_atyp=None, require_v6only=None):
    text = group.stop()
    if status == "PASS" and require_ipv6_loopback:
        try:
            assert_resolved_ipv6_loopback(text)
        except Exception as exc:
            status, reason = "FAIL", str(exc)
    if status == "PASS" and require_atyp is not None and ("atyp %d" % require_atyp) not in (text or ""):
        status, reason = "FAIL", "server log has no atyp %d" % require_atyp
    if status == "PASS" and require_v6only is not None and ("IPV6_V6ONLY=%s" % require_v6only) not in (text or ""):
        status, reason = "FAIL", "log has no IPV6_V6ONLY=%s" % require_v6only
    if status not in ("PASS", "EXPECTED-FAIL", "SKIP"):
        extra = excerpt(text)
        if extra:
            reason = "%s | %s" % (reason, extra)
    return status, reason, text


def _status_reason(finished):
    status, reason, _text = finished
    return status, reason


def case_tcp_literal(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(group, "ipv6_server.json", "ipv6_client.json", IPV6_LOOPBACK, IPV6_LOOPBACK)
        status, reason = "PASS", tcp_get_post(
            IPV6_LOOPBACK, IPV6_LOOPBACK, CONTENT_PORT, expect_atyp=4)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return _status_reason(finish_group(
        group, status, reason, require_ipv6_loopback=True, require_atyp=4, require_v6only="0"))


def case_tcp_hostname(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(group, "ipv6_server.json", "ipv6_client.json", IPV6_LOOPBACK, IPV6_LOOPBACK)
        detail = tcp_get_post(IPV6_LOOPBACK, HOSTNAME_V6, CONTENT_PORT, expect_atyp=3)
        status, reason = "PASS", "ATYP 3 hostname %s; %s" % (HOSTNAME_V6, detail)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return _status_reason(finish_group(
        group, status, reason, require_ipv6_loopback=True, require_atyp=3, require_v6only="0"))


def case_udp(binary, server_cfg, client_cfg, balance_cfg, label):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(group, server_cfg, client_cfg, IPV6_LOOPBACK, IPV6_LOOPBACK, balance_cfg)
        status, reason = "PASS", label + "; " + udp_associate_transfer(IPV6_LOOPBACK, IPV6_LOOPBACK, CONTENT_PORT)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return _status_reason(finish_group(
        group, status, reason, require_ipv6_loopback=True, require_atyp=4, require_v6only="0"))


def case_pipeline_tcp(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(
            group, "ipv6_server_pipeline.json", "ipv6_client_pipeline.json",
            IPV6_LOOPBACK, IPV6_LOOPBACK, "ipv6_server_pipeline_balance.json")
        status, reason = "PASS", "pipeline " + tcp_get_post(
            IPV6_LOOPBACK, IPV6_LOOPBACK, CONTENT_PORT, expect_atyp=4)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return _status_reason(finish_group(
        group, status, reason, require_ipv6_loopback=True, require_atyp=4, require_v6only="0"))


def case_dual_stack(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        server = group.start("ipv6_server.json")
        if not wait_until(lambda: port_open(IPV6_LOOPBACK, SERVER_PORT), server):
            raise RuntimeError("dual-stack server did not accept ::1")
        if not wait_until(lambda: port_open(IPV4_LOOPBACK, SERVER_PORT), server, timeout=3):
            raise RuntimeError(
                "IPv4 127.0.0.1:%d cannot connect to server bound on :: (IPV6_V6ONLY or bind family)"
                % SERVER_PORT)
        client = group.start("ipv6_client_v4_to_dual.json")
        if not wait_until(lambda: port_open(IPV4_LOOPBACK, SOCKS_PORT), client):
            raise RuntimeError("IPv4 client did not listen")
        status, reason = "PASS", "v4 client -> :: server; " + tcp_get_post(
            IPV4_LOOPBACK, IPV4_LOOPBACK, DUAL_CONTENT_PORT, expect_atyp=1)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return _status_reason(finish_group(
        group, status, reason, require_ipv6_loopback=False, require_atyp=1, require_v6only="0"))


def case_fallback(binary):
    try:
        rc = fulltest_fallback.main(
            binary, mock_bind=IPV6_LOOPBACK, request_host=IPV6_LOOPBACK,
            server_config="ipv6_fallback_server.json")
        logs = ""
        for name in ("ipv6_fallback_server.json.output", "fallback_server.output", "fallback_mock_server.output"):
            path = os.path.join(CONFIG_DIR, name)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    logs += handle.read() + "\n"
        if rc != 0:
            return "FAIL", "fallback returned %d | %s" % (rc, excerpt(logs))
        assert_resolved_ipv6_loopback(logs)
        if "IPV6_V6ONLY=0" not in logs:
            raise RuntimeError("fallback listener did not log IPV6_V6ONLY=0")
        return "PASS", "HTTPS fallback via [::1]"
    except Exception as exc:
        return "FAIL", str(exc)


def case_ipv4_hostname(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(
            group, "ipv6_server_v4ref.json", "ipv6_client_v4ref.json",
            IPV4_LOOPBACK, IPV4_LOOPBACK)
        detail = tcp_get_post(IPV4_LOOPBACK, HOSTNAME_V4, DUAL_CONTENT_PORT, expect_atyp=3)
        status, reason = "PASS", "IPv4 ATYP 3 %s; %s" % (HOSTNAME_V4, detail)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return _status_reason(finish_group(group, status, reason, require_ipv6_loopback=False, require_atyp=3))


def resolver_addresses(host, port):
    found = []
    for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        addr = info[4][0]
        if addr not in found:
            found.append(addr)
    return found


def case_prefer_ipv4(binary, server_cfg, expect_addr, label):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        families = resolver_addresses(HOSTNAME_DUAL, DUAL_CONTENT_PORT)
        if IPV4_LOOPBACK not in families or not any(":" in addr for addr in families):
            raise RuntimeError("dual hostname families were %s" % families)
        require_pair(group, server_cfg, "ipv6_client.json", IPV6_LOOPBACK, IPV6_LOOPBACK)
        detail = tcp_get_post(IPV6_LOOPBACK, HOSTNAME_DUAL, DUAL_CONTENT_PORT, expect_atyp=3)
        status, reason = "PASS", "%s; %s" % (label, detail)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    status, reason, text = finish_group(
        group, status, reason, require_ipv6_loopback=False, require_atyp=3, require_v6only="0")
    if status == "PASS":
        resolved = RESOLVED_TO_RE.findall(text or "")
        if expect_addr not in resolved:
            status, reason = "FAIL", "resolved %s, expected %s | %s" % (
                resolved, expect_addr, excerpt(text))
        else:
            reason = "resolved to %s; %s" % (expect_addr, reason)
    return status, reason


def case_ipv6_only(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        server = group.start("ipv6_server_v6only.json")
        if not wait_until(lambda: port_open(IPV6_LOOPBACK, SERVER_PORT), server):
            raise RuntimeError("ipv6_only server did not accept ::1")
        if port_open(IPV4_LOOPBACK, SERVER_PORT):
            raise RuntimeError("ipv6_only server accepted 127.0.0.1")
        client = group.start("ipv6_client.json")
        if not wait_until(lambda: port_open(IPV6_LOOPBACK, SOCKS_PORT), client):
            raise RuntimeError("client did not listen")
        detail = tcp_get_post(IPV6_LOOPBACK, IPV6_LOOPBACK, CONTENT_PORT, expect_atyp=4)
        status, reason = "PASS", "IPV6_V6ONLY rejects 127.0.0.1; " + detail
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return _status_reason(finish_group(
        group, status, reason, require_ipv6_loopback=True, require_atyp=4, require_v6only="1"))


def write_forward(name, target, target_port):
    cfg = tune_timeouts(load_json("client_config.json"))
    cfg["run_type"] = "forward"
    cfg["local_addr"] = IPV6_LOOPBACK
    cfg["local_port"] = SOCKS_PORT
    cfg["remote_addr"] = IPV6_LOOPBACK
    cfg["remote_port"] = SERVER_PORT
    cfg["target_addr"] = target
    cfg["target_port"] = target_port
    save_json(name, cfg)
    return name


def log_contains(group, token):
    for proc in group.procs:
        try:
            proc.log_file.flush()
            with open(proc.log_path, "r", encoding="utf-8", errors="replace") as handle:
                if token in handle.read():
                    return True
        except Exception:
            continue
    return False


def case_forward_zoned(binary, target):
    """Forward a scoped literal and require ATYP 3 plus the original zone text."""
    group = ProcGroup(binary)
    cfg_name = write_forward("ipv6_forward_zoned.json", target, CONTENT_PORT)
    status, reason = "FAIL", "zoned forward probe failed"
    try:
        require_pair(group, "ipv6_server.json", cfg_name, IPV6_LOOPBACK, IPV6_LOOPBACK)
        sock = open_tcp(IPV6_LOOPBACK, SOCKS_PORT)
        try:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: zoned\r\nConnection: close\r\n\r\n")
            if not wait_until(lambda: log_contains(group, "atyp 3"), None, timeout=4):
                raise RuntimeError("server did not log atyp 3 for %s" % target)
        finally:
            sock.close()
        status, reason = "PASS", "probe sent"
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    status, reason, text = finish_group(group, status, reason, require_atyp=3)
    if status == "PASS":
        if target not in (text or ""):
            status, reason = "FAIL", "zone text %s was not kept | %s" % (target, excerpt(text))
        elif "atyp 4" in (text or "") or "atyp 1" in (text or ""):
            status, reason = "FAIL", "scoped literal was not left as ATYP 3 | %s" % excerpt(text)
        else:
            reason = "ATYP 3 %s" % target
    return status, reason


def case_forward_v4_mapped(binary):
    group = ProcGroup(binary)
    cfg_name = write_forward("ipv6_forward_v4mapped.json", "::ffff:127.0.0.1", DUAL_CONTENT_PORT)
    old_retry = fulltest_client.UDP_RETRY_MAX_COUNT
    old_timeout = fulltest_client.RECV_DATA_TIMEOUT
    fulltest_client.UDP_RETRY_MAX_COUNT = 2
    fulltest_client.RECV_DATA_TIMEOUT = TIMEOUT
    status, reason = "FAIL", "v4-mapped forward failed"
    text = ""
    try:
        require_pair(group, "ipv6_server.json", cfg_name, IPV6_LOOPBACK, IPV6_LOOPBACK)
        ok = fulltest_client.start_query(
            IPV6_LOOPBACK, 0, SOCKS_PORT, CONTENT_DIR,
            tcp=True, udp=False, file_list=content_files())
        if not ok:
            raise RuntimeError("transfer failed")
        status, reason = "PASS", "transfer"
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    finally:
        fulltest_client.UDP_RETRY_MAX_COUNT = old_retry
        fulltest_client.RECV_DATA_TIMEOUT = old_timeout
        text = group.stop()
    if status == "PASS":
        if "atyp 1" not in text or "requested connection to 127.0.0.1:" not in text:
            status, reason = "FAIL", "server did not log unwrapped ATYP 1 127.0.0.1"
        elif "atyp 4" in text:
            status, reason = "FAIL", "v4-mapped literal stayed ATYP 4"
        else:
            reason = "ATYP 1 127.0.0.1 from ::ffff:127.0.0.1"
    if status != "PASS":
        reason = "%s | %s" % (reason, excerpt(text))
    return status, reason


def case_v4_mapped_socks_bind(binary):
    """IPv4 client to a dual-stack SOCKS listener. The bind reply must be ATYP 1."""
    group = ProcGroup(binary)
    cfg = tune_timeouts(load_json("client_config.json"))
    cfg["run_type"] = "client"
    cfg["local_addr"] = IPV6_ANY
    cfg["local_port"] = SOCKS_PORT
    cfg["remote_addr"] = IPV6_LOOPBACK
    cfg["remote_port"] = SERVER_PORT
    save_json("ipv6_client_dualstack_socks.json", cfg)
    status, reason = "FAIL", "v4-mapped SOCKS bind failed"
    try:
        require_pair(
            group, "ipv6_server.json", "ipv6_client_dualstack_socks.json",
            IPV6_LOOPBACK, IPV6_LOOPBACK)
        if not port_open(IPV4_LOOPBACK, SOCKS_PORT):
            raise RuntimeError("dual-stack SOCKS listener rejected 127.0.0.1")
        detail = tcp_get_post(IPV4_LOOPBACK, IPV4_LOOPBACK, DUAL_CONTENT_PORT, expect_atyp=1)
        status, reason = "PASS", "bind unwrapped; " + detail
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return _status_reason(finish_group(
        group, status, reason, require_ipv6_loopback=False, require_atyp=1, require_v6only="0"))


def case_nat(binary, enabled):
    if not enabled:
        return "SKIP", (
            "expected-fail, skipped by default. Pass --ipv6-include-expected-fail to execute. "
            "NAT/TPROXY IPv6 is deferred; it must not fail the default IPv4 run or the default -6 run."
        )
    group = ProcGroup(binary)
    data = b""
    setup_error = None
    try:
        server = group.start("ipv6_server.json", use_sudo=True)
        wait_until(lambda: port_open(IPV6_LOOPBACK, SERVER_PORT), server, timeout=4)
        nat = group.start("ipv6_nat.json", use_sudo=True)
        listened = wait_until(lambda: port_open(IPV6_LOOPBACK, NAT_PORT), nat, timeout=4)
        if nat.poll() is not None:
            setup_error = "nat process exited %s before the probe" % nat.returncode
        elif not listened:
            setup_error = "nat did not listen on ::1:%d" % NAT_PORT
        else:
            try:
                sock = open_tcp(IPV6_LOOPBACK, NAT_PORT, timeout=3)
                sock.sendall(b"GET / HTTP/1.1\r\nHost: ipv6\r\nConnection: close\r\n\r\n")
                try:
                    data = sock.recv(256)
                except socket.timeout:
                    data = b""
                sock.close()
            except OSError:
                data = b""
            time.sleep(0.4)
    except Exception as exc:
        setup_error = str(exc)
    text = group.stop()
    signature = ("IP6T_SO_ORIGINAL_DST failed" in text) and data == b""
    if setup_error is None and signature:
        return "EXPECTED-FAIL", "matched IP6T_SO_ORIGINAL_DST failed and a 0-byte probe"
    if data:
        reason = "NAT IPv6 unexpectedly returned %d bytes" % len(data)
    else:
        reason = setup_error or "NAT IPv6 did not match getsockopt error -1 / 0 bytes"
    extra = excerpt(text)
    if extra:
        reason = "%s | %s" % (reason, extra)
    return "FAIL", reason


TUN_SERVER_PORT = 24650
TUN_TCP_PORT = 18083
TUN_UDP_PORT = 18084
TUN_DST = "fd00:c::1"
TUN_HOST = "fd00::1"
TUN_LWIP = "fd00::2"
TUN_VETH_SRV = "fd00:1::1"
TUN_VETH_CLI = "fd00:1::2"
TUN_PROBE = r'''
import socket, sys
host, tcp_port, udp_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
tcp.settimeout(10)
tcp.connect((host, tcp_port, 0, 0))
tcp.sendall(b"GET / HTTP/1.1\r\nHost: tun6\r\nConnection: close\r\n\r\n")
data = b""
while True:
    chunk = tcp.recv(4096)
    if not chunk:
        break
    data += chunk
tcp.close()
if b"TUN6TCP_OK" not in data:
    sys.stderr.write("tcp body %r\n" % data[:300])
    sys.exit(2)
udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp.settimeout(10)
payload = b"TUN6UDP_OK"
udp.sendto(payload, (host, udp_port, 0, 0))
reply, _addr = udp.recvfrom(2048)
udp.close()
if reply != payload:
    sys.stderr.write("udp reply %r\n" % reply)
    sys.exit(3)
print("tcp+udp ok")
'''


TUN_REGRESS = r'''
import os
import socket
import struct
import time

import psutil

IFNAME, DST = sys.argv[1], sys.argv[2]
TCP_PORT, UDP_PORT = int(sys.argv[3]), int(sys.argv[4])


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def send_packet(packet, ethertype):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ethertype))
    sock.bind((IFNAME, 0))
    sock.send(packet)
    sock.close()


def ipv6_fixed(payload_len, next_header, src, dst):
    return struct.pack("!IHBB", 0x60000000, payload_len, next_header, 64) + src + dst


def find_client():
    mine = os.stat("/proc/self/ns/net").st_ino
    for proc in psutil.process_iter(["name"]):
        if proc.info["name"] != "trojan":
            continue
        try:
            if os.stat("/proc/%d/ns/net" % proc.pid).st_ino == mine:
                return proc
        except OSError:
            continue
    raise SystemExit("trojan client not in this netns")


def tcp_ok():
    tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    tcp.settimeout(8)
    tcp.connect((DST, TCP_PORT, 0, 0))
    tcp.sendall(b"GET / HTTP/1.1\r\nHost: tun6\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        chunk = tcp.recv(4096)
        if not chunk:
            break
        data += chunk
    tcp.close()
    if b"TUN6TCP_OK" not in data:
        raise SystemExit("regress tcp body %r" % data[:200])


client = find_client()
client.cpu_percent(interval=None)
src = socket.inet_pton(socket.AF_INET6, "fd00::1")
dst = socket.inet_pton(socket.AF_INET6, DST)
bad6 = ipv6_fixed(65496, 6, src, dst)
bad4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 0, 0, 0, 64, 6, 0,
                   socket.inet_aton("10.0.0.1"), socket.inet_aton("1.2.3.4"))
for _ in range(40):
    send_packet(bad6, 0x86DD)
    send_packet(bad4, 0x0800)
cpu = client.cpu_percent(interval=0.6)
tcp_ok()
if cpu > 50:
    raise SystemExit("malformed headers pegged the client at %.1f%%" % cpu)

rss0 = client.memory_info().rss
mapped = b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("10.9.9.9")
tcp_syn = struct.pack("!HHIIBBHHH", 40000, 80, 1, 0, 5 << 4, 0x02, 65535, 0, 0)
syn = ipv6_fixed(len(tcp_syn), 6, src, mapped) + tcp_syn
for _ in range(300):
    send_packet(syn, 0x86DD)
time.sleep(0.3)
rss1 = client.memory_info().rss
delta = rss1 - rss0
# A leaked pbuf is about 1.5 KiB. 300 of them are well above this ceiling.
if delta > 128 * 1024:
    raise SystemExit("mapped SYNs grew RSS by %d" % delta)

hbh = struct.pack("!BB", 17, 0) + b"\x01\x04" + b"\x00" * 4
udp_payload = b"hbh"
udp_len = 8 + len(udp_payload)
udp_src = socket.inet_pton(socket.AF_INET6, "fd00::1")
udp_dst = socket.inet_pton(socket.AF_INET6, "fd00:eeee::1")
udp = struct.pack("!HHHH", 41000, 9, udp_len, 0) + udp_payload
pseudo = udp_src + udp_dst + struct.pack("!I", udp_len) + struct.pack("!I", 17)
udp = struct.pack("!HHHH", 41000, 9, udp_len, checksum(pseudo + udp)) + udp_payload
hbh_pkt = ipv6_fixed(len(hbh) + len(udp), 0, udp_src, udp_dst) + hbh + udp
send_packet(hbh_pkt, 0x86DD)
time.sleep(0.3)
print("regress ok rss_delta=%d cpu=%.1f" % (delta, cpu))
'''


def root_args(args):
    if os.geteuid() == 0:
        return list(args)
    return ["sudo", "-n"] + list(args)


def run_root(args, check=True, timeout=20):
    proc = subprocess.run(
        root_args(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, timeout=timeout)
    text = ((proc.stderr or "") + (proc.stdout or "")).strip()
    if check and proc.returncode != 0:
        raise RuntimeError("%s -> %s" % (" ".join(args), text or ("exit %s" % proc.returncode)))
    return proc, text


def tun_skip_reason():
    if not os.path.exists("/dev/net/tun"):
        return "skipped: /dev/net/tun is not available"
    if os.geteuid() != 0:
        probe = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if probe.returncode != 0:
            return "skipped: TUN IPv6 needs root (sudo -n) to configure the interface"
    if not os.path.exists("/usr/sbin/ip") and not os.path.exists("/sbin/ip"):
        return "skipped: iproute2 is not available"
    return None


def _serve_tun_tcp(stop, bound):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((TUN_DST, TUN_TCP_PORT))
        sock.listen(4)
        sock.settimeout(0.5)
        bound.set()
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(5)
                conn.recv(4096)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nTUN6TCP_OK")
            except OSError:
                pass
            finally:
                conn.close()
    finally:
        sock.close()


def _serve_tun_udp(stop, bound):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((TUN_DST, TUN_UDP_PORT))
        sock.settimeout(0.5)
        bound.set()
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                sock.sendto(data, addr)
            except OSError:
                break
    finally:
        sock.close()


def _stop_process_group(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGINT)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def case_tun(binary):
    reason = tun_skip_reason()
    if reason:
        return "SKIP", reason

    tag = str(os.getpid())[-5:]
    ns = "tp6" + tag
    tun_name = "tn" + tag
    veth_srv = "v6s" + tag
    veth_cli = "v6c" + tag
    group = ProcGroup(binary)
    client = None
    client_log = None
    regress_note = ""
    stop = threading.Event()
    threads = []
    status, detail = "FAIL", "TUN IPv6 did not finish"
    client_text = ""
    server_text = ""

    def netns(*args, check=True, timeout=20):
        return run_root(["ip", "netns", "exec", ns] + list(args), check=check, timeout=timeout)

    try:
        run_root(["ip", "netns", "del", ns], check=False)
        run_root(["ip", "link", "del", veth_srv], check=False)
        run_root(["ip", "-6", "addr", "del", TUN_DST + "/128", "dev", "lo"], check=False)

        try:
            run_root(["ip", "netns", "add", ns])
        except RuntimeError as exc:
            message = str(exc).lower()
            if "not permitted" in message or "not supported" in message:
                return "SKIP", "skipped: cannot create a network namespace (%s)" % exc
            raise

        run_root(["ip", "link", "add", veth_srv, "type", "veth", "peer", "name", veth_cli])
        run_root(["ip", "link", "set", veth_cli, "netns", ns])
        run_root(["ip", "link", "set", veth_srv, "up"])
        run_root(["ip", "-6", "addr", "add", TUN_VETH_SRV + "/64", "dev", veth_srv, "nodad"])
        netns("ip", "link", "set", "lo", "up")
        netns("ip", "link", "set", veth_cli, "up")
        netns("ip", "-6", "addr", "add", TUN_VETH_CLI + "/64", "dev", veth_cli, "nodad")
        run_root(["ip", "-6", "addr", "add", TUN_DST + "/128", "dev", "lo", "nodad"])

        tcp_ready = threading.Event()
        udp_ready = threading.Event()
        threads = [
            threading.Thread(target=_serve_tun_tcp, args=(stop, tcp_ready)),
            threading.Thread(target=_serve_tun_udp, args=(stop, udp_ready)),
        ]
        for thread in threads:
            thread.daemon = True
            thread.start()
        if not tcp_ready.wait(3) or not udp_ready.wait(3):
            raise RuntimeError("content sockets did not bind %s" % TUN_DST)

        server = tune_timeouts(load_json("server_config.json"))
        server["local_addr"] = TUN_VETH_SRV
        server["local_port"] = TUN_SERVER_PORT
        server["tcp"]["prefer_ipv4"] = True
        server["quic"] = {"enabled": False}
        save_json("ipv6_tun_server.json", server)

        client_cfg = tune_timeouts(load_json("client_config.json"))
        client_cfg["run_type"] = "client_tun"
        client_cfg["remote_addr"] = TUN_VETH_SRV
        client_cfg["remote_port"] = TUN_SERVER_PORT
        client_cfg["tun"]["tun_name"] = tun_name
        client_cfg["tun"]["net_ip"] = ""
        client_cfg["tun"]["net_mask"] = ""
        client_cfg["tun"]["net_ipv6"] = TUN_LWIP
        client_cfg["tun"]["net_ipv6_prefix"] = 64
        client_cfg["tun"]["redirect_local"] = False
        client_cfg["quic"] = {"enabled": False}
        if "dns" in client_cfg:
            client_cfg["dns"]["enabled"] = False
        if "route" in client_cfg:
            client_cfg["route"]["enabled"] = True
            client_cfg["route"]["proxy_type"] = 0
        save_json("ipv6_tun.json", client_cfg)

        server_proc = group.start("ipv6_tun_server.json", use_sudo=True)
        if not wait_until(lambda: port_open(TUN_VETH_SRV, TUN_SERVER_PORT), server_proc, timeout=6):
            raise RuntimeError("trojan server did not listen on %s:%d" % (TUN_VETH_SRV, TUN_SERVER_PORT))

        client_log_path = os.path.join(CONFIG_DIR, "ipv6_tun_client.output")
        client_log = open(client_log_path, "w+", encoding="utf-8", errors="replace")
        client = subprocess.Popen(
            root_args(["ip", "netns", "exec", ns, binary, "-c",
                       os.path.join(CONFIG_DIR, "ipv6_tun.json")]),
            stdout=client_log, stderr=client_log, cwd=TEST_ROOT, start_new_session=True)
        if not wait_until(
                lambda: netns("ip", "link", "show", tun_name, check=False)[0].returncode == 0,
                client, timeout=6):
            raise RuntimeError("TUN device %s did not appear" % tun_name)

        netns("ip", "link", "set", tun_name, "up")
        netns("ip", "-6", "addr", "add", TUN_HOST + "/64", "dev", tun_name, "nodad")
        netns("ip", "-6", "route", "replace", TUN_DST + "/128", "dev", tun_name)
        _route_proc, route_text = netns("ip", "-6", "route", "get", TUN_DST)
        if tun_name not in route_text:
            raise RuntimeError("route to %s did not use %s: %s" % (TUN_DST, tun_name, route_text))
        _srv_route, srv_route = netns("ip", "-6", "route", "get", TUN_VETH_SRV)
        if tun_name in srv_route:
            raise RuntimeError("trojan server route leaked into %s: %s" % (tun_name, srv_route))

        probe_path = os.path.join(CONFIG_DIR, "ipv6_tun_probe.py")
        with open(probe_path, "w", encoding="utf-8") as handle:
            handle.write(TUN_PROBE)
        probe, probe_text = netns(
            sys.executable, probe_path, TUN_DST, str(TUN_TCP_PORT), str(TUN_UDP_PORT),
            timeout=25)
        if probe.returncode != 0 or "tcp+udp ok" not in probe_text:
            raise RuntimeError("probe failed: %s" % (probe_text or "exit %s" % probe.returncode))

        regress_path = os.path.join(CONFIG_DIR, "ipv6_tun_regress.py")
        with open(regress_path, "w", encoding="utf-8") as handle:
            handle.write("import sys\n" + TUN_REGRESS)
        regress, regress_text = netns(
            sys.executable, regress_path, tun_name, TUN_DST, str(TUN_TCP_PORT), str(TUN_UDP_PORT),
            timeout=30)
        if regress.returncode != 0 or "regress ok" not in regress_text:
            raise RuntimeError("malformed/mapped regress failed: %s" % (regress_text or "exit %s" % regress.returncode))
        regress_note = regress_text.strip().splitlines()[-1]

        # IPv6 disabled: a wrapped IPv6 length must not stall the IPv4 parser.
        v4_name = "t4" + tag
        v4_cfg = tune_timeouts(load_json("client_config.json"))
        v4_cfg["run_type"] = "client_tun"
        v4_cfg["remote_addr"] = TUN_VETH_SRV
        v4_cfg["remote_port"] = TUN_SERVER_PORT
        v4_cfg["tun"]["tun_name"] = v4_name
        v4_cfg["tun"]["net_ip"] = "10.66.0.2"
        v4_cfg["tun"]["net_mask"] = "255.255.255.0"
        v4_cfg["tun"]["net_ipv6"] = ""
        v4_cfg["tun"]["redirect_local"] = False
        v4_cfg["quic"] = {"enabled": False}
        if "dns" in v4_cfg:
            v4_cfg["dns"]["enabled"] = False
        if "route" in v4_cfg:
            v4_cfg["route"]["enabled"] = True
            v4_cfg["route"]["proxy_type"] = 0
        save_json("ipv6_tun_v4only.json", v4_cfg)
        v4_log_path = os.path.join(CONFIG_DIR, "ipv6_tun_v4only.output")
        v4_log = open(v4_log_path, "w+", encoding="utf-8", errors="replace")
        v4_cmd = ["ip", "netns", "exec", ns]
        if os.path.exists("/usr/bin/stdbuf"):
            v4_cmd += ["stdbuf", "-oL", "-eL"]
        v4_cmd += [binary, "-c", os.path.join(CONFIG_DIR, "ipv6_tun_v4only.json")]
        v4_proc = subprocess.Popen(
            root_args(v4_cmd), stdout=v4_log, stderr=v4_log, cwd=TEST_ROOT, start_new_session=True)
        try:
            if not wait_until(
                    lambda: netns("ip", "link", "show", v4_name, check=False)[0].returncode == 0,
                    v4_proc, timeout=6):
                raise RuntimeError("IPv4-only TUN %s did not appear" % v4_name)
            netns("ip", "link", "set", v4_name, "up")
            v4_script = os.path.join(CONFIG_DIR, "ipv6_tun_v4inject.py")
            with open(v4_script, "w", encoding="utf-8") as handle:
                handle.write(
                    "import socket, struct, sys\n"
                    "ifname = sys.argv[1]\n"
                    "def send(pkt, et):\n"
                    "    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(et))\n"
                    "    s.bind((ifname, 0))\n"
                    "    s.send(pkt)\n"
                    "    s.close()\n"
                    "bad6 = struct.pack('!IHBB', 0x60000000, 65496, 6, 64) + b'\\x00'*32\n"
                    "bad4 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 0, 0, 0, 64, 6, 0, "
                    "socket.inet_aton('10.66.0.1'), socket.inet_aton('1.2.3.4'))\n"
                    "for _ in range(20):\n"
                    "    send(bad6, 0x86DD)\n"
                    "    send(bad4, 0x0800)\n"
                    "src = socket.inet_aton('10.66.0.1')\n"
                    "dst = socket.inet_aton('1.2.3.4')\n"
                    "payload = b'ping'\n"
                    "udp_len = 8 + len(payload)\n"
                    "def csum(data):\n"
                    "    if len(data) % 2: data += b'\\x00'\n"
                    "    total = sum(struct.unpack('!%dH' % (len(data)//2), data))\n"
                    "    while total >> 16: total = (total & 0xFFFF) + (total >> 16)\n"
                    "    return (~total) & 0xFFFF\n"
                    "udp = struct.pack('!HHHH', 40000, 9, udp_len, 0) + payload\n"
                    "udp = struct.pack('!HHHH', 40000, 9, udp_len, "
                    "csum(src+dst+struct.pack('!BBH', 0, 17, udp_len)+udp)) + payload\n"
                    "ip = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(udp), 0, 0, 64, 17, 0) + src + dst\n"
                    "ip = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(udp), 0, 0, 64, 17, csum(ip)) + src + dst\n"
                    "send(ip+udp, 0x0800)\n"
                    "print('v4 inject ok')\n")
            injected, inject_text = netns(sys.executable, v4_script, v4_name, timeout=15)
            if injected.returncode != 0:
                raise RuntimeError("v4 inject failed: %s" % inject_text)
            time.sleep(0.4)
        finally:
            _stop_process_group(v4_proc)
            v4_log.close()
        with open(v4_log_path, encoding="utf-8", errors="replace") as handle:
            v4_text = handle.read()
        if "drop malformed IPv6 packet" not in v4_text:
            raise RuntimeError("IPv4-only TUN did not drop the wrapped IPv6 header")
        if "proxy connect: 1.2.3.4" not in v4_text:
            raise RuntimeError("IPv4-only TUN did not make progress after the bad header | %s" % excerpt(v4_text))

        status, detail = "PASS", "IPv6 TCP and UDP through TUN"
    except Exception as exc:
        status, detail = "FAIL", str(exc)
    finally:
        stop.set()
        _stop_process_group(client)
        if client_log is not None:
            client_log.close()
            try:
                with open(client_log.name, encoding="utf-8", errors="replace") as handle:
                    client_text = handle.read()
            except OSError:
                client_text = ""
        server_text = group.stop()
        for thread in threads:
            thread.join(timeout=2)
        run_root(["ip", "netns", "del", ns], check=False)
        run_root(["ip", "link", "del", veth_srv], check=False)
        run_root(["ip", "-6", "addr", "del", TUN_DST + "/128", "dev", "lo"], check=False)

    text = client_text + "\n" + server_text
    if status == "PASS":
        tcp_line = "requested connection to [%s]:%d atyp 4" % (TUN_DST, TUN_TCP_PORT)
        udp_line = "requested UDP associate to [%s]:%d atyp 4" % (TUN_DST, TUN_UDP_PORT)
        ipv6_line = "[tun] IPv6 netif %s/64" % TUN_LWIP
        if ipv6_line not in client_text:
            status, detail = "FAIL", "client did not log %s" % ipv6_line
        elif tcp_line not in server_text:
            status, detail = "FAIL", "server did not log %s" % tcp_line
        elif udp_line not in server_text:
            status, detail = "FAIL", "server did not log %s" % udp_line
        elif "fatal:" in client_text:
            status, detail = "FAIL", "client logged fatal during a passing transfer"
        elif "drop malformed IPv6 packet" not in client_text or "drop malformed IPv4 packet" not in client_text:
            status, detail = "FAIL", "client did not drop the wrapped IPv6 or zero IPv4 length"
        elif "drop IPv4-mapped IPv6 packet before lwIP" not in client_text:
            status, detail = "FAIL", "client did not drop the IPv4-mapped SYN"
        elif "fd00:eeee::1" not in client_text:
            status, detail = "FAIL", "hop-by-hop UDP was not forwarded"
        else:
            detail = "ATYP 4 TCP and UDP through TUN; malformed lengths and mapped SYNs dropped; %s" % regress_note
    if status != "PASS":
        extra = excerpt(text)
        if extra:
            detail = "%s | %s" % (detail, extra)
    return status, detail


def main(binary, include_expected_fail=False, include_ipv4_reference=False, include_nat=False):
    os.chdir(TEST_ROOT)
    RESULTS.clear()
    install_hosts_guards()
    print_time_log("IPv6 suite binary " + binary)
    print_time_log(
        "no-rule NAT is %s; REDIRECT/TPROXY are %s; TUN IPv6 runs when root and /dev/net/tun are available"
        % ("EXECUTED (must match the expected-fail signature)" if include_expected_fail
           else "SKIPPED (expected-fail)",
           "EXECUTED" if include_nat else "SKIPPED"))
    restore_error = None
    try:
        try:
            install_hosts()
        except Exception as exc:
            record("hosts", "FAIL", "cannot install IPv6 hostname in /etc/hosts: %s" % exc)
            return 1
        write_configs()
        start_content_servers()

        cases = [
            ("client_tcp_socks_ipv6_literal", lambda: case_tcp_literal(binary)),
            ("client_tcp_socks_hostname_aaaa", lambda: case_tcp_hostname(binary)),
            ("client_udp_associate_ipv6", lambda: case_udp(
                binary, "ipv6_server.json", "ipv6_client.json", None, "client")),
            ("client_pipeline_tcp_ipv6", lambda: case_pipeline_tcp(binary)),
            ("client_pipeline_udp_ipv6", lambda: case_udp(
                binary, "ipv6_server_pipeline.json", "ipv6_client_pipeline.json",
                "ipv6_server_pipeline_balance.json", "pipeline")),
            ("forward_tcp_ipv6", lambda: _forward_tcp(binary)),
            ("forward_udp_ipv6", lambda: _forward_udp(binary)),
            ("forward_pipeline_tcp_ipv6", lambda: _forward_pipe_tcp(binary)),
            ("forward_pipeline_udp_ipv6", lambda: _forward_pipe_udp(binary)),
            ("fallback_ipv6", lambda: case_fallback(binary)),
            ("dualstack_v4_client_to_v6_server", lambda: case_dual_stack(binary)),
            ("ipv6_only_listener", lambda: case_ipv6_only(binary)),
            ("prefer_ipv4_dual_hostname", lambda: case_prefer_ipv4(
                binary, "ipv6_server.json", IPV4_LOOPBACK, "tcp.prefer_ipv4=true")),
            ("prefer_ipv4_default_dual_hostname", lambda: case_prefer_ipv4(
                binary, "ipv6_server_resolver_default.json",
                resolver_addresses(HOSTNAME_DUAL, DUAL_CONTENT_PORT)[0],
                "tcp.prefer_ipv4 default")),
            ("forward_zoned_link_local", lambda: case_forward_zoned(binary, "fe80::1%lo")),
            ("forward_zoned_unknown_iface", lambda: case_forward_zoned(
                binary, "fe80::1%nosuchiface0")),
            ("forward_v4_mapped", lambda: case_forward_v4_mapped(binary)),
            ("socks_v4_mapped_bind", lambda: case_v4_mapped_socks_bind(binary)),
            ("nat_ipv6", lambda: case_nat(binary, include_expected_fail)),
            ("tun_ipv6", lambda: case_tun(binary)),
        ]
        import fulltest_ipv6_nat
        nat_cache = {}

        def nat_case(case_id):
            def run():
                if "rows" not in nat_cache:
                    nat_cache["rows"] = fulltest_ipv6_nat.run_cases(binary, include_nat)
                for row_id, status, reason in nat_cache["rows"]:
                    if row_id == case_id:
                        return status, reason
                return "FAIL", "nat case %s did not run" % case_id
            return run

        for case_id in fulltest_ipv6_nat.CASE_IDS:
            cases.append((case_id, nat_case(case_id)))
        if include_ipv4_reference:
            cases.insert(2, ("ipv4_client_tcp_socks_hostname", lambda: case_ipv4_hostname(binary)))

        for case_id, func in cases:
            print_time_log("---- " + case_id + " ----")
            run_recorded(case_id, func)
    except Exception as exc:
        record("harness", "FAIL", "suite setup failed: %s" % exc)
        traceback.print_exc()
    finally:
        for proc in list(_content_procs):
            stop_content_server(proc)
        del _content_procs[:]
        try:
            remove_hosts()
        except Exception as exc:
            restore_error = str(exc)
            record("hosts_restore", "FAIL", restore_error)

    print_time_log("==== IPv6 suite summary ====")
    failed = 0
    for row in RESULTS:
        print_time_log("%s\t%s\t%s" % (row["status"], row["case"], row["reason"].replace("\n", " ")[:500]))
        if row["status"] == "FAIL":
            failed += 1
    if failed:
        print_time_log("IPv6 suite failed %d case(s)" % failed)
        return 1
    print_time_log("IPv6 suite passed")
    return 0


def _forward_tcp(binary):
    return run_forward(binary, "ipv6_server.json", "ipv6_forward.json", None, True, False)


def _forward_udp(binary):
    return run_forward(binary, "ipv6_server.json", "ipv6_forward.json", None, False, True)


def _forward_pipe_tcp(binary):
    return run_forward(
        binary, "ipv6_server_pipeline.json", "ipv6_forward_pipeline.json",
        "ipv6_server_pipeline_balance.json", True, False)


def _forward_pipe_udp(binary):
    return run_forward(
        binary, "ipv6_server_pipeline.json", "ipv6_forward_pipeline.json",
        "ipv6_server_pipeline_balance.json", False, True)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: fulltest_ipv6.py BINARY [--include-expected-fail] [--include-ipv4-reference]")
        sys.exit(2)
    sys.exit(main(
        os.path.realpath(sys.argv[1]),
        include_expected_fail="--include-expected-fail" in sys.argv,
        include_ipv4_reference="--include-ipv4-reference" in sys.argv,
        include_nat="--ipv6-nat" in sys.argv))
