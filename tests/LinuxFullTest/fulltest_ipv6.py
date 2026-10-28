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

 NAT and client_tun IPv6 cases are registered here but skipped unless
 --ipv6-include-expected-fail is set. They are expected to fail until a
 later PR (NAT/TPROXY and the lwIP TUN stack are IPv4-only) and they do
 not affect this suite's exit status or the default IPv4 run.

 PySocks refuses IPv6 destinations (socks.py connect raises
 "PySocks doesn't support IPv6"), so client-mode cases speak SOCKS5
 directly. That is what lets the suite send ATYP 4 and ATYP 3 exactly.

 The suite exit status is non-zero when an in-scope IPv6 case fails.
 See IPV6_BASELINE.md.
'''

import json
import os
import signal
import socket
import struct
import subprocess
import sys
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
HOSTS_PATH = "/etc/hosts"
HOSTS_MARKER = "trojan-plus-ipv6-fulltest"

# In-scope cases affect the exit status. NAT/TUN are expected-fail.
RESULTS = []


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

    def client(pipeline, local_addr, remote_addr, remote_port, target_addr, run_type):
        cfg = tune_timeouts(load_json("client_config_pipeline.json" if pipeline else "client_config.json"))
        cfg["run_type"] = run_type
        cfg["local_addr"] = local_addr
        cfg["local_port"] = SOCKS_PORT
        cfg["remote_addr"] = remote_addr
        cfg["remote_port"] = remote_port
        cfg["target_addr"] = target_addr
        cfg["target_port"] = CONTENT_PORT
        if pipeline:
            cfg["experimental"]["pipeline_num"] = 10
            cfg["experimental"]["pipeline_ack_window"] = 10
        return cfg

    save_json("ipv6_client.json", client(
        False, IPV6_LOOPBACK, IPV6_LOOPBACK, SERVER_PORT, IPV6_LOOPBACK, "client"))
    save_json("ipv6_forward.json", client(
        False, IPV6_LOOPBACK, IPV6_LOOPBACK, SERVER_PORT, IPV6_LOOPBACK, "forward"))
    save_json("ipv6_client_v4_to_dual.json", client(
        False, IPV4_LOOPBACK, IPV4_LOOPBACK, SERVER_PORT, IPV4_LOOPBACK, "client"))
    save_json("ipv6_client_v4ref.json", client(
        False, IPV4_LOOPBACK, IPV4_LOOPBACK, SERVER_PORT, IPV4_LOOPBACK, "client"))

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
    # itself (observed: "forwarding to ::1:20621 via ::1:4650").
    nat["tcp"]["use_tproxy"] = False
    nat["password"] = ["88888888"]
    save_json("ipv6_nat.json", nat)

    tun = tune_timeouts(load_json("client_config.json"))
    tun["run_type"] = "client_tun"
    tun["remote_addr"] = IPV6_LOOPBACK
    tun["remote_port"] = SERVER_PORT
    tun["tun"]["tun_name"] = "tunipv6"
    tun["tun"]["net_ip"] = "fd00::2"
    tun["tun"]["net_mask"] = "ffff:ffff:ffff:ffff::"
    # Keep routing enabled so the failure is the IPv6 address parse, not the
    # "tun mode need route's config support" warning.
    if "route" in tun:
        tun["route"]["enabled"] = True
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


def start_content_server():
    fulltest_gen_content.gen_files(os.path.join(TEST_ROOT, CONTENT_DIR), 2, 1500)
    log_path = os.path.join(CONFIG_DIR, "ipv6_content_server.output")
    log_file = open(log_path, "w+", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [sys.executable, "-u", "fulltest_server.py", CONTENT_DIR, str(CONTENT_PORT), IPV6_ANY],
        stdout=log_file, stderr=log_file, cwd=TEST_ROOT, universal_newlines=True)
    proc.log_file = log_file
    ok_v6 = wait_until(lambda: port_open(IPV6_LOOPBACK, CONTENT_PORT), proc)
    ok_v4 = wait_until(lambda: port_open(IPV4_LOOPBACK, CONTENT_PORT), proc, timeout=3)
    if not ok_v6 or not ok_v4:
        log_file.flush()
        log_file.seek(0)
        detail = log_file.read()
        raise RuntimeError(
            "content server failed to accept both ::1 and 127.0.0.1 on %d (%s)"
            % (CONTENT_PORT, excerpt(detail) or "no log"))
    return proc


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


def tcp_get_post(proxy_host, dest_host, dest_port):
    name = content_files()[0]
    expected = read_content(name)
    sock, atyp, bnd_addr, bnd_port, request_addr = socks5_connect(
        proxy_host, SOCKS_PORT, dest_host, dest_port, b"\x01")
    try:
        atyp_n = request_addr[0]
        body = http_exchange(sock, (
            "GET /%s HTTP/1.1\r\nHost: ipv6-fulltest\r\nConnection: close\r\n\r\n" % name
        ).encode("ascii"))
        if body != expected:
            raise RuntimeError("GET body mismatch (%d vs %d)" % (len(body), len(expected)))
    finally:
        sock.close()

    payload = b"d=" + expected
    sock, _, _, _, _ = socks5_connect(proxy_host, SOCKS_PORT, dest_host, dest_port, b"\x01")
    try:
        header = (
            "POST /%s HTTP/1.1\r\nHost: ipv6-fulltest\r\nContent-Length: %d\r\n"
            "Connection: close\r\n\r\n" % (name, len(payload))
        ).encode("ascii")
        body = http_exchange(sock, header + payload)
        if body != b"OK":
            raise RuntimeError("POST body %r" % body[:80])
    finally:
        sock.close()
    return "ATYP %d, SOCKS bind %s:%s" % (atyp_n, bnd_addr, bnd_port)


def udp_associate_transfer(proxy_host, dest_host, dest_port):
    name = content_files()[0]
    expected = read_content(name)
    ctrl, _, bnd_addr, bnd_port, request_addr = socks5_connect(
        proxy_host, SOCKS_PORT, "::", 0, b"\x03")
    try:
        if request_addr[0] != 4:
            raise RuntimeError("UDP ASSOCIATE request was not ATYP 4")
        if bnd_port == 0:
            raise RuntimeError(
                "UDP ASSOCIATE bound port is 0 (reply ATYP %r addr %s)" % (ctrl, bnd_addr))
        relay_host = bnd_addr
        if relay_host in ("0.0.0.0", "::"):
            relay_host = proxy_host
        family = socket.AF_INET6 if is_ipv6_host(relay_host) else socket.AF_INET
        udp = socket.socket(family, socket.SOCK_DGRAM)
        udp.settimeout(TIMEOUT)
        query = ("file=%s&len=%d&m=GET\r\n" % (name, len(expected))).encode("ascii")
        header = b"\x00\x00\x00" + pack_socks_addr(dest_host, dest_port)
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
    if status != "PASS":
        reason = "%s | %s" % (reason, excerpt(text))
    return status, reason


def install_hosts():
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()
        writable = True
    except PermissionError:
        text = subprocess.check_output(["sudo", "-n", "cat", HOSTS_PATH], text=True)
        writable = False
    kept = [ln for ln in text.splitlines(True) if HOSTS_MARKER not in ln]
    if kept and not kept[-1].endswith("\n"):
        kept[-1] += "\n"
    kept.append("::1 %s # %s\n" % (HOSTNAME_V6, HOSTS_MARKER))
    kept.append("127.0.0.1 %s # %s\n" % (HOSTNAME_V4, HOSTS_MARKER))
    data = "".join(kept)
    if writable:
        try:
            with open(HOSTS_PATH, "w", encoding="utf-8") as handle:
                handle.write(data)
            return
        except PermissionError:
            pass
    proc = subprocess.run(["sudo", "-n", "tee", HOSTS_PATH], input=data, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError("cannot update /etc/hosts: %s" % (proc.stderr or proc.stdout))


def remove_hosts():
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8") as handle:
            text = handle.read()
        writable = True
    except PermissionError:
        try:
            text = subprocess.check_output(["sudo", "-n", "cat", HOSTS_PATH], text=True)
        except Exception:
            return
        writable = False
    except FileNotFoundError:
        return
    if HOSTS_MARKER not in text:
        return
    kept = [ln for ln in text.splitlines(True) if HOSTS_MARKER not in ln]
    data = "".join(kept)
    if writable:
        try:
            with open(HOSTS_PATH, "w", encoding="utf-8") as handle:
                handle.write(data)
            return
        except PermissionError:
            pass
    subprocess.run(["sudo", "-n", "tee", HOSTS_PATH], input=data, text=True, capture_output=True)


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


def finish_group(group, status, reason):
    text = group.stop()
    if status != "PASS":
        extra = excerpt(text)
        if extra:
            reason = "%s | %s" % (reason, extra)
    return status, reason


def case_tcp_literal(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(group, "ipv6_server.json", "ipv6_client.json", IPV6_LOOPBACK, IPV6_LOOPBACK)
        status, reason = "PASS", tcp_get_post(IPV6_LOOPBACK, IPV6_LOOPBACK, CONTENT_PORT)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return finish_group(group, status, reason)


def case_tcp_hostname(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(group, "ipv6_server.json", "ipv6_client.json", IPV6_LOOPBACK, IPV6_LOOPBACK)
        detail = tcp_get_post(IPV6_LOOPBACK, HOSTNAME_V6, CONTENT_PORT)
        status, reason = "PASS", "ATYP 3 hostname %s; %s" % (HOSTNAME_V6, detail)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return finish_group(group, status, reason)


def case_udp(binary, server_cfg, client_cfg, balance_cfg, label):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(group, server_cfg, client_cfg, IPV6_LOOPBACK, IPV6_LOOPBACK, balance_cfg)
        status, reason = "PASS", label + "; " + udp_associate_transfer(IPV6_LOOPBACK, IPV6_LOOPBACK, CONTENT_PORT)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return finish_group(group, status, reason)


def case_pipeline_tcp(binary):
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        require_pair(
            group, "ipv6_server_pipeline.json", "ipv6_client_pipeline.json",
            IPV6_LOOPBACK, IPV6_LOOPBACK, "ipv6_server_pipeline_balance.json")
        status, reason = "PASS", "pipeline " + tcp_get_post(IPV6_LOOPBACK, IPV6_LOOPBACK, CONTENT_PORT)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return finish_group(group, status, reason)


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
        status, reason = "PASS", "v4 client -> :: server; " + tcp_get_post(IPV4_LOOPBACK, IPV4_LOOPBACK, CONTENT_PORT)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return finish_group(group, status, reason)


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
        detail = tcp_get_post(IPV4_LOOPBACK, HOSTNAME_V4, CONTENT_PORT)
        status, reason = "PASS", "IPv4 ATYP 3 %s; %s" % (HOSTNAME_V4, detail)
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return finish_group(group, status, reason)


def case_nat(binary, enabled):
    if not enabled:
        return "SKIP", (
            "expected-fail, skipped by default. Pass --ipv6-include-expected-fail to execute. "
            "NAT/TPROXY IPv6 is deferred; it must not fail the default IPv4 run or the default -6 run."
        )
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        server = group.start("ipv6_server.json", use_sudo=True)
        wait_until(lambda: port_open(IPV6_LOOPBACK, SERVER_PORT), server, timeout=4)
        nat = group.start("ipv6_nat.json", use_sudo=True)
        listened = wait_until(lambda: port_open(IPV6_LOOPBACK, NAT_PORT), nat, timeout=4)
        if nat.poll() is not None:
            status, reason = "FAIL", "nat process exited %s" % nat.returncode
        elif not listened:
            status, reason = "FAIL", "nat did not listen on ::1:%d" % NAT_PORT
        else:
            try:
                sock = open_tcp(IPV6_LOOPBACK, NAT_PORT, timeout=3)
                sock.sendall(b"GET / HTTP/1.1\r\nHost: ipv6\r\nConnection: close\r\n\r\n")
                try:
                    data = sock.recv(256)
                except socket.timeout:
                    data = b""
                sock.close()
            except OSError as exc:
                data = str(exc).encode()
            time.sleep(0.4)
            status, reason = "FAIL", (
                "plain connect to [::1]:%d was not proxied (reply %r). "
                "use_tproxy is false, so the session depends on IP6T_SO_ORIGINAL_DST"
                % (NAT_PORT, data[:80])
            )
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return finish_group(group, status, reason)


def case_tun(binary, enabled):
    if not enabled:
        return "SKIP", (
            "expected-fail, skipped by default. Pass --ipv6-include-expected-fail to execute. "
            "client_tun IPv6 (lwIP + built-in DNS + routing) is deferred and must not fail the default run."
        )
    group = ProcGroup(binary)
    status, reason = "FAIL", "unknown"
    try:
        proc = group.start("ipv6_tun.json", use_sudo=True)
        time.sleep(1.5)
        code = proc.poll()
        if code is None:
            status, reason = "FAIL", "tun process stayed up with IPv6 net_ip fd00::2; expected make_address_v4 to reject it"
        else:
            status, reason = "FAIL", "tun exited %s with IPv6 net_ip fd00::2" % code
    except Exception as exc:
        status, reason = "FAIL", str(exc)
    return finish_group(group, status, reason)


def main(binary, include_expected_fail=False, include_ipv4_reference=False):
    os.chdir(TEST_ROOT)
    RESULTS.clear()
    print_time_log("IPv6 suite binary " + binary)
    print_time_log(
        "NAT/TUN IPv6 cases are %s"
        % ("EXECUTED (expected-fail, exit status ignored)" if include_expected_fail else "SKIPPED (expected-fail)"))
    content = None
    try:
        try:
            install_hosts()
        except Exception as exc:
            record("hosts", "FAIL", "cannot install IPv6 hostname in /etc/hosts: %s" % exc)
            return 1
        write_configs()
        content = start_content_server()

        cases = [
            ("client_tcp_socks_ipv6_literal", lambda: case_tcp_literal(binary), False),
            ("client_tcp_socks_hostname_aaaa", lambda: case_tcp_hostname(binary), False),
            ("client_udp_associate_ipv6", lambda: case_udp(
                binary, "ipv6_server.json", "ipv6_client.json", None, "client"), False),
            ("client_pipeline_tcp_ipv6", lambda: case_pipeline_tcp(binary), False),
            ("client_pipeline_udp_ipv6", lambda: case_udp(
                binary, "ipv6_server_pipeline.json", "ipv6_client_pipeline.json",
                "ipv6_server_pipeline_balance.json", "pipeline"), False),
            ("forward_tcp_ipv6", lambda: _forward_tcp(binary), False),
            ("forward_udp_ipv6", lambda: _forward_udp(binary), False),
            ("forward_pipeline_tcp_ipv6", lambda: _forward_pipe_tcp(binary), False),
            ("forward_pipeline_udp_ipv6", lambda: _forward_pipe_udp(binary), False),
            ("fallback_ipv6", lambda: case_fallback(binary), False),
            ("dualstack_v4_client_to_v6_server", lambda: case_dual_stack(binary), False),
            ("nat_ipv6", lambda: case_nat(binary, include_expected_fail), True),
            ("tun_ipv6", lambda: case_tun(binary, include_expected_fail), True),
        ]
        if include_ipv4_reference:
            cases.insert(2, ("ipv4_client_tcp_socks_hostname", lambda: case_ipv4_hostname(binary), False))

        for case_id, func, expected in cases:
            print_time_log("---- " + case_id + " ----")
            run_recorded(case_id, func, expected=expected)
    except Exception as exc:
        record("harness", "FAIL", "suite setup failed: %s" % exc)
        traceback.print_exc()
    finally:
        stop_content_server(content)
        remove_hosts()

    print_time_log("==== IPv6 suite summary ====")
    failed = 0
    for row in RESULTS:
        print_time_log("%s\t%s\t%s" % (row["status"], row["case"], row["reason"].replace("\n", " ")[:500]))
        if row["status"] == "FAIL" and not row["expected"]:
            failed += 1
    if failed:
        print_time_log("IPv6 suite failed %d in-scope case(s)" % failed)
        return 1
    print_time_log("IPv6 in-scope cases passed (NAT/TUN expected-fail ignored)")
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
        include_ipv4_reference="--include-ipv4-reference" in sys.argv))
