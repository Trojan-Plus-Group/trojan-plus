'''
Opt-in IPv6 NAT / TPROXY coverage for LinuxFullTest.

The cases need root (or passwordless sudo), a network namespace, and ip6tables.
TPROXY additionally needs the ip6tables TPROXY target or nftables. When the
privilege or the tool is missing the cases return SKIP. They are not part of
the default -6 run.

Layout (one netns, so host iptables is left alone):

  client netns                         host
  probe ---> fd00:9:9::9:port          trojan server on fd00:9:6::1
       REDIRECT or TPROXY              content server on fd00:9:9::9 and 10.9.9.9
       trojan NAT on [::]:20622
             ---> fd00:9:6::1:24650 ---+

fd00:9:9::9 and 10.9.9.9 are not configured inside the netns, so the UDP reply
socket has to bind a non-local address. That only succeeds with the matching
transparent option (IPV6_TRANSPARENT or IP_TRANSPARENT).
'''

import json
import os
import shutil
import socket
import subprocess
import sys
import time

TEST_ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(TEST_ROOT, "config")

NS = "tp6natfull"
HOST_VETH = "tp6hfull"
NS_VETH = "tp6nfull"
HOST_V6 = "fd00:9:6::1"
NS_V6 = "fd00:9:6::2"
V6_PREFIX = "fd00:9:6::/64"
HOST_V4 = "10.9.6.1"
NS_V4 = "10.9.6.2"
V4_PREFIX = "10.9.6.0/24"
DEST_V6 = "fd00:9:9::9"
DEST_V4 = "10.9.9.9"
SERVER_PORT = 24650
NAT_PORT = 20622
TCP_V6_PORT = 18082
TCP_V4_PORT = 18083
UDP_V6_PORT = 18084
UDP_V4_PORT = 18085
BODY_V6 = b"IPV6-NAT-OK"
BODY_V4 = b"V4MAPPED-NAT-OK"
UDP_V6_PAYLOAD = b"udp-v6-nat"
UDP_V4_PAYLOAD = b"udp-v4-nat"

CASE_IDS = (
    "nat_ipv6_redirect_tcp",
    "nat_ipv6_redirect_v4mapped",
    "nat_ipv6_tproxy_tcp",
    "nat_ipv6_tproxy_udp",
    "nat_ipv6_tproxy_udp_v4mapped",
)


def _which(name):
    return shutil.which(name)


def _run(args, check=True, timeout=20, input_text=None):
    proc = subprocess.run(
        args, text=True, input=input_text, capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(
            "%s -> %s\n%s" % (" ".join(args), proc.returncode, (proc.stderr or proc.stdout or "").strip()))
    return proc


def _sudo(args, check=True, timeout=20, input_text=None):
    return _run(["sudo", "-n"] + args, check=check, timeout=timeout, input_text=input_text)


def _ns(args, check=True, timeout=20, input_text=None):
    return _sudo(["ip", "netns", "exec", NS] + args, check=check, timeout=timeout, input_text=input_text)


def environment_skip_reason():
    if not sys.platform.startswith("linux"):
        return "NAT/TPROXY IPv6 tests run on Linux only"
    if os.geteuid() != 0:
        probe = _run(["sudo", "-n", "true"], check=False)
        if probe.returncode != 0:
            return "passwordless sudo (sudo -n) is required for the netns and ip6tables rules"
    for tool in ("ip", "ip6tables", "iptables"):
        if _which(tool) is None:
            return "%s is not installed" % tool
    return None


def _skip_all(reason):
    return [(case_id, "SKIP", reason) for case_id in CASE_IDS]


def _load(name):
    with open(os.path.join(CONFIG_DIR, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


def _save(name, obj):
    path = os.path.join(CONFIG_DIR, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=4)
        handle.write("\n")
    return path


def _write_configs(binary_unused=None):
    server = _load("server_config.json")
    server["local_addr"] = HOST_V6
    server["local_port"] = SERVER_PORT
    server["log_level"] = 0
    server["udp_timeout"] = 8
    server["tcp"]["prefer_ipv4"] = False
    server["tcp"]["fast_open"] = False
    server["tcp"]["connect_time_out"] = 5
    server["ssl"]["cert"] = os.path.join(CONFIG_DIR, "server.crt")
    server["ssl"]["key"] = os.path.join(CONFIG_DIR, "server.key")
    _save("ipv6_nat_server.json", server)

    def nat(use_tproxy):
        cfg = _load("client_config.json")
        cfg["run_type"] = "nat"
        cfg["local_addr"] = "::"
        cfg["local_port"] = NAT_PORT
        cfg["remote_addr"] = HOST_V6
        cfg["remote_port"] = SERVER_PORT
        cfg["log_level"] = 0
        cfg["udp_timeout"] = 8
        cfg["password"] = ["88888888"]
        cfg["tcp"]["use_tproxy"] = use_tproxy
        cfg["tcp"]["ipv6_only"] = False
        cfg["tcp"]["fast_open"] = False
        cfg["tcp"]["connect_time_out"] = 5
        cfg["ssl"]["verify"] = False
        cfg["ssl"]["verify_hostname"] = False
        cfg["ssl"]["cert"] = os.path.join(CONFIG_DIR, "server.crt")
        if "dns" in cfg:
            cfg["dns"]["enabled"] = False
        if "route" in cfg:
            cfg["route"]["enabled"] = False
        return cfg

    _save("ipv6_nat_redirect.json", nat(False))
    _save("ipv6_nat_tproxy.json", nat(True))


CONTENT_SCRIPT = r'''
import socket, sys, threading
BODY_V6 = b"IPV6-NAT-OK"
BODY_V4 = b"V4MAPPED-NAT-OK"

def http_response(body):
    return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)

def serve_tcp(family, addr, port, body):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((addr, port))
    sock.listen(32)
    response = http_response(body)
    while True:
        conn, _peer = sock.accept()
        conn.settimeout(3)
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
            conn.sendall(response)
        except OSError:
            pass
        finally:
            conn.close()

def serve_udp(family, addr, port):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((addr, port))
    while True:
        data, peer = sock.recvfrom(4096)
        sock.sendto(data, peer)

threads = [
    threading.Thread(target=serve_tcp, args=(socket.AF_INET6, "fd00:9:9::9", 18082, BODY_V6), daemon=True),
    threading.Thread(target=serve_tcp, args=(socket.AF_INET, "10.9.9.9", 18083, BODY_V4), daemon=True),
    threading.Thread(target=serve_udp, args=(socket.AF_INET6, "fd00:9:9::9", 18084), daemon=True),
    threading.Thread(target=serve_udp, args=(socket.AF_INET, "10.9.9.9", 18085), daemon=True),
]
for thread in threads:
    thread.start()
sys.stdout.write("content-ready\n")
sys.stdout.flush()
while True:
    time_mod = __import__("time")
    time_mod.sleep(3600)
'''

PROBE_SCRIPT = r'''
import socket, sys
mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
family = socket.AF_INET6 if ":" in host else socket.AF_INET
if mode == "http":
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(8)
    sock.connect((host, port))
    sock.sendall(b"GET / HTTP/1.1\r\nHost: nat\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sys.stdout.buffer.write(data)
elif mode == "udp":
    payload = sys.argv[4].encode()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(8)
    sock.sendto(payload, (host, port))
    data, _peer = sock.recvfrom(4096)
    sys.stdout.buffer.write(data)
else:
    sys.stderr.write("unknown mode\n")
    sys.exit(2)
'''


class Harness:
    def __init__(self, binary):
        self.binary = binary
        self.procs = []
        self.content_path = "/tmp/tp6nat_content.py"
        self.probe_path = "/tmp/tp6nat_probe.py"
        self.server_log = os.path.join(CONFIG_DIR, "ipv6_nat_server.json.output")
        self.nat_log = None
        self.tproxy_backend = None

    def start(self, args, log_path, netns=False):
        log_file = open(log_path, "w+", encoding="utf-8", errors="replace")
        cmd = list(args)
        if netns:
            cmd = ["sudo", "-n", "ip", "netns", "exec", NS] + cmd
        proc = subprocess.Popen(
            cmd, stdout=log_file, stderr=subprocess.STDOUT, cwd=TEST_ROOT, start_new_session=True)
        proc.log_file = log_file
        proc.log_path = log_path
        self.procs.append(proc)
        return proc

    def stop(self, proc):
        if proc is None:
            return
        if proc.poll() is None:
            _sudo(["kill", "-TERM", "--", "-%d" % proc.pid], check=False)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                _sudo(["kill", "-KILL", "--", "-%d" % proc.pid], check=False)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        try:
            proc.log_file.close()
        except Exception:
            pass

    def stop_all(self):
        for proc in reversed(self.procs):
            self.stop(proc)
        self.procs = []

    def read_log(self, path, offset=0):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                return handle.read()
        except OSError:
            return ""

    def log_size(self, path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    def wait_log(self, path, token, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if token in self.read_log(path):
                return True
            time.sleep(0.1)
        return False

    def wait_tcp(self, host, port, timeout=6):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(0.4)
                sock.connect((host, port))
                sock.close()
                return True
            except OSError:
                time.sleep(0.1)
        return False

    def cleanup_net(self):
        _ns(["ip6tables", "-t", "nat", "-F"], check=False)
        _ns(["ip6tables", "-t", "mangle", "-F"], check=False)
        _ns(["iptables", "-t", "nat", "-F"], check=False)
        _ns(["iptables", "-t", "mangle", "-F"], check=False)
        _ns(["nft", "delete", "table", "ip6", "tpnat"], check=False)
        _ns(["nft", "delete", "table", "ip", "tpnat"], check=False)
        _ns(["ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100"], check=False)
        _ns(["ip", "rule", "del", "fwmark", "1", "lookup", "100"], check=False)
        _ns(["ip", "-6", "route", "flush", "table", "100"], check=False)
        _ns(["ip", "route", "flush", "table", "100"], check=False)
        _sudo(["ip", "netns", "del", NS], check=False)
        _sudo(["ip", "link", "del", HOST_VETH], check=False)
        _sudo(["ip", "addr", "del", DEST_V6 + "/128", "dev", "lo"], check=False)
        _sudo(["ip", "addr", "del", DEST_V4 + "/32", "dev", "lo"], check=False)

    def setup_net(self):
        self.cleanup_net()
        _sudo(["ip", "netns", "add", NS])
        _sudo(["ip", "link", "add", HOST_VETH, "type", "veth", "peer", "name", NS_VETH])
        _sudo(["ip", "link", "set", NS_VETH, "netns", NS])
        _sudo(["ip", "link", "set", HOST_VETH, "up"])
        _sudo(["ip", "-6", "addr", "add", HOST_V6 + "/64", "dev", HOST_VETH, "nodad"])
        _sudo(["ip", "addr", "add", HOST_V4 + "/24", "dev", HOST_VETH])
        _sudo(["ip", "addr", "add", DEST_V6 + "/128", "dev", "lo", "nodad"])
        _sudo(["ip", "addr", "add", DEST_V4 + "/32", "dev", "lo"])
        _ns(["ip", "link", "set", "lo", "up"])
        _ns(["ip", "link", "set", NS_VETH, "up"])
        _ns(["ip", "-6", "addr", "add", NS_V6 + "/64", "dev", NS_VETH, "nodad"])
        _ns(["ip", "addr", "add", NS_V4 + "/24", "dev", NS_VETH])
        _ns(["ip", "-6", "route", "add", DEST_V6 + "/128", "via", HOST_V6])
        _ns(["ip", "route", "add", DEST_V4 + "/32", "via", HOST_V4])

    def install_redirect(self):
        _ns(["ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", DEST_V6,
             "--dport", str(TCP_V6_PORT), "-j", "REDIRECT", "--to-ports", str(NAT_PORT)])
        _ns(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", DEST_V4,
             "--dport", str(TCP_V4_PORT), "-j", "REDIRECT", "--to-ports", str(NAT_PORT)])

    def _ip6tables_tproxy_works(self):
        probe = _ns(
            ["ip6tables", "-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "-j", "TPROXY",
             "--on-port", "1", "--tproxy-mark", "0x1"],
            check=False)
        if probe.returncode == 0:
            _ns(["ip6tables", "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-j", "TPROXY",
                 "--on-port", "1", "--tproxy-mark", "0x1"], check=False)
            return True
        return False

    def install_tproxy_ip6tables(self):
        _ns(["ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100"])
        _ns(["ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100"])
        _ns(["ip", "rule", "add", "fwmark", "1", "lookup", "100"])
        _ns(["ip", "route", "add", "local", "default", "dev", "lo", "table", "100"])
        for proto, dest, dport in (
            ("tcp", DEST_V6, TCP_V6_PORT),
            ("udp", DEST_V6, UDP_V6_PORT),
        ):
            _ns(["ip6tables", "-t", "mangle", "-A", "OUTPUT", "-p", proto, "-d", dest,
                 "--dport", str(dport), "-j", "MARK", "--set-mark", "1"])
            _ns(["ip6tables", "-t", "mangle", "-A", "PREROUTING", "-i", "lo", "-p", proto, "-d", dest,
                 "--dport", str(dport), "-j", "TPROXY", "--on-port", str(NAT_PORT), "--tproxy-mark", "0x1"])
        _ns(["iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "-d", DEST_V4,
             "--dport", str(UDP_V4_PORT), "-j", "MARK", "--set-mark", "1"])
        _ns(["iptables", "-t", "mangle", "-A", "PREROUTING", "-i", "lo", "-p", "udp", "-d", DEST_V4,
             "--dport", str(UDP_V4_PORT), "-j", "TPROXY", "--on-port", str(NAT_PORT), "--tproxy-mark", "0x1"])

    def install_tproxy_nft(self):
        if _which("nft") is None:
            raise RuntimeError("nft is not installed and ip6tables has no TPROXY target")
        script = """
add table ip6 tpnat
add chain ip6 tpnat output { type route hook output priority mangle; }
add chain ip6 tpnat prerouting { type filter hook prerouting priority mangle; }
add rule ip6 tpnat output meta l4proto tcp ip6 daddr %s tcp dport %d meta mark set 1
add rule ip6 tpnat output meta l4proto udp ip6 daddr %s udp dport %d meta mark set 1
add rule ip6 tpnat prerouting iifname "lo" meta l4proto tcp ip6 daddr %s tcp dport %d tproxy to :%d meta mark set 1 accept
add rule ip6 tpnat prerouting iifname "lo" meta l4proto udp ip6 daddr %s udp dport %d tproxy to :%d meta mark set 1 accept
add table ip tpnat
add chain ip tpnat output { type route hook output priority mangle; }
add chain ip tpnat prerouting { type filter hook prerouting priority mangle; }
add rule ip tpnat output meta l4proto udp ip daddr %s udp dport %d meta mark set 1
add rule ip tpnat prerouting iifname "lo" meta l4proto udp ip daddr %s udp dport %d tproxy to :%d meta mark set 1 accept
""" % (DEST_V6, TCP_V6_PORT, DEST_V6, UDP_V6_PORT,
       DEST_V6, TCP_V6_PORT, NAT_PORT, DEST_V6, UDP_V6_PORT, NAT_PORT,
       DEST_V4, UDP_V4_PORT, DEST_V4, UDP_V4_PORT, NAT_PORT)
        nft_path = "/tmp/tp6nat.nft"
        with open(nft_path, "w", encoding="utf-8") as handle:
            handle.write(script)
        _ns(["nft", "-f", nft_path])
        _ns(["ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100"])
        _ns(["ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", "100"])
        _ns(["ip", "rule", "add", "fwmark", "1", "lookup", "100"])
        _ns(["ip", "route", "add", "local", "default", "dev", "lo", "table", "100"])

    def install_tproxy(self):
        if self._ip6tables_tproxy_works():
            self.install_tproxy_ip6tables()
            self.tproxy_backend = "ip6tables"
            return
        self.install_tproxy_nft()
        self.tproxy_backend = "nft"

    def start_content(self):
        with open(self.content_path, "w", encoding="utf-8") as handle:
            handle.write(CONTENT_SCRIPT)
        with open(self.probe_path, "w", encoding="utf-8") as handle:
            handle.write(PROBE_SCRIPT)
        proc = self.start([sys.executable, self.content_path], self.content_path + ".log", netns=False)
        if not self.wait_log(proc.log_path, "content-ready", timeout=4):
            raise RuntimeError("content server did not start: %s" % self.read_log(proc.log_path)[-400:])
        if not self.wait_tcp(DEST_V6, TCP_V6_PORT):
            raise RuntimeError("content server is not accepting %s:%d" % (DEST_V6, TCP_V6_PORT))
        if not self.wait_tcp(DEST_V4, TCP_V4_PORT):
            raise RuntimeError("content server is not accepting %s:%d" % (DEST_V4, TCP_V4_PORT))

    def start_server(self):
        proc = self.start(
            [self.binary, "-c", os.path.join(CONFIG_DIR, "ipv6_nat_server.json")], self.server_log)
        if not self.wait_log(self.server_log, "service (server) started", timeout=6):
            raise RuntimeError("trojan server did not start: %s" % self.read_log(self.server_log)[-500:])
        return proc

    def start_nat(self, config_name):
        self.nat_log = os.path.join(CONFIG_DIR, config_name + ".output")
        proc = self.start(
            [self.binary, "-c", os.path.join(CONFIG_DIR, config_name)], self.nat_log, netns=True)
        if not self.wait_log(self.nat_log, "service (nat) started", timeout=6):
            detail = self.read_log(self.nat_log)[-800:]
            self.stop(proc)
            raise RuntimeError("trojan nat did not start: %s" % detail)
        if "IPV6_TRANSPARENT failed" in self.read_log(self.nat_log):
            raise RuntimeError("IPV6_TRANSPARENT was rejected: %s" % self.read_log(self.nat_log)[-800:])
        return proc

    def probe(self, *args):
        proc = _ns([sys.executable, self.probe_path] + list(args), check=False, timeout=12)
        return proc.returncode, proc.stdout or "", proc.stderr or ""


def _fail(reason, extra):
    if extra:
        reason = "%s | %s" % (reason, " ".join(extra.split()))
    return "FAIL", reason[:800]


def _assert_http(harness, host, port, body, nat_token, server_token, server_offset):
    code, out, err = harness.probe("http", host, str(port))
    nat_log = harness.read_log(harness.nat_log)
    server_log = harness.read_log(harness.server_log, server_offset)
    if code != 0 or body.decode() not in out:
        return _fail(
            "HTTP probe rc=%s missing %s stderr=%s stdout=%r" % (code, body, err[-200:], out[-200:]),
            nat_log[-500:] + server_log[-300:])
    if nat_token not in nat_log:
        return _fail("nat log missing %s" % nat_token, nat_log[-600:])
    if server_token not in server_log:
        return _fail("server log missing %s" % server_token, server_log[-600:])
    return "PASS", nat_token


def _assert_udp(harness, host, port, payload, nat_token, server_token, server_offset):
    code, out, err = harness.probe("udp", host, str(port), payload.decode())
    nat_log = harness.read_log(harness.nat_log)
    server_log = harness.read_log(harness.server_log, server_offset)
    if code != 0 or payload.decode() not in out:
        return _fail(
            "UDP probe rc=%s stderr=%s stdout=%r" % (code, err[-200:], out[-200:]),
            nat_log[-500:] + server_log[-300:])
    if nat_token not in nat_log:
        return _fail("nat log missing %s" % nat_token, nat_log[-600:])
    if server_token not in server_log:
        return _fail("server log missing %s" % server_token, server_log[-600:])
    if "::ffff:%s" % host in nat_log and ":" not in host:
        return _fail("v4-mapped form was forwarded", nat_log[-600:])
    return "PASS", nat_token


def run_cases(binary, enabled):
    if not enabled:
        return _skip_all(
            "opt-in. Pass --ipv6-nat. Needs sudo -n, ip, and ip6tables. "
            "TPROXY also needs the ip6tables TPROXY target or nft.")
    reason = environment_skip_reason()
    if reason:
        return _skip_all(reason)

    harness = Harness(binary)
    results = []
    try:
        _write_configs()
        harness.setup_net()
        harness.start_content()
        harness.start_server()
        nat = harness.start_nat("ipv6_nat_redirect.json")
        harness.install_redirect()

        offset = harness.log_size(harness.server_log)
        status, detail = _assert_http(
            harness, DEST_V6, TCP_V6_PORT, BODY_V6,
            "original destination [%s]:%d" % (DEST_V6, TCP_V6_PORT),
            "requested connection to [%s]:%d atyp 4" % (DEST_V6, TCP_V6_PORT),
            offset)
        results.append(("nat_ipv6_redirect_tcp", status, detail))

        offset = harness.log_size(harness.server_log)
        status, detail = _assert_http(
            harness, DEST_V4, TCP_V4_PORT, BODY_V4,
            "original destination %s:%d" % (DEST_V4, TCP_V4_PORT),
            "requested connection to %s:%d atyp 1" % (DEST_V4, TCP_V4_PORT),
            offset)
        nat_log = harness.read_log(harness.nat_log)
        if status == "PASS" and ("forwarding to [::ffff:%s]" % DEST_V4) in nat_log:
            status, detail = "FAIL", "v4-mapped original destination was not unwrapped"
        results.append(("nat_ipv6_redirect_v4mapped", status, detail))

        harness.stop(nat)
        _ns(["ip6tables", "-t", "nat", "-F"], check=False)
        _ns(["iptables", "-t", "nat", "-F"], check=False)

        try:
            harness.install_tproxy()
        except Exception as exc:
            skip = "TPROXY rules are unavailable (%s)" % exc
            for case_id in CASE_IDS[2:]:
                results.append((case_id, "SKIP", skip))
            return _fill(results)

        nat = harness.start_nat("ipv6_nat_tproxy.json")
        backend = harness.tproxy_backend

        offset = harness.log_size(harness.server_log)
        status, detail = _assert_http(
            harness, DEST_V6, TCP_V6_PORT, BODY_V6,
            "original destination [%s]:%d" % (DEST_V6, TCP_V6_PORT),
            "requested connection to [%s]:%d atyp 4" % (DEST_V6, TCP_V6_PORT),
            offset)
        if status == "PASS":
            detail = "%s via %s" % (detail, backend)
        results.append(("nat_ipv6_tproxy_tcp", status, detail))

        offset = harness.log_size(harness.server_log)
        status, detail = _assert_udp(
            harness, DEST_V6, UDP_V6_PORT, UDP_V6_PAYLOAD,
            "[udp] original destination [%s]:%d" % (DEST_V6, UDP_V6_PORT),
            "requested UDP associate to [%s]:%d atyp 4" % (DEST_V6, UDP_V6_PORT),
            offset)
        if status == "PASS":
            detail = "%s via %s" % (detail, backend)
        results.append(("nat_ipv6_tproxy_udp", status, detail))

        offset = harness.log_size(harness.server_log)
        status, detail = _assert_udp(
            harness, DEST_V4, UDP_V4_PORT, UDP_V4_PAYLOAD,
            "[udp] original destination %s:%d" % (DEST_V4, UDP_V4_PORT),
            "requested UDP associate to %s:%d atyp 1" % (DEST_V4, UDP_V4_PORT),
            offset)
        if status == "PASS":
            detail = "%s via %s" % (detail, backend)
        results.append(("nat_ipv6_tproxy_udp_v4mapped", status, detail))
        return _fill(results)
    except Exception as exc:
        done = {row[0] for row in results}
        for case_id in CASE_IDS:
            if case_id not in done:
                results.append((case_id, "FAIL", "harness: %s" % exc))
        return results
    finally:
        harness.stop_all()
        harness.cleanup_net()


def _fill(results):
    done = {row[0] for row in results}
    for case_id in CASE_IDS:
        if case_id not in done:
            results.append((case_id, "FAIL", "case did not run"))
    order = {case_id: index for index, case_id in enumerate(CASE_IDS)}
    results.sort(key=lambda row: order.get(row[0], 99))
    return results
