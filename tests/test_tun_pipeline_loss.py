#!/usr/bin/env python3
"""Regression test: client_tun + pipeline must not stall after a UDP flood on a lossy link.

Bug: UDP datagrams read from the TUN device had no backpressure. A flood piled up (hundreds of MB) in the
pipeline's shared send queue; TCP sessions on the same pipelines waited behind it (curl rc 28, failed GETs),
and every UDP session that was destroyed with data still queued re-armed its GC timer from the send handlers
in a tight cancel/wait loop (millions of "Operation canceled" log lines).

Setup (needs root, `ip` with netns, `tc` with netem, /dev/net/tun):
    ns tpl-cli  --veth, 40 ms + 0.5% loss each direction--  ns tpl-srv
    tpl-cli: trojan client_tun (pipeline_num 10), routes 10.77.0.0/24 into tun0
    tpl-srv: trojan server, HTTP target on 10.77.0.1:80, UDP sink on 10.77.0.1:9
Drive: 3 UDP floods (new source port = new TUN UDP session) through the TUN, then rounds of 30 parallel TCP GETs
(until <= 3 fail, at most 100 s) and a timed download. Signature of the stall: GETs still failing after 100 s, or a
0-byte download, or >10000 "Operation canceled" lines in the client log.

Usage: test_tun_pipeline_loss.py [path/to/trojan]
Binary lookup order: argv[1], $TUN_LOSS_BINARY, $S5_BINARY, build/trojan in the repo root.
Prints exactly one PASS/FAIL/SKIP line last; exit 0 on PASS/SKIP, 1 on FAIL.
Not root (or not Linux): always SKIP, also under CI, so a plain `for t in tests/test_*.py` loop run as a normal user
stays green. Once running as root, a missing prerequisite (binary, `tc`/netem, netns, /dev/net/tun) SKIPs locally but
FAILs under CI (TF_BUILD or CI set).
"""
import concurrent.futures
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI, SRV = "tpl-cli", "tpl-srv"
CLI_IP, SRV_IP, TARGET_IP = "10.76.0.1", "10.76.0.2", "10.77.0.1"
BUDGET_S = 170
RECOVER_S = 100  # after the floods TCP must be healthy again within this long


def in_ci():
    return bool(os.environ.get("TF_BUILD") or os.environ.get("CI"))


def finish(status, msg):
    print("%s test_tun_pipeline_loss: %s" % (status, msg), flush=True)
    sys.exit(0 if status in ("PASS", "SKIP") else 1)


def unavailable(why):
    finish("FAIL" if in_ci() else "SKIP", "cannot run (%s)%s" % (why, "; failing because CI is set" if in_ci() else ""))


def sh(cmd, check=True, **kw):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)
    if check and r.returncode != 0:
        raise RuntimeError("%s -> rc=%d %s" % (cmd, r.returncode, (r.stderr or r.stdout).strip()))
    return r


def find_binary():
    cands = [sys.argv[1]] if len(sys.argv) > 1 else [os.environ.get("TUN_LOSS_BINARY", ""), os.environ.get("S5_BINARY", ""),
                                                      os.path.join(ROOT, "build", "trojan")]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def require_root():
    # Checked first and independent of CI: the current Azure Linux job runs every tests/test_*.py as a normal user.
    if sys.platform != "linux" or os.geteuid() != 0:
        finish("SKIP", "needs root (netns, tc netem, /dev/net/tun)")


def preflight():
    for tool in ("ip", "tc", "openssl"):
        if not shutil.which(tool):
            unavailable("%s not found" % tool)
    if not os.path.exists("/dev/net/tun"):
        unavailable("/dev/net/tun missing")
    try:
        sh("ip netns add tpl-probe && ip netns del tpl-probe")
        r = sh("ip link add tplprobe0 type veth peer name tplprobe1 && tc qdisc add dev tplprobe0 root netem delay 1ms loss 1%",
               check=False)
        sh("ip link del tplprobe0 2>/dev/null", check=False)
        if r.returncode != 0:
            unavailable("veth/netem unavailable: %s" % r.stderr.strip())
    except RuntimeError as e:
        unavailable("netns unavailable: %s" % e)


def ns(name, cmd):
    return "ip netns exec %s sh -c %s" % (name, shlex.quote(cmd))


def setup(tmp):
    cleanup()
    sh("ip netns add %s && ip netns add %s" % (CLI, SRV))
    sh("ip link add tplc type veth peer name tpls")
    sh("ip link set tplc netns %s && ip link set tpls netns %s" % (CLI, SRV))
    for n, dev, ip in ((CLI, "tplc", CLI_IP), (SRV, "tpls", SRV_IP)):
        sh(ns(n, "ip addr add %s/24 dev %s" % (ip, dev)))
        sh(ns(n, "ip link set %s up && ip link set lo up" % dev))
        sh(ns(n, "ethtool -K %s tso off gso off gro off" % dev), check=False)
        # 40 ms + 0.5% loss per direction (80 ms RTT, ~1% round-trip loss)
        sh(ns(n, "tc qdisc add dev %s root netem limit 10000 delay 40ms loss 0.5%%" % dev))
    sh(ns(SRV, "ip addr add %s/32 dev lo" % TARGET_IP))

    sh("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=tpl.local "
       "-keyout %s/k.pem -out %s/c.pem" % (tmp, tmp))
    pw = os.urandom(8).hex()
    ssl_client = {"verify": False, "verify_hostname": False, "sni": "tpl.local", "fingerprint": "none",
                  "alpn": ["h2", "http/1.1"], "reuse_session": False, "session_ticket": False}
    tcp = {"prefer_ipv4": True, "no_delay": True, "keep_alive": True, "reuse_port": False, "fast_open": False}
    pipeline = {"pipeline_num": 10}
    server = {"run_type": "server", "local_addr": "0.0.0.0", "local_port": 443, "remote_addr": "127.0.0.1",
              "remote_port": 80, "password": [pw], "log_level": 1, "tcp": tcp, "experimental": pipeline,
              "quic": {"enabled": False},
              "ssl": {"cert": tmp + "/c.pem", "key": tmp + "/k.pem", "key_password": "", "alpn": ["http/1.1"],
                      "reuse_session": True, "session_ticket": False, "curves": "X25519:P-256:P-384"}}
    client = {"run_type": "client_tun", "local_addr": "127.0.0.1", "local_port": 1080, "remote_addr": SRV_IP,
              "remote_port": 443, "password": [pw], "log_level": 1, "udp_timeout": 5, "ssl": ssl_client, "tcp": tcp,
              "experimental": pipeline, "quic": {"enabled": False},
              "tun": {"tun_name": "tun0", "net_ip": "10.0.0.2", "net_mask": "255.255.255.0", "mtu": 1500,
                      "redirect_local": False},
              "dns": {"enabled": False}, "route": {"enabled": True, "proxy_type": 0}}
    for name, cfg in (("server", server), ("client", client)):
        with open("%s/%s.json" % (tmp, name), "w") as fh:
            json.dump(cfg, fh)


def cleanup():
    for n in (CLI, SRV):
        sh("ip netns pids %s 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del %s 2>/dev/null" % (n, n), check=False)
    sh("ip link del tplc 2>/dev/null", check=False)


def spawn(name, cmd, log):
    fh = open(log, "wb")
    return subprocess.Popen(ns(name, cmd), shell=True, stdout=fh, stderr=subprocess.STDOUT, preexec_fn=os.setsid)


def wait_for(cond, what, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.1)
    raise RuntimeError("timeout waiting for " + what)


TARGET_PY = r'''
import socket, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/small":
            body = b"x" * 1024
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        else:  # /big: endless stream, the client stops reading
            self.send_response(200); self.end_headers()
            chunk = b"y" * 65536
            try:
                while True:
                    self.wfile.write(chunk)
            except OSError:
                pass
def udp_sink():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("%(ip)s", 9))
    while True:
        s.recv(65535)
threading.Thread(target=udp_sink, daemon=True).start()
ThreadingHTTPServer(("%(ip)s", 80), H).serve_forever()
''' % {"ip": TARGET_IP}

FLOOD_PY = r'''
import socket, sys, time
dur = float(sys.argv[1]); ip = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.1", 0))
pkt = b"u" * 1200
end = time.time() + dur
n = 0
while time.time() < end:
    for _ in range(200):
        try:
            s.sendto(pkt, (ip, 9))
        except OSError:
            pass
        n += 1
print(n)
'''

GET_PY = r'''
import json, sys, time, urllib.request
mode = sys.argv[1]; ip = sys.argv[2]
t0 = time.time()
try:
    if mode == "small":
        ok = len(urllib.request.urlopen("http://%s/small" % ip, timeout=float(sys.argv[3])).read()) == 1024
        print(json.dumps({"ok": ok, "s": time.time() - t0}))
    else:  # download for N seconds, report bytes
        r = urllib.request.urlopen("http://%s/big" % ip, timeout=float(sys.argv[3]))
        n = 0; end = t0 + float(sys.argv[4])
        while time.time() < end:
            b = r.read(65536)
            if not b: break
            n += len(b)
        print(json.dumps({"bytes": n}))
except Exception as e:
    print(json.dumps({"ok": False, "bytes": 0, "err": str(e)[:100]}))
'''


def cli_py(script, *args):
    return subprocess.run(ns(CLI, "python3 -c %s %s" % (shlex.quote(script), " ".join(map(str, args)))), shell=True,
                          capture_output=True, text=True, timeout=120)


def main():
    t_start = time.time()
    require_root()
    binary = find_binary()
    if binary is None:
        if in_ci():
            finish("FAIL", "trojan binary not found (argument, $TUN_LOSS_BINARY, $S5_BINARY or build/trojan) and CI is set")
        finish("SKIP", "trojan binary not found (argument, $TUN_LOSS_BINARY, $S5_BINARY or build/trojan)")
    preflight()

    tmp = tempfile.mkdtemp(prefix="tpl-")
    procs = []
    verdict = None
    try:
        setup(tmp)
        procs.append(spawn(SRV, "python3 -c %s" % shlex.quote(TARGET_PY), tmp + "/target.log"))
        procs.append(spawn(SRV, "%s -c %s/server.json -l %s/server.log" % (binary, tmp, tmp), "/dev/null"))
        wait_for(lambda: "started at" in open(tmp + "/server.log", errors="replace").read() if os.path.exists(tmp + "/server.log") else False,
                 "server start")
        procs.append(spawn(CLI, "%s -c %s/client.json -l %s/client.log" % (binary, tmp, tmp), "/dev/null"))
        wait_for(lambda: sh(ns(CLI, "ip link show tun0"), check=False).returncode == 0, "tun0")
        sh(ns(CLI, "ip addr add 10.0.0.1/24 dev tun0 && ip link set tun0 up mtu 1500 && ip route add 10.77.0.0/24 dev tun0"))

        # sanity: the tunnel carries a TCP request before any flood (retry: 1% round-trip loss)
        ok0 = False
        for _ in range(5):
            r = cli_py(GET_PY, "small", TARGET_IP, 10)
            if '"ok": true' in r.stdout:
                ok0 = True
                break
        if not ok0:
            finish("FAIL", "tunnel does not work at all before the flood (setup problem); client log tail: %s" %
                   open(tmp + "/client.log", errors="replace").read()[-300:].replace("\n", " | "))

        # 3 UDP floods, each a new TUN UDP session; ~1 Gbit/s offered against a link that carries a few Mbit/s
        for _ in range(int(os.environ.get("TUN_LOSS_FLOODS", "3"))):
            cli_py(FLOOD_PY, 4, TARGET_IP)
            time.sleep(1)

        # TCP behind the flood: rounds of 30 parallel small GETs until <= 3 fail. The fixed binary has a bounded UDP
        # backlog that drains within RECOVER_S; the broken one keeps hundreds of MB queued (and a log storm) and never does.
        def one(_):
            return json.loads(cli_py(GET_PY, "small", TARGET_IP, 6).stdout.strip().splitlines()[-1])
        t_flood = time.time()
        failed, rounds = 30, 0
        while True:
            rounds += 1
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                res = list(ex.map(one, range(30)))
            failed = sum(1 for r in res if not r.get("ok"))
            if failed <= 3 or time.time() - t_flood > RECOVER_S:
                break
        recovered_s = time.time() - t_flood
        dl = json.loads(cli_py(GET_PY, "big", TARGET_IP, 15, 8).stdout.strip().splitlines()[-1])

        canceled = 0
        with open(tmp + "/client.log", errors="replace") as fh:
            for line in fh:
                canceled += "Operation canceled" in line
        reasons = []
        if failed > 3:
            reasons.append("%d/30 GETs still failing %ds after the floods (%d rounds)" % (failed, recovered_s, rounds))
        if dl.get("bytes", 0) == 0:
            reasons.append("download got 0 bytes (%s)" % dl.get("err", ""))
        if canceled > 10000:
            reasons.append("%d 'Operation canceled' log lines" % canceled)
        detail = "failed_gets=%d/30 recovered_after=%ds download_bytes=%d canceled_lines=%d elapsed=%ds" % (
            failed, recovered_s, dl.get("bytes", 0), canceled, time.time() - t_start)
        verdict = ("FAIL", "stall signature: %s (%s)" % ("; ".join(reasons), detail)) if reasons else ("PASS", detail)
        if time.time() - t_start > BUDGET_S:
            verdict = ("FAIL", "test too slow (%s)" % detail)
    except Exception as e:  # noqa: BLE001
        verdict = ("FAIL", "harness error: %s" % e)
    finally:
        for p in procs:
            try:
                os.killpg(p.pid, 9)
            except OSError:
                pass
        cleanup()
        if verdict and verdict[0] == "FAIL" and os.environ.get("TUN_LOSS_KEEP_LOGS"):
            print("logs kept in " + tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    finish(*verdict)


if __name__ == "__main__":
    main()
