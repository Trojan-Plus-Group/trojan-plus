#!/usr/bin/env python3
"""Local DNS / IPv6 route regressions for -6; reuse the TUN netns, with no public resolvers."""
import json
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

# Bind the fake upstream to both loopbacks; use an extra veth address for proxied DNS from the Trojan server.
FAKE_DNS = r'''
import json, selectors, socket, struct, sys
port = int(sys.argv[1]) if len(sys.argv) > 1 else 53
sel = selectors.DefaultSelector()
addresses = [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]
if len(sys.argv) > 2:
    addresses.append((socket.AF_INET6, sys.argv[2]))
for family, address in addresses:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port))
    sel.register(sock, selectors.EVENT_READ)
print('ready', flush=True)
while True:
    for key, _ in sel.select():
        data, peer = key.fileobj.recvfrom(4096)
        end = 12
        labels = []
        while data[end]:
            size = data[end]
            labels.append(data[end+1:end+1+size].decode('ascii'))
            end += size + 1
        end += 1
        qtype, qclass = struct.unpack('!HH', data[end:end+4])
        end += 4
        if qtype not in (1, 28) or qclass != 1:
            continue
        name = '.'.join(labels)
        addr = '192.0.2.42' if qtype == 1 else '2001:db8::42'
        if name in ('gfw-route.test', 'direct-route.test') and qtype == 28:
            addr = sys.argv[3]
        packed = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, addr)
        answer = (data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
                  + data[12:end] + b'\xc0\x0c'
                  + struct.pack('!HHIH', qtype, 1, 120, len(packed)) + packed)
        if name.startswith(('nodata.', 'nxdomain.', 'nosoa.')):
            soa = not name.startswith('nosoa.')
            flags = 0x8183 if name.startswith('nxdomain.') else 0x8180
            answer = data[:2] + struct.pack('!HHHHH', flags, 1, 0, int(soa), 0) + data[12:end]
            if soa:
                # SOA TTL 120 / MINIMUM 60: negative cache lifetime must use 60.
                rdata = b'\0\0' + struct.pack('!IIIII', 1, 60, 60, 60, 60)
                answer += b'\xc0\x0c' + struct.pack('!HHIH', 6, 1, 120, len(rdata)) + rdata
        print(json.dumps([name, qtype, key.fileobj.family]), flush=True)
        if name.endswith('-route.test'):
            print('route upstream ' + name + ' ' + key.fileobj.getsockname()[0], flush=True)
        key.fileobj.sendto(answer, peer)
'''

DNS_PROBE = r'''
import socket, struct, sys
host, port, name, qtype, ident = sys.argv[1:6]
qtype, ident = int(qtype), int(ident)
question = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
question += struct.pack('!HH', qtype, 1)
query = struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 0) + question
with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(4)
    sock.sendto(query, (host, int(port)))
    data, peer = sock.recvfrom(4096)
assert data[:2] == query[:2], 'transaction ID not rewritten'
assert data[12:12+len(question)] == question, 'question type contaminated'
answer = data[12+len(question):]
if name.startswith(('nodata.', 'nxdomain.', 'nosoa.')):
    soa = not name.startswith('nosoa.')
    flags = 0x8183 if name.startswith('nxdomain.') else 0x8180
    assert struct.unpack('!HHHHH', data[2:12]) == (flags, 1, 0, int(soa), 0), data.hex()
    if soa:
        assert answer[:2] == b'\xc0\x0c'
        kind, cls, ttl, length = struct.unpack('!HHIH', answer[2:12])
        assert (kind, cls, length) == (6, 1, 22) and 0 < ttl <= 120
        assert answer[12:] == b'\0\0' + struct.pack('!IIIII', 1, 60, 60, 60, 60)
    else:
        assert not answer, data.hex()
    print('negative dns ok')
    sys.exit(0)
assert struct.unpack('!HHHHH', data[2:12]) == (0x8180, 1, 1, 0, 0), data.hex()
expected = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6,
                            sys.argv[6] if len(sys.argv) > 6 else
                            ('192.0.2.42' if qtype == 1 else '2001:db8::42'))
assert answer[:2] == b'\xc0\x0c'
kind, cls, ttl, length = struct.unpack('!HHIH', answer[2:12])
assert (kind, cls, length) == (qtype, 1, len(expected)) and 0 < ttl <= 120
assert answer[12:] == expected, 'wrong address / A-AAAA cache collision'
print('dns ok')
'''

ROUTE_PROBE = r'''
import socket, sys
host, port, source = sys.argv[1:]
with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
    sock.settimeout(10)
    sock.bind((source, 0))
    sock.connect((host, int(port)))
    sock.sendall(b'GET / HTTP/1.1\r\nHost: tun6\r\nConnection: close\r\n\r\n')
    data = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
head, separator, body = data.partition(b'\r\n\r\n')
assert separator and head.split(b'\r\n')[0] == b'HTTP/1.1 200 OK', data
assert body == b'TUN6TCP_OK', 'route TCP content mismatch: %r' % body
print('route tcp ok')
'''


def exercise(h: Any, binary: str, ns: str, tun_name: str,
             netns: Callable[..., Any], base: dict) -> str:
    """Caller has stopped the old TUN client; run each config separately and check production logs."""
    root = Path(h.CONFIG_DIR)
    for name, content in (("ipv6_fake_dns.py", FAKE_DNS),
                          ("ipv6_dns_probe.py", DNS_PROBE),
                          ("ipv6_route_probe.py", ROUTE_PROBE)):
        (root / name).write_text(content, encoding="utf-8")
    fake_log = open(root / "ipv6_fake_dns.output", "w+", encoding="utf-8")
    fake = None
    client = None
    log = None
    try:
        fake = subprocess.Popen(h.root_args([
            "ip", "netns", "exec", ns, sys.executable, str(root / "ipv6_fake_dns.py"),
            "53", h.TUN_VETH_CLI, h.TUN_DST]),
            stdout=fake_log, stderr=fake_log, start_new_session=True)
        if not h.wait_until(lambda: "ready" in Path(fake_log.name).read_text(), fake, timeout=4):
            raise RuntimeError("fake DNS did not bind both loopbacks")

        def start(config: dict, label: str) -> None:
            nonlocal client, log
            h.save_json("ipv6_dns_route.json", config)
            log = open(root / ("ipv6_" + label + ".output"), "w+", encoding="utf-8")
            client = subprocess.Popen(h.root_args([
                "ip", "netns", "exec", ns, binary, "-c", str(root / "ipv6_dns_route.json")]),
                stdout=log, stderr=log, cwd=h.TEST_ROOT, start_new_session=True)
            if not h.wait_until(lambda: netns("ip", "link", "show", tun_name,
                                             check=False)[0].returncode == 0, client, timeout=6):
                raise RuntimeError(label + ": TUN did not appear")
            netns("ip", "link", "set", tun_name, "up")
            netns("ip", "addr", "add", "10.66.0.1/24", "dev", tun_name)
            netns("ip", "-6", "addr", "add", h.TUN_HOST + "/64", "dev", tun_name, "nodad")
            netns("ip", "-6", "route", "replace", h.TUN_DST + "/128", "dev", tun_name)

        def stop() -> str:
            nonlocal client, log
            h._stop_process_group(client)
            client = None
            path = log.name
            log.close()
            log = None
            return Path(path).read_text(errors="replace")

        # Check startup rejects hostnames in up_dns_server and up_gfw_dns_server
        for key, host_val in (("up_dns_server", "dns.google"), ("up_gfw_dns_server", "localhost")):
            bad_cfg = json.loads(json.dumps(base))
            bad_cfg["dns"].update(enabled=True, **{key: [host_val]})
            h.save_json("bad_dns.json", bad_cfg)
            proc = subprocess.run(
                h.root_args(["ip", "netns", "exec", ns, binary, "-c", str(root / "bad_dns.json")]),
                capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                raise RuntimeError("trojan did not reject hostname in %s: %s" % (key, host_val))
            err = proc.stdout + proc.stderr
            expected_msg = "[dns] upstream must be an IPv4 or IPv6 literal: " + host_val
            if expected_msg not in err:
                raise RuntimeError("trojan rejection message mismatch for %s: %r" % (key, err))

        config = json.loads(json.dumps(base))
        config["tun"].update(net_ip="10.66.0.2", net_mask="255.255.255.0")
        empty = root / "ipv6_dns_empty.txt"
        empty.write_text("", encoding="utf-8")
        gfwlist = root / "ipv6_dns_gfwlist.txt"
        gfwlist.write_text("unused.invalid\n", encoding="utf-8")
        config["dns"].update(enabled=True, enable_cached=True, port=15353,
                              up_dns_server=["::1"], up_gfw_dns_server=["::1"], gfwlist=str(gfwlist))
        start(config, "dns_local")
        # Same name across A/AAAA, socket/TUN and both families. Cache hits must
        # not send another upstream datagram; every response gets fresh ID.
        for index, host in enumerate(("127.0.0.1", "::1", "10.66.0.2", h.TUN_LWIP)):
            name = "isolation%d.test" % index
            for offset, qtype in enumerate((1, 28, 28, 1)):
                result, detail = netns(sys.executable, str(root / "ipv6_dns_probe.py"), host, "15353",
                                       name, str(qtype), str(1000 + index * 10 + offset), timeout=6, check=False)
                if result.returncode:
                    log.flush()
                    raise RuntimeError(detail + " DNS client log: " + Path(log.name).read_text(errors="replace")[-12000:])
        # B: SOA-backed NODATA / NXDOMAIN cache once; no-SOA retries upstream.
        for kind in ("nodata", "nxdomain", "nosoa"):
            for qtype in (1, 28):
                for offset in range(2):
                    netns(sys.executable, str(root / "ipv6_dns_probe.py"), "::1", "15353",
                          kind + ".cache.test", str(qtype), str(2000 + qtype * 2 + offset), timeout=6)
        stop()

        # Test dns.enable_cached = false: positive/negative caching disabled, all queries hit upstream
        cfg_nocache = json.loads(json.dumps(base))
        cfg_nocache["tun"].update(net_ip="10.66.0.2", net_mask="255.255.255.0")
        cfg_nocache["dns"].update(enabled=True, enable_cached=False, port=15353,
                                  up_dns_server=["::1"], up_gfw_dns_server=["::1"], gfwlist=str(gfwlist))
        start(cfg_nocache, "dns_nocache")
        for qtype in (1, 28):
            for offset in range(2):
                netns(sys.executable, str(root / "ipv6_dns_probe.py"), "::1", "15353",
                      "nocache.test", str(qtype), str(5000 + qtype * 2 + offset), timeout=6)
        stop()

        rows = [json.loads(line) for line in Path(fake_log.name).read_text().splitlines()
                if line.startswith("[")]
        expected = sorted(
            [("isolation%d.test" % index, qtype, socket.AF_INET6)
             for index in range(4) for qtype in (1, 28)] +
            [(kind + ".cache.test", qtype, socket.AF_INET6)
             for kind in ("nodata", "nxdomain", "nosoa") for qtype in (1, 28)
             for _ in range(2 if kind == "nosoa" else 1)] +
            [("nocache.test", qtype, socket.AF_INET6)
             for qtype in (1, 28) for _ in range(2)])
        if sorted(tuple(row) for row in rows) != expected:
            raise RuntimeError("DNS upstream count/family mismatch: %r" % rows)

        config["dns"]["enabled"] = False
        lists = {}
        for key in ("cn_mainland_ips_file", "white_ips", "proxy_ips"):
            path = root / ("ipv6_" + key + ".txt")
            path.write_text("192.0.2.0/24\n" + h.TUN_DST + "/128\n", encoding="utf-8")
            lists[key] = str(path)
        # Proxy override wins over white; mainland inclusion/exclusion and
        # absent IPv6 files retain compatibility with IPv4-only configs.
        miss = root / "ipv6_route_miss.txt"
        miss.write_text("192.0.2.0/24\n2001:db8::/32\n", encoding="utf-8")
        legacy = root / "ipv6_route_legacy.txt"
        legacy.write_text("192.0.2.0/24\n", encoding="utf-8")
        profiles = [
            ("white", 0, {"white_ips": lists["white_ips"]}, False),
            ("proxy_override", 0, dict(lists), True),
            ("proxy", 5, {"proxy_ips": lists["proxy_ips"],
                           "cn_mainland_ips_file": str(miss)}, True),
            ("bypass_cn", 2, {"cn_mainland_ips_file": lists["cn_mainland_ips_file"]}, False),
            ("bypass_cn_miss", 2, {"cn_mainland_ips_file": str(miss)}, True),
            ("bypass_local_and_cn", 3, {"cn_mainland_ips_file": lists["cn_mainland_ips_file"]}, False),
            ("bypass_local_and_cn_miss", 3, {"cn_mainland_ips_file": str(miss)}, True),
            ("bypass_local_and_cn_no_v6", 3, {"cn_mainland_ips_file": str(legacy)}, True),
            ("only_cn", 5, {"cn_mainland_ips_file": lists["cn_mainland_ips_file"]}, True),
            ("only_cn_miss", 5, {"cn_mainland_ips_file": str(miss)}, False),
            ("legacy_ipv4_only", 5, {key: str(legacy) for key in lists}, True),
        ]
        # Only the probe's explicit TUN source enters TUN. Direct outbound
        # sockets select the veth source and reach the same real content server
        # through the main table, avoiding recursive capture by TUN.
        netns("ip", "-6", "rule", "add", "priority", "106",
              "from", h.TUN_HOST + "/128", "lookup", "106")
        # A: independent clients avoid merged IP indexes from a prior proxied
        # domain. Both AAAA answers reach the existing real TCP content server.
        gfwlist.write_text("gfw-route.test\n", encoding="utf-8")
        config["dns"].update(enabled=True, up_gfw_dns_server=[h.TUN_VETH_CLI])
        config["route"].update(enabled=True, proxy_type=4,
                              **{key: str(empty) for key in lists})
        for name, proxy in (("gfw-route.test", True), ("direct-route.test", False)):
            start(config, "dns_route_" + name)
            netns("ip", "-6", "route", "replace", h.TUN_DST + "/128",
                  "dev", tun_name, "table", "106")
            netns("ip", "-6", "route", "replace", h.TUN_DST + "/128",
                  "via", h.TUN_VETH_SRV, "src", h.TUN_VETH_CLI)
            for offset in range(2):
                netns(sys.executable, str(root / "ipv6_dns_probe.py"), h.TUN_LWIP, "15353",
                      name, "28", str(3000 + offset), h.TUN_DST, timeout=6)
            netns(sys.executable, str(root / "ipv6_route_probe.py"), h.TUN_DST,
                  str(h.TUN_TCP_PORT), h.TUN_HOST, timeout=15)
            text = stop()
            wanted = "proxy connect: " if proxy else "directly connect: "
            unwanted = "directly connect: " if proxy else "proxy connect: "
            if wanted + h.TUN_DST not in text or unwanted + h.TUN_DST in text:
                raise RuntimeError("DNS route %s classification mismatch: %s" % (name, h.excerpt(text)))
        rows = [json.loads(line) for line in Path(fake_log.name).read_text().splitlines()
                if line.startswith("[")]
        route_rows = [row for row in rows if row[0].endswith("-route.test")]
        if sorted(tuple(row) for row in route_rows) != sorted(
                (name, 28, socket.AF_INET6) for name in ("gfw-route.test", "direct-route.test")):
            raise RuntimeError("DNS route upstream/cache mismatch: %r" % route_rows)
        upstreams = [line for line in Path(fake_log.name).read_text().splitlines()
                     if line.startswith("route upstream ")]
        if sorted(upstreams) != sorted([
                "route upstream gfw-route.test " + h.TUN_VETH_CLI,
                "route upstream direct-route.test ::1"]):
            raise RuntimeError("DNS route upstream selection mismatch: %r" % upstreams)
        config["dns"]["enabled"] = False
        for label, mode, files, proxy in profiles:
            for key in lists:
                config["route"][key] = str(empty)
            config["route"].update(enabled=True, proxy_type=mode, **files)
            start(config, "route_" + label)
            netns("ip", "-6", "route", "replace", h.TUN_DST + "/128",
                  "dev", tun_name, "table", "106")
            netns("ip", "-6", "route", "replace", h.TUN_DST + "/128",
                  "via", h.TUN_VETH_SRV, "src", h.TUN_VETH_CLI)
            probe, probe_text = netns(
                sys.executable, str(root / "ipv6_route_probe.py"), h.TUN_DST,
                str(h.TUN_TCP_PORT), h.TUN_HOST, timeout=15)
            if probe.returncode != 0 or "route tcp ok" not in probe_text:
                raise RuntimeError("route %s TCP transfer failed: %s" % (label, probe_text))
            text = stop()
            if label == "legacy_ipv4_only":
                if "[route] load 1 IPv4 + 0 IPv6 cn_mainland_ips from file" not in text:
                    raise RuntimeError("legacy IPv4-only route file log mismatch: %s" % h.excerpt(text))
            wanted = "proxy connect: " if proxy else "directly connect: "
            unwanted = "directly connect: " if proxy else "proxy connect: "
            if wanted + h.TUN_DST not in text or unwanted + h.TUN_DST in text:
                raise RuntimeError("route %s classification mismatch: %s" % (label, h.excerpt(text)))
        return "local DNS: A/AAAA isolation, NODATA/NXDOMAIN SOA cache, no-SOA retries, enable_cached=false check, dual loopback/TUN; upstream literal validation; gfw AAAA proxy and non-gfw direct TCP; 11 route profiles with TCP content checks"
    finally:
        h._stop_process_group(client)
        if log is not None:
            log.close()
        h._stop_process_group(fake)
        fake_log.close()


def self_check() -> None:
    """Check A/AAAA packets and counts with real dual-loopback fake DNS; no root required."""
    compile(ROUTE_PROBE, "<ipv6-route-probe>", "exec")
    # Same response as the existing TUN TCP server; wrong body must fail.
    for body in (b"TUN6TCP_OK", b"wrong"):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
            listener.bind(("::1", 0))
            listener.listen(1)
            listener.settimeout(6)

            def serve() -> None:
                with listener.accept()[0] as conn:
                    conn.settimeout(4)
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                result = subprocess.run([
                    sys.executable, "-c", ROUTE_PROBE, "::1",
                    str(listener.getsockname()[1]), "::1"],
                    capture_output=True, text=True, timeout=6)
                assert (result.returncode == 0) == (body == b"TUN6TCP_OK"), result.stderr
            finally:
                thread.join(timeout=7)
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
        probe.bind(("::1", 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+", dir=Path(__file__).parent) as log:
        proc = subprocess.Popen([sys.executable, "-u", "-c", FAKE_DNS, str(port)],
                                stdout=subprocess.PIPE, stderr=log, text=True)
        try:
            assert proc.stdout.readline().strip() == "ready"
            for index, host in enumerate(("127.0.0.1", "::1")):
                for name in ("selfcheck.test", "nodata.test", "nxdomain.test", "nosoa.test"):
                    for qtype in (1, 28):
                        subprocess.run([sys.executable, "-c", DNS_PROBE, host, str(port),
                                        name, str(qtype), str(100 + index)],
                                       check=True, timeout=6, stdout=subprocess.PIPE)
                        row = json.loads(proc.stdout.readline())
                        assert row == [name, qtype,
                                       socket.AF_INET if index == 0 else socket.AF_INET6]
        finally:
            proc.terminate()
            proc.wait(timeout=3)
            proc.stdout.close()


if __name__ == "__main__":
    self_check()
    print("IPv6 fake DNS dual-loopback A/AAAA checks passed")
