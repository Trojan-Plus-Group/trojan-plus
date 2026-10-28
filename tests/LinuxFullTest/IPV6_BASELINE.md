# IPv6 LinuxFullTest baseline

This file records the IPv6 pass/fail matrix for `tests/LinuxFullTest`.
Core TCP and UDP-over-TCP paths (server, client, forward) now set `IPV6_V6ONLY`, encode address literals with ATYP 1/4, return the real SOCKS bind address, and log IPv6 endpoints as `[addr]:port`. QUIC, NAT/TPROXY, and TUN behaviour are unchanged. QUIC tests were not run.

The default IPv4 invocation is unchanged. CI (`azure-pipelines.yml`, `build_and_test.sh`) does not pass `-6`.

## How to run

From `tests/LinuxFullTest/`, with IPv6 loopback enabled (`::1` present, `net.ipv6.conf.all.disable_ipv6=0`):

```bash
# IPv4 suite used for the IPv4 column (client, pipeline, forward, fallback).
python3 -u fulltest_main.py /path/to/trojan -g -n -f

# IPv6 suite. NAT and TUN are skipped. Exit status follows the in-scope cases.
python3 -u fulltest_main.py /path/to/trojan -6

# Also execute the expected-fail NAT and TUN cases. Their failures do not change the exit status.
python3 -u fulltest_main.py /path/to/trojan -6 --ipv6-include-expected-fail

# Also run the IPv4 SOCKS hostname reference (not part of the default -n run).
python3 -u fulltest_main.py /path/to/trojan -6 --ipv6-include-ipv4-reference
```

`-6` can be combined with `-n` / `-f` / `-t` / `-d` / `-q`. Those existing stages run first, exactly as before, and the IPv6 suite runs after them.

What `-6` configures, generated at runtime from the existing JSON (not committed):

| Role | Address |
| :--- | :--- |
| Trojan server `local_addr` | `::` |
| Trojan client `remote_addr` | `::1` |
| SOCKS / forward listener | `::1` |
| Pure IPv6 content server (HTTP and UDP) | `::` port 18080 with `IPV6_V6ONLY=1`. `127.0.0.1` cannot connect, so a silent IPv4 fallback fails the case |
| Dual-stack content server | `::` port 18081 with `IPV6_V6ONLY=0`, used only by the dual-stack case and the IPv4 hostname reference |
| Dual-stack Trojan server | server on `::`, client and SOCKS on `127.0.0.1`, target `127.0.0.1:18081` |
| Hostname | `trojanplus-ipv6.test` is inserted into `/etc/hosts` as `::1` only. The original file bytes are restored with an atomic rename on normal exit, `SIGINT`, `SIGTERM`, and `atexit` |

Client-mode cases speak SOCKS5 themselves. PySocks rejects an IPv6 destination (`socks.py` `connect()` raises `PySocks doesn't support IPv6`), so it cannot drive ATYP 4 or an IPv6 proxy address.

The IPv6 content set is 2 files of 1500 bytes. The IPv4 `-g -n -f` run is the stock suite (50 files, TCP and UDP, RSS cooldown). NAT and TUN need root (`sudo -n`) when `--ipv6-include-expected-fail` is set.

## Result matrix

Host: IPv6 loopback up, `net.ipv6.bindv6only=0`. Binary built from this tree with the default CMake options (QUIC and mimalloc on) using gcc, because this VM's default `c++` is Clang 18 and wolfssl's `-s` flag fails under `-Werror`.

| Case | IPv4 | IPv6 |
| :--- | :--- | :--- |
| Client TCP SOCKS, IP literal | PASS. `-n` client stage. PySocks sends ATYP 1 for `127.0.0.1`. | PASS. SOCKS listener `::1`, request ATYP 4, SOCKS bind ATYP 4 `[::1]:10620`, server log `atyp 4` and `resolved to ::1`, endpoints logged as `[::1]:port`. |
| Client TCP SOCKS, hostname | PASS. Reference case `--ipv6-include-ipv4-reference`, ATYP 3 `trojanplus-ipv4.test` -> `127.0.0.1`. Not part of default `-n`. | PASS. ATYP 3 `trojanplus-ipv6.test` -> `::1` only. Server log `atyp 3`. SOCKS bind ATYP 4 `[::1]:10620`. `tcp.prefer_ipv4` stayed true. |
| Client UDP associate | PASS. Same `-n` client stage (UDP GET and POST). | PASS. UDP ASSOCIATE request and reply ATYP 4, relay `[::1]:<ephemeral>`, 1500-byte GET matched. Server log `atyp 4`. |
| Client pipeline TCP | PASS. `-n` pipeline client stage. | PASS. ATYP 4 through pipeline plus the balance server on `::`. |
| Client pipeline UDP | PASS. Same `-n` pipeline client stage. | PASS. ATYP 4 UDP ASSOCIATE through pipeline. |
| Forward TCP | PASS. `-n` forward stage. | PASS. Direct TCP to `[::1]:10620`, target `::1:18080`. Server log `atyp 4` and not `atyp 1` or `atyp 3`. |
| Forward UDP | PASS. Same `-n` forward stage. | PASS. Direct UDP to `[::1]:10620`. Server log `atyp 4` for the literal target. |
| Forward pipeline TCP | PASS. `-n` forward pipeline stage. | PASS. |
| Forward pipeline UDP | PASS. Same stage. | PASS. |
| Fallback (TLS, non-Trojan HTTP) | PASS. `-f`, `Fallback Success` from `127.0.0.1`. | PASS. Server `::`, mock HTTP on `::1`, request `https://[::1]:14650/`. |
| IPv4 client to dual-stack server | The default server listens on `0.0.0.0` and that path PASSed inside `-n`. There is no separate dual-stack IPv4 case. | PASS. Server bound to `::` with `tcp.ipv6_only` omitted (default false). The log contains `IPV6_V6ONLY=0`. Client `remote_addr` `127.0.0.1`, SOCKS request ATYP 1 to `127.0.0.1:18081`, server log `atyp 1`, SOCKS bind reply ATYP 1 `127.0.0.1:10620`. |
| `tcp.ipv6_only` true | No separate IPv4 case. Listeners on IPv4 addresses do not set the option. | PASS. Server on `::` with `tcp.ipv6_only` true logs `IPV6_V6ONLY=1`, rejects `127.0.0.1`, and still proxies `::1` (request ATYP 4, SOCKS bind `[::1]:10620`). |
| `tcp.prefer_ipv4` true, dual-stack name | Existing `-n` configs set `prefer_ipv4` true. Targets in that run are IPv4 literals, so the flag is not what selects the family. | PASS. `trojanplus-dual.test` has both `127.0.0.1` and `::1`. Server log contains `resolved to 127.0.0.1` and `atyp 3`. |
| `tcp.prefer_ipv4` omitted | Code default is false: the resolver's first result. | PASS. Same dual-stack name. On this host the first `getaddrinfo` result was `::1`, and the server log said `resolved to ::1`. |
| Scoped IPv6 literal | Not covered by `-n` (targets are IPv4). | PASS. Forward target `fe80::1%lo` and `fe80::1%nosuchiface0` are ATYP 3 on the wire. The server log keeps the original text, including the zone. |
| IPv4-mapped literal | Not a separate `-n` case. | PASS. Forward target `::ffff:127.0.0.1` is ATYP 1 `127.0.0.1` and the transfer succeeds. A dual-stack SOCKS listener answers an IPv4 client with bind ATYP 1 `127.0.0.1:10620`. |
| NAT | No case in `LinuxFullTest`. | SKIP on default `-6`. Opt-in returns EXPECTED-FAIL only when the log contains `getsockopt error -1` and the probe reads 0 bytes. Any other outcome fails the suite. |
| TUN (`client_tun`) | Not run here. Existing `-t` installs a `tun0` default route; CI runs that on a privileged agent. | SKIP on default `-6`. Opt-in returns EXPECTED-FAIL only when the log contains `fatal: Invalid argument`. Any other outcome (including a missing `/dev/net/tun`) fails the suite. |

IPv4 command: `python3 -u fulltest_main.py ../../build/trojan -g -n -f` exited 0 (`ALL SUCC`). Stages: client, client pipeline, forward, forward pipeline, fallback.

IPv6 command: `python3 -u fulltest_main.py ../../build/trojan -6` exited 0 on two consecutive runs. Every in-scope case passed, including `ipv6_only_listener`, `prefer_ipv4_dual_hostname` (`resolved to 127.0.0.1`), `prefer_ipv4_default_dual_hostname` (`resolved to ::1`), `forward_zoned_link_local` (`ATYP 3 fe80::1%lo`), `forward_zoned_unknown_iface` (`ATYP 3 fe80::1%nosuchiface0`), `forward_v4_mapped` (`ATYP 1 127.0.0.1`), and `socks_v4_mapped_bind`. `nat_ipv6` and `tun_ipv6` were `SKIP`.

Opt-in command: `python3 -u fulltest_main.py ../../build/trojan -6 --ipv6-include-expected-fail` exited 0. NAT and TUN returned EXPECTED-FAIL after matching `getsockopt error -1` plus a 0-byte probe, and `fatal: Invalid argument`. A different outcome fails the suite. The same in-scope cases passed.

## Failure notes

No in-scope IPv6 case failed on this host. The two failures are the deferred NAT and TUN cases.

### NAT (`nat_ipv6`)

Observed with `run_type=nat`, `local_addr=::1`, `tcp.use_tproxy=false`, and a plain TCP connect (no ip6tables redirect):

```
[utils.cpp:836] recv_target_endpoint + getsockopt error -1
[clientsession.cpp:834] session_id: 0 disconnected, 0 bytes received, 0 bytes sent
```

`recv_target_endpoint` (`src/core/utils.cpp:831`) calls `getsockopt(SOL_IPV6, IP6T_SO_ORIGINAL_DST)` and, on failure, `getsockopt(SOL_IP, SO_ORIGINAL_DST)`. Both fail on a normal accept, so it returns port 0 (`utils.cpp:839`). `NATSession::start` then destroys the session (`src/session/natsession.cpp:47`). The probe read 0 bytes. The listener itself did come up: `trojan plus service (nat) started at [::1]:20621` (`service.cpp`). IPv6 endpoints in the core logs use `[addr]:port`.

An earlier probe with `tcp.use_tproxy=true` and no TPROXY rule is not the committed case (it self-connects). It logged:

```
[service.cpp:80] [nat] [tcp] to process TPROXY tcp message
[utils.cpp:829] recv_target_endpoint + getsockname error 0
[natsession.cpp:51] forwarding to [::1]:20621 via [::1]:4650
```

`getsockname` on the accepted socket is the listen address, so the session forwards to itself and accepts again. The committed test leaves `use_tproxy` false to avoid that loop.

Not hit by this TCP probe. In the NAT UDP path, `UDPForwardSession::start_udp` still passes a flag that is true for IPv6 into `prepare_nat_udp_target_bind`, and that function selects `SOL_IPV6` when the flag is true (`src/core/utils.cpp`). The two inversions cancel, so the socket level is unchanged. `utils.cpp` transparent-socket options (`IP_TRANSPARENT` at the IPv4/IPv6 `setsockopt` sites) are left for the NAT step. The call site names the flag for what it does today and does not change the value.

### TUN (`tun_ipv6`)

Observed with `run_type=client_tun`, `tun.net_ip=fd00::2`, `tun.net_mask=ffff:ffff:ffff:ffff::`, route tables loaded, and `/dev/net/tun` opened:

```
[tundev.cpp:115] [tun] /dev/net/tun ifr.ifr_mtu: 4097
[main.cpp:245] fatal: Invalid argument [system:22]
```

`TUNDev`'s constructor parses both addresses with `make_address_v4` (`src/tun/tundev.cpp:128` and `:130`). `fd00::2` is not an IPv4 address, so Boost.Asio throws `EINVAL` and `main_impl` exits at `src/main.cpp:245`.

The process never reached packet handling. The same class is explicitly IPv4-only (`src/tun/tundev.h:76`). IPv6 input is discarded (`src/tun/tundev.cpp:279`), lwIP endpoints are built with `make_address_v4` (`src/tun/lwip_tcp_client.cpp:41`), the built-in DNS socket is `make_address_v4("0.0.0.0")` (`src/tun/dnsserver.cpp:58`), and the route matcher is `IPv4Matcher` (`src/core/utils.h:416`). This run did not exercise those lines; they are the next failures once address parsing no longer aborts startup.

## Notes on cases that passed

TCP CONNECT replies carry the accepted socket's local endpoint. An IPv6 SOCKS listener replies ATYP 4 `[::1]:10620`. An IPv4 SOCKS listener replies ATYP 1 `127.0.0.1:10620`. UDP ASSOCIATE replies ATYP 4 with the real `[::1]:<ephemeral>` relay. `0.0.0.0:0` fails these cases.

`tcp.prefer_ipv4` defaults to false and is unchanged for callers that omit it: outbound TCP (`connect_out_socket`) and UDP associate resolution keep the resolver's first address, and an IPv6-only name such as `trojanplus-ipv6.test` still resolves to `::1` when the flag is true because there is no A record. The dual-stack name `trojanplus-dual.test` is the coverage for the flag. `true` must log `resolved to 127.0.0.1`. The omitted key must log the first `getaddrinfo` result.

Listening sockets on IPv6 set `IPV6_V6ONLY` from `tcp.ipv6_only` (default false) and log `listening socket IPV6_V6ONLY=0` or `=1`. The dual-stack case requires `=0` and a successful `127.0.0.1` connection. The `ipv6_only` case requires `=1` and a refused `127.0.0.1` connection. The pure-IPv6 content server is separate and sets `IPV6_V6ONLY=1`, so those cases cannot succeed by connecting to `127.0.0.1`. Literal SOCKS requests are rejected unless the ATYP byte on the wire is 4.

`TrojanRequest::generate` and the UDP packet address encoder write ATYP 1 for IPv4 literals and for IPv4-mapped IPv6 literals (`::ffff:127.0.0.1`), ATYP 4 for unscoped IPv6 literals, and ATYP 3 for domains. A scoped literal (`fe80::1%lo`, or any text containing `%`, or a non-zero scope id) stays ATYP 3 with the original text so the zone is not dropped. `SOCKS5Address::generate` keeps the port and the family of an unspecified address (`::` is ATYP 4, `0.0.0.0` is ATYP 1). Forward cases for `::1` require the server log to contain `atyp 4` and not `atyp 1` or `atyp 3`. Client literal cases require `atyp 4`. Hostname cases require `atyp 3`. Parsed IPv6 text is the compressed form from `address_v6::to_string()` (`::1`). The uncompressed form fails the pure-IPv6 log check. Endpoint logs use `[addr]:port`.
