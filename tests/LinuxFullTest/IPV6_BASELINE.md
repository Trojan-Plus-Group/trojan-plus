# IPv6 LinuxFullTest baseline

This file records the first IPv6 pass/fail matrix for `tests/LinuxFullTest`.
Product code under `src/` is unchanged. QUIC tests were not run and were not modified.

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
| Content server (HTTP and UDP) | `::` with `IPV6_V6ONLY=0`, so both `::1` and `127.0.0.1` hit it |
| Dual-stack case | server on `::`, client and SOCKS on `127.0.0.1`, target `127.0.0.1` |
| Hostname | `trojanplus-ipv6.test` is inserted into `/etc/hosts` as `::1` only, then removed |

Client-mode cases speak SOCKS5 themselves. PySocks rejects an IPv6 destination (`socks.py` `connect()` raises `PySocks doesn't support IPv6`), so it cannot drive ATYP 4 or an IPv6 proxy address.

The IPv6 content set is 2 files of 1500 bytes. The IPv4 `-g -n -f` run is the stock suite (50 files, TCP and UDP, RSS cooldown). NAT and TUN need root (`sudo -n`) when `--ipv6-include-expected-fail` is set.

## Result matrix

Host: IPv6 loopback up, `net.ipv6.bindv6only=0`. Binary built from this tree with the default CMake options (QUIC and mimalloc on) using gcc, because this VM's default `c++` is Clang 18 and wolfssl's `-s` flag fails under `-Werror`.

| Case | IPv4 | IPv6 |
| :--- | :--- | :--- |
| Client TCP SOCKS, IP literal | PASS. `-n` client stage. PySocks sends ATYP 1 for `127.0.0.1`. | PASS. SOCKS listener `::1`, ATYP 4 to `::1:18080`, GET and POST matched. |
| Client TCP SOCKS, hostname | PASS. Reference case `--ipv6-include-ipv4-reference`, ATYP 3 `trojanplus-ipv4.test` -> `127.0.0.1`. Not part of default `-n`. | PASS. ATYP 3 `trojanplus-ipv6.test` -> `::1` only. `tcp.prefer_ipv4` stayed true. |
| Client UDP associate | PASS. Same `-n` client stage (UDP GET and POST). | PASS. UDP ASSOCIATE with ATYP 4, 1500-byte GET matched, relay was `::1:<ephemeral>`. |
| Client pipeline TCP | PASS. `-n` pipeline client stage. | PASS. ATYP 4 through pipeline plus the balance server on `::`. |
| Client pipeline UDP | PASS. Same `-n` pipeline client stage. | PASS. ATYP 4 UDP ASSOCIATE through pipeline. |
| Forward TCP | PASS. `-n` forward stage. | PASS. Direct TCP to `[::1]:10620`, target `::1:18080`. |
| Forward UDP | PASS. Same `-n` forward stage. | PASS. Direct UDP to `[::1]:10620`. |
| Forward pipeline TCP | PASS. `-n` forward pipeline stage. | PASS. |
| Forward pipeline UDP | PASS. Same stage. | PASS. |
| Fallback (TLS, non-Trojan HTTP) | PASS. `-f`, `Fallback Success` from `127.0.0.1`. | PASS. Server `::`, mock HTTP on `::1`, request `https://[::1]:14650/`. |
| IPv4 client to dual-stack server | The default server listens on `0.0.0.0` and that path PASSed inside `-n`. There is no separate dual-stack IPv4 case. | PASS. Server bound to `::`, client `remote_addr` `127.0.0.1`, SOCKS ATYP 1 to `127.0.0.1:18080`. |
| NAT | No case in `LinuxFullTest`. | SKIP on default `-6`. With `--ipv6-include-expected-fail`: FAIL. See below. |
| TUN (`client_tun`) | Not run here. Existing `-t` installs a `tun0` default route; CI runs that on a privileged agent. | SKIP on default `-6`. With `--ipv6-include-expected-fail`: FAIL. See below. |

IPv4 command: `python3 -u fulltest_main.py ../../build/trojan -g -n -f` exited 0 (`ALL SUCC`). Stages: client, client pipeline, forward, forward pipeline, fallback.

IPv6 command: `python3 -u fulltest_main.py ../../build/trojan -6` exited 0. Every in-scope case passed. `nat_ipv6` and `tun_ipv6` were `SKIP`.

Opt-in command: `python3 -u fulltest_main.py ../../build/trojan -6 --ipv6-include-expected-fail --ipv6-include-ipv4-reference` exited 0 because NAT/TUN failures are expected and do not affect the exit status. The same in-scope cases passed; NAT and TUN failed as below.

## Failure notes

No in-scope IPv6 case failed on this host. The two failures are the deferred NAT and TUN cases.

### NAT (`nat_ipv6`)

Observed with `run_type=nat`, `local_addr=::1`, `tcp.use_tproxy=false`, and a plain TCP connect (no ip6tables redirect):

```
[utils.cpp:836] recv_target_endpoint + getsockopt error -1
[clientsession.cpp:834] session_id: 0 disconnected, 0 bytes received, 0 bytes sent
```

`recv_target_endpoint` (`src/core/utils.cpp:831`) calls `getsockopt(SOL_IPV6, IP6T_SO_ORIGINAL_DST)` and, on failure, `getsockopt(SOL_IP, SO_ORIGINAL_DST)`. Both fail on a normal accept, so it returns port 0 (`utils.cpp:839`). `NATSession::start` then destroys the session (`src/session/natsession.cpp:47`). The probe read 0 bytes. The listener itself did come up: `trojan plus service (nat) started at ::1:20621` (`service.cpp:220`).

An earlier probe with `tcp.use_tproxy=true` and no TPROXY rule is not the committed case (it self-connects). It logged:

```
[service.cpp:80] [nat] [tcp] to process TPROXY tcp message
[utils.cpp:829] recv_target_endpoint + getsockname error 0
[natsession.cpp:51] forwarding to ::1:20621 via ::1:4650
```

`getsockname` on the accepted socket is the listen address, so the session forwards to itself and accepts again. The committed test leaves `use_tproxy` false to avoid that loop.

Not hit by this TCP probe, but in the NAT UDP path for the later PR: `UDPForwardSession::start_udp` sets `is_ipv4` by comparing the family to `v6()` (`src/session/udpforwardsession.cpp:75`), and `prepare_nat_udp_target_bind` then picks `SOL_IPV6` when `is_ipv4` is true (`src/core/utils.cpp:965`).

### TUN (`tun_ipv6`)

Observed with `run_type=client_tun`, `tun.net_ip=fd00::2`, `tun.net_mask=ffff:ffff:ffff:ffff::`, route tables loaded, and `/dev/net/tun` opened:

```
[tundev.cpp:115] [tun] /dev/net/tun ifr.ifr_mtu: 4097
[main.cpp:245] fatal: Invalid argument [system:22]
```

`TUNDev`'s constructor parses both addresses with `make_address_v4` (`src/tun/tundev.cpp:128` and `:130`). `fd00::2` is not an IPv4 address, so Boost.Asio throws `EINVAL` and `main_impl` exits at `src/main.cpp:245`.

The process never reached packet handling. The same class is explicitly IPv4-only (`src/tun/tundev.h:76`). IPv6 input is discarded (`src/tun/tundev.cpp:279`), lwIP endpoints are built with `make_address_v4` (`src/tun/lwip_tcp_client.cpp:41`), the built-in DNS socket is `make_address_v4("0.0.0.0")` (`src/tun/dnsserver.cpp:58`), and the route matcher is `IPv4Matcher` (`src/core/utils.h:416`). This run did not exercise those lines; they are the next failures once address parsing no longer aborts startup.

## Notes on cases that passed

TCP CONNECT replies were `ATYP 1, 0.0.0.0:0` on every IPv6 and IPv4 SOCKS TCP case. That bytestring is fixed in `src/session/clientsession.cpp:420` (`socks5_request_reply_succ_tcp`). The transfer still completed because the test client does not use BND.ADDR. UDP ASSOCIATE did return the real IPv6 relay (`SOCKS5Address::generate` at `clientsession.cpp:516`).

`tcp.prefer_ipv4` remains true on the generated server configs. The hostname case still reached `::1` because `trojanplus-ipv6.test` has no A record, so the scan in `connect_out_socket` (`src/core/utils.h:450`) keeps the first result.

The dual-stack pass used the kernel default `net.ipv6.bindv6only=0` (confirmed 0 on this host). `Service` binds the resolved `::` endpoint (`src/core/service.cpp:92`) and does not set `IPV6_V6ONLY`. A host with `bindv6only=1` would reject the IPv4 client.

`TrojanRequest::generate` always writes ATYP 3 (`src/proto/trojanrequest.cpp:67`). Forward mode therefore sends the target `::1` as a hostname. The server still connects, because `make_address("::1")` succeeds before any DNS lookup.
