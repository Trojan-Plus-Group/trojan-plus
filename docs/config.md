# Config

In this page, we will look at the config file of trojan. Trojan uses [`JSON`](https://en.wikipedia.org/wiki/JSON) as the format of the config.

**Note: all "\\" in the paths under Windows MUST be replaced with "/".**

## Optional live diagnostics

Top-level `log_live_counters` defaults to `false`. When enabled, an event-loop
timer logs `[mem] live objects=... bytes=... sessions=... quic_connections=...
quic_proxy_sessions=...` at INFO every second on Linux, macOS and Windows.
Object/byte totals cover the tp allocator, excluding BoringSSL allocations,
not every allocation made by third-party libraries. QUIC counts are zero when
QUIC is compiled out. No timer is created when disabled. T16 enables this only
in its temporary configs to check fresh post-quiescence snapshots.

## QUIC certificate identity

With `ssl.verify` and `ssl.verify_hostname` enabled, QUIC verifies the certificate
against `ssl.sni`, or `remote_addr` when `ssl.sni` is empty. An IP literal must match an IP SAN. A name mismatch fails the handshake.
Setting `ssl.verify_hostname` to `false` keeps CA chain verification only;
setting `ssl.verify` to `false` disables certificate verification entirely.

## QUIC ALPN

`quic.alpn_token` defaults to `"h3"`. Clients offer this token, including with
`ssl.fingerprint` set to `chrome`; a custom token therefore changes the handshake
fingerprint. Servers prefer the configured token and also accept `h3`, rejecting
unrelated protocols. Set the same custom token on both ends when needed.

## QUIC retry and timing

`quic.retry_connect_timeout_ms` defaults to `1000` milliseconds when omitted.
Set it explicitly to `0` to disable automatic client reconnection. For example:

```json
"quic": {
    "enabled": true,
    "retry_connect_timeout_ms": 1000
}
```

QUIC timestamps and loss deadlines include suspend time on Linux and Android
using `CLOCK_BOOTTIME`. Reactor waits are capped at one second so overdue loss
deadlines are checked within one second after resume. Other platforms use
`std::chrono::steady_clock`, whose suspend behavior is platform-dependent.

## A valid client.json

```json
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "example.com",
    "remote_port": 443,
    "password": [
        "password1"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "fingerprint": "chrome",
        "padding": true,
        "padding_bytes": 16384,
        "padding_flushes": 8,
        "cipher": "",
        "cipher_tls13": "",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": true,
        "curves": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "ipv6_only": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
```

- `run_type`: running trojan as `client`
- `local_addr`: a `SOCKS5` server interface will be bound to the specified interface. Feel free to change this to ``0.0.0.0``, ``::1``, ``::`` or other addresses, if you know what you are doing.
- `local_port`: a `SOCKS5` interface will be bound to this port
- `remote_addr`: server address (hostname)
- `remote_port`: server port
- `password`: password used for verification (only the first password in the array will be used)
- `log_level`: how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.
- `ssl`: `SSL` specific configurations
    - `verify`: whether to verify `SSL` certificate **STRONGLY RECOMMENDED**
    - `verify_hostname`: whether to verify `SSL` hostname (specified in the `sni` field) **STRONGLY RECOMMENDED**
    - `cert`: if `verify` is set to `true`, the same certificate used by the server or a collection of `CA` certificates could be provided. If you leave this field blank, BoringSSL will try to look for a system `CA` store and will be likely to fail. Certificates can be retrieved with [this simple Python script](https://github.com/trojan-gfw/trojan/blob/master/scripts/getcert.py).
    - `padding`: enables the padded CONNECT command for client TCP sessions, including QUIC streams; defaults to `true`. Pipeline sessions retain their existing framing. Unsupported servers are remembered for the process lifetime and retried once with legacy CONNECT. Retry preserves up to 64 KiB of pre-response application data in memory, with no replay file I/O. Larger uploads continue normally but disable retry for that session and log one INFO line; if the server is legacy, that session fails and later sessions use legacy CONNECT.
    - `padding_bytes`: real-data budget per direction before END switches the stream to raw bytes; defaults to `16384`, valid range `0` through `4294967295`. Servers accept padded CONNECT regardless of `padding`; `0` ends their outbound framing immediately. Each framed flush uses a random size from 900 through 1450 bytes without adding delay.
    - `padding_flushes`: maximum padded flushes per direction, including a prefix-only flush; defaults to `8`, valid range `0` through `4294967295`. `0` disables this cap, not the byte budget. Padding ends at whichever limit is reached first, with END inside the final padded flush. Inner TLS handshakes fit within the first few flushes; later traffic stays raw to avoid bandwidth overhead from small writes.
    - `fingerprint`: client TLS handshake profile, `chrome` (default) or `none`; any other value is rejected. `chrome` uses Chrome-like TLS handshake defaults. `none` uses plain BoringSSL defaults for debugging. This affects only the TLS handshake, not browser application behavior (HTTP headers, HTTP/2 settings, JavaScript, or other browser features).
    - `cipher`: a cipher list to send and use; empty by default to preserve the selected fingerprint
    - `cipher_tls13`: a cipher list for TLS 1.3 to use; empty by default to preserve the selected fingerprint
    - `sni`: the Server Name Indication field in the `SSL` handshake. If left blank, it will be set to `remote_addr`.
    - `alpn`: a list of `ALPN` protocols to send
    - `reuse_session`: controls server session reuse. Explicit client reuse is not implemented; a true value on clients is ignored with a warning.
    - `session_ticket`: whether to use session tickets for session resumption
    - `curves`: `ECC` curves to send and use; empty by default to preserve the selected fingerprint. Nonempty `cipher`, `cipher_tls13`, or `curves` overrides the selected defaults and logs one `WARN` per client config load that the fingerprint differs, even when several lists are set.
- `tcp`: `TCP` specific configurations
    - `prefer_ipv4`: whether to connect to the IPv4 address when a domain has both IPv6 and IPv4 addresses. The default is `false`, which keeps the resolver's first result.
    - `ipv6_only`: when `local_addr` is IPv6, set `IPV6_V6ONLY` on the TCP listening socket in client, forward, server, and nat modes, and on the UDP listening socket in forward and nat modes. `false` (default) is dual-stack, so an IPv4 client can connect to a listener bound to `::`. `true` accepts IPv6 only. The option is set explicitly and does not follow the kernel `net.ipv6.bindv6only` sysctl.
    - `no_delay`: whether to disable Nagle's algorithm
    - `keep_alive`: whether to enable TCP Keep Alive
    - `reuse_port`: whether to enable TCP port reuse (kernel support required). **Best Practice**: Enabling `reuse_port` (SO_REUSEPORT) allows multiple Trojan processes to listen on the same port. The Linux kernel (since 3.9) automatically distributes incoming connections across these processes using a 4-tuple hash, ensuring high performance and scalability on multi-core systems without lock contention. It is recommended to use a modern Linux kernel (4.5+ for enhanced balancing) for optimal results.
    - `fast_open`: whether to enable TCP Fast Open (kernel support required)
    - `fast_open_qlen`: the server's limit on the size of the queue of TFO requests that have not yet completed the three-way handshake

## A valid forward.json

This forward config is for port forwarding through a trojan connection. Everything is the same as the client config, except for `target_addr` and `target_port`, which point to the destination endpoint, and `udp_timeout`, which controls how long (in seconds) a UDP session will last in idle.

PROTIP: If you simply want to redirect a raw TCP connection, you can use `iptables` or `socat` to do that. The forward mode is not for this purpose.

```json
{
    "run_type": "forward",
    "local_addr": "127.0.0.1",
    "local_port": 5901,
    "remote_addr": "example.com",
    "remote_port": 443,
    "target_addr": "127.0.0.1",
    "target_port": 5901,
    "password": [
        "password1"
    ],
    "udp_timeout": 60,
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "fingerprint": "chrome",
        "padding": true,
        "padding_bytes": 16384,
        "padding_flushes": 8,
        "cipher": "",
        "cipher_tls13": "",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": true,
        "curves": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "ipv6_only": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
```

## A valid nat.json

The NAT config is for transparent proxy. IPv4 uses `iptables`. IPv6 uses the same `run_type` with `ip6tables` (examples below). A listener on `::` is dual-stack unless `tcp.ipv6_only` is true. An IPv4-mapped original destination (`::ffff:a.b.c.d`) is normalized to IPv4 before it is sent to the server, so the Trojan request uses ATYP 1.

`tcp.use_tproxy` selects the TCP original-destination lookup:

- `false` (default): `REDIRECT`. IPv4 calls `getsockopt(SOL_IP, SO_ORIGINAL_DST)`. IPv6 calls `getsockopt(SOL_IPV6, IP6T_SO_ORIGINAL_DST)`. A dual-stack socket that accepted an IPv4 connection uses `SO_ORIGINAL_DST`.
- `true`: `TPROXY`. The listener sets `IP_TRANSPARENT` (IPv4) or `IPV6_TRANSPARENT` (IPv6). `getsockname` on the accepted socket is the original destination.

UDP always reads the original destination from `recvmsg` ancillary data: `IP_RECVORIGDSTADDR` for IPv4 and `IPV6_RECVORIGDSTADDR` for IPv6. A dual-stack socket sets both. The UDP reply socket binds that original destination and sets the transparent option for its family.

Do not redirect the Trojan server's own address, or the NAT process will loop. A full IPv6 example is [nat-ipv6.json-example](../examples/nat-ipv6.json-example).

```json
{
    "run_type": "nat",
    "local_addr": "127.0.0.1",
    "local_port": 12345,
    "remote_addr": "example.com",
    "remote_port": 443,
    "password": [
        "password1"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "fingerprint": "chrome",
        "padding": true,
        "padding_bytes": 16384,
        "padding_flushes": 8,
        "cipher": "",
        "cipher_tls13": "",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": true,
        "curves": ""
    },
    "tcp": {
        "ipv6_only": false,
        "use_tproxy": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
```

### IPv6 REDIRECT (TCP)

`tcp.use_tproxy` stays false. `local_port` is the port below.

```bash
ip6tables -t nat -A PREROUTING -p tcp -d 2001:db8:1::/64 -j REDIRECT --to-ports 12345
ip6tables -t nat -A OUTPUT -p tcp -d 2001:db8:1::/64 -j REDIRECT --to-ports 12345
```

Match the destinations to proxy, and leave the Trojan server's prefix out of that match. `OUTPUT` covers processes on the same host. `PREROUTING` covers forwarded traffic.

### IPv6 TPROXY (TCP and UDP)

Set `tcp.use_tproxy` to true. The same listening port receives TCP and UDP.

```bash
ip -6 rule add fwmark 1 lookup 100
ip -6 route add local ::/0 dev lo table 100

ip6tables -t mangle -A PREROUTING -p tcp -d 2001:db8:1::/64 -j TPROXY --on-port 12345 --tproxy-mark 0x1
ip6tables -t mangle -A PREROUTING -p udp -d 2001:db8:1::/64 -j TPROXY --on-port 12345 --tproxy-mark 0x1
ip6tables -t mangle -A OUTPUT -p tcp -d 2001:db8:1::/64 -j MARK --set-mark 1
ip6tables -t mangle -A OUTPUT -p udp -d 2001:db8:1::/64 -j MARK --set-mark 1
```

IPv4 keeps the same shape with `iptables`, `ip rule`, and `ip route add local 0.0.0.0/0 dev lo table 100`. On a dual-stack listener (`local_addr` `::`, `tcp.ipv6_only` false) one process handles both families. IPv4 datagrams on that socket arrive with `IP_RECVORIGDSTADDR`.

## A valid server.json

```json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "password1",
        "password2"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/path/to/certificate.crt",
        "key": "/path/to/private.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "alpn_port_override": {
            "h2": 81
        },
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "plain_http_server": "nginx",
        "handshake_timeout": 60,
        "curves": "X25519:P-256:P-384",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "ipv6_only": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
```

- `run_type`: running trojan as `server`
- `local_addr`: trojan server will be bound to the specified interface. Feel free to change this to `::` or other addresses, if you know what you are doing.
- `local_port`: trojan server will be bound to this port
- `remote_addr`: the endpoint address that trojan server will connect to when encountering [other protocols](protocol#other-protocols). **Note**: Trojan will decrypt the incoming SSL traffic and forward the **decrypted plain text** to this address. It is strongly recommended to point this to a local plain text server (e.g., Nginx on port 80).
- `remote_port`: the endpoint port that trojan server will connect when encountering [other protocols](protocol#other-protocols). **Note**: This should be a port that accepts plain text (e.g., port 80), not an SSL-enabled port (e.g., port 443).
- `password`: an array of passwords used for verification
- `log_level`: how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.
- `ssl`: `SSL` specific configurations
    - `cert`: server certificate **STRONGLY RECOMMENDED TO BE SIGNED BY A CA**. It's preferred to use the full chain certificate here instead of the certificate alone.
    - `key`: private key file for encryption
    - `key_password`: password of the private key file
    - `cipher`: a cipher list to use
    - `cipher_tls13`: a cipher list for TLS 1.3 to use
    - `prefer_server_cipher`: whether to prefer server cipher list in a connection
    - `alpn`: a list of `ALPN` protocols to reply
    - `alpn_port_override`: overrides the remote port to the specified value if an `ALPN` is matched. Useful for running NGINX with HTTP/1.1 and HTTP/2 Cleartext on different ports.
    - `reuse_session`: controls server session reuse. Explicit client reuse is not implemented; a true value on clients is ignored with a warning.
    - `session_ticket`: whether to use session tickets for session resumption
    - `session_timeout`: if `reuse_session` is set to `true`, specify `SSL` session timeout
    - `plain_http_response`: raw TCP response file for plain HTTP requests sent to the TLS port. Empty (default) uses the built-in nginx-style `400 Bad Request` response, including the "The plain HTTP request was sent to HTTPS port" HTML page, current GMT `Date`, `Content-Type: text/html`, computed `Content-Length`, and `Connection: close`. A nonempty file overrides the entire response.
    - `plain_http_server`: built-in response `Server` header and HTML footer identity; defaults to `nginx`. Empty string omits both. Control characters are rejected; HTML text is escaped. Set this to match the fallback web server's identity.
    - `padding`: client preference only; servers always accept padded CONNECT (`0x05`) regardless of this value.
    - `padding_bytes`: outbound real-data budget for padded sessions, default `16384`; `0` sends END on the first outbound write and then uses raw bytes. DATA and random PAD frames use a one-byte type and two-byte big-endian length; END has zero length. The target-side connection is unchanged.
    - `padding_flushes`: outbound padded-flush cap, default `8`; `0` leaves only the byte budget. The first limit reached ends padding, with END inside the final padded flush. This covers the first few inner TLS handshake flushes without padding later traffic indefinitely.
    - `handshake_timeout`: maximum TLS handshake duration in seconds for TCP server and QUIC server; defaults to `60`; `0` disables the timeout.
    - `curves`: `ECC` curves to use
    - `dhparam`: ignored. A nonempty value logs one warning at config startup: `ssl.dhparam is ignored: FFDHE is not supported`. ECDHE uses `curves`.
- `tcp`: `TCP` specific configurations
    - `prefer_ipv4`: whether to connect to the IPv4 address when a domain has both IPv6 and IPv4 addresses. The default is `false`, which keeps the resolver's first result, including for TCP outbound connections and UDP associate destinations. Set it to `true` to pick an IPv4 address when one exists.
    - `ipv6_only`: when `local_addr` is IPv6, set `IPV6_V6ONLY` on the TCP listening socket in client, forward, server, and nat modes, and on the UDP listening socket in forward and nat modes. `false` (default) is dual-stack. `true` accepts IPv6 only. The option is set explicitly and does not follow the kernel `net.ipv6.bindv6only` sysctl.
    - `no_delay`: whether to disable Nagle's algorithm
    - `keep_alive`: whether to enable TCP Keep Alive
    - `reuse_port`: whether to enable TCP port reuse (kernel support required). **Best Practice**: Enabling `reuse_port` (SO_REUSEPORT) allows multiple Trojan processes to listen on the same port. The Linux kernel (since 3.9) automatically distributes incoming connections across these processes using a 4-tuple hash, ensuring high performance and scalability on multi-core systems without lock contention. It is recommended to use a modern Linux kernel (4.5+ for enhanced balancing) for optimal results.
    - `fast_open`: whether to enable TCP Fast Open (kernel support required)
    - `fast_open_qlen`: the server's limit on the size of the queue of TFO requests that have not yet completed the three-way handshake

## TUN mode (`client_tun`)

`run_type` `client_tun` reads IP packets from a TUN device and forwards them through the Trojan client. IPv4 behaviour is unchanged: `tun.net_ip` and `tun.net_mask` are the lwIP netif address and mask (for example `10.0.0.2` and `255.255.255.0`).

IPv6 is off unless you set it. Add `tun.net_ipv6` (a unicast IPv6 address without a zone id) and, optionally, `tun.net_ipv6_prefix` (0–128, default 64). An existing config that omits both keeps working and does not install an IPv6 address on the lwIP netif. Putting an IPv6 literal in `tun.net_ip` is also accepted: that address is used as `net_ipv6`, and if `net_mask` is an IPv6 mask its prefix length is used. Do not set `net_ip` to an IPv6 literal and `net_ipv6` at the same time.

On the host, assign the other side of the prefix and route the destinations you want to capture. For `net_ipv6` `fd00::2` and prefix 64:

```bash
ip link set tun0 up
ip -6 addr add fd00::1/64 dev tun0 nodad
ip -6 route add 2001:db8:1::/64 dev tun0
```

### TUN IPv6 route rules

When `route.enabled` is true and `run_type` is `client_tun`, the same three file paths apply. Each file can mix IPv4 and IPv6:

```json
"route": {
  "enabled": true,
  "proxy_type": 2,
  "cn_mainland_ips_file": "china_mainland_ips.txt",
  "white_ips": "white_ips.txt",
  "proxy_ips": "proxy_ips.txt"
}
```

- One address or CIDR per line. Addresses containing a colon go to IPv6Matcher; others retain existing IPv4 parsing and error logging. IPv6 supports `/0` through `/128`, blank lines, surrounding whitespace, and `#` comments. CIDRs have host bits cleared; zone IDs are rejected. Invalid IPv6 lines are skipped with a WARN naming the file and line; read failures also log WARN.
- IPv6 ranges are sorted and overlapping or adjacent ranges merged at load time. Binary-search lookups take `O(log n)`. Load logs report valid IPv4 and IPv6 input lines separately, not merged range counts.
- Priority: `proxy_ips` forces proxying and overrides `white_ips`, which forces direct access. Other addresses follow `proxy_type`: `0` / `1` proxy all; `2` / `3` proxy non-mainland addresses; `5` proxies only mainland addresses. Local bypass remains controlled by the system routing table.
- Checks short-circuit in priority order: a `proxy_ips` match proxies immediately; otherwise a `white_ips` match connects directly. Only `2` / `3` / `5` query the mainland list; only `4` queries DNS GFWList address mappings.
- `4` (GFWList) queries the DNS address mapping for IPv4 / native IPv6 addresses absent from explicit lists. Missing mappings or mappings not marked GFWList connect directly.
- `5` (mainland-only proxy) falls back to proxying native IPv6 addresses absent from explicit lists when the mainland list has no valid IPv6 entries, even if white or proxy lists contain IPv6 entries. Once the mainland list has valid IPv6 entries, only mainland matches are proxied. An empty path, empty file, read failure, or file containing only invalid lines counts as having no valid IPv6 entries.
- IPv4 rules are unchanged. Unified address dispatch unwraps IPv4-mapped IPv6 before checking IPv4 rules. Raw mapped TUN packets remain subject to the drop restrictions below.

Standalone matcher check: `python3 tests/test_ipv6_matcher.py` (requires a C++17 compiler and Boost headers).

lwIP accepts TCP for any native IPv6 destination (`pretend TCP`) and writes the replies with `output_ip6`. The destination passed to the Trojan client is ATYP 4. An IPv6 packet whose source or destination is IPv4-mapped (`::ffff:0:0/96`) is dropped before lwIP; that stack rejects those addresses and would leak the packet buffer. Use a native IPv4 packet for an IPv4 destination. Non-DNS IPv6 UDP is forwarded with the original endpoints, and the reply written back to the TUN is an IPv6 UDP packet with a checksum. UDP may follow a hop-by-hop, routing, or destination-options header. Fragments, AH, and ESP are not reassembled on that path. Native IPv6 uses the route rules above; mainland-only mode falls back to proxy when the mainland list has no valid IPv6 entries. Built-in DNS intercepts UDP requests to `dns.port` on both the TUN IPv4 address and `tun.net_ipv6`, replying in the client's address family; IPv6 UDP checksums reuse the existing helper. A / AAAA caches are isolated by `(name, qtype)`, with TTLs decreasing as entries age. Valid cached A / AAAA records for GFWList domains populate an expiring address index with `O(log n)` route lookups; negative cache entries create no address mappings. NODATA / NXDOMAIN responses are cached only when authority contains SOA, for at most `min(SOA TTL, SOA MINIMUM, 300 seconds)`; responses without SOA are not cached. Socket DNS first tries dual-stack `::`, logging WARN and falling back to IPv4 if IPv6 is unavailable. `dns.up_dns_server` and `dns.up_gfw_dns_server` require IPv4 or IPv6 literals, such as `["::1"]`; hostnames are rejected at startup. The upstream port is fixed at 53. Packets whose length is shorter than the IP header, or longer than `tun.mtu`, are dropped so a wrapped length cannot stall the reader.

`redirect_local` still rewrites the proxied destination to `127.0.0.1` for the IPv4 test suite. Leave it false when the Trojan server should connect to the real IPv6 destination.

[Homepage](.) | [Prev Page](protocol) | [Next Page](build)
