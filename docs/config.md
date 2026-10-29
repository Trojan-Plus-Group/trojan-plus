# Config

In this page, we will look at the config file of trojan. Trojan uses [`JSON`](https://en.wikipedia.org/wiki/JSON) as the format of the config.

**Note: all "\\" in the paths under Windows MUST be replaced with "/".**

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
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:AES256-SHA",
        "cipher_tls13": "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": true,
        "curves": "X25519"
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
    - `cert`: if `verify` is set to `true`, the same certificate used by the server or a collection of `CA` certificates could be provided. If you leave this field blank, wolfSSL will try to look for a system `CA` store and will be likely to fail. Certificates can be retrieved with [this simple Python script](https://github.com/trojan-gfw/trojan/blob/master/scripts/getcert.py).
    - `cipher`: a cipher list to send and use
    - `cipher_tls13`: a cipher list for TLS 1.3 to use
    - `sni`: the Server Name Indication field in the `SSL` handshake. If left blank, it will be set to `remote_addr`.
    - `alpn`: a list of `ALPN` protocols to send
    - `reuse_session`: whether to reuse `SSL` session
    - `session_ticket`: whether to use session tickets for session resumption
    - `curves`: `ECC` curves to send and use
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
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:AES256-SHA",
        "cipher_tls13": "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": true,
        "curves": "X25519"
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
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:AES256-SHA",
        "cipher_tls13": "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": true,
        "curves": "X25519"
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
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
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
        "curves": "",
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
    - `reuse_session`: whether to reuse `SSL` session
    - `session_ticket`: whether to use session tickets for session resumption
    - `session_timeout`: if `reuse_session` is set to `true`, specify `SSL` session timeout
    - `plain_http_response`: respond to plain http request with this file (raw TCP)
    - `curves`: `ECC` curves to use
    - `dhparam`: if left blank, default (RFC 3526) dhparam will be used, otherwise the specified dhparam file will be used
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

lwIP accepts TCP for any IPv6 destination (`pretend TCP`) and writes the replies with `output_ip6`. The destination passed to the Trojan client is ATYP 4, or ATYP 1 when the destination is an IPv4-mapped IPv6 address. Non-DNS IPv6 UDP is forwarded the same way, and the reply written back to the TUN is an IPv6 UDP packet with a checksum. IPv6 route-table matching and the built-in DNS server (AAAA, DNS over IPv6) are not part of this path: every non-mapped IPv6 destination is proxied, and DNS interception stays on the IPv4 TUN address.

`redirect_local` still rewrites the proxied destination to `127.0.0.1` for the IPv4 test suite. Leave it false when the Trojan server should connect to the real IPv6 destination.

[Homepage](.) | [Prev Page](protocol) | [Next Page](build)
