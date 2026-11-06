# The Trojan Protocol

We will now show how a trojan server will react to a **valid Trojan Protocol** and **other protocols** (possibly `HTTPS` or any other probes).

## Valid Trojan Protocol

When a trojan client connects to a server, it first performs a **real** `TLS` handshake. If the handshake succeeds, all subsequent traffic will be protected by `TLS`; otherwise, the server will close the connection immediately as any `HTTPS` server would. (Trojan now also supports nginx-like response to plain HTTP requests.) Then the client sends the following structure:

```
+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+

where Trojan Request is a SOCKS5-like request:

+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+

where:

    o  CMD
        o  CONNECT X'01'
        o  UDP ASSOCIATE X'03'
        o  CONNECT_PADDED X'05'
    o  ATYP address type of following address
        o  IP V4 address: X'01'
        o  DOMAINNAME: X'03'
        o  IP V6 address: X'04'
    o  DST.ADDR desired destination address
    o  DST.PORT desired destination port in network octet order
```

More information on `SOCKS5` requests can be found [here](https://tools.ietf.org/html/rfc1928).

If the connection is a `CONNECT_PADDED`, the request header above is unchanged except for command X'05'. The payload in each direction starts with frames:

```
+------+--------+----------+
| Type | Length | Payload  |
+------+--------+----------+
|  1   |   2    | Variable |
+------+--------+----------+
```

`Length` is the payload length in network octet order. DATA (type 0) carries application bytes; PAD (type 1) carries random bytes that the receiver discards. Frame payloads must not exceed 1447 bytes. END (type 2) must have zero length and ends framing in that direction only: all following bytes are raw application data, not frames. Unknown types, invalid lengths and a stream ending with incomplete framing are errors. A framed direction must send END before a normal end of stream.

Each direction has independent limits: `ssl.padding_bytes` defaults to 16384 real DATA bytes (excluding headers and padding), and `ssl.padding_flushes` defaults to 8 flushes, including a request-prefix-only flush. The first limit reached puts END inside the final padded flush. A byte budget of 0 ends framing immediately; a flush cap of 0 disables only that cap. Padded flushes use uniformly random sizes from 900 through 1450 bytes without adding delay; an empty-input END and subsequent raw writes are exempt. The first client flush includes the unframed Trojan request header before the frames. These are write sizes, not guaranteed TLS record or network packet sizes.

Both ends must be upgraded to benefit from padding. With `ssl.padding` enabled (the default), a client remembers capability per server for the process lifetime and can retry once using legacy CONNECT X'01' against an old server, before receiving application data. The retry replays at most 64 KiB of pre-response application data held in memory; exceeding that cap disables retry for that session. Pipeline sessions do not support padding. CONNECT X'01' and UDP ASSOCIATE X'03' keep their existing wire formats. See [Config](config) for padding settings.

If the connection is a `UDP ASSOCIATE`, then each `UDP` packet has the following format:

```
+------+----------+----------+--------+---------+----------+
| ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
+------+----------+----------+--------+---------+----------+
|  1   | Variable |    2     |   2    | X'0D0A' | Variable |
+------+----------+----------+--------+---------+----------+
```

When the server receives the first data packet, it checks if the hashed password is correct and the Trojan Request is valid. If not, the protocol is considered "other protocols" (see next section). Note that the first packet will have payload appended. This avoids length pattern detection and may reduce the number of packets to be sent.

If the request is valid, the trojan server connects to the endpoint indicated by the `DST.ADDR` and `DST.PORT` field and opens a direct tunnel between the endpoint and trojan client.

(Trojan client is simply a Trojan Protocol-`SOCKS5` converter. There is no detail worth illustrating.)

## Other Protocols

Because typically a trojan server is to be assumed to be an `HTTPS` server, the listening socket is always a `TLS` socket. After performing `TLS` handshake, if the trojan server decides that the traffic is "other protocols", it opens a tunnel between a preset endpoint (by default it is `127.0.0.1:80`, the local `HTTP` server) to the client so the preset endpoint takes the control of the decrypted `TLS` traffic.

## Anti-detection

### Active Detection

After a successful `TLS` handshake, connections without the correct structure and password are redirected to a preset endpoint (by default `HTTP`). Before the handshake, recognized plain HTTP requests receive a built-in nginx-style `400 Bad Request` response, configurable through `ssl.plain_http_server` and `ssl.plain_http_response`; other non-TLS first records are closed silently. TCP and QUIC server handshakes have a 60-second timeout by default (`ssl.handshake_timeout`). TCP rejects offered `ALPN` lists with no supported protocol using `no_application_protocol`; QUIC accepts only `h3` or the configured `quic.alpn_token`. Malformed UDP probes do not trigger Stateless Reset, while eligible unknown-version Initial datagrams of at least 1200 bytes receive Version Negotiation. Valid-looking short-header packets for unknown connections can still receive Stateless Reset. These behaviors resemble nginx but do not imply equivalence with every nginx build.

### Passive Detection

Because the traffic is protected by `TLS` (it is users' responsibility to use a valid certificate), if you are visiting an `HTTP` site, the traffic looks the same as `HTTPS` (there is only one `RTT` after `TLS` handshake); if you are not visiting an `HTTP` site, then the traffic looks the same as `HTTPS` kept alive or `WebSocket`. Because of this, trojan can also bypass ISP `QoS` limitations.

Padded CONNECT reduces early application-write size patterns by using uniformly random flush sizes within the limits above; later traffic is raw. It does not make all packet sizes uniform or conceal traffic timing. The `chrome` client fingerprint also starts QUIC Initial packet numbers at 1 and uses a Chrome-like Initial flight layout; packet-shape comparisons require capture evidence, not just configuration.

For more information, go to [Issue #14](https://github.com/trojan-gfw/trojan/issues/14).

[Homepage](.) | [Prev Page](overview) | [Next Page](config)
