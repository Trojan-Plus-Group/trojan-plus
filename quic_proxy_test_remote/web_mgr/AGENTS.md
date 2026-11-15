# web_mgr (qmgr)

Phone-friendly web console on the test server (CentOS Stream 10, 1 CPU / 1 GB, root) to tell apart why QUIC
(UDP 443) fails on some mobile networks: all UDP 443 dropped (iperf3 UDP on 443 also fails), only QUIC-looking
traffic dropped, a bug in our server, or datagram size. Also captures packets for later analysis.

## Architecture

- `server.js`: Node 22, stdlib only, no build. Exports `createApp({config, runner, clock, logger})`; runs when executed directly.
  - All external commands go through the injected `runner` (`run`, `spawn`, `kill`, `cmdline`), argument arrays only, never a shell.
  - `fake_runner.js`: in-memory runner (ss/ps/run script/iperf3/tcpdump) for tests and `QMGR_FAKE=1` demo mode.
- `public/`: vanilla JS page, relative URLs only (works under `/qmgr/`).
- State: `stateFile` (mode, deadline, tracked PIDs with exact argv), `<state dir>/actions.log` (JSON lines, every state change),
  `control-config.json` / `control.log` (second trojan instance), `captureDir` (pcap ring, `live.log`).
- Modes: `trojan` (normal), `iperf3` (trojan stopped, `iperf3 -s -p 443`), `control` (extra trojan on `controlPort`). One switch at a time (mutex).

## Deploy

1. `dnf install -y nodejs tcpdump iperf3` (node 22).
2. `mkdir -p /opt/qmgr /etc/qmgr && cp -r server.js fake_runner.js public /opt/qmgr/` (fake_runner.js is only loaded when `QMGR_FAKE=1`).
3. `cp config.example.json /etc/qmgr/config.json`, edit paths (`trojanDir`, `trojanLog`, `iface`).
4. `cp deploy/qmgr.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now qmgr`.
5. nginx: `cp deploy/nginx-qmgr.conf /etc/nginx/conf.d/qmgr.conf && nginx -t && systemctl reload nginx`. Open TCP 3443 in the firewall.
6. certbot renew reload: `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh` (executable, runs `systemctl reload nginx`) already exists on the server; certbot runs it after each renewal.
7. Token (first start only): `journalctl -u qmgr | grep token`. Later: `cat /etc/qmgr/token`.

Update: copy `server.js fake_runner.js public` to `/opt/qmgr/`, then `systemctl restart qmgr` (tracked processes survive because of `KillMode=process`).

## Login

Open `https://vpn1.yuchs.com:3443/qmgr/?token=<token>` once. A cookie `qmgr` (HMAC of the token, 30 days) is set and the URL is cleaned.
Rotate: write a new value to `/etc/qmgr/token` (cookies become invalid at once, no restart needed).
POSTs need header `X-Qmgr: 1` (the page sends it).

## Field test procedure

1. Log in from the phone on the failing carrier. Start capture (ports 443, controlPort; protocol `UDP only` by default, `TCP + UDP` only if you need TCP too; optionally your phone IP). Summary rows are per IP, protocol and direction.
2. Reproduce the QUIC failure. Look at the live summary: does `in` traffic from your IP arrive? Does `out` reach the size buckets?
3. Mode `iperf3` (set auto-restore 10 min). On the phone: `iperf3 -c vpn1.yuchs.com -p 443 -u -b 2M -l 1200 -t 10`, then with `-R`,
   then other `-l` sizes (1250/1350/1400/1452). UDP 443 works but QUIC fails: QUIC-specific filtering. Both directions fail: UDP 443 blocked.
4. Mode `control`: compare QUIC on controlPort vs 443.
5. Back to `trojan`, set server TX payload size (1200..1452), set the same key on the client, retest.
6. Back to `trojan` mode, stop capture, download pcap/live log, then delete them (`Clear log file`, `rm /var/lib/qmgr/cap/*`).

## Safety

- Only PIDs qmgr started are killed, and only if `/proc/<pid>/cmdline` still equals the recorded argv. Never pkill by pattern; the iperf3 on port 9988 is untouched.
- Auto-restore (off/5/10/15 min) returns to trojan; a past deadline is honored at qmgr start. Capture auto-stops (default 30 min).
- Failed mode switch restores trojan. Payload change backs up the config, runs `trojan -t`, restores on failure.
- Secrets from trojan config are never shown; only `quic.tx_udp_payload_size`. Token file is 0600.
- pcap and live log contain client IPs: delete after analysis.
- With `quic.udp_gso` on, tcpdump sees server sends before segmentation, so one line can show e.g. `length 3600`;
  the summary's `>1452` bucket then counts GSO aggregates, not on-wire datagrams.
- Both tcpdumps use `-nn` (numeric ports; `-n` still prints `.https`, which the summary cannot parse).
- Privileges: the pcap tcpdump runs with `-Z root` because the default drop to user `tcpdump` cannot rotate files (`-C/-W`) in the 0700 capture dir.
  The text tcpdump keeps the default and drops privileges to `tcpdump` (logs `dropped privs to tcpdump`); it only writes to a pipe, so it needs no file access.
- `KillMode=process` in the unit: stopping qmgr leaves tracked iperf3/control trojan running (state file knows them; use the page to return to trojan first).

## Tests

```
node --test quic_proxy_test_remote/web_mgr/test/
```

No root, ss or tcpdump needed (fake runner and fake clock). Demo: `QMGR_FAKE=1 QMGR_CONFIG=<temp config> node server.js`.
