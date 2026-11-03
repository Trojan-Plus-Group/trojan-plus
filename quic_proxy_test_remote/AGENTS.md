# Remote QUIC Harness

## Purpose and prerequisites

Stress, soak and outage tests over a real network; compare TCP TLS and forced QUIC
in `client`, `nat` and `client_tun` modes. `forward` is out of scope.
Work from repository root. Python 3, cryptography, CMake, curl, SSH/SCP, lsof,
iperf3 (baseline only), and QUIC-enabled Release binaries are required.
Default disposable host: `root@172.236.226.35`, SSH port `9922`, repo `/root/trojan-plus`.
Confirm host identity, branch, commit, free memory and ports before each round.
Remote host has 1 CPU/1 GB RAM: remote builds MUST use `--jobs 1`.
Local builds may run in parallel. Never commit or push without explicit permission.

## Sync and preparation

```bash
python3 -m unittest discover -s quic_proxy_test_remote/scripts -p 'test_*.py'
python3 quic_proxy_test_remote/scripts/sync_remote.py --status
python3 quic_proxy_test_remote/scripts/sync_remote.py --jobs 1 --build-timeout 3600
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD)-r1"
python3 quic_proxy_test_remote/scripts/run.py prepare --run-id "$RUN_ID"
python3 quic_proxy_test_remote/scripts/run.py trojan-deploy --run-id "$RUN_ID" --server-disable-tcp
```

Sync bundles committed content only, including slash-named branches. It resets only
same-named remote test branch, never another branch; never runs `git clean`.
Uncommitted harness changes run locally; do not claim bundle includes them.
Save dirty diff with run evidence. Use unique Run IDs; never overwrite failed results.
For TCP, omit `--server-disable-tcp`, use `--protocol tcp`, and create a new run.
Do not use `--protocol both` for forced-QUIC acceptance.

## Cases

```bash
# Managed cases start clients/server/bytesource and stop them afterwards.
python3 quic_proxy_test_remote/scripts/run.py r2 --run-id "$RUN_ID" --protocol quic --sizes 1048576 --runs 1
# Redeploy under a NEW Run ID before each subsequent managed case.
python3 quic_proxy_test_remote/scripts/run.py concurrency --run-id "$RUN_ID" --protocol quic --streams 200 --total-bytes 50000000 --warmup 0 --runs 1
python3 quic_proxy_test_remote/scripts/run.py soak --run-id "$RUN_ID" --protocol quic --minutes 5 --cooldown 2
python3 quic_proxy_test_remote/scripts/run.py netem --run-id "$RUN_ID" --protocol quic --delay-ms 100 --loss-percent 0.1 --bytes 1048576
python3 quic_proxy_test_remote/scripts/run.py baseline --run-id "$RUN_ID" --warmup 1 --runs 1
# Manual lifecycle, for diagnostics only:
python3 quic_proxy_test_remote/scripts/run.py bytesource-start --run-id "$RUN_ID"
python3 quic_proxy_test_remote/scripts/run.py trojan-start --run-id "$RUN_ID"
python3 quic_proxy_test_remote/scripts/run.py trojan-stop --run-id "$RUN_ID"
```

Use `--help` for per-command timing controls. Retries default to zero;
`--allowed-retries 1` or `2` explicitly permits them. Keep every attempt and first failure.
Use 30-minute soak + 10-minute cooldown only for release/lifetime investigations.
Memory slopes are diagnostic, not proof of leaks. Missing observations fail soak.
Netem scopes UDP/TCP source port 3443 to client IPv4 `/32`, uses IFB and watchdog;
never impair SSH or replace default routes. Preserve existing rules and verify restoration.

## Container modes

Require container engine, NET_ADMIN, `/dev/net/tun`, and executable `build/trojan`.
Use unique run for each mode/protocol. Engine selection and external target controls
are documented by `docker_modes.py --help`.

```bash
python3 quic_proxy_test_remote/scripts/docker_modes.py --mode nat --protocol quic --run-id "$RUN_ID" --size 1048576 --requests 1 --concurrency 1 --watchdog 240
python3 quic_proxy_test_remote/scripts/docker_modes.py --mode client_tun --protocol tcp --run-id "$RUN_ID" --size 250000 --requests 200 --concurrency 32 --watchdog 240
```

NAT redirects only target `/32` TCP port 8001 (controlled bytesource) or 443 (Cloudflare).
TUN policy routing scopes target `/32` and TCP port; remote port 3443 must bypass tun0.
Images rebuild when entry/template changes. Select `--container-engine 'sudo -n podman'`
or `CONTAINER_ENGINE`; otherwise working Docker/Podman is detected automatically.
Cloudflare requires `--target cloudflare --expected-sha256 <trusted digest>`.
`run.py cloudflare` requires `--protocol tcp|quic --allow-external --expected-sha256 <trusted digest>`.

## Evidence and gates

`runtime/<run_id>/`: private credentials/configs; never commit.
`results/<run_id>/metadata/`: manifest, deploy directory, PIDs, commands and attempts.
`results/<run_id>/logs/`: client logs and archived remote logs.
Case `summary.json`: explicit `pass`, parameters, thresholds and failures.
R2 also keeps `r2-summary.json`; other cases retain samples/observations in case directories.
Pass requires exit 0, HTTP 200, exact bytes and SHA-256; no failed samples or cleanup errors.
QUIC requires both roles' completed handshake with ALPN h3 and actual stream evidence;
UDP listener must exist and forced-QUIC server must have no TCP listener.
Client QUIC diagnostic logging enables stream evidence; do not use these runs as throughput baselines.
Payload uses deterministic SHAKE-256 stream, not repeated 256-byte blocks.

## Cleanup and pitfalls

`trojan-stop` stops owned server and bytesource, archives logs, deletes exact deployed directory.
Failure paths must do same. Never bulk-pkill or bulk-delete `/tmp/trojan-*`.
Stop only recorded PIDs; never kill unrelated iperf3, containers or listeners.
Confirm no owned processes, ports 3443/5201/8001, containers, routes, IFB or private keys remain.
Keep failed evidence; rerun with new Run ID. Never end while started tests/remote jobs run.
