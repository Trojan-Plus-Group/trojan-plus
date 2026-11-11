# QUIC UDP buffer matrix

## One-command container run

Initialize repository submodules first. Use an image built from `scripts/Dockerfile`, or the Linux CI image `trojanplusgroup/centos-build:debian` from `azure-pipelines.yml`. The image needs the repository's C++/CMake/Boost build dependencies, Bash, `ip`, `tc` with netem/TBF support, `sysctl`, `stat`, and Python 3.9+. The host kernel must support network namespaces, veth, netem and TBF. Missing tools fail explicitly; unsupported kernel features fail with command errors. `localhost/trojan-builder:full` is also suitable when available locally; no preexisting local image name is required.

```sh
tests/netem/run_in_container.sh trojanplusgroup/centos-build:debian "$PWD/../netem-logs" --profile clean --workload A --mode all --repeat 1 --buffer-size 76800
```

Requires rootful privileged containers. Set `CONTAINER=docker` to use Docker, or `CONTAINER="sudo -n podman"` when elevation is needed; the command is split on whitespace, not evaluated as shell code. Source is mounted read-only, copied and built once in Release with QUIC enabled. Build output goes to the external log directory's `build.log`; measurements run serially. Choose a fresh external log directory for every run. No host packages are installed by this entry point.

Container mount paths `/src`, `/work`, `/logs` are the entry point's fixed internal layout, not host locations. For a different internal layout, invoke the Python harness directly: `--source` overrides `/work`, `--binary` overrides `/work/build/trojan`, and required `--output-dir` selects result storage (`/logs` in the entry point). The entry point forwards all harness flags. `--link-network` overrides default isolated subnet `10.88.0.0/24`; its first two usable IPv4 addresses are client/server. Loopback and wildcard addresses are namespace-local socket roles, not host endpoints.

`--log-level` defaults to `1` (INFO), is applied to both endpoint configs and recorded in every result row. Use `0` (ALL) only for debugging: its logging overhead can distort CPU and throughput. Levels above INFO, including `5` (OFF), use `ss -u -a -n -m -p` to verify UDP buffers from kernel socket memory limits; the image must include `ss`. OFF still permits the program's startup banner. Do not compare measurements taken at different logging levels.

The harness reuses only repository test passwords and test certificates from `tests/LinuxFullTest/config/quic_*_config.json`. No new keys or credentials are generated. Generated configs (including test-only credentials), logs and results go only to `--output-dir`, outside the source tree; do not use production credentials.

Diagnostic delay/relay profiles, OFF logging, UDP reordering probes and extra CPU/wire counters: see [DIAGNOSTICS.md](DIAGNOSTICS.md). Original matrix profiles and `--profile all` behavior remain unchanged.


## Opt-in sender-state sampling

Build diagnostics explicitly before using `--quic-stats` or `--quic-cc`:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DTROJAN_QUIC_STATS=ON
cmake --build build --parallel
```

Default `TROJAN_QUIC_STATS=OFF` removes sampler state, scopes, CSV and environment reads
at compile time; production always uses BBR. Product/Android build defaults stay unchanged.
The harness rejects diagnostic flags for binaries without the compiled-in marker.
The one-command runner builds production defaults; use the direct harness with a diagnostics build.
`--quic-stats` sets `TROJAN_QUIC_STATS` to separate client/server CSV paths in each cell.
In diagnostics builds, unset or empty means no sampler timer, file access, queue scans or extra clock reads.
Enabled sampling runs every 100 ms and adds synchronous counters; its overhead can be large.
Use stats-OFF controls for performance claims. The download sender is the server.
`python3 tests/netem/analyze_cc.py CSV` reports RTT, credit, queue buckets, rates,
trigger attribution and observed gaps; `--self-check` runs its stdlib-only checks.
A process writes one append-only CSV; use one connection/process for attribution and
unique paths per process. Do not share CSV paths across worker processes.

`--quic-cc {bbr,cubic,reno}` selects ngtcp2's existing algorithms for both roles;
BBR remains the product default, including unknown `TROJAN_QUIC_CC` values (with warning).
`--netem-before-handshake` applies the selected qdisc before endpoint startup, so
handshake/warmup also cross impairment. Without it, warmup precedes impairment as before.
These fields participate in result grouping; TCP strips inherited diagnostic variables.
Counters describe observations, not proof of pacing limitation or causal packet contents.
UDP failures are counted as `udp_send_errors`, without changing socket error handling.

## Opt-in CPU profiling

`perf_in_container.sh` leaves the normal runner unchanged. It uses a privileged container with host PID visibility and host root mounted read-only at `/host`; only the selected external log directory is rebound writable inside that view. Review this host exposure before use. Host `/usr/bin/perf` runs through `chroot /host`; no tools are installed and host perf settings are not changed.

```sh
CONTAINER="sudo -n podman" CMAKE_EXTRA_CXX_FLAGS="-g -fno-omit-frame-pointer" tests/netem/perf_in_container.sh localhost/trojan-builder:full /absolute/external/perf-logs --perf-matrix --profile clean --workload A --mode quic --repeat 3 --buffer-size 76800 --log-level 5
```

`CMAKE_EXTRA_CXX_FLAGS` defaults to `-g -fno-omit-frame-pointer` and applies only in this separate runner. Build logs include effective flags, link command and ELF symbol/debug sections; `trojan.symbols` retains the unstripped binary. Matrix builds once, then runs unprofiled controls, server/client sampling, server/client software counters and server/client syscall recording serially. Each group uses the requested repeats; stats remain at harness defaults unless explicitly overridden. Reports resolve symbols before the container exits. Hardware counters may be unavailable on virtual machines. `PERF_REUSE_BINARY=/absolute/path/to/trojan.symbols` reuses a previously verified profiling binary instead of rebuilding; retain its original build log and flags. `--perf-kind trace` uses `perf trace -S` (syscall details plus summary) when raw tracepoint recordings cannot be decoded. Profiler overhead must be measured, not assumed negligible.

## Direct harness and self-check

Run inside one rootful privileged Linux container with a built trojan binary:

```sh
python3 /src/tests/netem/harness.py --source /work --binary /work/build/trojan --profile all --workload all --mode all --repeat 3 --slow-repeats 1 --timeout 900 --output-dir /logs/matrix
PYTHONDONTWRITEBYTECODE=1 python3 tests/netem/test_harness.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/netem/summarize.py /logs/matrix/results.jsonl --output-dir /logs
```

To run UDP reordering probes without building the binary or transferring data:

```sh
python3 /src/tests/netem/harness.py --profile delay100-jitter-ordered --probe-only
python3 /src/tests/netem/harness.py --profile delay100-jitter-ordered --probe-only --probe-spacing 0.0002
```

Mount source read-only at `/src`; copy to `/work`, build once there, mount an external log directory at `/logs`. Never run cells or containers concurrently. `--dry-run` prints the plan without requiring privileges. `--buffer-size` selects one matrix buffer; `--recv-buffer` and `--send-buffer` independently override it. Use a new output directory for each invocation; existing results are never overwritten. Failed requests produce a nonzero final exit; startup or handshake failures abort immediately. Hard deadlines record failed measurements and allow subsequent cells to run.

Two fresh namespaces use a directly connected veth pair. Both egress devices have netem; g3 uses a parent 1 Mbit/s TBF with a 16 KiB burst and 500 ms latency, plus child netem. Delay values apply **per direction**: delay100 has about 200 ms RTT; g3 has about 400 ms RTT. Netem queue limit is the kernel default 1000 packets, recorded in each row. Burst uses `loss 5% 25%` (5% random loss, 25% correlation), not independent loss. Clean still has an empty netem qdisc. Seeds are kernel-generated and recorded in qdisc dumps, not paired between buffer values.

Warmup verifies a complete SHA256-checked SOCKS/HTTP request and QUIC buffer logs before impairment. This measures established-connection behavior, not impaired initial handshakes. TCP control disables QUIC and pipeline (`pipeline_num=0`); it uses the native TCP/TLS proxy path. UDP buffer fields are null for TCP because TCP has no QUIC socket.

A transfers exactly 50,000,000 bytes, B transfers 20 concurrent 65,536-byte responses, C waits five seconds after warmup then transfers 65,536 bytes. All verify status, length and SHA256. C duration excludes its five-second idle; wall time includes it. B p95 uses nearest rank. Hard workload deadlines include all worker overhead and idle; failed transfers have no invented throughput. Server and client CPU are cumulative `/proc/PID/stat` user+system time, including startup/warmup; peak RSS is sampled from VmHWM every 20 ms.

Outage/rebind start after target writes the first 1024 payload bytes, before it sends the rest. The HTTP sender waits for netem's 100% loss acknowledgement, ensuring even small requests overlap the ten-second blackout. This intentional sender gate is part of those profiles. Both directions restore after ten seconds. Rebind uses the self-contained UDP relay in `harness.py`: it resides in the server namespace, forwards to server loopback, opens a new upstream UDP socket before restoration, and retains/drains the old socket without forwarding. Server observes a changed peer port; client destination stays stable. Port changes are retained in relay.log. TCP rebind control is outage only: TCP cannot preserve an existing connection across a source-port change; this is explicitly not a TCP NAT migration test.

Only per-network-namespace rmem_max/wmem_max files with distinct procfs inode identities are written. Parent values are verified unchanged. The harness records namespace values, attempts, and requested/actual Boost.Asio socket values on both endpoints. Linux doubles raw SO_RCVBUF/SO_SNDBUF internally; the application logs Boost.Asio's normalized value. All logs are retained, not only slow/failed cells. Wire packet counts come from qdisc statistics (include ACK/control traffic); exact QUIC packet counts remain null when unavailable. EAGAIN and recovery event counts cover both endpoint logs.

Results: append-only results.jsonl, aggregate.json (successful-repeat median/min/max, failures and EAGAIN totals). Do not interpret one-repeat slow profiles as evidence for a default change. Random-loss variance, logging overhead, shared-host scheduling, relay overhead, and existing congestion control can dominate buffer differences. No CI integration, external network, host sysctl changes, source edits, or new dependencies.
