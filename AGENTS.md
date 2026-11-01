# Trojan Plus: Agent Guide

C++17 Trojan-compatible proxy for Linux, macOS, Windows, Android and iOS.
Run modes: `client` (SOCKS5), `server`, `forward`, `nat` (Linux), `client_tun`.
QUIC uses ngtcp2 + nghttp3 + wolfSSL; TUN uses embedded lwIP.

## Conventions and safety

- All repository text is English: comments, docs, log messages, commit messages and PR text.
- No commit/push unless the user or maintainer's workflow explicitly requests it; never push to master.
- Preserve user changes and failure evidence. Do not overwrite failed run results with retries.
- Follow `.clang-format` and Microsoft GSL conventions.
- Do not enable `ENABLE_SSL_KEYLOG` outside debugging: it exposes TLS secrets.

## Non-obvious architecture rules

- Linux favors multiple processes with `SO_REUSEPORT`, not threads sharing session state.
  Each process has its own `boost::asio::io_context`; session state stays on that event loop.
- Performance-sensitive core/session paths use `tp::` containers, not raw `std::` heap containers.
  See [src/mem/memallocator.h](src/mem/memallocator.h): `tp::string`, `tp::vector`,
  `TP_NEW`/`TP_DELETE`, `TP_MALLOC`/`TP_FREE`, `TP_MAKE_UNIQUE`, `TP_MAKE_SHARED`.
  Wrap Asio handlers with `tp::bind_mem_alloc`.
- Main directories: `src/core` (config/lifecycle), `src/session` (proxy modes),
  `src/proto` (wire formats), `src/ssl`, `src/quic` (including `h1_upstream`),
  `src/tun` (lwIP/DNS), `src/mem`.
- Submodules include wolfSSL, ngtcp2, nghttp3, mimalloc, GSL, badvpn and mobile dependencies.

## Address, IPv6 and DNS invariants

- SOCKS5/Trojan: ATYP 1 for IPv4; ATYP 4 for native IPv6. Unwrap IPv4-mapped
  addresses to IPv4. Keep scoped literals (`%zone`) as ATYP 3 text.
- Log IPv6 endpoints as `[addr]:port`. `tcp.ipv6_only` controls `IPV6_V6ONLY`
  on `::` listeners; do not assume kernel defaults.
- `tun.net_ipv6` / `tun.net_ipv6_prefix` enable TUN IPv6; old IPv4 configs remain valid.
- Built-in DNS caches by `(name, qtype)`, including AAAA and RFC 2308 negative answers.
- Route list files (`cn_mainland_ips_file`, `white_ips`, `proxy_ips`) accept mixed IPv4/IPv6.
  Mainland modes keep proxying native IPv6 when the mainland list has no IPv6 entries.
- GFWList domains always use the proxied DNS upstream in every route mode because
  mainland answers may be poisoned. Do not gate this on `route_gfwlist`.
- `dns.up_dns_server` / `dns.up_gfw_dns_server` must contain IP literals, not hostnames.
- Details: [docs/config.md](docs/config.md),
  [tests/LinuxFullTest/IPV6_BASELINE.md](tests/LinuxFullTest/IPV6_BASELINE.md).

## Build

Requires C++17, CMake >=3.20, Boost >=1.77 (`program_options`), initialized submodules.

```bash
git submodule update --init --recursive
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Use `build_and_test.sh` on Linux/macOS/MSYS, `build_and_test.bat` on MSVC,
or `build_and_test_docker_linux.sh` for Docker. Important defaults:
`ENABLE_QUIC=ON`, `ENABLE_MIMALLOC=ON`, Linux `ENABLE_NAT=ON`.
`BUILD_LIBRARY` produces libraries and is enabled automatically for mobile builds.
Android: `build_android_so.sh`; iOS: `make_ios.sh`, `make_xcframework_ios.sh`.
Library exports: [src/platform_exports.h](src/platform_exports.h).
More: [docs/build.md](docs/build.md), `CMakeLists.txt`.

## Testing

Install Python dependencies: `pip install PySocks psutil dnspython aioquic`.
Run from `tests/LinuxFullTest`; use an absolute binary path.
Suites without `-g` need existing `tests/LinuxFullTest/html`; generate content with `-g`.

```bash
python3 fulltest_main.py /absolute/path/to/trojan -g -n -f
sudo python3 fulltest_main.py /absolute/path/to/trojan -g -n -d 5333 -f
sudo python3 fulltest_main.py /absolute/path/to/trojan -t -d 5333
python3 fulltest_main.py /absolute/path/to/trojan -q
python3 fulltest_main.py /absolute/path/to/trojan -q T22
sudo python3 fulltest_main.py /absolute/path/to/trojan -6
sudo env TP_IPV6_REQUIRE_ALL=1 python3 fulltest_main.py /absolute/path/to/trojan -6 --ipv6-nat --ipv6-include-expected-fail
```

- QUIC cases extend through T22; `fulltest_quic.py BINARY all` is the direct runner.
- TUN requires root, `/dev/net/tun`, and appropriate interface/routes; see CI setup.
  IPv6 NAT needs root/passwordless sudo, network namespaces and ip6tables/nftables.
- CI uses `TP_IPV6_REQUIRE_ALL=1`: required IPv6 cases must fail rather than silently skip.
  Container `/etc/hosts` may be bind-mounted; the IPv6 suite falls back to in-place rewrite,
  verifies readback and restores original bytes on exit/signals.
- `-d` uses a local DNS fixture at `127.0.0.1:53`, no public resolver.
  Fixture bind failures fail under `TF_BUILD` or `CI`; local macOS/Windows may skip.
  macOS CI runs IPv4/DNS with sudo and restores generated-file ownership.
- From repository root, run `tests/test_*.py` with Python. Production-code compile checks
  require a C++17 compiler and Boost headers. Also run relevant
  `tests/LinuxFullTest/check_*.py` regressions; some require the Python dependencies above.
- Stable tests use event-based waits with bounded deadlines, not fixed sleeps as synchronization.
  Avoid public-network dependencies. Verify flaky fixes with repeated runs on one CPU.
- T16 enables optional `log_live_counters` (default false): periodic tp allocator live
  objects/bytes, Session, QUIC connection and proxy-session counts. Fresh quiescent snapshots
  are the primary leak gate; RSS is secondary with an 80% sustained-growth threshold.
- [azure-pipelines.yml](azure-pipelines.yml) runs IPv4, QUIC, local DNS and, on Linux,
  IPv6 plus unit/regression checks. A red pipeline is a blocker.
- Manual fixtures: [quic_proxy_test/](quic_proxy_test/).

## Remote validation: only when requested

Follow [quic_proxy_test_remote/AGENTS.md](quic_proxy_test_remote/AGENTS.md) for host
confirmation, exact commands, safe sync, result retention and cleanup.

1. Local build and relevant fulltest must pass before a validation-only commit; no push.
2. Run `python3 quic_proxy_test_remote/scripts/sync_remote.py --jobs 1`.
   Sync only the same-named test branch via git bundle; never reset other branches or clean files.
3. Build remotely at the same commit, single-threaded; keep local builds parallel.
4. Run `client`, `nat`, `client_tun` TCP-TLS and forced-QUIC smoke: all six must pass
   content/protocol checks and cleanup. On failure, retain evidence, fix locally, and use a new
   commit/Run ID only after local tests pass again.
