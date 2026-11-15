# Build

We'll only cover the build process on Linux since we will be providing Windows and macOS binaries. Building trojan on every platform is similar.

## Dependencies

Install these dependencies before you build:

- [CMake](https://cmake.org/) >= 3.22
- [Visual Studio](https://visualstudio.microsoft.com/) 2022 and [NASM](https://www.nasm.us/) on PATH (Windows x86/x64 assembly)
- A C++17 compiler: GCC, or Clang with [Xcode](https://developer.apple.com/xcode/) 14+ on macOS
- [Git](https://git-scm.com/) (the build needs the git submodules)
- [Boost](http://www.boost.org/) >= 1.77.0, `program_options` component only (Boost.System is header-only and is not linked on desktop platforms)
- [BoringSSL](https://boringssl.googlesource.com/boringssl/), built from the pinned `boringssl` submodule and linked statically

BoringSSL is the sole TLS provider, including ngtcp2's QUIC crypto adapter. System OpenSSL and `libssl-dev` are not required.

TLS behavior:

- FFDHE is unavailable. Nonempty `ssl.dhparam` is ignored with one startup warning: `ssl.dhparam is ignored: FFDHE is not supported`. Use `ssl.curves` for ECDHE.
- `ssl.cipher` configures TLS <= 1.2. `ssl.cipher_tls13` accepts the three standard AES-GCM/ChaCha20 TLS 1.3 names; unknown names and duplicates fail startup. Invalid cipher/curve lists also fail startup.
- Explicit client session reuse is disabled: `ssl.reuse_session=true` on clients warns and is ignored. Server cache, timeout and tickets remain supported.

Link policy:

- Linux keeps glibc and its system libraries dynamic; Boost, BoringSSL, QUIC, mimalloc and the C++/compiler runtimes link statically (`-static-libstdc++ -static-libgcc`, `Boost_USE_STATIC_LIBS ON`). The static C++ runtime (`libstdc++.a`) and static Boost archives (`libboost_program_options.a`) must therefore be installed. Fully static glibc binaries are not supported because getaddrinfo/NSS needs the system runtime.
- Windows uses static MSVC CRT and Boost built with `runtime-link=static`. Android keeps `libtrojan.so` shared but uses `ANDROID_STL=c++_static`; iOS exports static archives.
- Apple and Android allow only platform system libraries/frameworks as dynamic dependencies. Third-party dependencies link statically; use static Boost archives, not shared packages.
- Mimalloc uses its explicit API for tp allocations only. It does not override process-wide allocation or BoringSSL allocation.

For Debian users, run `sudo apt -y install build-essential cmake git libboost-program-options-dev` to install all the necessary dependencies.

For RHEL / Rocky / AlmaLinux / CentOS Stream users, the static libraries live in the CRB repository (named `powertools` on EL8):

```bash
sudo dnf --enablerepo=crb install gcc-c++ make cmake git boost-devel boost-static libstdc++-static
```

- If `libstdc++-static` is missing, compiling succeeds but linking fails with `/usr/bin/ld: cannot find -lstdc++`.
- EL9 ships Boost 1.75, below the required 1.77. On EL9, build Boost >= 1.77 from source (static, `link=static`, with at least `--with-program_options`) and pass it with `-DBOOST_ROOT=/path/to/boost` when running `cmake`. EL10 ships Boost 1.83 and works as is.
- Verified on Rocky Linux 10 (GCC 14.3.1): BoringSSL is built with `-Werror` and GCC 14.3 reports `-Wstringop-overflow` in `boringssl/crypto/fipsmodule/keccak/keccak.cc.inc`, which fails the build. Configure with `CFLAGS=-Wno-error=stringop-overflow CXXFLAGS=-Wno-error=stringop-overflow cmake ..` to downgrade it to a warning.

For macOS users, see [macOS Build](#macos-build) below.

## Clone

Type in

```bash
git clone https://github.com/Trojan-Plus-Group/trojan-plus.git
cd trojan-plus/
```

to clone the project and go into the directory.

Then, initialize and update the git submodules (Required):
```bash
git submodule update --init --recursive
```

## Build and Install

Type in

```bash
mkdir build
cd build/
cmake ..
make
sudo make install
```

to build and install trojan. `make` does not run any tests; see [Docker Build Environment](#docker-build-environment) for the test suite. If everything goes well you'll be able to use trojan.

The `cmake ..` command can be extended with the following options.

- `-DDEFAULT_CONFIG=/path/to/default/config.json`: the default path trojan will look for config (defaults to `${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan/config.json`).
- `ENABLE_MIMALLOC`
    - `-DENABLE_MIMALLOC=ON`: build the `mimalloc` submodule as a static, API-only allocator for tp allocations (default).
    - `-DENABLE_MIMALLOC=OFF`: build without mimalloc support.
- `ENABLE_NAT` (Only on Linux)
    - `-DENABLE_NAT=ON`: build with NAT support (default).
    - `-DENABLE_NAT=OFF`: build without NAT support.
- `ENABLE_REUSE_PORT` (Only on Linux)
    - `-DENABLE_REUSE_PORT=ON`: build with `SO_REUSEPORT` support (default).
    - `-DENABLE_REUSE_PORT=OFF`: build without `SO_REUSEPORT` support.
- `TROJAN_QUIC_STATS` (diagnostics only, default `OFF`)
    - `-DTROJAN_QUIC_STATS=ON`: compile QUIC sender-state CSV sampling and diagnostic `TROJAN_QUIC_CC` selection. Set the `TROJAN_QUIC_STATS` environment variable to a CSV path to sample. Default builds contain neither feature and always use BBR. See [diagnostics](../tests/netem/DIAGNOSTICS.md).
- `ENABLE_QUIC` (Experimental)
    - `-DENABLE_QUIC=ON`: build QUIC/HTTP3 from the `boringssl`, `ngtcp2`, and `nghttp3` submodules (default).
    - `-DENABLE_QUIC=OFF`: build without QUIC support.
- `ENABLE_SSL_KEYLOG` (DEBUG ONLY; exposes TLS master secrets)
    - `-DENABLE_SSL_KEYLOG=ON`: build with SSL KeyLog support. While `ENABLE_QUIC` is on, the KeyLog callback is not installed.
    - `-DENABLE_SSL_KEYLOG=OFF`: build without SSL KeyLog support (default). `./trojan --version` then reports `[Disabled] SSL KeyLog Support`.
- `FORCE_TCP_FASTOPEN`
    - `-DFORCE_TCP_FASTOPEN=ON`: force build with `TCP_FASTOPEN` support.
    - `-DFORCE_TCP_FASTOPEN=OFF`: build with `TCP_FASTOPEN` support based on system capabilities (default).
- `SYSTEMD_SERVICE`
    - `-DSYSTEMD_SERVICE=AUTO`: detect systemd automatically and decide whether to install service (default).
    - `-DSYSTEMD_SERVICE=ON`: install systemd service unconditionally.
    - `-DSYSTEMD_SERVICE=OFF`: don't install systemd service unconditionally.
- `-DSYSTEMD_SERVICE_PATH=/path/to/systemd/system`: the path to which the systemd service will be installed (auto-detected as `/usr/lib/systemd/system` or `/lib/systemd/system` when `SYSTEMD_SERVICE=AUTO`; otherwise defaults to `/lib/systemd/system`).

## Android Build

To build the Android shared library (.so), you need the Android NDK.

### Dependencies

- Android NDK; CI and development use NDK 27.2.12479018 (r27). Neither the script nor CMake enforces a minimum version, but the build requires 16 KB page-size support (`-DANDROID_SUPPORT_16KB_PAGE_SIZE=ON`, `-Wl,-z,max-page-size=16384`), so use a recent NDK like r27.

### Build

1. Ensure you have the precompiled Android libraries in the `trojan-plus-android-libs` directory. CMake links Boost from there (`libboost_system` and `libboost_program_options`). TLS is the `boringssl` submodule, built and linked statically.

2. Run the build script:

```bash
./build_android_so.sh /path/to/android-ndk
```

This builds `arm64-v8a` and `x86_64` only (`ANDROID_API` 31; armeabi-v7a and x86 are not built) and outputs the .so files to `android_lib/<arch>/libtrojan.so`.

Options:
- Add `-r` for clean build: `./build_android_so.sh /path/to/android-ndk -r`
- Add `-d` for a debug build (`CMAKE_BUILD_TYPE=Debug`, symbols kept); the unstripped library is also copied to `android_lib/<arch>_debug/libtrojan.so`.

## iOS Build

To build the iOS static library (.a) and XCFramework for use in iOS applications (e.g., MAUI apps).

### Dependencies

- Xcode (tested with Xcode 17.0+)
- CMake >= 3.22
- Pre-built Boost 1.85.0 in the `trojan-plus-ios-libs` submodule (`libboost_system` and `libboost_program_options`). TLS is the `boringssl` submodule, built by CMake.

### Build

1. Initialize the iOS libraries submodule:

```bash
git submodule update --init --recursive
cd trojan-plus-ios-libs
./make_boost.sh
cd ..
```

2. Build the iOS static library:

```bash
./make_ios.sh /Applications/Xcode.app -r
```

This will build for all iOS architectures (iphoneos arm64, iphonesimulator arm64/x86_64) and create an XCFramework at `ios_lib/trojan.xcframework`.

Options:
- Add `-r` for clean build.

The script checks CMake >= 3.22 before building. BoringSSL-specific build directories
avoid stale caches from previous providers. Do not run builds concurrently against
shared `ios_lib` outputs. CMake merges BoringSSL `ssl`/`crypto`, enabled QUIC/mimalloc,
and Boost archives into each packaged `libtrojan.a`; static linking alone does not
embed dependencies. Consumers still link Apple Security/CoreFoundation frameworks
and the C++ runtime. iOS does not use the desktop Keychain root-import path; configure
`ssl.cert` with an application-provided CA bundle when system default paths are unavailable.

## macOS Build

Desktop macOS uses the normal CMake build (same as the macOS job in `azure-pipelines.yml`).

### Dependencies

- Xcode 14+ (or Command Line Tools)
- CMake >= 3.22 and Boost >= 1.77.0 from Homebrew. TLS is the `boringssl` submodule, built by CMake:

```bash
brew install boost cmake
```

### Build

```bash
git submodule update --init --recursive
mkdir build && cd build
cmake -DBoost_USE_STATIC_LIBS=ON -DCMAKE_OSX_DEPLOYMENT_TARGET=10.14 ..
make -j$(sysctl -n hw.ncpu)
```

This produces the `build/trojan` executable. CMake looks for Homebrew Boost in `/opt/homebrew/opt/boost` and `/usr/local/opt/boost`. CI uses deployment target 10.14.

## Docker Build Environment

The Docker scripts use a Debian trixie build image. BoringSSL, QUIC libraries and optional mimalloc build from pinned submodules; no system TLS development package is needed.

### 1. Build the Docker Image
First, build the local Docker image (`scripts/build_docker.sh` tags it `trojanplusgroup/centos-build:debian`):

```bash
./scripts/build_docker.sh
```

### 2. Push to Docker Hub (Maintainers only)
To update the standardized build environment on Docker Hub for CI:

```bash
./scripts/push_to_docker_hub.sh
```

### 3. Compile and Test
Run the compilation and full test suite inside the container:

```bash
./scripts/compile_and_test.sh
```

`compile_and_test.sh` runs the image named `trojan-builder`, so tag the image first: `docker tag trojanplusgroup/centos-build:debian trojan-builder`.

This script will:
1.  Clean previous build artifacts.
2.  Configure CMake with `-DENABLE_MIMALLOC=ON`.
3.  Compile the project.
4.  Run the full Python integration test suite (excluding DNS tests).

### BoringSSL CI and native trust roots

Azure's existing Build and Test jobs use BoringSSL on Linux, macOS, and Windows;
release artifact names remain unchanged. Jobs check CMake >= 3.22
(installing/upgrading where needed).
Windows installs NASM, adds it to subsequent steps' PATH, and uses VS2022 x64.
Linux follows the IPv4/DNS, IPv6/NAT, TUN and QUIC suites; macOS and Windows follow
their existing IPv4/DNS and QUIC suites. This is not iOS runtime coverage.

With `ssl.verify=true` and an empty `ssl.cert`, Windows imports certificates from
its native `ROOT` store; desktop macOS searches the current Keychain list plus
`/System/Library/Keychains/SystemRootCertificates.keychain`. These paths do not
require OpenSSL-style default CA files. Logs report `Windows native trust roots
loaded: N` or `macOS native trust roots loaded: N`, counting only successful
`X509_STORE_add_cert` calls; zero emits a warning. This confirms store import,
not hostname verification or successful peer validation. Keychain certificates
are imported as before; native per-certificate trust/distrust policies are not
translated into TLS-library policy. Explicit `ssl.cert` bypasses native import.

### CI IPv6 coverage

Azure Linux Test runs `tests/test_*.py`, `fulltest_main.py BINARY -6`, and
`fulltest_main.py BINARY -6 --ipv6-nat --ipv6-include-expected-fail` before the IPv4 suites.
The privileged container installs `iproute2`, `iptables`, `nftables`, a C++ compiler,
and Boost headers, enables kernel IPv6, and checks binding to `::1`.
`TP_IPV6_REQUIRE_ALL=1` makes a skipped required IPv6 case fail CI; the intentionally
opt-in no-rule NAT and REDIRECT/TPROXY cases are not required in the core-only run.
TUN and NAT coverage requires `/dev/net/tun`, network namespaces, and passwordless sudo.
Hosts updates prefer atomic rename. Container bind mounts returning `EBUSY` or
`EXDEV` use an in-place rewrite with `fsync` and readback verification, including
the sudo path. Exit and signal handlers restore the original bytes.
The local Docker image includes the same firewall tools.

DNS forwarding (`-d 5333`) uses a local UDP DNS fixture at `127.0.0.1:53`,
reserved `.test` names, fixed answers, and NXDOMAIN checks for both direct and
proxied queries. Timeouts fail the suite; no public resolver or Internet domain
is required. The IPv4 TUN job routes only fixture destinations
`188.188.188.188/32` and `199.199.199.199/32` through `tun0`, leaving the
runner's default route intact. Linux CI runs as root. macOS CI runs the IPv4/DNS
suite with passwordless sudo and the same isolated Python environment, then
restores generated-file ownership before running QUIC as the agent user.
Fixture bind failures are fatal whenever `TF_BUILD` or `CI` is present.
Local macOS/Windows runs may report an explicit DNS skip when binding fails
(for example, privileged port access or another DNS service).

T16 enables `log_live_counters` only in its temporary configs. Fresh periodic
snapshots after quiescence record tp allocator live objects/bytes, Session count,
QUIC connections, and QUIC proxy sessions. Exactly ten round samples are required;
lifecycle counts must match round 1 in every round. Client allocator peak growth
over round 1 is capped at 1000 objects, including warm-up. Server round samples
have no allocator peak cap. Neither side uses late-growth or monotonic-growth
gates for round samples.

Before starting the client, T16 records a fresh server idle baseline. After closing
the client, it waits for a fresh server snapshot with all QUIC connection and proxy
session pools gone. Both idle samples must have zero QUIC connections and proxy
sessions; the final Session count must equal the baseline. Final allocator object
growth over that baseline may not exceed 32; decreases are allowed. The client has
no idle-baseline comparison because it eagerly connects at startup and reconnects;
process exit is not a useful live-counter snapshot. Missing or stale telemetry
fails; allocator bytes are diagnostic. `check_t16_live_counters.py` covers round
plateaus and growth, optional peak caps, lifecycle leftovers, and the post-close
32-object retention limit. These are bounded retention gates, not proof against
every small/intermittent leak.

RSS remains a secondary gate: sample every round, discard the first three
warm-up rounds, and measure median pairwise slope across rounds 4-10 relative
to median steady-state RSS. Growth above 80% fails. No tail heuristic or
warm-up extrapolation is used. `tests/test_t16_rss_growth.py` checks warm-up,
noise, and large sustained resident leaks; object accounting detects smaller
retained allocations independently of mimalloc's resident-page behavior.

QUIC regression checks require one validated H3 result per request, including
repeated paths. T17 requires observed Stateless Reset receipt, server reset
transmission, a fresh handshake, and matching response content; either immediate
request failure or successful early recovery is valid.

macOS and Windows keep the IPv4 and QUIC suites. The current `-6` suite edits
`/etc/hosts` and includes Linux TUN/netns checks, so it is not an unprivileged
cross-platform suite. IPv6 coverage on those runners remains unverified.

After installation, config examples will be installed to `${CMAKE_INSTALL_DOCDIR}/examples/` and a server config will be installed to `${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan/config.json`.

[Homepage](.) | [Prev Page](config) | [Next Page](usage)
