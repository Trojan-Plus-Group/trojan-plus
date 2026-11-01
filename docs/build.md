# Build

We'll only cover the build process on Linux since we will be providing Windows and macOS binaries. Building trojan on every platform is similar.

## Dependencies

Install these dependencies before you build:

- [CMake](https://cmake.org/) >= 3.20
- [Visual Studio](https://visualstudio.microsoft.com/) >= 2019 (only for Windows)
- [XCode](https://developer.apple.com/xcode/) 14+ (only for XCode)
- [Boost](http://www.boost.org/) >= 1.77.0 (1.85.0+ recommended for stable async_wait support)
- [wolfSSL](https://www.wolfssl.com/) 5.9.1, built from the `wolfssl` submodule and linked statically

TLS is always that bundled wolfSSL. There is no system SSL package and no CMake option that selects one. `libssl-dev` is not required. QUIC (on by default) builds ngtcp2 with its wolfSSL backend; ngtcp2's own `ENABLE_OPENSSL` defaults to `ON`, and this project forces it `OFF`, so a configure log that reports OpenSSL as false is expected.

For Debian users, run `sudo apt -y install build-essential cmake libboost-system-dev libboost-program-options-dev` to install all the necessary dependencies.

For macOS users, we recommend **macOS 10.13 (High Sierra)** or newer for full C++17 compatibility and modern security framework support. Using Homebrew, you can install Boost with:
```bash
brew install boost
```
If you encounter compatibility issues with older Boost versions (e.g., `< 1.77.0`), ensure you are using the latest version provided by Homebrew.

## Clone

Type in

```bash
git clone https://github.com/Trojan-Plus-Group/trojan-plus.git
cd trojan/
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

to build, test, and install trojan. If everything goes well you'll be able to use trojan.

The `cmake ..` command can be extended with the following options. None of them selects an SSL library; wolfSSL from the submodule is always linked statically.

- `-DDEFAULT_CONFIG=/path/to/default/config.json`: the default path trojan will look for config (defaults to `${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan/config.json`).
- `ENABLE_MIMALLOC`
    - `-DENABLE_MIMALLOC=ON`: build with mimalloc support for improved performance (default if found).
    - `-DENABLE_MIMALLOC=OFF`: build without mimalloc support.
- `ENABLE_NAT` (Only on Linux)
    - `-DENABLE_NAT=ON`: build with NAT support (default).
    - `-DENABLE_NAT=OFF`: build without NAT support.
- `ENABLE_REUSE_PORT` (Only on Linux)
    - `-DENABLE_REUSE_PORT=ON`: build with `SO_REUSEPORT` support (default).
    - `-DENABLE_REUSE_PORT=OFF`: build without `SO_REUSEPORT` support.
- `ENABLE_QUIC` (Experimental)
    - `-DENABLE_QUIC=ON`: build QUIC/HTTP3 from the `wolfssl`, `ngtcp2`, and `nghttp3` submodules (default).
    - `-DENABLE_QUIC=OFF`: build without QUIC support.
- `ENABLE_SSL_KEYLOG` (DEBUG ONLY; exposes TLS master secrets)
    - `-DENABLE_SSL_KEYLOG=ON`: build with SSL KeyLog support. wolfSSL is still built with `WOLFSSL_KEYLOG_EXPORT=no` (forced). While `ENABLE_QUIC` is on, the KeyLog callback is not installed.
    - `-DENABLE_SSL_KEYLOG=OFF`: build without SSL KeyLog support (default). `./trojan --version` then reports `[Disabled] SSL KeyLog Support`.
- `ENABLE_TLS13_CIPHERSUITES`
    - `-DENABLE_TLS13_CIPHERSUITES=ON`: build with TLS1.3 ciphersuites support (default). wolfSSL TLS 1.3 itself is always compiled in (`WOLFSSL_TLS13=yes`).
    - `-DENABLE_TLS13_CIPHERSUITES=OFF`: build without TLS1.3 ciphersuites support.
- `FORCE_TCP_FASTOPEN`
    - `-DFORCE_TCP_FASTOPEN=ON`: force build with `TCP_FASTOPEN` support.
    - `-DFORCE_TCP_FASTOPEN=OFF`: build with `TCP_FASTOPEN` support based on system capabilities (default).
- `SYSTEMD_SERVICE`
    - `-DSYSTEMD_SERVICE=AUTO`: detect systemd automatically and decide whether to install service (default).
    - `-DSYSTEMD_SERVICE=ON`: install systemd service unconditionally.
    - `-DSYSTEMD_SERVICE=OFF`: don't install systemd service unconditionally.
- `-DSYSTEMD_SERVICE_PATH=/path/to/systemd/system`: the path to which the systemd service will be installed (defaults to `/lib/systemd/system`).

## Android Build

To build the Android shared library (.so), you need the Android NDK.

### Dependencies

- Android NDK >= r19 (tested with r23b)

### Build

1. Ensure you have the precompiled Android libraries in the `trojan-plus-android-libs` directory. CMake links Boost from there (`libboost_system` and `libboost_program_options`). TLS is the `wolfssl` submodule, built and linked statically.

2. Run the build script:

```bash
./build_android_so.sh /path/to/android-ndk
```

This will build the library for multiple architectures (armeabi-v7a, arm64-v8a, x86, x86_64) and output the .so files to `android_lib/<arch>/libtrojan.so`.

Options:
- Add `-r` for clean build: `./build_android_so.sh /path/to/android-ndk -r`

## iOS Build

To build the iOS static library (.a) and XCFramework for use in iOS applications (e.g., MAUI apps).

### Dependencies

- Xcode (tested with Xcode 17.0+)
- CMake >= 3.20
- Pre-built Boost 1.85.0 in the `trojan-plus-ios-libs` submodule (`libboost_system` and `libboost_program_options`). TLS is the `wolfssl` submodule, built by CMake.

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
- Add `-r` for clean build

## macOS Build

To build the macOS static library (.a) and XCFramework for use in macOS applications (e.g., MAUI apps).

### Dependencies

- Xcode (tested with Xcode 17.0+)
- CMake >= 3.20
- Boost via Homebrew. TLS is the `wolfssl` submodule, built by CMake:

```bash
brew install boost
```

### Build

```bash
./make_macos.sh /Applications/Xcode.app -r
```

This will build for the current architecture (arm64 on Apple Silicon, x86_64 on Intel) and create an XCFramework at `macos_lib/trojan.xcframework`.

Options:
- Add `-r` for clean build

**Note**: To create a universal binary with both arm64 and x86_64, build on both types of Macs and combine the libraries using `lipo`.

## Docker Build Environment

To ensure a consistent build environment and run tests easily, you can use the provided Docker scripts. These scripts use a Debian trixie image with all necessary dependencies pre-installed (including mimalloc).

### 1. Build the Docker Image
First, build the local Docker image (`trojan-builder`):

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

This script will:
1.  Clean previous build artifacts.
2.  Configure CMake with `-DENABLE_MIMALLOC=ON`.
3.  Compile the project.
4.  Run the full Python integration test suite (excluding DNS tests).

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
runner's default route intact. Linux CI runs as root. macOS/Windows report an explicit DNS skip
only when binding the local fixture fails (for example, privileged port access
or another DNS service).

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
