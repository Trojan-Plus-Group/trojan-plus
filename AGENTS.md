# Trojan Plus - Development Context

`trojan-plus` is a high-performance C++17 proxy server compatible with the original Trojan protocol. It is optimized for cross-platform deployment (Linux, macOS, Windows, Android, iOS) and incorporates key experimental features:
- **QUIC / HTTP3** - Trojan-over-QUIC transport via ngtcp2 + nghttp3 + wolfSSL, supporting HTTP/1.1 and HTTP/3 upstream fallback
- **UDP over NAT** - High-speed transparent UDP proxy
- **Pipeline Mode** - Request pipelining to minimize latency
- **Load Balancing** - Multi-upstream server load balancing and failover
- **TUN Mode** - Integrated lwIP user-space TCP/IP stack with transparent TUN proxying and built-in DNS server
- **ICMP Proxying** - ICMP echo/reply proxying daemon
- **Custom Memory Pool** - Fine-grained memory tracking and mimalloc allocator integration

### Run Modes (`run_type`)
- `client`: SOCKS5 local client mode
- `server`: Server mode accepting Trojan connections, with HTTP/HTTPS fallback
- `forward`: Port forwarding proxy mode
- `nat`: Transparent proxy via Linux netfilter/iptables NAT (Linux only)
- `client_tun`: TUN interface transparent proxy mode (Linux / mobile platforms)

### Target Artifacts
- **Executable**: Standalone CLI binary (`trojan` / `trojan.exe`)
- **Shared Library (`.so`)**: Android JNI library (`libtrojan.so`) with JNI exports in `com.trojan_plus.android.TrojanPlusVPNService`
- **Static Library / Framework (`.a` / `.xcframework`)**: iOS / macOS library (`libtrojan.a` / `trojan.xcframework`) exposing unified C exports in [src/platform_exports.h](src/platform_exports.h) (`trojan_run_main`, `trojan_stop_main`, `trojan_get_version`)

---

## Build

### Prerequisites
- **C++17 Compiler**: GCC >= 7.0, Clang >= 5.0, AppleClang, or MSVC >= 2017 (15.7+)
- **CMake**: >= 3.20
- **Boost**: >= 1.72.0 (recommended 1.80.0+, program_options required)
- **Submodules / Included**: wolfSSL, ngtcp2, nghttp3, mimalloc, GSL, badvpn (lwIP)
- **Mobile SDKs**: Android NDK >= r23b (Android); Xcode with iOS SDK (iOS)
- **Test Dependencies**: Python 3 with `PySocks`, `psutil`, `dnspython`, `aioquic`

### Quick Build & Test Scripts
The repository provides unified platform-aware scripts:
```bash
# macOS / Linux / Windows MSYS (auto-detects CPU count and platform flags)
./build_and_test.sh

# Windows (MSVC batch script)
build_and_test.bat

# Docker (Linux automated build & test)
./build_and_test_docker_linux.sh
```

### Standard CMake Build

```bash
# Initialize submodules
git submodule update --init --recursive

# Linux
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)

# macOS
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(sysctl -n hw.ncpu)

# Windows (MSVC)
cmake -B build
cmake --build build --config Release --parallel
```

### Mobile Platforms
```bash
# Android (.so for arm64-v8a, x86_64, etc.)
./build_android_so.sh /path/to/android-ndk

# iOS (.a static library)
./make_ios.sh

# iOS XCFramework
./make_xcframework_ios.sh
```

### CMake Options
| Option | Default | Description |
| :--- | :--- | :--- |
| `ENABLE_QUIC` | `ON` | Build QUIC/HTTP3 transport via ngtcp2 + nghttp3 + wolfSSL |
| `ENABLE_MIMALLOC` | `ON` | Build and statically link mimalloc allocator |
| `ENABLE_NAT` | `ON` | Build with Linux NAT transparent proxy (Linux only) |
| `ENABLE_REUSE_PORT` | `ON` | Enable `SO_REUSEPORT` socket option (Linux only) |
| `ENABLE_TLS13_CIPHERSUITES` | `ON` | Enable TLS 1.3 ciphersuites support |
| `FORCE_TCP_FASTOPEN` | `OFF` | Force build with TCP Fast Open support |
| `BUILD_LIBRARY` | `OFF` | Build as library without `main()` (auto-enabled on iOS/Android) |
| `ENABLE_SSL_KEYLOG` | `OFF` | Enable SSLKEYLOGFILE export (**DEBUG ONLY** - exposes TLS master secrets) |
| `USE_GUARD_BACKSTACK` | `OFF` | Wrap functions in try/catch for backstack error guarding |
| `ENABLE_ANDROID_LOG` | `ON` | Output logs to Android LogCat (Android only) |
| `ENABLE_IOS_LOG` | `ON` | Output logs to iOS unified logging (iOS only) |

---

## Testing

### 修改后的日常远端验证闭环

用户要求执行本地到远端验证时，严格按以下顺序迭代：

1. 本地修改代码。
2. 本地构建并运行相关 fulltest。
3. 本地测试全部通过后提交本轮代码；提交仅用于用户明确要求的验证流程，禁止 `git push`。
4. 使用 `quic_proxy_test_remote/scripts/sync_remote.py --jobs 1` 通过 git bundle 将远端同名测试分支 `reset --hard` 到本地当前已提交分支；不得 reset 其他分支或执行 `git clean`。
5. 在远端以相同 commit 单线程编译。
6. 执行 `client`、`nat`、`client_tun` 三模式 TCP TLS/强制 QUIC smoke。
7. 六组 smoke、内容校验、协议校验和 cleanup 全部通过，才宣布本轮验证通过。

本地构建或 fulltest 失败时，返回步骤 1 修复；不得提交失败版本。远端同步、编译或多模式 smoke 失败时，保留失败证据，返回步骤 1 修复；本地测试通过后创建新 commit、新 Run ID，再同步和重测。禁止修改或删除原失败结果。

详细命令、安全规则和验收条件见 [quic_proxy_test_remote/AGENTS.md](quic_proxy_test_remote/AGENTS.md)。

Integration tests reside in [tests/LinuxFullTest/](tests/LinuxFullTest/).

### Python Dependencies
```bash
pip install PySocks psutil dnspython aioquic
```

### Running Tests
```bash
cd tests/LinuxFullTest/

# Standard proxy & pipeline test
python3 fulltest_main.py /path/to/build/trojan -g -n

# Linux Full Test with DNS & Root privileges
sudo python3 fulltest_main.py /path/to/build/trojan -g -d 5333

# TUN Mode (requires root / privileges)
sudo python3 fulltest_main.py /path/to/build/trojan -t -n -d 5333

# Server Fallback test
python3 fulltest_main.py /path/to/build/trojan -f

# QUIC Test Suite (runs all QUIC cases T1-T19)
python3 fulltest_main.py /path/to/build/trojan -q

# Run single QUIC test case (e.g. T4)
python3 fulltest_main.py /path/to/build/trojan -q T4

# Direct QUIC test runner
python3 fulltest_quic.py /path/to/build/trojan [all|T1|T2|...|T19]
```
> [!NOTE]
> On macOS, DNS forwarding test (`-d`) is automatically skipped in `fulltest_main.py` due to local macOS resolver timeouts.

### Manual Testing Suite
- [quic_proxy_test/](quic_proxy_test/) - Local manual verification scripts (`start_server.sh`, `start_client.sh`, `start_http1.sh`)
- [quic_proxy_test_remote/AGENTS.md](quic_proxy_test_remote/AGENTS.md) - Required workflow and safety rules for local/remote QUIC baselines, `client`/`nat`/`client_tun` comparisons, stress tests, result retention, and cleanup. Reconfirm remote host settings before every iteration.

---

## Architecture & Directory Layout

### Codebase Organization
- [src/core/](src/core/) - Service instantiation, lifecycle, config parser (`Config`), logging (`Log`), pipeline coordinator, ICMP daemon
- [src/session/](src/session/) - Session implementations:
  - `ClientSession`: Inbound SOCKS5 handling and upstream Trojan forwarding
  - `ServerSession`: Inbound Trojan authentication, proxy tunneling, and fallback dispatch
  - `ForwardSession` / `NATSession`: Port-forwarding and Linux netfilter NAT redirection
  - `PipelineSession` / `PipelineComponent`: Request multiplexing over persistent connections
  - `UDPForwardSession`: UDP packet encapsulation and proxying
- [src/proto/](src/proto/) - Protocol headers and packet parsers: SOCKS5, Trojan protocol, DNS packets, ICMP, IPv4/IPv6 headers
- [src/ssl/](src/ssl/) - wolfSSL context abstraction and TLS handshake logic
- [src/tun/](src/tun/) - TUN interface (`TunDev`), embedded lwIP TCP/IP stack, built-in DNS server, and local UDP forwarder
- [src/quic/](src/quic/) - ngtcp2 + nghttp3 + wolfSSL QUIC transport:
  - `QuicEndpoint`, `QuicClientEndpoint`, `QuicServerEndpoint`: UDP socket event loops, connection demuxing, packet dispatch
  - `QuicConnection`: ngtcp2 connection state machine, packet send/recv loops, crypto callbacks, loss/idle timers
  - `QuicSession`: High-level session translating between SOCKS5/Trojan and QUIC streams
  - [src/quic/h1_upstream/](src/quic/h1_upstream/): HTTP/1.1 and HTTP/3 upstream fallback and connection tunneling
  - `OutboundTransport`: Unified polymorphic transport abstraction
- [src/mem/](src/mem/) - Custom memory allocator wrappers (`tp::` namespace) backed by mimalloc

### Concurrency Model
- **Multi-Process + `SO_REUSEPORT`**: On Linux, Trojan Plus favors multi-process architecture over multi-threading for the core event loop. Each process runs an isolated, lock-free `boost::asio::io_context` bound to shared sockets via `SO_REUSEPORT` for kernel-level load balancing.
- **Single-Threaded Session State**: Session objects operate entirely within their parent `io_context` strand/thread, eliminating mutex contention in data paths.

---

## Submodules

| Submodule | Description |
| :--- | :--- |
| `wolfssl` | Embedded TLS 1.3 / 1.2 library (forked for Trojan Plus) |
| `ngtcp2` | IETF QUIC protocol implementation (forked) |
| `nghttp3` | HTTP/3 protocol implementation (forked) |
| `mimalloc` | High-performance memory allocator (source tree) |
| `badvpn` | lwIP TCP/IP stack wrapper for TUN interface (forked) |
| `GSL` | Microsoft Guidelines Support Library (C++ Core Guidelines) |
| `trojan-plus-android-libs` | Precompiled Boost and dependencies for Android architectures |
| `trojan-plus-ios-libs` | Precompiled Boost and dependencies for iOS device and simulator |

---

## Development & Safety Conventions

### Memory Allocators
**Strict Rule**: Avoid raw `std::` heap containers in performance-sensitive core and session paths. Use the custom `tp::` namespace:
```cpp
#include "mem/memallocator.h"

// Containers
tp::string, tp::vector, tp::map, tp::list, tp::set, tp::unordered_map, ...

// Allocation Macros
TP_NEW(Type, ...) / TP_DELETE(ptr)
TP_NEW_ARR(Type, num) / TP_DELETE_ARR(ptr)
TP_MALLOC(size) / TP_FREE(ptr)
TP_MAKE_UNIQUE(Type, ...) / TP_MAKE_SHARED(Type, ...)

// Asio Handlers
tp::bind_mem_alloc(handler)
```
See [src/mem/memallocator.h](src/mem/memallocator.h).

### Code Style
- Configured via [.clang-format](.clang-format)
- Adhere to Microsoft GSL practices (`gsl::span`, `gsl::narrow_cast`, etc.)

### Critical Git Safety Rule
- **No Unauthorized Git Commit / Push**:
  - **DO NOT** execute `git commit`, `git push`, or alter remote branches without explicit, direct instructions from the user.