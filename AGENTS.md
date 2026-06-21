# Trojan Plus - Development Context

`trojan-plus` is a high-performance C++17 proxy server compatible with the original Trojan protocol. Experimental features:
- **UDP over NAT** - Transparent UDP proxy
- **Pipeline Mode** - Request pipelining to reduce latency
- **Load Balancing** - Multiple upstream servers
- **ICMP Proxying** - ICMP message proxy
- **QUIC/HTTP3** - Trojan-over-QUIC and HTTP/3 fallback

Run modes (`run_type`): `client`, `server`, `forward`, `nat` (Linux only)

---

## Build

**Prerequisites**:
- C++17 compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake >= 3.20
- Boost >= 1.72.0 (recommended 1.80.0+)
- wolfSSL, ngtcp2, nghttp3 (via submodules)
- Android NDK >= r23b (Android only)

```bash
git submodule update --init --recursive
mkdir build && cd build
cmake ..
make -j$(nproc)      # Linux
make -j$(sysctl -n hw.ncpu)  # macOS
```

**CMake Options**:
- `-DENABLE_MIMALLOC=ON/OFF` (default ON) - mimalloc allocator
- `-DENABLE_NAT=ON/OFF` (default ON, Linux) - NAT transparent proxy
- `-DENABLE_REUSE_PORT=ON/OFF` (default ON, Linux) - `SO_REUSEPORT`
- `-DENABLE_SSL_KEYLOG=ON/OFF` (default OFF) - SSL key logging (debug)
- `-DBUILD_LIBRARY=ON/OFF` (default OFF) - Compile as library (auto for iOS/Android)

**Mobile Platforms**:
```bash
./build_android_so.sh /path/to/ndk        # Android
./make_ios.sh                            # iOS
./make_xcframework_ios.sh               # XCFramework
```

---

## Testing

Integration tests in [tests/LinuxFullTest/](tests/LinuxFullTest/), requires PySocks, psutil, dnspython.

```bash
# Linux (requires root)
sudo python3 fulltest_main.py /path/to/build/trojan -g -d 5333
# TUN mode
sudo python3 fulltest_main.py /path/to/build/trojan -t -n -d 5333

# macOS
python3 fulltest_main.py /path/to/build/trojan -g -n

# QUIC tests
python3 fulltest_main.py /path/to/build/trojan -q

# QUIC tests for single testcase T4
python3 fulltest_main.py /path/to/build/trojan -q T4

# Fallback test
python3 fulltest_main.py /path/to/build/trojan -f
```

**Docker Environment**:
```bash
./scripts/build_docker.sh
./scripts/compile_and_test.sh
```

---

## Architecture

### Directory Layout
- [src/core/](src/core/) - Service instantiation, config loading, logging, pipeline, ICMP daemon
- [src/session/](src/session/) - Session implementations (ClientSession, ServerSession, NATSession, etc.)
- [src/proto/](src/proto/) - SOCKS5/Trojan parsers, DNS, ICMP, IP headers
- [src/ssl/](src/ssl/) - SSL context and TLS handshake
- [src/tun/](src/tun/) - TUN interface, lwIP stack, DNS server
- [src/quic/](src/quic/) - ngtcp2 + nghttp3 + wolfSSL QUIC/HTTP3 wrapper
- [src/mem/](src/mem/) - Memory allocator hooks

### Concurrency Model
Multi-process + `SO_REUSEPORT` (kernel-level load balancing) over threads, ensuring process isolation and lock-free execution. Enable via `"reuse_port": true`.

### Session Architecture
`Service` manages `io_context` and dynamically creates polymorphic `Session` objects. Base `Session` handles garbage collection and pipeline integration.

---

## Submodules
```
badvpn          - lwIP TCP/IP stack (fork)
GSL             - Microsoft GSL
wolfssl         - TLS library (fork)
ngtcp2          - QUIC protocol (fork)
nghttp3         - HTTP/3 (fork)
trojan-plus-android-libs  - Android prebuilt libs
trojan-plus-ios-libs      - iOS prebuilt libs
```

---

## Development Conventions

### Memory Allocators
**Do not** use raw `std::` containers. Use `tp::` namespace.

```cpp
#include "mem/memallocator.h"

// Containers
tp::string, tp::vector, tp::map, tp::list, tp::set, tp::unordered_map, ...

// Allocation
TP_NEW(Type, ...) / TP_DELETE(ptr)
TP_NEW_ARR(Type, num) / TP_DELETE_ARR(ptr)
TP_MALLOC(size) / TP_FREE(ptr)
TP_MAKE_UNIQUE(Type, ...) / TP_MAKE_SHARED(Type, ...)

// Asio handlers
tp::bind_mem_alloc(handler)
```

See [src/mem/memallocator.h](src/mem/memallocator.h)

### Code Style
- `.clang-format` configured
- Follow GSL (Guidelines Support Library) conventions