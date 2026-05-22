# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Trojan Plus is a C++17 proxy server compatible with the original trojan protocol, with experimental features including UDP NAT, Pipeline Mode (latency reduction), Load Balancing, and ICMP proxying. It can operate as a client, server, or in specialized modes (forward, nat).

The project prioritizes performance and features over simplicity, using a multi-process model with SO_REUSEPORT for horizontal scaling rather than multi-threading.

## Build System

### Prerequisites

- C++17 compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake >= 3.10.2
- Boost >= 1.72.0 (1.80.0+ recommended)
- wolfSSL (via submodule)
- Git submodules (badvpn, GSL, mimalloc)

**CRITICAL**: Always initialize git submodules before building:
```bash
git submodule update --init --recursive
```

### Build Commands

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)  # Linux
make -j$(sysctl -n hw.ncpu)  # macOS
```

### Key CMake Options

- `-DENABLE_MIMALLOC=ON/OFF`: Enable mimalloc allocator (default ON, recommended)
- `-DENABLE_NAT=ON/OFF`: NAT support (Linux only, default ON)
- `-DENABLE_REUSE_PORT=ON/OFF`: SO_REUSEPORT support (Linux only, default ON)
- `-DENABLE_SSL_KEYLOG=ON/OFF`: SSL KeyLog support (default ON)
- `-DFORCE_TCP_FASTOPEN=ON/OFF`: Force TCP Fast Open support

### Docker Build Environment

For consistent builds and testing:
```bash
./scripts/build_docker.sh          # Build local image
./scripts/compile_and_test.sh      # Compile and run full tests in container
./scripts/push_to_docker_hub.sh    # Push to Docker Hub (maintainers only)
```

## Testing

Located in `tests/LinuxFullTest/`, requires Python 3 with PySocks, psutil, dnspython.

**Linux**:
```bash
cd tests/LinuxFullTest/
sudo python3 fulltest_main.py /path/to/build/trojan -g -d 5333
# TUN mode test (requires root):
sudo python3 fulltest_main.py /path/to/build/trojan -t -n -d 5333
```

**macOS**:
```bash
cd tests/LinuxFullTest/
python3 -m pip install PySocks psutil dnspython --break-system-packages
python3 fulltest_main.py /path/to/build/trojan -g -n
```

**Windows**:
```bash
cd tests/LinuxFullTest/
py -3 -m pip install PySocks psutil dnspython
py -3 fulltest_main.py /path/to/build/trojan.exe -g -n -d 5333
```

**QUIC tests**:
```bash
cd tests/LinuxFullTest/
python3 fulltest_main.py ../../build/trojan -q

# Run a single QUIC test case
python3 fulltest_main.py ../../build/trojan -q T4
python3 fulltest_main.py ../../build/trojan -q T15
```

## Architecture

### Core Components

- **src/core/**: Service orchestration, configuration, logging, pipeline management, ICMP daemon
- **src/session/**: Session implementations (ClientSession, ServerSession, NATSession, ForwardSession, PipelineSession, UDPForwardSession)
- **src/proto/**: Protocol handlers (TrojanRequest, SOCKS5Address, UDPPacket, PipelineRequest, DNS/ICMP/IPv4/IPv6 headers)
- **src/ssl/**: SSL/TLS session management
- **src/tun/**: TUN device handling with lwip integration, DNS server, UDP forwarder
- **src/quic/**: QUIC transport implementation via ngtcp2 + nghttp3 + wolfSSL + boost.beast(http protocol parsing) 
- **src/mem/**: Custom memory allocator system

### Session Architecture

The Service class manages an io_context and creates Session objects for each connection. Sessions are polymorphic (ClientSession, ServerSession, etc.) and handle protocol-specific logic. All sessions inherit from the base Session class which provides UDP garbage collection timers and pipeline component integration.

### Run Modes

Configured via `run_type` in JSON config:
- **client**: SOCKS5/HTTP proxy client connecting to trojan server
- **server**: Trojan server accepting client connections
- **forward**: Port forwarding mode
- **nat**: Transparent proxy mode (Linux only, requires NAT support)

### Concurrency Model

**Multi-Process over Multi-Threading**: The project uses SO_REUSEPORT to run multiple independent processes on the same port, leveraging kernel-level load balancing (4-tuple hashing). This provides process isolation, lock-free execution, and better fault tolerance than shared-memory multi-threading.

To scale: run multiple instances with `"reuse_port": true` in config.

## Code Conventions

### Custom Memory Allocator

The codebase uses custom `tp::` containers instead of `std::` for memory tracking:
- `tp::string`, `tp::vector`, `tp::map`, `tp::list`, `tp::set`, `tp::unordered_map`, `tp::unordered_set`, `tp::deque`, `tp::queue`, `tp::stack`, `tp::priority_queue`
- `tp::to_string()` for conversions (uses std::to_chars)
- `tp::ifstream`, `tp::ofstream`, `tp::fstream`, `tp::stringstream`, etc.

**When writing new code**: Use `tp::` containers and include `mem/memallocator.h` at the top of files.

### Code Style

- Enforced via `.clang-format` (LLVM-based, 4-space indent)
- No `using namespace std;` - use explicit `std::` prefixes
- Use `snprintf` instead of `sprintf` for security
- Modern Boost.Asio: `async_wait()` instead of deprecated `null_buffers()`

### Platform-Specific Code

- NAT mode: Linux only (uses iptables/netfilter)
- SO_REUSEPORT: Linux only (kernel 4.5+ recommended for best load balancing)
- TUN device: Platform-specific implementations (uses badvpn's lwip)
- macOS: Uses CoreFoundation and Security frameworks

## Configuration

Runtime configuration via JSON files in `examples/`:
- `client.json-example`: Client mode configuration
- `server.json-example`: Server mode configuration (installed to /etc/trojan/config.json)
- `forward.json-example`: Forward mode configuration
- `nat.json-example`: NAT mode configuration

See `docs/config.md` for full configuration documentation.

## Dependencies

### Submodules

- **badvpn**: Provides lwip (lightweight IP stack) for TUN device handling
- **GSL**: Microsoft's Guidelines Support Library for modern C++ patterns
- **mimalloc**: Microsoft's high-performance memory allocator (bundled, compiled from source)
- **ngtcp2**: QUIC transport protocol (patched in `build/ngtcp2_patched/` for MSVC `_Generic` compatibility)
- **nghttp3**: HTTP/3 implementation used by QUIC transport

### External Libraries

- **Boost**: Uses program_options, asio (io_context, ssl, timers, sockets), beast (HTTP protocol parsing)
- **wolfSSL**: SSL/TLS implementation, integrated with ngtcp2 via `SSL_set_quic_method` for QUIC TLS

## Running

```bash
./trojan -c /path/to/config.json     # Run with config
./trojan -t -c /path/to/config.json  # Test config
./trojan -v                          # Print version
```
