# Gemini Project Context: trojan-plus

This document provides a comprehensive overview of the `trojan-plus` project, generated to guide future development and maintenance.

## Project Overview

`trojan-plus` is a C++ proxy server designed to bypass network firewalls. It is a fork of the original [trojan](https://github.com/trojan-gfw/trojan) project, maintaining compatibility while introducing several experimental features:

*   **UDP over NAT**: Enhanced support for UDP traffic in NAT mode.
*   **Pipeline Mode**: A feature to decrease connection latency.
*   **Load Balancing**: Distributes traffic across multiple servers to increase bandwidth.
*   **ICMP Proxying**: Ability to proxy ICMP messages (like `ping`).

The project is built using CMake and is intended to be cross-platform, with specific build configurations for Linux, macOS, and Windows. It can function as a client, a server, or in specialized modes like `forward` (port forwarding) and `nat` (transparent proxy).

## Building and Running

### Dependencies

To build the project, the following dependencies are required:

*   A C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
*   CMake (>= 3.7.2)
*   Boost (>= 1.72.0)
*   OpenSSL (>= 1.1.0)
*   (Optional) MySQL/MariaDB client library for database authentication.

On Debian-based systems, these can be installed with:
`sudo apt -y install build-essential cmake libboost-system-dev libboost-program-options-dev libssl-dev default-libmysqlclient-dev`

### Build Commands

The standard build process uses CMake:

```bash
# Create a build directory
mkdir build
cd build

# Configure the project
cmake ..

# Compile the source code
make -j$(nproc)

# The executable will be created at ./trojan
```

The `azure-pipelines.yml` file contains more detailed build configurations and platform-specific flags, which can be referenced for advanced build setups.

### Running

The `trojan` executable is configured and run using a JSON file.

```bash
# Run trojan with a specific configuration
./trojan -c /path/to/config.json

# Run a configuration test
./trojan -t -c /path/to/config.json

# Print version and build information
./trojan -v
```

Configuration examples can be found in the `examples/` directory. The main `run_type` values are `client`, `server`, `forward`, and `nat`.

## Testing

The project includes both smoke tests and a more comprehensive "full test" suite.

*   **Smoke Tests**: These are integrated with CMake's CTest framework.
    ```bash
    # After building, run from the build directory
    ctest
    ```
*   **Full Tests**: A Python-based test suite located in `tests/LinuxFullTest/`. These are run in the CI pipeline as seen in `azure-pipelines.yml` and provide more in-depth testing of different modes.
    ```bash
    # Example from CI pipeline
    cd tests/LinuxFullTest/
    sudo python3.8 fulltest_main.py /path/to/build/trojan -g -d 5333
    ```

## Development Conventions

*   **Coding Style**: The project enforces a specific C++ coding style using `.clang-format`. The style is based on the LLVM format with an indent width of 4 spaces.
*   **Project Philosophy**: As stated in the `README.md`, `trojan-plus` prioritizes adding effective features over maintaining project simplicity, which is a key difference from the original `trojan` project.
*   **Configuration**: All runtime configuration is managed through JSON files. Documentation for the configuration options is available in `docs/config.md`.

## Recent Changes and Fixes (January 2026)

### macOS CI Build Repair
Fixed a critical failure in the macOS CI pipeline caused by environmental changes in Homebrew and system utilities.

*   **OpenSSL Upgrade**: Switched from the deprecated `openssl@1.1` to the current `openssl` (v3.x). Updated `azure-pipelines.yml` to use `brew --prefix openssl` to dynamically locate the library paths, ensuring compatibility with OpenSSL 3.
*   **Build Robustness**: Replaced the Linux-specific `nproc` command with the macOS-native `sysctl -n hw.ncpu` for parallel compilation in the CI script.
*   **Verification**: The changes were verified with a successful local build on macOS using the updated configuration.

