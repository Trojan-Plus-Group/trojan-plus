# Build

We'll only cover the build process on Linux since we will be providing Windows and macOS binaries. Building trojan on every platform is similar.

## Dependencies

Install these dependencies before you build:

- [CMake](https://cmake.org/) >= 3.10.2
- [Boost](http://www.boost.org/) >= 1.72.0 (1.80.0+ recommended for stable async_wait support)
- [OpenSSL](https://www.openssl.org/) >= 1.1.0

For Debian users, run `sudo apt -y install build-essential cmake libboost-system-dev libboost-program-options-dev libssl-dev` to install all the necessary dependencies.

For macOS users, we recommend **macOS 10.13 (High Sierra)** or newer for full C++17 compatibility and modern security framework support. Using Homebrew, you can install Boost with:
```bash
brew install boost
```
If you encounter compatibility issues with older Boost versions (e.g., `< 1.72.0`), ensure you are using the latest version provided by Homebrew.

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

## Docker Build Environment

To ensure a consistent build environment and run tests easily, you can use the provided Docker scripts. These scripts use a lightweight Alpine Linux image with all necessary dependencies pre-installed (including mimalloc).

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

The `cmake ..` command can be extended with the following options:

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
- `ENABLE_SSL_KEYLOG` (OpenSSL >= 1.1.1)
    - `-DENABLE_SSL_KEYLOG=ON`: build with SSL KeyLog support (default).
    - `-DENABLE_SSL_KEYLOG=OFF`: build without SSL KeyLog support.
- `ENABLE_TLS13_CIPHERSUITES` (OpenSSL >= 1.1.1)
    - `-DENABLE_TLS13_CIPHERSUITES=ON`: build with TLS1.3 ciphersuites support (default).
    - `-DENABLE_TLS13_CIPHERSUITES=OFF`: build without TLS1.3 ciphersuites support.
- `FORCE_TCP_FASTOPEN`
    - `-DFORCE_TCP_FASTOPEN=ON`: force build with `TCP_FASTOPEN` support.
    - `-DFORCE_TCP_FASTOPEN=OFF`: build with `TCP_FASTOPEN` support based on system capabilities (default).
- `SYSTEMD_SERVICE`
    - `-DSYSTEMD_SERVICE=AUTO`: detect systemd automatically and decide whether to install service (default).
    - `-DSYSTEMD_SERVICE=ON`: install systemd service unconditionally.
    - `-DSYSTEMD_SERVICE=OFF`: don't install systemd service unconditionally.
- `-DSYSTEMD_SERVICE_PATH=/path/to/systemd/system`: the path to which the systemd service will be installed (defaults to `/lib/systemd/system`).

After installation, config examples will be installed to `${CMAKE_INSTALL_DOCDIR}/examples/` and a server config will be installed to `${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan/config.json`.

[Homepage](.) | [Prev Page](config) | [Next Page](usage)
