#!/bin/bash

# Trojan Plus Docker Build and Test Script for Linux
# This script runs the build and test process inside the trojanplusgroup/centos-build:debian container.

IMAGE_NAME="trojanplusgroup/centos-build:debian"
CONTAINER_NAME="trojan-plus-linux-build"
PROJECT_ROOT="$(pwd)"
BUILD_DIR="linux64-build"

# Ensure build_linux exists locally so it's mapped correctly
mkdir -p "$BUILD_DIR"

echo "--- Starting Docker Container for Build and Test ---"

# We use --privileged for TUN/TAP tests
# We map the current directory to /workspace inside the container
# We explicitly use --platform linux/amd64 for compatibility with Apple Silicon
docker run --rm --privileged -t --platform linux/amd64 \
    -v "$PROJECT_ROOT":/workspace \
    -w /workspace \
    "$IMAGE_NAME" \
    /bin/bash -c "
        set -euo pipefail
        set -v

        echo '--- Building Trojan Plus ---'
        mkdir -p $BUILD_DIR && cd $BUILD_DIR
        cmake -DDEFAULT_CONFIG=config.json -DFORCE_TCP_FASTOPEN=ON -DBoost_USE_STATIC_LIBS=ON -DOPENSSL_USE_STATIC_LIBS=ON -DENABLE_MIMALLOC=ON ..
        make -j\$(nproc)
        cd ..

        echo '--- Running Integration Tests ---'
        BINARY=\"/workspace/$BUILD_DIR/trojan\"
        
        # TUN Mode Tests (Requires privileged mode)
        echo '--- Setting up TUN device for testing ---'
        # Basic network setup similar to CI
        ip tuntap add dev tun0 mode tun user root || true
        ifconfig tun0 10.0.0.1 netmask 255.255.255.0 || true
        ip link set dev tun0 up mtu 1500 txqueuelen 1000 || true
        
        # Identify default gateway to add routes for test targets
        DEFAULT_GW=\$(route -n | grep '0\.0\.0\.0.*UG' | awk '{print \$2}' | head -n 1)
        
        # Add routes (ignore errors if they already exist)
        route add default gw 10.0.0.2 metric 0 || true
        route add 114.114.114.114 gw \"\$DEFAULT_GW\" metric 0 || true
        route add 8.8.8.8 gw \"\$DEFAULT_GW\" metric 0 || true

        echo '--- Running TUN Full Test ---'
        cd tests/LinuxFullTest/
        export PYTHONUNBUFFERED=1
        # python3 -u fulltest_main.py \"\$BINARY\" -t -n -g -f
        python3 -u fulltest_main.py \"\$BINARY\" -t
    "

if [ $? -eq 0 ]; then
    echo "--- Build and Test Successful! ---"
else
    echo "--- Build or Test Failed! ---"
    exit 1
fi
