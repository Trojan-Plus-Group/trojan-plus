#!/bin/bash
set -e

IMAGE_NAME="trojan-builder"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "Running compilation and tests inside the container..."
docker run --rm -v "$(pwd):/usr/src/trojan" $IMAGE_NAME /bin/bash -c "
    set -e
    
    echo '--- Configuring CMake ---'
    # Clean previous build artifacts to ensure a fresh build
    rm -f CMakeCache.txt
    rm -rf CMakeFiles
    rm -rf build
    mkdir -p build
    cd build
    cmake -DENABLE_MIMALLOC=ON ..
    
    echo '--- Building Trojan ---'
    make -j\$(nproc)
    
    echo '--- Running Full Python Tests (Normal + Fallback) ---'
    cd ../tests/LinuxFullTest
    # -g generates files, -n tests normal modes, -f tests server fallback (remote_addr).
    python3 -u fulltest_main.py /usr/src/trojan/build/trojan -g -n -f
"

echo "Compilation and tests completed successfully!"
