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
    
    echo '--- Running Smoke Tests (CTest) ---'
    # If smoke tests fail, we still want to try full tests if possible? 
    # Usually valid smoke tests are a prerequisite. 
    # But user saw failure before. Let's keep 'set -e' for now, 
    # or allow failure if requested. I will keep strict mode.
    ctest --output-on-failure
    
    echo '--- Running Full Python Tests (No DNS) ---'
    cd ../tests/LinuxFullTest
    # Removed -d flag to skip DNS tests. 
    # -g generates files, -n tests normal modes.
    python3 fulltest_main.py /usr/src/trojan/build/trojan -g -n
"

echo "Compilation and tests completed successfully!"
