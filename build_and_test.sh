#!/bin/bash

# Trojan Plus Unified Build and Platform-Aware Test Script

# 1. Standard Build (Using default CMake configuration)
echo "--- Building trojan-plus ---"
mkdir -p build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

if [ $? -ne 0 ]; then
    echo "Error: Compilation failed!"
    exit 1
fi
cd ..

# 2. Dependency Check
echo "--- Checking dependencies ---"
PIP_FLAGS="--quiet"
[[ "$OSTYPE" == "darwin"* ]] && PIP_FLAGS="$PIP_FLAGS --break-system-packages"
python3 -m pip install PySocks psutil dnspython $PIP_FLAGS

# 3. Platform-Aware Testing with Real-time Logging
echo "--- Running Integration Tests ---"
cd tests/LinuxFullTest/

# Define arguments based on runtime platform
TEST_ARGS="../../build/trojan -g"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux setup
    TEST_ARGS="$TEST_ARGS -n -d 5333"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS setup
    TEST_ARGS="$TEST_ARGS -n"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    # Windows setup
    TEST_ARGS="$TEST_ARGS -n -d 5333"
fi

# Run python with -u for unbuffered output to see logs in real-time
# Output is displayed on terminal and saved to test.log
python3 -u fulltest_main.py $TEST_ARGS
