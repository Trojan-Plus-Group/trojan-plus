#!/bin/bash

# Trojan Plus Unified Build and Platform-Aware Test Script

# 1. Standard Build (Using default CMake configuration)
echo "--- Building trojan-plus ---"
mkdir -p build && cd build
cmake ..

# Detect if we are on Windows (even if using bash) to use correct build config
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    cmake --build . --config Release --parallel $(nproc 2>/dev/null || echo 4)
else
    cmake --build . --parallel $(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
fi

if [ $? -ne 0 ]; then
    echo "Error: Compilation failed!"
    exit 1
fi
cd ..

# 2. Dependency Check
echo "--- Checking dependencies ---"
PIP_FLAGS="--quiet"
[[ "$OSTYPE" == "darwin"* ]] && PIP_FLAGS="$PIP_FLAGS --break-system-packages"

# Use python3 if available, otherwise fallback to python
PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

$PYTHON_CMD -m pip install PySocks psutil dnspython aioquic $PIP_FLAGS

# 3. Platform-Aware Testing with Real-time Logging
echo "--- Running Integration Tests ---"
cd tests/LinuxFullTest/

# Define arguments based on runtime platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux setup
    TEST_ARGS="../../build/trojan -g -q -n -d 5333 -f"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS setup
    TEST_ARGS="../../build/trojan -g -q -n -f"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    # Windows setup
    TEST_ARGS="../../build/Release/trojan.exe -g -q -n -d 5333 -f"
fi

# Run python with -u for unbuffered output to see logs in real-time
# Output is displayed on terminal and saved to test.log
$PYTHON_CMD -u fulltest_main.py $TEST_ARGS

