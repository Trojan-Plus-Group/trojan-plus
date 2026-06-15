@echo off
REM Trojan Plus Unified Build and Platform-Aware Test Script for Windows

REM 1. Standard Build (Using CMake)
echo --- Building trojan-plus ---
if not exist build (
    mkdir build
)
cd build
cmake ..
if %ERRORLEVEL% NEQ 0 (
    echo Error: CMake configuration failed!
    exit /b 1
)

REM Use --config Release for multi-config generators like MSVC
cmake --build . --config Release --parallel %NUMBER_OF_PROCESSORS%
if %ERRORLEVEL% NEQ 0 (
    echo Error: Compilation failed!
    exit /b 1
)
cd ..

REM 2. Dependency Check
echo --- Checking dependencies ---
python -m pip install PySocks psutil dnspython aioquic --quiet
if %ERRORLEVEL% NEQ 0 (
    echo Warning: Failed to install some dependencies. Tests might fail.
)

REM 3. Running Integration Tests
echo --- Running Integration Tests ---
cd tests\LinuxFullTest\

REM On Windows, the binary is typically in build/Release/
set TEST_ARGS=../../build/Release/trojan.exe -g -q -n -f

REM Run python with -u for unbuffered output to see logs in real-time
python -u fulltest_main.py %TEST_ARGS%

if %ERRORLEVEL% NEQ 0 (
    echo Error: Tests failed!
    cd ..\..
    exit /b 1
)

cd ..\..
echo --- All steps completed successfully ---
