#!/usr/bin/env python3
"""Compile and run actual logger, allocator and C callback ABI (no test substitutes)."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="log-callback-") as directory:
    binary = Path(directory) / "check"
    command = [
        os.environ.get("CXX", "c++"), "-std=c++17", "-pthread",
        "-DBOOST_ASIO_NO_DEPRECATED", "-I", str(ROOT / "src"),
        "-I", str(ROOT / "GSL/include"),
        str(ROOT / "tests/log_callback_test.cpp"),
        str(ROOT / "src/core/log.cpp"), str(ROOT / "src/mem/memallocator.cpp"),
        "-o", str(binary),
    ]
    subprocess.run(command, check=True)
    subprocess.run([str(binary)], check=True, timeout=30, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    # Exercise actual Android branch on host with only platform output intercepted.
    include = Path(directory) / "android"
    include.mkdir()
    (include / "log.h").write_text(
        '#define ANDROID_LOG_VERBOSE 2\n#define ANDROID_LOG_DEBUG 3\n'
        '#define ANDROID_LOG_WARN 5\n#define ANDROID_LOG_ERROR 6\n'
        '#define ANDROID_LOG_FATAL 7\n'
        'extern "C" int __android_log_print(int, const char*, const char*, ...);\n')
    subprocess.run(command + ["-DENABLE_ANDROID_LOG", "-DTEST_ANDROID_LOG",
                              "-I", directory], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
print("Production log callback: PASS")
