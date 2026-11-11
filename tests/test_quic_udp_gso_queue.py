#!/usr/bin/env python3
"""Compile/run production UDP queue and loss-timer helper checks; no binary needed."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="tp-quic-gso-queue-") as directory:
        binary = Path(directory) / "queue"
        compiler = shlex.split(os.environ.get("CXX", "c++"))
        command = compiler + ["-std=c++17", "-Wall", "-Wextra", "-DTROJAN_QUIC_STATS=1",
                              "-I" + str(ROOT / "src"),
                              str(ROOT / "tests/test_quic_udp_gso_queue.cpp"), "-o", str(binary)]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True, timeout=10)
    print("PASS QUIC UDP GSO production queue and timer helpers")


if __name__ == "__main__":
    main()
