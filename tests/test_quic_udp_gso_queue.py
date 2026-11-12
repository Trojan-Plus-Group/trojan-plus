#!/usr/bin/env python3
"""Compile/run production UDP queue and loss-timer helper checks; no binary needed."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
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
        subprocess.run([str(binary)], check=True, timeout=60)
        if not sys.platform.startswith("linux"):
            print("PASS QUIC UDP GSO timer helpers; SKIP Linux-only cross-TU stats layout")
            return
        # Layout must match source-specific stats instrumentation across translation units.
        types = Path(directory) / "layout.h"
        types.write_text('''#include "quic/quic_udp_gso.h"
#include <deque>
#include <memory>
#include <vector>
struct LayoutPacket {
    std::vector<uint8_t> bytes;
    std::size_t segment{1};
    std::size_t offset{0};
};
using LayoutQueue = quic_udp_gso::Queue<std::deque<LayoutPacket>>;
using LayoutPool = quic_udp_gso::BufferPool<std::unique_ptr<uint8_t[]>>;
''')
        layout = Path(directory) / "layout.cpp"
        layout.write_text('''#include "layout.h"
std::size_t queue_layout_size() { return sizeof(LayoutQueue); }
std::size_t pool_layout_size() { return sizeof(LayoutPool); }
''')
        stats = Path(directory) / "stats.cpp"
        stats.write_text('''#include "layout.h"
std::size_t queue_layout_size();
std::size_t pool_layout_size();
int main() {
    assert(queue_layout_size() == sizeof(LayoutQueue));
    assert(pool_layout_size() == sizeof(LayoutPool));
}
''')
        common = compiler + ["-std=c++17", "-Wall", "-Wextra",
                             "-DTROJAN_QUIC_STATS_LAYOUT=1", "-I" + str(ROOT / "src")]
        layout_object = Path(directory) / "layout.o"
        stats_object = Path(directory) / "stats.o"
        subprocess.run(common + ["-c", str(layout), "-o", str(layout_object)], check=True)
        subprocess.run(common + ["-DTROJAN_QUIC_STATS=1", "-c", str(stats),
                                 "-o", str(stats_object)], check=True)
        layout_binary = Path(directory) / "layout"
        subprocess.run(compiler + [str(layout_object), str(stats_object),
                                   "-o", str(layout_binary)], check=True)
        subprocess.run([str(layout_binary)], check=True, timeout=60)
    print("PASS QUIC UDP GSO production queue, timer helpers and cross-TU stats layout")


if __name__ == "__main__":
    main()
