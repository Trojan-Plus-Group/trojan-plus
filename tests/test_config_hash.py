#!/usr/bin/env python3
"""Config hashing keeps its signed representation without signed overflow."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = (ROOT / "src/core/utils.cpp").read_text()
    start = source.index("int get_hashCode(")
    end = source.index("\nvoid write_data_to_file", start)
    program = """#include <cassert>
#include <cstring>
#include <string>
#define _guard
#define _unguard
namespace tp { using string = std::string; }
""" + source[start:end] + """
int main() {
    assert(get_hashCode("") == 0);
    assert(get_hashCode("abc") == 96354);
    assert(get_hashCode("127.0.0.1:18080") == -1114069148);
    assert(get_hashCode("127.0.0.1:14651") == -1114182638);
}
"""
    with tempfile.TemporaryDirectory(prefix="tp-config-hash-") as directory:
        cpp = Path(directory) / "hash.cpp"
        binary = Path(directory) / "hash"
        cpp.write_text(program)
        subprocess.run(shlex.split(os.environ.get("CXX", "c++")) +
                       ["-std=c++17", "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                        str(cpp), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
    print("PASS config hash signed representation and overflow check")


if __name__ == "__main__":
    main()
