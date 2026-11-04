#!/usr/bin/env python3
"""Compile/run production Chrome-profile compressed-certificate handshake checks.

Usage: python3 tests/check_chrome_profile.py --build build
Build core first. Outputs retained under /tmp/opencode (including failed runs).
No CMake changes, new framework, network traffic, or keylogs.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def library(build, name):
    matches = sorted(build.rglob("lib" + name + ".a"))
    if not matches:
        raise SystemExit("Missing lib" + name + ".a; build dependencies first")
    if len(matches) != 1:
        raise SystemExit("Ambiguous library: " + ", ".join(map(str, matches)))
    return str(matches[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build")
    parser.add_argument("--host", help="Optional verified TLS-only probe to HOST:443; no authentication")
    parser.add_argument("--ca", type=Path, help="CA bundle required with --host")
    args = parser.parse_args()
    if bool(args.host) != bool(args.ca):
        parser.error("--host and --ca must be supplied together")
    build = args.build.resolve()
    entries = json.loads((build / "compile_commands.json").read_text())
    entry = next(item for item in entries if item["file"].endswith("/src/ssl/chrome_profile.cpp"))
    command = entry.get("arguments") or shlex.split(entry["command"])
    # Reuse real compiler/include options, but use libc allocator in standalone check.
    flags = []
    skip = False
    for value in command[1:]:
        if skip:
            skip = False
        elif value in ("-o", "-MF", "-MT", "-MQ"):
            skip = True
        elif value not in ("-c", "-MD", "-MMD", "-MP", "-DENABLE_MIMALLOC") and value != entry["file"]:
            flags.append(value)
    output = Path(tempfile.mkdtemp(prefix="chrome-profile-", dir="/tmp/opencode"))
    executable = output / "check_chrome_profile"
    compile_command = [os.environ.get("CXX", command[0]), *flags,
                       "-I" + str(ROOT / "brotli/c/include"),
                       str(ROOT / "tests/check_chrome_profile.cpp"),
                       str(ROOT / "src/ssl/chrome_profile.cpp"),
                       str(ROOT / "src/mem/memallocator.cpp"),
                       library(build, "ssl"), library(build, "crypto"),
                       library(build, "brotlienc"), library(build, "brotlidec"),
                       library(build, "brotlicommon"), "-pthread", "-ldl", "-o", str(executable)]
    (output / "command.txt").write_text(shlex.join(compile_command) + "\n")
    print("Evidence: " + str(output), flush=True)
    with (output / "compile.log").open("w") as log:
        subprocess.run(compile_command, cwd=entry["directory"], stdout=log,
                       stderr=subprocess.STDOUT, check=True, timeout=180)
    fixtures = ROOT / "tests/LinuxFullTest/config"
    with (output / "run.log").open("w") as log:
        subprocess.run([str(executable), str(fixtures / "server.crt"), str(fixtures / "server.key")],
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=15)
    print((output / "run.log").read_text(), end="")
    if args.host:
        with (output / "external.log").open("w") as log:
            subprocess.run([str(executable), "--host", args.host, "--ca", str(args.ca.resolve())],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=20)
        print((output / "external.log").read_text(), end="")


if __name__ == "__main__":
    main()
