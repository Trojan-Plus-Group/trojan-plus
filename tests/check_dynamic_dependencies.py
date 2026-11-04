#!/usr/bin/env python3
"""Fail if a built binary imports non-system shared libraries (stdlib only)."""

import argparse
import pathlib
import re
import struct
import subprocess
import sys


def pe_dependencies(binary):
    """Read normal and delay-load PE imports without a VS developer shell."""
    data = binary.read_bytes()

    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError("truncated PE structure")
        return struct.unpack_from(fmt, data, offset)

    if data[:2] != b"MZ":
        raise ValueError("not a PE binary")
    pe = unpack("<I", 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    sections = unpack("<H", pe + 6)[0]
    optional_size = unpack("<H", pe + 20)[0]
    optional = pe + 24
    magic = unpack("<H", optional)[0]
    if magic == 0x20B:
        directory, count_offset = optional + 112, optional + 108
        image_base = unpack("<Q", optional + 24)[0]
    elif magic == 0x10B:
        directory, count_offset = optional + 96, optional + 92
        image_base = unpack("<I", optional + 28)[0]
    else:
        raise ValueError("unsupported PE optional header")
    count = unpack("<I", count_offset)[0]
    header_size = unpack("<I", optional + 60)[0]
    section_table = optional + optional_size

    def offset(rva):
        if 0 < rva < min(header_size, len(data)):
            return rva
        for index in range(sections):
            size, address, raw_size, raw = unpack("<IIII", section_table + index * 40 + 8)
            if address <= rva < address + max(size, raw_size):
                delta = rva - address
                if delta < raw_size and raw + delta < len(data):
                    return raw + delta
                break
        raise ValueError("invalid PE RVA: 0x%x" % rva)

    dependencies = []
    for index, width in ((1, 20), (13, 32)):
        if count <= index:
            continue
        if directory + (index + 1) * 8 > optional + optional_size:
            raise ValueError("truncated PE data directory")
        rva, size = unpack("<II", directory + index * 8)
        if not rva and not size:
            continue
        if not rva or size < width:
            raise ValueError("invalid PE import directory")
        for position in range(0, size - width + 1, width):
            fields = unpack("<" + "I" * (width // 4), offset(rva + position))
            if not any(fields):
                break
            name_rva = fields[3] if index == 1 else fields[1]
            if index == 13 and not fields[0] & 1:
                name_rva -= image_base
            start = offset(name_rva)
            end = data.find(b"\0", start, start + 4096)
            if end <= start:
                raise ValueError("invalid PE import name")
            dependencies.append(data[start:end].decode("ascii"))
        else:
            raise ValueError("unterminated PE import directory")
    return dependencies


def dependencies(args):
    if args.platform == "windows":
        return pe_dependencies(args.binary)
    if args.platform == "macos":
        output = subprocess.check_output(["otool", "-L", str(args.binary)], text=True)
        print(output, end="")
        result = []
        for line in output.splitlines():
            if line[:1].isspace():
                match = re.fullmatch(r"\s+(.+) \(compatibility version .+\)", line)
                if not match:
                    raise ValueError("unrecognized otool dependency: " + line)
                result.append(match[1])
        return result
    output = subprocess.check_output(
        [args.readelf or "readelf", "-W", "-d", "-l", str(args.binary)], text=True
    )
    print(output, end="")
    result = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", output)
    result += re.findall(r"\[Requesting program interpreter: ([^\]]+)\]", output)
    return result


def allowed(name, platform):
    if platform == "linux":
        return bool(re.fullmatch(r"(?:libc\.so\.6|libm\.so\.6|(?:(?:/[^/]+)*/)?ld-linux[^/]*\.so\.[0-9]+)", name))
    if platform == "android":
        return name in {"liblog.so", "libm.so", "libdl.so", "libc.so"}
    if platform == "macos":
        return name.startswith(("/usr/lib/", "/System/Library/")) and ".." not in name.split("/")
    name = name.lower()
    return name in {
        "kernel32.dll", "kernelbase.dll", "ntdll.dll", "advapi32.dll",
        "bcrypt.dll", "bcryptprimitives.dll", "crypt32.dll", "cryptbase.dll",
        "ws2_32.dll", "wsock32.dll", "mswsock.dll", "iphlpapi.dll", "dnsapi.dll",
        "secur32.dll", "sspicli.dll", "user32.dll", "shell32.dll",
        "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "shlwapi.dll",
        "gdi32.dll", "userenv.dll", "version.dll", "winmm.dll",
        "normaliz.dll", "ncrypt.dll", "psapi.dll",
    } or bool(re.fullmatch(r"(?:api-ms-win|ext-ms-win)-(?!crt-)[a-z0-9-]+\.dll", name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("platform", choices=("linux", "windows", "macos", "android"))
    parser.add_argument("--readelf", help="readelf or Android NDK llvm-readelf path")
    args = parser.parse_args()
    try:
        names = sorted(set(dependencies(args)))
        print("Dynamic dependencies (%s):" % args.platform, flush=True)
        for name in names:
            print("  " + name, flush=True)
        rejected = [name for name in names if not allowed(name, args.platform)]
        if rejected:
            raise ValueError("non-system dependencies: " + ", ".join(rejected))
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        print("Dependency check failed: " + str(error), file=sys.stderr)
        return 1
    print("System-only dynamic dependencies verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
