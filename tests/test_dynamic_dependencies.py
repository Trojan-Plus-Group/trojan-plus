#!/usr/bin/env python3
"""Run with python3 tests/test_dynamic_dependencies.py; no compiler required."""

import pathlib
import struct
import subprocess
import sys
import tempfile

from check_dynamic_dependencies import allowed, pe_dependencies


def make_pe(normal, delayed, *, pe32=False, delay_va=False):
    """One .idata section, two import tables, and one function per DLL."""
    data = bytearray(0x600)

    def put(fmt, offset, *values):
        struct.pack_into(fmt, data, offset, *values)

    data[:2] = b"MZ"
    put("<I", 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 224 if pe32 else 240
    put("<HHIIIHH", 0x84, 0x14C if pe32 else 0x8664, 1, 0, 0, 0,
        optional_size, 0x102 if pe32 else 0x22)
    optional = 0x98
    put("<H", optional, 0x10B if pe32 else 0x20B)
    image_base = 0x400000 if pe32 else 0x140000000
    put("<I" if pe32 else "<Q", optional + (28 if pe32 else 24), image_base)
    put("<II", optional + 32, 0x1000, 0x200)
    put("<HH", optional + 40, 6, 0)
    put("<HH", optional + 48, 6, 0)
    put("<II", optional + 56, 0x2000, 0x200)
    put("<H", optional + 68, 3)
    directory = optional + (96 if pe32 else 112)
    put("<I", directory - 4, 16)
    put("<II", directory + 8, 0x1000, 40)
    put("<II", directory + 13 * 8, 0x1080, 64)
    section = optional + optional_size
    data[section:section + 8] = b".idata\0\0"
    put("<IIII", section + 8, 0x400, 0x1000, 0x400, 0x200)
    put("<I", section + 36, 0xC0000040)
    put("<IIIII", 0x200, 0x1200, 0, 0, 0x1100, 0x1220)
    base = image_base if delay_va else 0
    put("<IIIIIIII", 0x280, 0 if delay_va else 1, base + 0x1140,
        base + 0x1240, base + 0x1260, base + 0x1280, 0, 0, 0)
    for offset, name in ((0x300, normal), (0x340, delayed)):
        encoded = name.encode("ascii") + b"\0"
        assert len(encoded) <= 64
        data[offset:offset + len(encoded)] = encoded
    for offset in (0x400, 0x420, 0x460, 0x480):
        put("<I" if pe32 else "<Q", offset, (base if offset >= 0x460 else 0) + 0x12A0)
    data[0x4A0:0x4A8] = b"\0\0Sleep\0"
    return data


def main():
    cases = {
        "linux": (
            ("libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"),
            ("libstdc++.so.6", "libgcc_s.so.1", "libc.so", "/lib/libc.so.6", "libc.so.6.extra", "ld-linux.so.2/extra", "")),
        "android": (
            ("liblog.so", "libm.so", "libdl.so", "libc.so"),
            ("libc++_shared.so", "libstdc++.so", "libc.so.6", "/system/lib64/libc.so", "LIBC.SO", "")),
        "macos": (
            ("/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/Security.framework/Versions/A/Security"),
            ("@rpath/libc++.dylib", "/usr/local/lib/libfoo.dylib", "/usr/lib/../local/lib/libfoo.dylib", "/System/Library/../../tmp/libfoo.dylib", "/usr/library/libfoo.dylib", "")),
        "windows": (
            ("KERNEL32.dll", "WS2_32.DLL", "WSOCK32.dll", "wsock32.DLL", "MSWSOCK.dll", "USER32.dll", "BCRYPT.dll", "IPHLPAPI.dll", "SECUR32.dll", "NTDLL.dll", "ADVAPI32.dll", "CRYPT32.dll", "api-ms-win-core-synch-l1-2-0.dll", "ext-ms-win-ntuser-window-l1-1-0.dll"),
            ("ucrtbase.dll", "UCRTBASE.dll", "msvcrt.dll", "vcruntime140.dll", "VCRUNTIME140_1.dll", "msvcp140.dll", "MSVCP140_ATOMIC_WAIT.dll", "libssl.dll", "boost_program_options.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "ext-ms-win-crt-runtime-l1-1-0.dll", "C:\\Windows\\System32\\kernel32.dll", "")),
    }
    for platform, (accepted, rejected) in cases.items():
        for name in accepted:
            assert allowed(name, platform), (platform, name)
        for name in rejected:
            assert not allowed(name, platform), (platform, name)

    checker = pathlib.Path(__file__).with_name("check_dynamic_dependencies.py")
    with tempfile.TemporaryDirectory(prefix="dynamic-dependencies-") as temporary:
        binary = pathlib.Path(temporary) / "fixture.exe"
        for pe32, delay_va in ((False, False), (True, False), (True, True)):
            for normal, delayed, rejected in (
                ("KERNEL32.dll", "WSOCK32.dll", None),
                ("wsock32.DLL", "MSWSOCK.dll", None),
                ("MSVCP140.dll", "WSOCK32.dll", "MSVCP140.dll"),
                ("KERNEL32.dll", "libssl.dll", "libssl.dll"),
                ("vcruntime140.dll", "WS2_32.dll", "vcruntime140.dll"),
                ("KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll"),
            ):
                binary.write_bytes(make_pe(normal, delayed, pe32=pe32, delay_va=delay_va))
                assert pe_dependencies(binary) == [normal, delayed]
                result = subprocess.run(
                    [sys.executable, str(checker), str(binary), "windows"],
                    capture_output=True, text=True, timeout=5,
                )
                assert result.returncode == (1 if rejected else 0), result
                if rejected:
                    assert "non-system dependencies: " + rejected in result.stderr, result
                else:
                    assert "System-only dynamic dependencies verified." in result.stdout, result
    print("Dynamic dependency checks passed.")


if __name__ == "__main__":
    main()
