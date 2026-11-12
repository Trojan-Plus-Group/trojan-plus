#!/usr/bin/env python3
"""Build/run real QUIC endpoint regressions with production dependencies.

python3 tests/test_quic_udp_gso_runtime.py --build-dir OUTSIDE_REPOSITORY
Optional --sanitize instruments all production C/C++ sources with ASan/UBSan.
CMAKE_ARGS supplies platform dependency locations, like a normal project build.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=os.environ.get("QUIC_GSO_TEST_BUILD_DIR"))
    parser.add_argument("--binary", type=Path, default=os.environ.get("QUIC_GSO_TEST_BINARY"),
                        help="run an already built runtime fixture")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        print("SKIP real UDP GSO runtime regression: Linux UDP_SEGMENT required")
        return
    if args.build_dir is None and args.binary is None:
        args.build_dir = Path(tempfile.mkdtemp(prefix="tp-quic-gso-runtime-"))
    output = args.build_dir.resolve() if args.build_dir else args.binary.resolve().parent
    if output == ROOT or ROOT in output.parents:
        parser.error("build directory must be outside repository")
    output.mkdir(parents=True, exist_ok=True)
    binary = args.binary.resolve() if args.binary else output / "build/trojan"
    if args.binary is None:
        wrapper = output / "source"
        wrapper.mkdir(exist_ok=True)
        # Patch only the entry point after the normal root project is configured.
        hook = wrapper / "runtime.cmake"
        hook.write_text(f'''if(CMAKE_CURRENT_SOURCE_DIR STREQUAL "{ROOT.as_posix()}")
function(runtime_entry)
get_target_property(sources trojan SOURCES)
list(FILTER sources EXCLUDE REGEX "(^|/)main[.]cpp$")
list(APPEND sources "{ROOT.as_posix()}/tests/test_quic_udp_gso_runtime.cpp")
set_property(TARGET trojan PROPERTY SOURCES "${{sources}}")
target_compile_definitions(trojan PRIVATE TP_QUIC_GSO_TEST=1)
endfunction()
cmake_language(DEFER CALL runtime_entry)
endif()
''')
        command = ["cmake", "-S", str(ROOT), "-B", str(output / "build"),
                   f"-DCMAKE_PROJECT_INCLUDE={hook}", "-DCMAKE_BUILD_TYPE=Debug", "-DENABLE_QUIC=ON"]
        if args.sanitize:
            flags = "-fsanitize=address,undefined -fno-omit-frame-pointer"
            command += ["-DENABLE_MIMALLOC=OFF", f"-DCMAKE_C_FLAGS={flags}", f"-DCMAKE_CXX_FLAGS={flags}",
                        "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"]
        subprocess.run(command + shlex.split(os.environ.get("CMAKE_ARGS", "")), check=True)
        subprocess.run(["cmake", "--build", str(output / "build"), "--parallel",
                        os.environ.get("CMAKE_BUILD_PARALLEL_LEVEL", "2")], check=True)
    with tempfile.TemporaryDirectory(prefix="runtime-fixture-", dir=output) as temporary:
        directory = Path(temporary)
        key, cert = directory / "key.pem", directory / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        paths = []
        for role in ("server", "client"):
            config = json.loads((ROOT / f"tests/LinuxFullTest/config/quic_{role}_config.json").read_text())
            config["ssl"]["cert"] = str(cert)
            config["ssl"]["key"] = str(key)
            config["ssl"].pop("key_password", None)
            config["ssl"]["verify"] = False
            config["ssl"]["fingerprint"] = "none"
            config["quic"]["udp_gso"] = True
            path = directory / f"{role}.json"
            path.write_text(json.dumps(config))
            paths.append(str(path))
        log = output / ("runtime-" + str(os.getpid()) + ".log")
        with log.open("w") as stream:
            result = subprocess.run([str(binary)] + paths, timeout=90,
                                    stdout=stream, stderr=subprocess.STDOUT, text=True)
        text = log.read_text()
        print(text, end="")
        result.check_returncode()
        assert text.count("QUIC UDP send failed: errno=") == 1, "expected exactly one send WARN"
        assert "initial ngtcp2_conn_read_pkt: ERR_CRYPTO" in text, "Initial must fail with NGTCP2_ERR_CRYPTO"
        assert "QUIC aggregate write: ERR_CLOSING" in text, "native CLOSING path not exercised"
        assert "QUIC aggregate write: ERR_DRAINING" in text, "native DRAINING path not exercised"


if __name__ == "__main__":
    main()
