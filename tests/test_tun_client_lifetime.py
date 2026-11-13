#!/usr/bin/env python3
"""Client dies, session destroy must not call the raw-this close callback.

Also: TUNProxySession padded-write failure + legacy retry must not re-enter its start handler.
Run one scenario with: test_tun_client_lifetime.py [local|proxy|padding_retry]
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    ROOT / "tests/tun_client_lifetime_test.cpp",
    ROOT / "src/tun/lwip_tcp_client.cpp",
    ROOT / "src/tun/tunlocalsession.cpp",
    ROOT / "src/tun/tunproxysession.cpp",
    ROOT / "src/tun/tunsession.cpp",
    ROOT / "src/proto/trojanrequest.cpp",
    ROOT / "src/proto/socks5address.cpp",
    ROOT / "src/session/session.cpp",
    ROOT / "src/session/pipelinecomponent.cpp",
    ROOT / "src/core/log.cpp",
    ROOT / "src/core/utils.cpp",
    ROOT / "src/mem/memallocator.cpp",
]

def main():
    with tempfile.TemporaryDirectory(prefix="tun-client-lifetime-") as directory:
        binary = Path(directory) / "check"
        command = [
            os.environ.get("CXX", "c++"), "-std=c++17", "-pthread",
            "-DBOOST_ASIO_NO_DEPRECATED", "-DBADVPN_LINUX=1", "-DBADVPN_LITTLE_ENDIAN=1",
            "-DBADVPN_THREAD_SAFE=1", "-D_GNU_SOURCE=1",
            "-ffunction-sections", "-fdata-sections",
            "-I", str(ROOT / "src"),
            "-I", str(ROOT / "src/tun/lwip_custom"),
            "-I", str(ROOT / "badvpn/lwip/src/include"),
            "-I", str(ROOT / "badvpn"),
            "-I", str(ROOT / "GSL/include"),
            "-I", str(ROOT / "boringssl/include"),
            *map(str, SOURCES),
            "-Wl,--gc-sections",
            # Production TUNProxySession::destroy is in this link. Its close-callback
            # block does not call these symbols (pipeline off, m_out null, socket closed).
            # Defining them would pull Service, Pipeline, QUIC transport, and brotli.
            # -no-pie: ignore-all under PIE emits PLT reloc type 0x00 and will not load.
            "-no-pie",
            "-Wl,--unresolved-symbols=ignore-all",
            "-lssl", "-lcrypto",
            "-o", str(binary),
        ]
        subprocess.run(command, check=True)
        subprocess.run([str(binary), *sys.argv[1:]], check=True, timeout=30)
    print("TUN client lifetime (%s): PASS" % (sys.argv[1] if len(sys.argv) > 1 else "all"))

if __name__ == "__main__":
    main()
