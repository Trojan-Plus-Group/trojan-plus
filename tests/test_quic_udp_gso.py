#!/usr/bin/env python3
"""Real-binary UDP GSO regression: server-only and both endpoints, 1 MiB SHA256.

Usage: python3 tests/test_quic_udp_gso.py [BINARY], or S5_BINARY.
Artifacts use S5_LOG_DIR or tempfile.gettempdir()/tp-s5. Linux exercises
UDP_SEGMENT when available; other platforms verify transparent fallback.
"""
import os
from pathlib import Path
import sys
import tempfile

from test_quic_initial_loss import ROOT, main as run


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("S5_BINARY")
    if not binary:
        candidates = [ROOT / "build/trojan"]
        if os.environ.get("PIPELINE_WORKSPACE"):
            candidates.append(Path(os.environ["PIPELINE_WORKSPACE"]) / "LinuxBinary/trojan")
        binary = next((str(path) for path in candidates if path.is_file()), None)
    if not binary:
        if "TF_BUILD" in os.environ or "CI" in os.environ:
            sys.exit("QUIC UDP GSO: binary missing; pass BINARY, set S5_BINARY, or build build/trojan")
        print("SKIP QUIC UDP GSO: pass BINARY, set S5_BINARY, or build build/trojan")
        return
    output = Path(os.environ.get("S5_LOG_DIR", Path(tempfile.gettempdir()) / "tp-s5"))
    run(["--binary", str(Path(binary).resolve()), "--output-dir", str(output), "--udp-gso"])


if __name__ == "__main__":
    main()
