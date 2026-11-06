#!/usr/bin/env python3
"""Keep Linux CI tests on one venv, including sudo and sys.executable children."""
from pathlib import Path
import re

pipeline = (Path(__file__).resolve().parents[1] / "azure-pipelines.yml").read_text()
linux = pipeline.split("- stage: Test\n", 1)[1].split("  - job: Windows\n", 1)[0]
assert "python3-venv" in linux
assert 'python3 -m venv "$AGENT_TEMPDIRECTORY/fulltest-venv"' in linux
assert 'PYTHON="$AGENT_TEMPDIRECTORY/fulltest-venv/bin/python3"' in linux
assert '"$PYTHON" -m pip install PySocks psutil dnspython aioquic' in linux
assert "AGENT_TEMPDIRECTORY: $(Agent.TempDirectory)" in linux
assert 'export S5_BINARY="$BINARY"' in linux
assert "--break-system-packages" not in linux
for line in linux.splitlines():
    if re.search(r"\bpython3\b", line):
        assert any(marker in line for marker in (
            "python3-venv", "python3 -m venv", 'PYTHON="')), line
    if "sudo" in line and '"$PYTHON"' in line:
        assert "env TF_BUILD=True" in line, line
assert linux.count('TP_IPV6_REQUIRE_ALL=1 "$PYTHON"') == 2
assert linux.count('"$PYTHON" -u fulltest_main.py') == 5
print("Linux CI Python interpreter checks passed")
