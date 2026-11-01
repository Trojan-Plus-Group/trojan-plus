#!/usr/bin/env python3
"""Check strict CI skip policy without starting privileged fixtures."""
import ast
import os
from pathlib import Path
from unittest.mock import patch

source = Path(__file__).parent / "LinuxFullTest/fulltest_ipv6.py"
module = ast.parse(source.read_text())
function = next(node for node in module.body
                if isinstance(node, ast.FunctionDef) and node.name == "required_case_skipped")
namespace = {"os": os}
exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
check = namespace["required_case_skipped"]
with patch.dict(os.environ, {"TP_IPV6_REQUIRE_ALL": "1"}):
    for expected, nat in ((False, False), (True, True)):
        assert check({"status": "SKIP", "case": "tun_ipv6"}, expected, nat, ("redirect",))
        assert not check({"status": "PASS", "case": "tun_ipv6"}, expected, nat, ("redirect",))
        assert check({"status": "SKIP", "case": "nat_ipv6"}, expected, nat, ("redirect",)) == expected
        assert check({"status": "SKIP", "case": "redirect"}, expected, nat, ("redirect",)) == nat
with patch.dict(os.environ, {"TP_IPV6_REQUIRE_ALL": "0"}):
    assert not check({"status": "SKIP", "case": "tun_ipv6"}, True, True, ())
print("IPv6 CI skip policy passed")
