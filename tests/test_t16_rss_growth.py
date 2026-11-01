#!/usr/bin/env python3
"""Exercise production T16 RSS estimator without network or dependencies."""
import ast
from pathlib import Path

source = Path(__file__).parent / "LinuxFullTest/fulltest_quic.py"
function = next(node for node in ast.parse(source.read_text()).body
                if isinstance(node, ast.FunctionDef) and node.name == "_t16_sustained_growth")
namespace = {}
exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
growth = namespace["_t16_sustained_growth"]
threshold = 0.80
# Warm-up changes must not affect steady-state measurements.
for warmup in ([7, 9, 11], [7, 16, 12], [7, 8, 8]):
    assert growth(warmup + [13, 13, 13, 13, 13, 13, 13]) == 0
    assert growth(warmup + [13, 13.1, 12.9, 17, 13.2, 13, 13.1]) < threshold
# A per-round leak remains visible despite warm-up, a spike, or a drop.
for samples in ([8 + 10 * i for i in range(10)],
                [7, 10, 13, 13, 18, 23, 28, 33, 38, 43],
                [7, 10, 13, 13, 18, 60, 28, 33, 38, 43],
                [7, 10, 13, 13, 18, 23, 8, 33, 38, 43]):
    assert growth(samples) > threshold, samples
# Measured cache step then plateau must not look like a continuing leak.
assert growth([11.21, 14.47, 14.73, 13.77, 9.73, 13.74, 13.63, 16.80, 17.05, 17.25]) < threshold
assert growth([20 - i for i in range(10)]) < 0
for invalid in ([1] * 6, [1] * 9 + [0]):
    try:
        growth(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid RSS measurements accepted")
print("T16 RSS warm-up/noise passes; sustained leaks fail; invalid samples fail")
