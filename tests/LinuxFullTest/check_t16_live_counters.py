"""Run: python3 tests/LinuxFullTest/check_t16_live_counters.py"""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import fulltest_quic as quic


LINE = ("[mem] live objects=1000 bytes=4096 sessions=0 "
        "quic_connections=1 quic_proxy_sessions=0\n")


def check() -> None:
    process = Mock()
    process.poll.return_value = None
    with TemporaryDirectory() as directory:
        path = Path(directory, "server.log")
        path.write_text(LINE)
        offset = path.stat().st_size
        # Old telemetry must fail, not become the post-quiescence baseline.
        try:
            quic._wait_t16_live_counters(process, str(path), offset, timeout=0)
        except ValueError:
            pass
        else:
            raise AssertionError("Missing fresh telemetry passed")

        poll = Mock()
        def tick(_: float) -> None:
            with path.open("a") as log:
                log.write(LINE.replace("bytes=4096", "bytes=8192"))
        poll.wait.side_effect = tick
        with patch.object(quic.threading, "Event", return_value=poll):
            baseline = quic._wait_t16_live_counters(process, str(path), offset)
        assert poll.wait.call_count == 1
        assert baseline["bytes"] == 8192
        def errors(objects: list[int]) -> list[str]:
            return quic._t16_live_counter_errors([baseline | {"objects": n} for n in objects])

        assert not errors([1000] * 10)
        assert not errors([173, 296, 296, 414, 414, 414, 414, 414, 414, 414])
        assert not errors([197, 210, 220, 235, 235, 235, 235, 235, 235, 235])
        assert not errors([1000] * 8 + [1032, 1032])  # Bounded late step, then flat.
        assert errors(list(range(1000, 1010)))  # One leaked object per round.
        assert errors([1000] * 6 + [1100, 1101, 1102, 1103])  # Late continuing leak.
        assert errors([1000] * 8 + [1033, 1033])  # Excess late net growth.
        assert errors([1000, 2001] + [2001] * 8)  # Large early plateau still fails.
        assert not errors([1000, 2000] + [2000] * 8)
        assert errors([1000] * 9)
        # Even a transient lifecycle leak fails; allocator count and RSS may stay flat.
        for key in ("sessions", "quic_connections", "quic_proxy_sessions"):
            samples = [baseline.copy() for _ in range(10)]
            samples[5][key] += 1
            assert quic._t16_live_counter_errors(samples)
        # Incomplete records are not accepted as a counter sample.
        path.write_text(LINE.rstrip("\n"))
        try:
            quic._wait_t16_live_counters(process, str(path), 0, timeout=0)
        except ValueError:
            pass
        else:
            raise AssertionError("Incomplete telemetry passed")

    assert quic._t16_sustained_growth([100] * 10) == 0
    # Rounds 4-10: median=130, slope=10, six observed intervals.
    assert abs(quic._t16_sustained_growth([1, 1, 1, 100, 110, 120, 130, 140, 150, 160])
               - 60 / 130) < 1e-12
    assert quic._t16_sustained_growth([1, 1, 1, 10, 20, 30, 40, 50, 60, 70]) > 0.80


if __name__ == "__main__":
    check()
    print("T16 live-counter checks passed")
