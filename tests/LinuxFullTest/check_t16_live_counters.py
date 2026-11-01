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
        assert not quic._t16_live_counter_errors(baseline, baseline.copy())
        # Each live resource leak fails even when allocator count and RSS stay flat.
        for key in ("sessions", "quic_connections", "quic_proxy_sessions"):
            assert quic._t16_live_counter_errors(baseline, baseline | {key: baseline[key] + 1})
        assert not quic._t16_live_counter_errors(baseline, baseline | {"objects": 1200})
        assert quic._t16_live_counter_errors(baseline, baseline | {"objects": 1201})
        assert quic._t16_live_counter_errors(baseline, baseline | {"objects": 799})
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
