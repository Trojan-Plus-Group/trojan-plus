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

        # A fresh but active sample must be skipped until an idle event arrives.
        offset = path.stat().st_size
        with path.open("a") as log:
            log.write(LINE)
        idle_line = LINE.replace("sessions=0 ", "sessions=2 ").replace(
            "quic_connections=1", "quic_connections=0")
        def append_idle(_: float) -> None:
            with path.open("a") as log:
                log.write(idle_line)
        poll.reset_mock()
        poll.wait.side_effect = append_idle
        with patch.object(quic.threading, "Event", return_value=poll), \
                patch.object(quic.time, "monotonic", side_effect=[0.0, 0.0]):
            sample = quic._wait_t16_live_counters(
                process, str(path), offset, timeout=1.0, idle_sessions=2)
        assert poll.wait.call_count == 1
        assert sample["sessions"] == 2
        assert sample["quic_connections"] == sample["quic_proxy_sessions"] == 0

        # Active telemetry cannot extend the deadline; no real sleeps are needed.
        path.write_text(LINE)
        poll.reset_mock()
        poll.wait.side_effect = tick
        with patch.object(quic.threading, "Event", return_value=poll), \
                patch.object(quic.time, "monotonic", side_effect=[0.0, 0.0, 1.0]):
            try:
                quic._wait_t16_live_counters(
                    process, str(path), 0, timeout=1.0, idle_sessions=2)
            except ValueError:
                pass
            else:
                raise AssertionError("Active telemetry passed the idle deadline")
        assert poll.wait.call_count == 1

        def errors(objects: list[int], *, peak_cap: bool = True) -> list[str]:
            return quic._t16_live_counter_errors(
                [baseline | {"objects": n} for n in objects], peak_cap=peak_cap)

        assert not errors([1000] * 10)
        assert not errors([173, 296, 296, 414, 414, 414, 414, 414, 414, 414])
        assert not errors([197, 210, 220, 235, 235, 235, 235, 235, 235, 235])
        assert not errors([404] * 9 + [405])
        assert not errors([1000] * 8 + [1032, 1032])
        assert not errors(list(range(1000, 1010)))
        assert not errors([1000] * 6 + [1100, 1101, 1102, 1103])
        assert not errors([1000] * 8 + [1033, 1033])
        assert errors([1000, 2001] + [2001] * 8)
        assert not errors([1000, 2000] + [2000] * 8)
        assert not errors([1000, 2001] + [2001] * 8, peak_cap=False)
        assert errors([1000] * 9)
        assert errors([1000] * 11, peak_cap=False)
        # Even a transient lifecycle leak fails with either peak-cap policy.
        for key in ("sessions", "quic_connections", "quic_proxy_sessions"):
            samples = [baseline.copy() for _ in range(10)]
            samples[5][key] += 1
            assert quic._t16_live_counter_errors(samples)
            assert quic._t16_live_counter_errors(samples, peak_cap=False)

        idle = baseline | {"sessions": 2, "quic_connections": 0}
        assert not quic._t16_idle_counter_errors(idle, idle.copy())
        assert not quic._t16_idle_counter_errors(idle, idle | {"objects": 1032})
        assert not quic._t16_idle_counter_errors(idle, idle | {"objects": 999})
        assert quic._t16_idle_counter_errors(idle, idle | {"objects": 1033})
        assert quic._t16_idle_counter_errors(idle, idle | {"sessions": 3})
        assert quic._t16_idle_counter_errors(idle, idle | {"sessions": 1})
        for key in ("quic_connections", "quic_proxy_sessions"):
            assert quic._t16_idle_counter_errors(idle, idle | {key: 1})
            assert quic._t16_idle_counter_errors(idle | {key: 1}, idle)
            assert quic._t16_idle_counter_errors(idle | {key: 1}, idle | {key: 1})
        # Incomplete records are not accepted as a counter sample.
        path.write_text(LINE.rstrip("\n"))
        try:
            quic._wait_t16_live_counters(process, str(path), 0, timeout=0)
        except ValueError:
            pass
        else:
            raise AssertionError("Incomplete telemetry passed")

    # Service shutdown closes locally, without waiting for network capacity.
    source = (Path(__file__).resolve().parents[2] /
              "src/quic/quic_client_endpoint.cpp").read_text()
    stop = source.split("void QuicClientEndpoint::stop() {", 1)[1].split(
        "\nvoid QuicClientEndpoint::connect_to_server()", 1)[0]
    assert stop.index("QuicEndpoint::stop();") < stop.index("conn->shutdown();"), \
        "Close the endpoint socket before local connection shutdown"

    assert quic._t16_sustained_growth([100] * 10) == 0
    # Rounds 4-10: median=130, slope=10, six observed intervals.
    assert abs(quic._t16_sustained_growth([1, 1, 1, 100, 110, 120, 130, 140, 150, 160])
               - 60 / 130) < 1e-12
    assert quic._t16_sustained_growth([1, 1, 1, 10, 20, 30, 40, 50, 60, 70]) > 0.80


if __name__ == "__main__":
    check()
    print("T16 live-counter checks passed")
