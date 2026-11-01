"""Run: python3 tests/LinuxFullTest/check_t16_quiescence.py"""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import fulltest_quic as quic


CONNECTION = "QuicConnection: QuicConnection constructed for peer 127.0.0.1:1\n"
DESTROYED = "QuicConnection: ~QuicConnection destructed for peer 127.0.0.1:1\n"
SESSION = "QuicProxySession: QuicProxySession constructed stream_id=0\n"
FINISHED = "QuicProxySession: QuicProxySession destructed stream_id=0\n"


def check() -> None:
    process = Mock()
    process.poll.return_value = None
    with TemporaryDirectory() as directory:
        path = Path(directory, "server.log")
        active = CONNECTION * 2 + SESSION
        path.write_text(active)
        poll = Mock()
        # A connection close alone is insufficient while proxy sessions live.
        def teardown(_: float) -> None:
            path.write_text(path.read_text() +
                            (DESTROYED if poll.wait.call_count == 1 else FINISHED))
        poll.wait.side_effect = teardown
        with patch.object(quic.threading, "Event", return_value=poll):
            assert quic._wait_t16_quiescence(process, process, str(path), 1)
        assert poll.wait.call_count == 2
        # Old destructor events must not satisfy a later load iteration.
        with patch.object(quic, "print_time_log"):
            assert not quic._wait_t16_quiescence(process, process, str(path), 2, timeout=0)
            path.write_text(active)
            assert not quic._wait_t16_quiescence(process, process, str(path), 1, timeout=0)
        process.poll.return_value = 1
        assert not quic._wait_t16_quiescence(process, process, str(path), 1)


if __name__ == "__main__":
    check()
    print("T16 quiescence checks passed")
