"""Run with: python3 tests/LinuxFullTest/check_quic_regressions.py"""
import socket
import tempfile
import threading
from pathlib import Path
from unittest.mock import Mock, patch

import fulltest_quic as quic


def check_h3_results() -> None:
    valid = "FILE:a:OK:1:hash\nFILE:a:OK:1:hash"
    assert quic._parse_h3_load_results(valid, ["a", "a"]) == {
        "a": [(1, "hash"), (1, "hash")]
    }
    for output in ("FILE:a:OK:1:hash", valid + "\nH3_FILE_ERROR: timeout",
                   valid + "\nAIOQUIC_ERROR: closed", "FILE:a:ERROR:timeout"):
        try:
            quic._parse_h3_load_results(output, ["a", "a"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"Accepted incomplete or failed load: {output}")


def check_restart(early_success: bool, retry_seen: bool = True, reset_seen: bool = True) -> None:
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "file").write_bytes(b"data")
        server, client, restarted = Mock(), Mock(), Mock()
        requests = [b"file\n", b"data",
                    b"data" if early_success else ConnectionResetError(), b"data"]
        with patch.multiple(quic, TEST_FILES_DIR=directory,
                            print_time_log=Mock(), close_process=Mock(),
                            wait_for_log=Mock(return_value=True),
                            wait_for_port=Mock(return_value=True)), \
                patch.object(quic.time, "sleep"), \
                patch.object(quic, "patch_quic_config_with_suffix", return_value="config") as config, \
                patch.object(quic, "start_trojan", side_effect=[
                    (server, "server.log"), (client, "client.log"), (restarted, "restart.log")]), \
                patch.object(quic, "_get_log_offset", return_value=42), \
                patch.object(quic, "_wait_for_log_after", side_effect=[reset_seen, retry_seen]) as retry, \
                patch.object(quic, "http_get_via_socks5", side_effect=requests):
            assert quic.test_stateless_reset("trojan") is (reset_seen and retry_seen)
            server.kill.assert_called_once()
            server.wait.assert_called_once_with(timeout=5)
            options = [call.args[2]["quic"] for call in config.call_args_list]
            assert all(option["debug_disable_tcp"] for option in options)
            assert options[0]["stateless_reset_secret"] == options[2]["stateless_reset_secret"]
            assert retry.call_args_list[0].args[1] == r"QuicConnection: stateless reset received"
            assert all(call.args[2] == 42 for call in retry.call_args_list)
            if reset_seen and retry_seen:
                assert "reconnect quic client!" in retry.call_args.args[1]


def check_udp_shutdown() -> None:
    failures = []
    done = threading.Event()
    original_thread = threading.Thread

    def tracked_thread(*args, **kwargs):
        target = kwargs["target"]

        def run() -> None:
            try:
                target()
            except BaseException as error:
                failures.append(error)
            finally:
                done.set()

        kwargs["target"] = run
        return original_thread(*args, **kwargs)

    with patch.object(quic.threading, "Thread", side_effect=tracked_thread):
        server, stop, thread = quic._start_udp_echo_server(0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(b"echo", server.getsockname())
        assert client.recv(4096) == b"echo"
    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive(), "UDP helper did not stop"
    server.close()
    assert done.is_set()
    assert not failures, failures


if __name__ == "__main__":
    check_h3_results()
    check_restart(early_success=True)
    check_restart(early_success=False)
    check_restart(early_success=True, retry_seen=False)
    check_restart(early_success=True, reset_seen=False)
    check_udp_shutdown()
    print("QUIC regression checks passed")
