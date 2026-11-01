"""Run with: python3 tests/LinuxFullTest/check_quic_resolver_fixtures.py"""
import socket
from unittest.mock import Mock, patch

import fulltest_quic as quic


def check_native_resolver() -> None:
    # Bytes bypass Python's IDNA encoder: exercise native getaddrinfo itself.
    host = quic._RESOLVER_FAILURE_HOST.encode("ascii")
    assert len(host) > 253 and b"." not in host
    for socktype in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        try:
            socket.getaddrinfo(host, 443, type=socktype)
        except socket.gaierror:
            pass
        else:
            raise AssertionError("Oversized hostname unexpectedly resolved")


def check_retry_requires_failure() -> None:
    with patch.multiple(quic, print_time_log=Mock(), close_process=Mock(),
                        patch_quic_config=Mock(return_value="a"),
                        patch_quic_config_with_suffix=Mock(return_value="b"),
                        start_trojan=Mock(return_value=(Mock(), "unused.log"))), \
            patch.object(quic, "wait_for_log", side_effect=[True, True, None]):
        assert not quic.test_client_retry_no_server("trojan")
        assert quic.patch_quic_config.call_args.args[1]["remote_addr"] == quic._RESOLVER_FAILURE_HOST
        assert quic.patch_quic_config_with_suffix.call_args.args[2]["remote_addr"] == quic._RESOLVER_FAILURE_HOST


def check_upstream_fixture() -> None:
    with patch.multiple(quic, print_time_log=Mock(), close_process=Mock(),
                        patch_quic_config=Mock(return_value="config"),
                        start_trojan=Mock(return_value=(None, "unused.log"))):
        assert not quic.test_h1_upstream_dns_failure("trojan")
        config = quic.patch_quic_config.call_args_list[0].args[1]
        assert config["quic"]["h1_upstream"] == f"{quic._RESOLVER_FAILURE_HOST}:443"


if __name__ == "__main__":
    check_native_resolver()
    check_retry_requires_failure()
    check_upstream_fixture()
    print("T9/T13 resolver fixture checks passed")
