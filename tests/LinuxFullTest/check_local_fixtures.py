"""Run with: python3 check_local_fixtures.py (no binary or privileges needed)."""
import os
import runpy
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import fulltest_dns
import fulltest_server


def main() -> None:
    # Fail immediately if HTTP startup consults DNS, including IPv6 binding.
    with patch.object(socket, "getfqdn", side_effect=AssertionError("external DNS used")):
        for host in ("127.0.0.1", "::1"):
            if host == "::1" and not socket.has_ipv6:
                continue
            with fulltest_server.make_http_server(host, 0, host == "::1") as server:
                assert server.request_queue_size >= 60
                assert server.server_port > 0
                assert server.server_name == host

    with fulltest_dns.local_fixture(0) as (port, _):
        assert fulltest_dns.start_query("127.0.0.1", 2, port)
        with patch.dict(fulltest_dns.ANSWERS, {fulltest_dns.DIRECT_DOMAIN: "192.0.2.99"}):
            # Force an unexpected response, and prove checks cannot silently pass.
            with patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
                assert not fulltest_dns.lookup_domain(fulltest_dns.DIRECT_DOMAIN, "127.0.0.1", 1, port)

    # Simulate macOS bind denial: local runs may skip, CI must never skip.
    script = Path(fulltest_server.__file__).with_name("fulltest_main.py")
    for ci_variable in (None, "TF_BUILD", "CI"):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("TF_BUILD", "CI")}
        if ci_variable:
            environment[ci_variable] = "True"
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(sys, "argv", [str(script), "unused-binary", "-d", "5333"]), \
                patch("fulltest_utils.is_macos_system", return_value=True), \
                patch("fulltest_utils.is_windows_system", return_value=False), \
                patch.object(fulltest_dns, "local_fixture", side_effect=PermissionError("bind denied")):
            try:
                runpy.run_path(str(script), run_name="__main__")
            except RuntimeError as error:
                assert ci_variable and "DNS fixture required in CI" in str(error), str(error)
            except SystemExit as error:
                assert ci_variable is None and error.code == 0, (ci_variable, error.code)
            else:
                raise AssertionError("Fixture bind failure did not stop execution")

    # Generation-only mode must work in a clean checkout without a binary.
    with tempfile.TemporaryDirectory() as directory:
        script = Path(fulltest_server.__file__).with_name("fulltest_main.py")
        result = subprocess.run([sys.executable, str(script), "unused-binary", "-g", "2"],
                                cwd=directory, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        assert len(list(Path(directory, "html").glob("*.txt"))) == 2

    if sys.platform != "win32":
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            process = subprocess.Popen([sys.executable, "-u", str(Path(fulltest_server.__file__)),
                                        directory, str(port)], stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    assert process.poll() is None, "fixture exited before listening"
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise AssertionError("fixture did not start within five seconds")
                process.send_signal(signal.SIGINT)
                output, _ = process.communicate(timeout=5)
                assert process.returncode == 0, output
                assert "Traceback" not in output, output
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
    print("Local fixture checks passed")


if __name__ == "__main__":
    import dns.resolver
    main()
