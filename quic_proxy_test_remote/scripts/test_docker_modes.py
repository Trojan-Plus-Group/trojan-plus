import datetime
import importlib.util
import pathlib
import subprocess
import time
import unittest
from unittest import mock


PATH = pathlib.Path(__file__).with_name("docker_modes.py")
SPEC = importlib.util.spec_from_file_location("docker_modes", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
STARTED = None


def stage_log(message):
    timestamp = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def setUpModule():
    global STARTED
    STARTED = time.monotonic()
    stage_log("[阶段] docker_modes.py 单元测试开始；通常少于 10 秒")


def tearDownModule():
    stage_log(f"[阶段] docker_modes.py 单元测试完成；耗时 {time.monotonic() - STARTED:.1f} 秒")


class DockerModesTest(unittest.TestCase):
    def test_cloudflare_ipv4_validation(self):
        self.assertEqual(MODULE.parse_cloudflare_ipv4(["8.8.8.8", "8.8.8.8"]), "8.8.8.8")
        for values in (("127.0.0.1",), ("10.0.0.1",), ("2001:4860:4860::8888",), ("8.8.8.8", "1.1.1.1"), ("bad",), ()):
            with self.assertRaises(ValueError):
                MODULE.parse_cloudflare_ipv4(values)

    def test_nat_command_targets_cloudflare_https_exactly(self):
        command = MODULE.docker_commands("nat", "quic", "safe-run", pathlib.Path("/tmp/runtime"), "8.8.8.8")["run"]
        self.assertIn("NET_ADMIN", command)
        self.assertIn("NET_RAW", command)
        self.assertIn("/dev/net/tun", command)
        self.assertIn("/tmp/runtime:/runtime:ro", command)
        self.assertEqual(command[-6:], ["nat", "quic", "/runtime/nat-quic.json", "8.8.8.8", "1048576", "180"])

    def test_tun_command_does_not_add_net_raw(self):
        command = MODULE.docker_commands("client_tun", "tcp", "safe-run", pathlib.Path("/tmp/runtime"), "8.8.8.8")["run"]
        self.assertIn("NET_ADMIN", command)
        self.assertNotIn("NET_RAW", command)

    def test_entry_has_exact_nat_and_tun_targets(self):
        entry = (MODULE.ROOT / "docker-entry.sh").read_text()
        self.assertIn('-d "$target_ip/32" -p tcp --dport 443', entry)
        self.assertIn('ss -H -ltn sport = :12345', entry)
        self.assertIn('cat /tmp/trojan.log >&2', entry)
        self.assertIn('ip route replace "$target_ip/32" dev tun0', entry)
        self.assertIn('--resolve "speed.cloudflare.com:443:$target_ip"', entry)
        self.assertNotIn("8001", entry)
        self.assertNotIn("sha256", entry)

    def test_tun_config_does_not_redirect_local(self):
        self.assertIn('"redirect_local": False', PATH.read_text())

    def test_unsafe_run_id_rejected(self):
        for value in ("", "x;rm", "x y", "../x", "x" * 65):
            with self.assertRaises(ValueError):
                MODULE.validate_run_id(value)

    def test_image_source_hash_is_stable(self):
        self.assertEqual(MODULE.image_source_hash(), MODULE.image_source_hash())
        self.assertEqual(len(MODULE.image_source_hash()), 64)

    def test_timeout_cli_defaults_and_overrides(self):
        required = ["docker_modes.py", "--mode", "nat", "--protocol", "tcp", "--run-id", "safe-run"]
        with mock.patch.object(MODULE.sys, "argv", required):
            args = MODULE.parse_args()
        self.assertEqual((args.watchdog, args.watchdog_grace, args.command_timeout, args.ssh_connect_timeout), (180, 10, 30, 10))
        self.assertEqual((args.iperf_stop_timeout, args.iperf_start_timeout, args.iperf_client_timeout), (10, 15, 15))
        self.assertEqual((args.image_build_timeout, args.image_inspect_timeout, args.scp_timeout, args.server_log_scp_timeout, args.progress_interval), (300, 30, 180, 15, 5))
        options = required + ["--watchdog", "181", "--watchdog-grace", "11", "--command-timeout", "31", "--ssh-connect-timeout", "12", "--iperf-stop-timeout", "13", "--iperf-start-timeout", "16", "--iperf-client-timeout", "17", "--image-build-timeout", "301", "--image-inspect-timeout", "32", "--scp-timeout", "182", "--server-log-scp-timeout", "18", "--progress-interval", "6"]
        with mock.patch.object(MODULE.sys, "argv", options):
            args = MODULE.parse_args()
        self.assertEqual((args.watchdog, args.watchdog_grace, args.command_timeout, args.ssh_connect_timeout), (181, 11, 31, 12))
        self.assertEqual((args.iperf_stop_timeout, args.iperf_start_timeout, args.iperf_client_timeout), (13, 16, 17))
        self.assertEqual((args.image_build_timeout, args.image_inspect_timeout, args.scp_timeout, args.server_log_scp_timeout, args.progress_interval), (301, 32, 182, 18, 6))

    @mock.patch.object(MODULE, "command_output")
    @mock.patch.object(MODULE.subprocess, "run")
    def test_build_image_reuses_matching_image(self, run, command_output):
        source_hash = MODULE.image_source_hash()
        inspect = [{"Config": {"Labels": {"trojan-plus.source-hash": source_hash}}}]
        run.return_value = subprocess.CompletedProcess([], 0, MODULE.json.dumps(inspect), "")
        self.assertFalse(MODULE.build_image())
        command_output.assert_not_called()

    @mock.patch.object(MODULE, "command_output")
    @mock.patch.object(MODULE.subprocess, "run")
    def test_build_image_rebuilds_changed_image(self, run, command_output):
        inspect = [{"Config": {"Labels": {"trojan-plus.source-hash": "old-hash"}}}]
        run.return_value = subprocess.CompletedProcess([], 0, MODULE.json.dumps(inspect), "")
        self.assertTrue(MODULE.build_image())
        build = command_output.call_args.args[0]
        self.assertIn("docker", build)
        self.assertIn("build", build)
        self.assertIn(f"trojan-plus.source-hash={MODULE.image_source_hash()}", build)

    @mock.patch.object(MODULE.time, "sleep")
    @mock.patch.object(MODULE.subprocess, "Popen")
    def test_docker_progress_returns_completed_process(self, popen, sleep):
        process = popen.return_value
        process.poll.side_effect = [None, 0]
        process.returncode = 0
        process.communicate.return_value = ('{"valid":true}', "")
        completed = MODULE.run_docker_with_progress(["docker", "run"], "test-container", 10)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, '{"valid":true}')
        sleep.assert_called_once()


if __name__ == "__main__":
    unittest.main()
