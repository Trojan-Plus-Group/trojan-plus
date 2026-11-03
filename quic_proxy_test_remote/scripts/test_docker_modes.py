import datetime
import importlib.util
import pathlib
import subprocess
import time
import tempfile
import argparse
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
    stage_log("[stage] docker_modes.py tests started; usually under 10 seconds")


def tearDownModule():
    stage_log(f"[stage] docker_modes.py tests finished; elapsed {time.monotonic() - STARTED:.1f} seconds")


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

    def test_rootful_modes_can_read_private_runtime_mount(self):
        for mode in ("nat", "client_tun"):
            command = MODULE.docker_commands(mode, "quic", "private-runtime", pathlib.Path("/tmp/runtime"), MODULE.HOST, engine=["sudo", "-n", "podman"])["run"]
            self.assertIn("DAC_OVERRIDE", command)
            self.assertIn("/tmp/runtime:/runtime:ro", command)
            self.assertNotIn("--privileged", command)

    def test_tun_command_does_not_add_net_raw(self):
        command = MODULE.docker_commands("client_tun", "tcp", "safe-run", pathlib.Path("/tmp/runtime"), "8.8.8.8")["run"]
        self.assertIn("NET_ADMIN", command)
        self.assertNotIn("NET_RAW", command)

    def test_entry_has_exact_nat_and_tun_targets(self):
        entry = (MODULE.ROOT / "docker-entry.sh").read_text()
        self.assertIn('-d "$target_ip/32" -p tcp --dport "$target_port"', entry)
        self.assertIn('ss -H -ltn sport = :12345', entry)
        self.assertIn('cat /tmp/trojan.log >&2', entry)
        self.assertIn('ip route replace table 17777 "$target_ip/32" dev tun0', entry)
        self.assertIn('ipproto tcp dport "$target_port" lookup 17777', entry)
        self.assertIn('ss -H -uanp', entry)
        self.assertIn('--resolve "speed.cloudflare.com:443:$target_ip"', entry)
        self.assertIn("8001", entry)
        self.assertIn("actual_sha256 == expected_sha256", entry)

    def test_protocol_actual_log_patterns(self):
        client = "QuicConnection: handshake completed (role=client, peer=1.2.3.4:3443, alpn=h3)\nsend_stream_data_impl enter: stream_id=0 datalen=100"
        server = "QuicConnection: handshake completed (role=server, peer=1.2.3.4:1234, alpn=h3)\nQuicProxySession: stream 0 opened"
        self.assertTrue(MODULE.protocol_evidence(client, server)["valid"])
        self.assertFalse(MODULE.protocol_evidence(client, "")["valid"])
        self.assertFalse(MODULE.protocol_evidence(client, server.replace("h3", "h2"))["valid"])
        self.assertFalse(MODULE.protocol_evidence(client, server + " TCP fallback")["valid"])
        self.assertFalse(MODULE.protocol_evidence(client, server.split("\n")[0])["valid"])

    @mock.patch.object(MODULE.shutil, "which", return_value="/bin/engine")
    @mock.patch.object(MODULE.subprocess, "run")
    def test_engine_supports_sudo_podman(self, run, which):
        run.side_effect = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
        with mock.patch.dict(MODULE.os.environ, {}, clear=True):
            self.assertEqual(MODULE.container_engine(), ["sudo", "-n", "podman"])
        command = MODULE.docker_commands("nat", "quic", "run", pathlib.Path("/tmp/runtime"), MODULE.HOST,
                                         engine=["sudo", "-n", "podman"], target="bytesource", expected_sha256="abc")
        self.assertEqual(command["run"][:4], ["sudo", "-n", "podman", "run"])
        self.assertEqual(command["run"][-2:], ["bytesource", "abc"])

    @mock.patch.object(MODULE.subprocess, "run")
    def test_iperf_refuses_busy_host_without_bulk_kill(self, run):
        run.side_effect = [subprocess.CompletedProcess([], 73, "", "busy"), subprocess.CompletedProcess([], 0, "", "")]
        result = MODULE.measure_iperf3_baseline()
        self.assertFalse(result["available"])
        self.assertTrue(result["cleanup_valid"])
        commands = " ".join(str(call.args[0]) for call in run.call_args_list)
        self.assertNotIn("pkill", commands)
        self.assertIn("pgrep -x iperf3", commands)
        self.assertIn("/proc/$pid/cmdline", commands)

    def test_smoke_cleanup_failure_is_summary_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            runner = mock.Mock()
            runner.bytesource_sha256.return_value = "a" * 64
            runner.prepare.side_effect = RuntimeError("preflight failed")
            args = argparse.Namespace(run_id="safe-run", mode="nat", protocol="tcp", size=10, requests=1, concurrency=1)
            with mock.patch.object(MODULE, "ROOT", root), mock.patch.object(MODULE, "load_runner", return_value=runner), mock.patch.object(MODULE, "container_engine", return_value=["podman"]), mock.patch.object(MODULE, "command_output", side_effect=RuntimeError("engine unavailable")):
                with self.assertRaisesRegex(RuntimeError, "validation failed"):
                    MODULE.smoke(args)
            summary = MODULE.json.loads((root / "results/docker-safe-run-nat-tcp.json").read_text())
            self.assertFalse(summary["valid"])
            self.assertFalse(summary["gates"]["cleanup"])
            self.assertEqual(summary["error"], "preflight failed")

    def test_cloudflare_requires_trusted_hash_and_writes_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            args = argparse.Namespace(run_id="hash-run", mode="nat", protocol="tcp", size=10,
                                      requests=1, concurrency=1, target="cloudflare")
            with mock.patch.object(MODULE, "ROOT", root), mock.patch.object(MODULE, "container_engine") as engine:
                with self.assertRaises(RuntimeError):
                    MODULE.smoke(args)
                engine.assert_not_called()
            summary = MODULE.json.loads((root / "results/hash-run/docker/nat/tcp/summary.json").read_text())
            self.assertFalse(summary["passed"])
            self.assertIn("--expected-sha256", summary["error"])
            self.assertEqual(summary["thresholds"]["http_code"], 200)
            self.assertEqual(summary, MODULE.json.loads((root / "results/docker-hash-run-nat-tcp.json").read_text()))
        sample = dict(exit_code=0, http_code=200, actual_size=10, size_download=10, actual_sha256="a" * 64)
        self.assertTrue(MODULE.valid_samples([sample], 1, 10, "a" * 64))
        self.assertFalse(MODULE.valid_samples([sample], 1, 10, "b" * 64))
        self.assertFalse(MODULE.valid_samples([sample], 1, 10, ""))

    def test_deployment_cleanup_failure_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            deploy = root / "results/cleanup-run/metadata/trojan-deploy.json"
            runner = mock.Mock()
            runner.bytesource_sha256.return_value = "a" * 64
            def fail_deploy(args):
                deploy.parent.mkdir(parents=True)
                deploy.write_text("{}")
                raise RuntimeError("deployment failed")
            runner.trojan_deploy.side_effect = fail_deploy
            runner.trojan_stop.side_effect = RuntimeError("deployment cleanup failed")
            args = argparse.Namespace(run_id="cleanup-run", mode="nat", protocol="tcp", size=10, requests=1, concurrency=1)
            with mock.patch.object(MODULE, "ROOT", root), mock.patch.object(MODULE, "load_runner", return_value=runner), mock.patch.object(MODULE, "container_engine", return_value=["podman"]), mock.patch.object(MODULE, "command_output", return_value=""):
                with self.assertRaises(RuntimeError):
                    MODULE.smoke(args)
            summary = MODULE.json.loads((root / "results/cleanup-run/docker/nat/tcp/summary.json").read_text())
            self.assertFalse(summary["passed"])
            self.assertFalse(summary["gates"]["cleanup"])
            self.assertIn("server/deploy stop: deployment cleanup failed", summary["cleanup"]["errors"])
            runner.trojan_stop.assert_called_once()

    @mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/sudo")
    @mock.patch.object(MODULE.subprocess, "run")
    def test_engine_environment_is_honored(self, run, which):
        run.return_value = subprocess.CompletedProcess([], 0)
        with mock.patch.dict(MODULE.os.environ, {"CONTAINER_ENGINE": "sudo -n podman"}):
            self.assertEqual(MODULE.container_engine(), ["sudo", "-n", "podman"])
        self.assertEqual(run.call_args.args[0], ["sudo", "-n", "podman", "info"])
        run.return_value = subprocess.CompletedProcess([], 1)
        with self.assertRaises(RuntimeError):
            MODULE.container_engine("sudo -n podman")

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
