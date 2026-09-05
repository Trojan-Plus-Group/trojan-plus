import importlib.util
import pathlib
import subprocess
import unittest
from unittest import mock


PATH = pathlib.Path(__file__).with_name("docker_modes.py")
SPEC = importlib.util.spec_from_file_location("docker_modes", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


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
