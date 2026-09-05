import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


PATH = pathlib.Path(__file__).with_name("run.py")
SPEC = importlib.util.spec_from_file_location("baseline_runner", PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class RunnerTest(unittest.TestCase):
    def test_percentile(self):
        self.assertEqual(RUNNER.percentile([10, 20, 30, 40, 50], 0.1), 14)
        self.assertEqual(RUNNER.percentile([10, 20, 30, 40, 50], 0.9), 46)
        self.assertIsNone(RUNNER.percentile([], 0.5))

    def test_valid_iperf(self):
        self.assertTrue(RUNNER.valid_iperf({"exit_code": 0}, '{"end": {}}'))
        self.assertFalse(RUNNER.valid_iperf({"exit_code": 1}, '{"end": {}}'))
        self.assertFalse(RUNNER.valid_iperf({"exit_code": 0}, '{"error": "failed"}'))

    def test_summarize_marks_invalid_samples(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = pathlib.Path(temporary)
            (results / "baseline").mkdir()
            output = results / "sample.stdout"
            output.write_text('{"end":{"sum_received":{"bits_per_second":100},"sum_sent":{"retransmits":2}}}')
            items = [
                {"name": "valid", "valid": True, "protocol": "tcp", "case": "tcp-p1-forward", "warmup": False, "attempts": [{"stdout": "sample.stdout"}]},
                {"name": "invalid", "valid": False, "protocol": "tcp", "case": "tcp-p1-forward", "warmup": False, "attempts": []},
            ]
            summary = RUNNER.summarize(items, results)
            self.assertEqual(summary["valid_sample_count"], 1)
            self.assertEqual(summary["invalid_samples"], ["invalid"])
            self.assertEqual(summary["groups"]["tcp-p1-forward"]["median_bits_per_second"], 100)


class BytesourcePayloadTest(unittest.TestCase):
    def test_zero_length(self):
        self.assertEqual(RUNNER.bytesource_payload(0), b"")
        self.assertEqual(RUNNER.bytesource_sha256(0), hashlib.sha256(b"").hexdigest())

    def test_deterministic_first_bytes(self):
        expected = bytes(((i * 31 + 7) & 0xFF) for i in range(8))
        self.assertEqual(RUNNER.bytesource_payload(8), expected)

    def test_sha256_matches_python(self):
        for size in (1, 1024, 4096, 1 << 20):
            payload = RUNNER.bytesource_payload(size)
            self.assertEqual(len(payload), size)
            self.assertEqual(RUNNER.bytesource_sha256(size), hashlib.sha256(payload).hexdigest())

    def test_negative_rejected(self):
        with self.assertRaises(ValueError):
            RUNNER.bytesource_payload(-1)

    def test_large_payload_size(self):
        size = RUNNER.R2_MAX_SAMPLE_BYTES
        payload = RUNNER.bytesource_payload(size)
        self.assertEqual(len(payload), size)
        expected_digest = hashlib.sha256(bytes(((i * 31 + 7) & 0xFF) for i in range(size))).hexdigest()
        self.assertEqual(RUNNER.bytesource_sha256(size), expected_digest)


class TrojanSampleValidTest(unittest.TestCase):
    def _make_record(self, exit_code, timed_out=False, duration=1.0):
        return {
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_seconds": duration,
            "started_utc": "2026-09-03T00:00:00Z",
            "ended_utc": "2026-09-03T00:00:01Z",
        }

    def _make_summary(self, results, protocol, size, run_number, exit_code, actual_size, actual_sha):
        return {
            "run": run_number,
            "protocol": protocol,
            "bytes": size,
            "port": 9081 if protocol == "tcp" else 9080,
            "url": f"http://127.0.0.1:8001/{size}",
            "exit_code": exit_code,
            "duration_seconds": 1.0,
            "started_utc": "2026-09-03T00:00:00Z",
            "ended_utc": "2026-09-03T00:00:01Z",
            "actual_size": actual_size,
            "expected_size": size,
            "actual_sha256": actual_sha,
            "expected_sha256": RUNNER.bytesource_sha256(size),
            "valid": exit_code == 0 and actual_size == size and actual_sha == RUNNER.bytesource_sha256(size),
        }

    def test_valid_sample_full_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = pathlib.Path(temporary)
            (results / "trojan-tests" / "tcp").mkdir(parents=True)
            size = 4096
            output_path = results / "trojan-tests" / "tcp" / f"{size}-1.bin"
            output_path.write_bytes(RUNNER.bytesource_payload(size))
            record = self._make_record(0)
            output = ""
            self.assertTrue(RUNNER.valid_trojan(record, output, output_path, size))

    def test_invalid_wrong_exit_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = pathlib.Path(temporary)
            (results / "trojan-tests" / "tcp").mkdir(parents=True)
            size = 4096
            output_path = results / "trojan-tests" / "tcp" / f"{size}-1.bin"
            output_path.write_bytes(RUNNER.bytesource_payload(size))
            record = self._make_record(56)
            self.assertFalse(RUNNER.valid_trojan(record, "", output_path, size))

    def test_invalid_wrong_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = pathlib.Path(temporary)
            (results / "trojan-tests" / "tcp").mkdir(parents=True)
            size = 4096
            output_path = results / "trojan-tests" / "tcp" / f"{size}-1.bin"
            output_path.write_bytes(RUNNER.bytesource_payload(size - 1))
            record = self._make_record(0)
            self.assertFalse(RUNNER.valid_trojan(record, "", output_path, size))

    def test_invalid_wrong_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = pathlib.Path(temporary)
            (results / "trojan-tests" / "tcp").mkdir(parents=True)
            size = 4096
            output_path = results / "trojan-tests" / "tcp" / f"{size}-1.bin"
            output_path.write_bytes(b"\x00" * size)
            record = self._make_record(0)
            self.assertFalse(RUNNER.valid_trojan(record, "", output_path, size))

    def test_summary_includes_expected_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = pathlib.Path(temporary)
            (results / "trojan-tests" / "quic").mkdir(parents=True)
            size = 1024
            output_path = results / "trojan-tests" / "quic" / f"{size}-1.bin"
            output_path.write_bytes(RUNNER.bytesource_payload(size))
            record = self._make_record(0)
            summary = RUNNER.summarize_trojan(record, "", output_path, size, 1, "quic")
            self.assertTrue(summary["valid"])
            self.assertEqual(summary["expected_sha256"], RUNNER.bytesource_sha256(size))
            self.assertEqual(summary["actual_sha256"], RUNNER.bytesource_sha256(size))
            self.assertEqual(summary["actual_size"], size)


class JsonRoundTripTest(unittest.TestCase):
    def test_write_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "sub" / "data.json"
            payload = {"a": 1, "b": [1, 2, 3], "c": "x"}
            RUNNER.write_json(target, payload)
            self.assertTrue(target.exists())
            raw = target.read_text()
            json.loads(raw)
            self.assertEqual(RUNNER.load_json(target), payload)


class ConcurrencyPureFunctionTest(unittest.TestCase):
    def test_split_total_bytes_exact(self):
        sizes = RUNNER.split_total_bytes(15_000_000, 64)
        self.assertEqual(len(sizes), 64)
        self.assertEqual(sum(sizes), 15_000_000)
        self.assertLessEqual(max(sizes) - min(sizes), 1)

    def test_split_total_bytes_limits(self):
        with self.assertRaises(ValueError):
            RUNNER.split_total_bytes(0, 1)
        with self.assertRaises(ValueError):
            RUNNER.split_total_bytes(50_000_001, 1)
        with self.assertRaises(ValueError):
            RUNNER.split_total_bytes(1, 0)

    def test_group_summary(self):
        samples = [
            {"valid": True, "duration_seconds": 1.0, "expected_size": 60},
            {"valid": True, "duration_seconds": 3.0, "expected_size": 40},
            {"valid": False, "duration_seconds": 2.0, "expected_size": 20},
        ]
        summary = RUNNER.concurrency_group_summary(samples, 4.0, 120)
        self.assertEqual(summary["valid_bytes"], 100)
        self.assertEqual(summary["aggregate_bits_per_second"], 200)
        self.assertEqual(summary["p50_duration_seconds"], 2)
        self.assertEqual(summary["p95_duration_seconds"], 2.9)
        self.assertEqual(summary["failure_count"], 1)


class AdditionalPureFunctionTest(unittest.TestCase):
    def test_linear_slope_per_minute(self):
        self.assertEqual(RUNNER.linear_slope_per_minute([(0, 100), (60, 220), (120, 340)]), 120)
        self.assertIsNone(RUNNER.linear_slope_per_minute([(0, 100)]))

    def test_series_summary(self):
        summary = RUNNER.series_summary([(0, 300), (60, 100), (120, 200)])
        self.assertEqual(summary["first"], 300)
        self.assertEqual(summary["last"], 200)
        self.assertEqual(summary["min"], 100)
        self.assertEqual(summary["max"], 300)
        self.assertEqual(summary["linear_slope_bytes_per_minute"], -50)

    def test_parse_proc_memory(self):
        output = "VmRSS:\t123 kB\n=== SMAPS_ROLLUP ===\nPss: 45 kB\n"
        self.assertEqual(RUNNER.parse_proc_memory(output), {"rss_bytes": 125952, "pss_bytes": 46080})

    def test_cloudflare_length_validation(self):
        metrics = {"size_download": 5000000}
        self.assertTrue(RUNNER.valid_cloudflare_sample(0, 5000000, 5000000, metrics))
        self.assertFalse(RUNNER.valid_cloudflare_sample(0, 4999999, 5000000, metrics))
        self.assertFalse(RUNNER.valid_cloudflare_sample(0, 5000000, 5000000, None))


class NetemPureFunctionTest(unittest.TestCase):
    def test_parameter_matrix(self):
        RUNNER.validate_netem_parameters("tcp", 20, 0, 1 << 20)
        RUNNER.validate_netem_parameters("quic", 300, 1, 15 << 20)
        for values in (("both", 20, 0, 1), ("tcp", 21, 0, 1), ("tcp", 20, 0.2, 1), ("tcp", 20, 0, 0), ("tcp", 20, 0, (15 << 20) + 1)):
            with self.assertRaises(ValueError):
                RUNNER.validate_netem_parameters(*values)

    def test_route_parse(self):
        output = '114.248.4.218\n[{"dst":"114.248.4.218","gateway":"172.236.226.1","dev":"eth0","prefsrc":"172.236.226.35","flags":[]}]\n'
        self.assertEqual(RUNNER.parse_netem_route(output), ("114.248.4.218", "eth0"))

    def test_route_parse_pretty_json(self):
        output = '114.248.4.218\n[\n  {\n    "dst": "114.248.4.218",\n    "gateway": "172.236.226.1",\n    "dev": "eth0",\n    "prefsrc": "172.236.226.35",\n    "flags": []\n  }\n]\n'
        self.assertEqual(RUNNER.parse_netem_route(output), ("114.248.4.218", "eth0"))

    def test_route_parse_rejects_unsafe_results(self):
        invalid = (
            'not-an-ip\n[{"dst":"114.248.4.218","dev":"eth0"}]\n',
            '2001:db8::1\n[{"dst":"2001:db8::1","dev":"eth0"}]\n',
            '114.248.4.218\n[]\n',
            '114.248.4.218\n[{"dst":"114.248.4.218","dev":"eth0"},{"dst":"114.248.4.218","dev":"eth1"}]\n',
            '114.248.4.218\n[{"dst":"203.0.113.9","dev":"eth0"}]\n',
            '114.248.4.218\n[{"dst":"114.248.4.218","dev":"eth0;bad"}]\n',
        )
        for output in invalid:
            with self.assertRaises(ValueError):
                RUNNER.parse_netem_route(output)

    def test_tcp_commands_are_precisely_scoped(self):
        commands = RUNNER.netem_commands("eth0", "203.0.113.9", "tcp", 100, 0.1, "ifbabcdef12", 32123)
        setup = commands["setup"]
        self.assertIn("dev eth0 egress protocol ip pref 32123 flower", setup)
        self.assertIn("dst_ip 203.0.113.9/32", setup)
        self.assertIn("ip_proto tcp src_port 3443", setup)
        self.assertIn("action mirred egress redirect dev ifbabcdef12", setup)
        self.assertIn("dev ifbabcdef12 root netem delay 100ms loss 0.1%", setup)
        self.assertNotIn("dev eth0 root netem", setup)
        self.assertNotIn("qdisc del dev eth0", commands["cleanup"])
        self.assertNotIn("qdisc del dev eth0 clsact", commands["cleanup"])

    def test_quic_uses_udp(self):
        setup = RUNNER.netem_commands("enp1s0", "198.51.100.2", "quic", 20, 0, "ifb12345678", 30001)["setup"]
        self.assertIn("dst_ip 198.51.100.2/32 ip_proto udp src_port 3443", setup)


class ProtocolSelectionTest(unittest.TestCase):
    def test_protocol_selection(self):
        self.assertEqual(RUNNER.selected_protocols("tcp"), ("tcp",))
        self.assertEqual(RUNNER.selected_protocols("quic"), ("quic",))
        self.assertEqual(RUNNER.selected_protocols("both"), ("tcp", "quic"))
        with self.assertRaises(ValueError):
            RUNNER.selected_protocols("udp")

    def test_deploy_protocol_contract(self):
        self.assertFalse(RUNNER.validate_protocol_deploy("tcp", {"server_disable_tcp": False}))
        self.assertFalse(RUNNER.validate_protocol_deploy("both", {}))
        self.assertTrue(RUNNER.validate_protocol_deploy("quic", {"server_disable_tcp": True}))
        for protocol, disabled in (("tcp", True), ("both", True), ("quic", False)):
            with self.assertRaises(ValueError):
                RUNNER.validate_protocol_deploy(protocol, {"server_disable_tcp": disabled})

    def test_listener_validation(self):
        output = "=== TCP ===\nLISTEN 0 4096 0.0.0.0:3443 0.0.0.0:*\n=== UDP ===\nUNCONN 0 0 0.0.0.0:3443 0.0.0.0:*\n"
        snapshot = RUNNER.parse_listener_snapshot(output)
        self.assertEqual(snapshot, {"port": 3443, "tcp": True, "udp": True})
        self.assertTrue(RUNNER.validate_listener_snapshot(snapshot, False)["valid"])
        self.assertFalse(RUNNER.validate_listener_snapshot(snapshot, True)["valid"])

    def test_quic_only_listener_validation(self):
        output = "=== TCP ===\n=== UDP ===\nUNCONN 0 0 [::]:3443 [::]:*\n"
        snapshot = RUNNER.parse_listener_snapshot(output)
        self.assertFalse(snapshot["tcp"])
        self.assertTrue(snapshot["udp"])
        self.assertTrue(RUNNER.validate_listener_snapshot(snapshot, True)["valid"])
        self.assertFalse(RUNNER.validate_listener_snapshot(snapshot, False)["valid"])


class ConstantsTest(unittest.TestCase):
    def test_r2_max_enforced(self):
        self.assertEqual(RUNNER.R2_MAX_SAMPLE_BYTES, 15 * 1024 * 1024)
        self.assertEqual(len(RUNNER.R2_DEFAULT_SIZES), 4)
        self.assertEqual(RUNNER.R2_DEFAULT_SIZES[-1], RUNNER.R2_MAX_SAMPLE_BYTES)


if __name__ == "__main__":
    unittest.main()
