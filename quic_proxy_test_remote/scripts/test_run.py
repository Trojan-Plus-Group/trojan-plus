import datetime
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import time
import unittest
from unittest import mock


PATH = pathlib.Path(__file__).with_name("run.py")
SPEC = importlib.util.spec_from_file_location("baseline_runner", PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
STARTED = None


def stage_log(message):
    timestamp = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def setUpModule():
    global STARTED
    STARTED = time.monotonic()
    stage_log("[stage] run.py unit tests started; usually under 10 seconds")


def tearDownModule():
    stage_log(f"[stage] run.py unit tests completed; elapsed {time.monotonic() - STARTED:.1f} seconds")


class RunnerTest(unittest.TestCase):
    def test_percentile(self):
        self.assertEqual(RUNNER.percentile([10, 20, 30, 40, 50], 0.1), 14)
        self.assertEqual(RUNNER.percentile([10, 20, 30, 40, 50], 0.9), 46)
        self.assertIsNone(RUNNER.percentile([], 0.5))

    def test_valid_iperf(self):
        valid = '{"end":{"sum_sent":{"seconds":1,"bytes":100,"bits_per_second":800}}}'
        incomplete = '{"end":{"sum_received":{"seconds":0.000008,"bytes":131072,"bits_per_second":131072000000}}}'
        self.assertTrue(RUNNER.valid_iperf({"exit_code": 0}, valid))
        self.assertTrue(RUNNER.valid_iperf({"exit_code": 0}, incomplete))
        self.assertFalse(RUNNER.valid_iperf({"exit_code": 1}, valid))
        self.assertFalse(RUNNER.valid_iperf({"exit_code": 0}, '{"error": "failed"}'))

    def test_iperf_metrics_ignores_incomplete_receiver_summary(self):
        output = json.dumps({
            "end": {
                "sum_received": {"seconds": 0.000008, "bytes": 131072, "bits_per_second": 131072000000},
                "sum_sent": {"seconds": 0.297786, "bytes": 16121856, "bits_per_second": 433112530.47},
            }
        })
        self.assertEqual(RUNNER.iperf_metrics(output, "tcp")["bits_per_second"], 433112530.47)

    def test_throughput_summary_excludes_invalid_samples(self):
        samples = [
            {"valid": True, "bytes": 100, "duration_seconds": 1},
            {"valid": True, "bytes": 300, "duration_seconds": 1},
            {"valid": False, "bytes": 1000, "duration_seconds": 1},
        ]
        summary = RUNNER.throughput_summary(samples)
        self.assertEqual(summary["valid_samples"], 2)
        self.assertEqual(summary["median_bits_per_second"], 1600)

    def test_summarize_marks_invalid_samples(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = pathlib.Path(temporary)
            (results / "baseline").mkdir()
            output = results / "sample.stdout"
            output.write_text('{"end":{"sum_received":{"seconds":1,"bytes":100,"bits_per_second":100},"sum_sent":{"seconds":1,"bytes":100,"bits_per_second":100,"retransmits":2}}}')
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
        expected = hashlib.shake_256(b"trojan-plus-bytesource-v1").digest(8)
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
        expected_digest = hashlib.sha256(hashlib.shake_256(b"trojan-plus-bytesource-v1").digest(size)).hexdigest()
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
            output = "200"
            self.assertTrue(RUNNER.valid_trojan(record, output, output_path, size))

    def test_http_error_rejected_even_with_matching_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / 'payload'
            output.write_bytes(RUNNER.bytesource_payload(32))
            self.assertFalse(RUNNER.valid_trojan(self._make_record(0), '503', output, 32))
            self.assertTrue(RUNNER.valid_trojan(self._make_record(0), '200', output, 32))

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
            summary = RUNNER.summarize_trojan(record, "200", output_path, size, 1, "quic")
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
        metrics = {"size_download": 5000000, "http_code": 200}
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
        with self.assertRaises(ValueError):
            RUNNER.validate_protocol_deploy("both", {})
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


class CertificateTest(unittest.TestCase):
    def test_write_self_signed_cert(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
        except ImportError:
            self.skipTest("cryptography is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            key_path = directory / "server.key"
            cert_path = directory / "server.crt"
            RUNNER.write_self_signed_cert(key_path, cert_path, RUNNER.HOST)
            load_pem_private_key(key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual([str(ip) for ip in sans.get_values_for_type(x509.IPAddress)], [RUNNER.HOST])


class RuntimeArgumentsTest(unittest.TestCase):
    def test_defaults(self):
        args = RUNNER.parse_args(["soak", "--run-id", "x"])
        self.assertEqual(args.item_timeout, 170)
        self.assertEqual(args.retry_delays, (3, 10))
        self.assertEqual(args.default_attempt_timeout, 140)
        self.assertEqual(args.run_item_attempt_timeout, 50)
        self.assertEqual(args.ssh_connect_timeout, 10)
        self.assertEqual(args.local_port_timeout, 30)
        self.assertEqual(args.poll_interval, 0.5)
        self.assertEqual(args.cloudflare_outer_timeout, 180)
        self.assertEqual(args.soak_sample_interval, 60)
        self.assertEqual(args.netem_watchdog, 300)
        self.assertEqual(args.minutes, 5)
        self.assertEqual(args.cooldown, 2)

    def test_runtime_arguments_after_subcommand(self):
        args = RUNNER.parse_args(["netem", "--run-id", "x", "--protocol", "quic", "--delay-ms", "20", "--loss-percent", "0", "--retry-delays", "1", "2", "--command-timeout", "7", "--netem-watchdog", "9"])
        RUNNER.apply_runtime_arguments(args)
        self.assertEqual(RUNNER.RETRY_DELAYS, (1, 2))
        self.assertEqual(RUNNER.COMMAND_TIMEOUT, 7)
        self.assertEqual(RUNNER.NETEM_WATCHDOG, 9)


class CleanupGateTest(unittest.TestCase):
    def test_quic_requires_both_handshakes_and_streams(self):
        client = 'QuicConnection: handshake completed (role=client, peer=x, alpn=h3)\nsend_stream_data_impl enter: stream_id=0 datalen=42'
        server = 'QuicConnection: handshake completed (role=server, peer=x, alpn=h3)\nQuicProxySession: stream 0 opened'
        self.assertTrue(RUNNER.verify_quic_logs(client, server)['valid'])
        for left, right in ((client, ''), ('TCP tunnel established', server), (client.replace('h3', 'h2'), server), (client.split('\n')[0], server)):
            self.assertFalse(RUNNER.verify_quic_logs(left, right)['valid'])

    def test_stop_removes_deploy_without_server_metadata(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(RUNNER, 'ROOT', pathlib.Path(temporary)), mock.patch.object(RUNNER, 'archive_remote_logs'), mock.patch.object(RUNNER, 'stop_remote_named', return_value={'skipped': True}), mock.patch.object(RUNNER, 'execute_attempt', return_value=({'exit_code': 0}, '')) as execute:
            args = RUNNER.parse_args(['trojan-stop', '--run-id', 'sample'])
            results = pathlib.Path(temporary) / 'results/sample'
            RUNNER.write_json(results / 'metadata/trojan-deploy.json', {'remote_dir': '/tmp/trojan-deploy.ABC123'})
            RUNNER.trojan_stop(args)
            self.assertIn('rm -rf -- /tmp/trojan-deploy.ABC123', execute.call_args.args[0][-1])

    def test_deploy_failure_always_stops(self):
        args = RUNNER.parse_args(['trojan-deploy', '--run-id', 'sample'])
        with mock.patch.object(RUNNER, 'deploy_files', side_effect=RuntimeError('scp failed')), mock.patch.object(RUNNER, 'trojan_stop') as stop:
            with self.assertRaisesRegex(RuntimeError, 'scp failed'):
                RUNNER.trojan_deploy(args)
            stop.assert_called_once_with(args)

    def test_deployed_config_checked_before_server_start(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(RUNNER, 'ROOT', pathlib.Path(temporary)), mock.patch.object(RUNNER, 'execute_attempt', return_value=({'exit_code': 0}, '{"quic":{"enabled":false}}')), mock.patch.object(RUNNER, 'start_remote_named') as start:
            results = pathlib.Path(temporary) / 'results/sample'
            RUNNER.write_json(results / 'metadata/trojan-deploy.json', {'remote_dir': '/tmp/trojan-deploy.ABC123', 'server_disable_tcp': True})
            RUNNER.write_json(results / 'metadata/manifest.json', {})
            with self.assertRaisesRegex(RuntimeError, 'config mismatch'):
                RUNNER.trojan_start(RUNNER.parse_args(['trojan-start', '--run-id', 'sample']))
            start.assert_not_called()

    def test_soak_rejects_wrong_deploy(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(RUNNER, 'ROOT', pathlib.Path(temporary)), mock.patch.object(RUNNER, 'bytesource_start') as start:
            args = RUNNER.parse_args(['soak', '--run-id', 'sample', '--protocol', 'quic'])
            RUNNER.write_json(pathlib.Path(temporary) / 'results/sample/metadata/trojan-deploy.json', {'server_disable_tcp': False})
            with self.assertRaises(ValueError):
                RUNNER.soak(args)
            start.assert_not_called()

    def test_cloudflare_requires_opt_in_and_hash(self):
        args = RUNNER.parse_args(['cloudflare', '--run-id', 'sample', '--protocol', 'quic'])
        with self.assertRaisesRegex(ValueError, 'allow-external'):
            RUNNER.cloudflare(args)

    def test_uploaded_bytesource_matches_local_hash(self):
        source = RUNNER.BYTESOURCE_SCRIPT.split('port = int(sys.argv[1])')[0]
        namespace = {}
        exec(source, namespace)
        self.assertEqual(hashlib.shake_256(namespace['seed']).digest(65537), RUNNER.bytesource_payload(65537))
        self.assertIn('payload[sent:sent + 65536]', source)
        self.assertIn('n > 50000000', source)

    def test_payload_not_periodic(self):
        data = RUNNER.bytesource_payload(131072)
        self.assertNotEqual(data[:256], data[256:512])
        self.assertNotEqual(data[:65536], data[65536:])

    def test_retry_explicit_and_first_failure_retained(self):
        with mock.patch.object(RUNNER, 'execute_attempt', side_effect=[({'exit_code': 1}, ''), ({'exit_code': 0}, '')]), mock.patch.object(RUNNER, 'write_json'), mock.patch.object(RUNNER, 'ALLOWED_RETRIES', 1), mock.patch.object(RUNNER, 'RETRY_DELAYS', (0, 0)):
            item = RUNNER.run_item([], pathlib.Path('/unused'), 'sample', pathlib.Path('/unused'))
        self.assertTrue(item['valid'])
        self.assertEqual(item['allowed_retries'], 1)
        self.assertEqual(item['first_failure']['exit_code'], 1)
        self.assertEqual(len(item['attempts']), 2)

    def test_no_retry_by_default(self):
        with mock.patch.object(RUNNER, 'execute_attempt', return_value=({'exit_code': 1}, '')) as execute, mock.patch.object(RUNNER, 'write_json'), mock.patch.object(RUNNER, 'ALLOWED_RETRIES', 0):
            item = RUNNER.run_item([], pathlib.Path('/unused'), 'sample', pathlib.Path('/unused'))
        self.assertFalse(item['valid'])
        self.assertEqual(execute.call_count, 1)

    def test_failed_case_writes_gate_and_raises(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(RUNNER, 'ROOT', pathlib.Path(temporary)):
            args = RUNNER.parse_args(['baseline', '--run-id', 'sample'])
            def fail(args):
                raise RuntimeError('first failure')
            with self.assertRaisesRegex(RuntimeError, 'first failure'):
                RUNNER.case_gate(args, fail)
            summary = RUNNER.load_json(pathlib.Path(temporary) / 'results/sample/baseline/summary.json')
            self.assertFalse(summary['pass'])
            self.assertEqual(summary['thresholds']['max_failed_samples'], 0)

class ConstantsTest(unittest.TestCase):
    def test_r2_max_enforced(self):
        self.assertEqual(RUNNER.R2_MAX_SAMPLE_BYTES, 15 * 1024 * 1024)
        self.assertEqual(len(RUNNER.R2_DEFAULT_SIZES), 4)
        self.assertEqual(RUNNER.R2_DEFAULT_SIZES[-1], RUNNER.R2_MAX_SAMPLE_BYTES)


if __name__ == "__main__":
    unittest.main()
