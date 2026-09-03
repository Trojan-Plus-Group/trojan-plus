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


class ConstantsTest(unittest.TestCase):
    def test_r2_max_enforced(self):
        self.assertEqual(RUNNER.R2_MAX_SAMPLE_BYTES, 15 * 1024 * 1024)
        self.assertEqual(len(RUNNER.R2_DEFAULT_SIZES), 4)
        self.assertEqual(RUNNER.R2_DEFAULT_SIZES[-1], RUNNER.R2_MAX_SAMPLE_BYTES)


if __name__ == "__main__":
    unittest.main()
