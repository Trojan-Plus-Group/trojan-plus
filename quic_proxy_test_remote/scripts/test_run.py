import importlib.util
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


if __name__ == "__main__":
    unittest.main()
