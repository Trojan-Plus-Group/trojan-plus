import importlib.util
import pathlib
import unittest


PATH = pathlib.Path(__file__).with_name("sync_remote.py")
SPEC = importlib.util.spec_from_file_location("sync_remote", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SyncRemoteTest(unittest.TestCase):
    def test_remote_sync_switches_or_creates_target_branch(self):
        command = MODULE.remote_sync_command("opt_perf", "/tmp/opt_perf.bundle")
        self.assertIn("show-ref --verify --quiet refs/heads/opt_perf", command)
        self.assertIn("switch opt_perf", command)
        self.assertIn("switch -c opt_perf FETCH_HEAD", command)
        self.assertIn("reset --hard FETCH_HEAD", command)
        self.assertNotIn("merge --ff-only FETCH_HEAD", command)

    def test_remote_sync_verifies_branch_and_commit(self):
        command = MODULE.remote_sync_command("opt_perf", "/tmp/opt_perf.bundle")
        self.assertIn('branch --show-current)\" = opt_perf', command)
        self.assertIn("rev-parse HEAD", command)
        self.assertIn("rev-parse FETCH_HEAD", command)

    def test_remote_sync_quotes_values(self):
        command = MODULE.remote_sync_command("feature;test", "/tmp/test bundle")
        self.assertIn("'feature;test'", command)
        self.assertIn("'refs/heads/feature;test'", command)
        self.assertIn("'/tmp/test bundle'", command)


if __name__ == "__main__":
    unittest.main()
