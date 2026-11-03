import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


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

    def test_slash_branch_uses_unique_flat_bundle_names(self):
        bundles: list[pathlib.Path] = []

        def run(cmd, **kwargs):
            if cmd[:3] == ["git", "bundle", "create"]:
                path = pathlib.Path(cmd[3])
                self.assertEqual(path.parent, pathlib.Path("/tmp/opencode"))
                self.assertTrue(path.name.startswith("tp-sync-"))
                self.assertEqual(cmd[4], "refs/heads/feature/test")
                bundles.append(path)
            if cmd[0] == "scp":
                self.assertEqual(cmd[-1], f"root@{MODULE.HOST}:/tmp/{bundles[-1].name}")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with mock.patch.object(MODULE, "run_cmd", side_effect=run):
            for _ in range(2):
                MODULE.sync_bundle("feature/test", 10, 120, 120, 60, 15)
        self.assertNotEqual(bundles[0], bundles[1])
        self.assertTrue(all(not path.exists() for path in bundles))

    def test_bundle_creation_failure_cleans_unique_file(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as directory:
            path = pathlib.Path(directory) / "failed.bundle"
            path.touch()
            bundle = mock.MagicMock()
            bundle.__enter__.return_value.name = str(path)
            error = subprocess.CalledProcessError(1, ["git", "bundle"])
            with mock.patch.object(MODULE.tempfile, "NamedTemporaryFile", return_value=bundle), \
                    mock.patch.object(MODULE, "run_cmd", side_effect=[None, error, None]):
                with self.assertRaises(subprocess.CalledProcessError):
                    MODULE.sync_bundle("feature/test", 10, 120, 120, 60, 15)
            self.assertFalse(path.exists())

    def test_android_host_selection_and_quoted_paths(self):
        script = PATH.parents[2] / "build_android_so.sh"
        for system, machine, tag in [
            ("Linux", "x86_64", "linux-x86_64"),
            ("Darwin", "x86_64", "darwin-x86_64"),
            ("Darwin", "arm64", "darwin-x86_64"),
            ("Darwin", "arm64", "darwin-arm64"),
            ("Linux", "aarch64", "linux-x86_64"),
        ]:
            with self.subTest(system=system, machine=machine, tag=tag), \
                    tempfile.TemporaryDirectory(prefix="android quoted ", dir="/tmp/opencode") as directory:
                root = pathlib.Path(directory)
                shutil.copy(script, root / script.name)
                tools = root / "bin"
                tools.mkdir()
                ndk = root / "ndk with spaces"
                prebuilt = ndk / "toolchains/llvm/prebuilt" / tag / "bin"
                prebuilt.mkdir(parents=True)
                for name, content in {
                    "uname": f'#!/bin/bash\nif [ "$1" = -s ]; then echo {system}; else echo {machine}; fi\n',
                    "sysctl": '#!/bin/bash\necho 2\n',
                    "cmake": '#!/bin/bash\nprintf "%s\\n" "$@" >> "$ARG_LOG"\n',
                }.items():
                    tool = tools / name
                    tool.write_text(content)
                    tool.chmod(0o755)
                readelf = prebuilt / "llvm-readelf"
                readelf.touch()
                readelf.chmod(0o755)
                log = root / "args.log"
                env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}", ARG_LOG=str(log))
                subprocess.run(["bash", str(root / script.name), str(ndk)], env=env, check=True)
                args = log.read_text().splitlines()
                self.assertEqual(args.count(f"-DANDROID_TOOLCHAIN_PREFIX={prebuilt}/llvm-"), 2)
                self.assertIn("-DANDROID_ABI=arm64-v8a", args)
                self.assertIn("-DANDROID_ABI=x86_64", args)
                self.assertEqual(args.count(str(root)), 2)
                self.assertNotEqual(subprocess.run(["bash", str(root / script.name)], env=env,
                                                   capture_output=True).returncode, 0)
                (tools / "cmake").write_text('#!/bin/bash\nexit 19\n')
                self.assertEqual(subprocess.run(["bash", str(root / script.name), str(ndk)],
                                                env=env, capture_output=True).returncode, 19)


if __name__ == "__main__":
    unittest.main()
