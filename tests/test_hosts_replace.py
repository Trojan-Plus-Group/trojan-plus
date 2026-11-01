#!/usr/bin/env python3
"""Check atomic and bind-mounted hosts updates without touching /etc/hosts."""
import ast
import errno
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

source = Path(__file__).parent / "LinuxFullTest/fulltest_ipv6.py"
tree = ast.parse(source.read_text())
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name in ("atomic_replace_hosts", "read_hosts_bytes")]
namespace = dict(os=os, errno=errno, tempfile=tempfile, sys=sys)
exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)
mkstemp = tempfile.mkstemp
with tempfile.TemporaryDirectory() as directory:
    target = Path(directory) / "hosts"
    namespace["HOSTS_PATH"] = str(target)

    def make_temp(*args, **kwargs):
        kwargs["dir"] = directory
        return mkstemp(*args, **kwargs)

    for privileged in (False, True):
        for error in (None, errno.EBUSY, errno.EXDEV, errno.EIO):
            original = b"127.0.0.1 localhost\n# original\n"
            target.write_bytes(original)
            inode = target.stat().st_ino
            replacement = b"::1 localhost\n"

            def temp_with_permissions(*args, **kwargs):
                if privileged and kwargs.get("dir") == "/etc":
                    raise PermissionError()
                return make_temp(*args, **kwargs)

            def checked(cmd, action):
                # Emulate sudo commands on scratch files, including the actual script.
                if cmd[2] == "cp":
                    Path(cmd[4]).write_bytes(Path(cmd[3]).read_bytes())
                elif cmd[2] == "chmod":
                    pass
                elif cmd[2] == "rm":
                    Path(cmd[4]).unlink(missing_ok=True)
                else:
                    with patch.object(sys, "argv", ["-c", *cmd[5:]]):
                        exec(cmd[4], {})

            # Redirect the privileged staging file as well as mkstemp files.
            replace = os.replace

            def rename(src, dst):
                if error is not None:
                    raise OSError(error, os.strerror(error))
                replace(src, dst)

            # The privileged path constructs /etc/.hosts-...; redirect only that path.
            def redirect_checked(cmd, action):
                cmd = [str(Path(directory) / Path(arg).name)
                       if arg.startswith("/etc/.hosts-trojan-plus-") else arg for arg in cmd]
                checked(cmd, action)

            namespace["_run_checked"] = redirect_checked
            with patch.object(tempfile, "mkstemp", side_effect=temp_with_permissions), \
                    patch.object(os, "replace", side_effect=rename):
                try:
                    namespace["atomic_replace_hosts"](replacement)
                except OSError as exc:
                    assert error == errno.EIO and exc.errno == errno.EIO
                    assert target.read_bytes() == original
                else:
                    assert error != errno.EIO
                    assert target.read_bytes() == replacement
                    if error is not None:
                        assert target.stat().st_ino == inode
                    namespace["atomic_replace_hosts"](original)
                    assert target.read_bytes() == original
            assert sorted(path.name for path in Path(directory).iterdir()) == ["hosts"]
print("Hosts atomic, bind-mount fallback, sudo, restoration and error checks passed")
