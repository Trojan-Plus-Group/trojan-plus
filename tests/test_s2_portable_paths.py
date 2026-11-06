#!/usr/bin/env python3
"""Exercise S2 default cleanup and explicit artifact retention without a home path."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
binary = os.environ.get('S5_BINARY') or os.environ.get('S2_BINARY')
if not binary:
    workspace = Path(os.environ.get('PIPELINE_WORKSPACE', root))
    binary = next((str(path) for path in (root / 'build/trojan', workspace / 'LinuxBinary/trojan')
                   if path.is_file()), None)
assert binary, 'S2 portability regression requires real binary; set S5_BINARY'
with tempfile.TemporaryDirectory(prefix='s2-portability-') as directory:
    work = Path(directory)
    env = dict(os.environ, S2_BINARY=binary, TMPDIR=directory, HOME=str(work / 'absent-home'))
    env.pop('S2_LOG_DIR', None)
    for retain in (False, True):
        if retain:
            env['S2_LOG_DIR'] = str(work / 'retained')
        for name in ('test_s2_padding.py', 'test_s2_padding_codec.py'):
            result = subprocess.run([sys.executable, '-u', str(root / 'tests' / name)],
                                    env=env, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            print(result.stdout, end='')
            assert result.returncode == 0, (name, result.returncode)
            assert 'skipped' not in result.stdout.lower(), result.stdout
            assert ('Ran 7 tests' if name == 'test_s2_padding.py' else
                    'S2 codec checks passed') in result.stdout
        if retain:
            assert list((work / 'retained').glob('s2-padding-*/cert.pem'))
            assert list((work / 'retained').glob('codec-*/output.log'))
        else:
            assert not list(work.iterdir()), list(work.iterdir())
print('S2 portable paths, cleanup and explicit retention checks passed')
