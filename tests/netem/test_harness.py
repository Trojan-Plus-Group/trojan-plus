#!/usr/bin/env python3
"""Container-free checks: python3 tests/netem/test_harness.py."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from harness import (BUFFERS, PROFILES, DIAGNOSTIC_PROFILES, aggregate, buffer_log, digest, make_config,
                      parser, plan, quic_process_env, perf_command, Profiler, cpu_snapshot, cpu_delta, main, run_cell)


class HarnessTests(unittest.TestCase):
    def test_compiled_diagnostics_required(self):
        from harness import require_quic_diagnostics
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'trojan'
            binary.write_bytes(b'production')
            args = parser().parse_args(['--binary', str(binary)])
            require_quic_diagnostics(args)
            for flags in (['--quic-stats'], ['--quic-cc', 'bbr'], ['--quic-cc', 'cubic']):
                args = parser().parse_args(['--binary', str(binary)] + flags)
                with self.assertRaisesRegex(SystemExit, '-DTROJAN_QUIC_STATS=ON'):
                    require_quic_diagnostics(args)
                binary.write_bytes(b'quic stats: compiled in')
                require_quic_diagnostics(args)
                binary.write_bytes(b'production')

    def test_perf_options_commands_and_groups(self):
        args = parser().parse_args([])
        self.assertIsNone(args.perf_role)
        self.assertEqual(args.perf_kind, 'record')
        args = parser().parse_args(['--perf-role', 'server', '--perf-host-output', '/external/run'])
        root = Path('/logs/cell')
        argv = perf_command(args, root, 123)
        self.assertEqual(argv[:4], ['chroot', '/host', '/usr/bin/perf', 'record'])
        self.assertEqual(argv[-7:], ['-F', '999', '-g', '--call-graph', 'fp', '-o', '/external/run/cell/perf.data'])
        self.assertIn('--control=fifo:/external/run/cell/perf.control,/external/run/cell/perf.ack', argv)
        self.assertIn('--delay=-1', argv)
        args.perf_kind = 'stat'
        argv = perf_command(args, root, 123)
        self.assertEqual(argv[3], 'stat')
        self.assertEqual(argv[argv.index('-e') + 1], 'task-clock,context-switches,cpu-migrations,page-faults')
        args.perf_kind = 'syscalls'
        argv = perf_command(args, root, 123)
        self.assertIn('raw_syscalls:sys_enter,raw_syscalls:sys_exit', argv)
        self.assertNotIn('-g', argv)
        args = parser().parse_args(['--perf-kind', 'trace', '--perf-host-output', '/external/run'])
        self.assertEqual(perf_command(args, root, 123),
                         ['chroot', '/host', '/usr/bin/perf', 'trace', '-S', '--summary-mode', 'total',
                          '-p', '123', '-o', '/external/run/cell/perf.trace'])
        base = dict(profile='clean', workload='A', mode='quic', recv_buffer=1, send_buffer=1,
                    success=True, eagain=0, duration_s=1, throughput_mbps=1)
        rows = [base, dict(base, perf_role='server'), dict(base, perf_role='client'),
                dict(base, perf_role='server', perf_kind='stat'), dict(base, perf_role='server', perf_kind='syscalls')]
        self.assertEqual(len(aggregate(rows)), 5)

    def test_transfer_cpu(self):
        before = dict(total=20, threads={'1': 10, '2': 10})
        after = dict(total=50, threads={'1': 20, '3': 5})
        hz = os.sysconf('SC_CLK_TCK')
        self.assertEqual(cpu_delta(before, after), dict(total_s=30/hz, max_thread_s=10/hz))
        snapshot = cpu_snapshot(os.getpid())
        self.assertIn(str(os.getpid()), snapshot['threads'])
        self.assertGreaterEqual(snapshot['total'], sum(snapshot['threads'].values()))

    def test_profiler_fifo_lifecycle(self):
        # Fake perf validates readiness without requiring perf permissions or containers.
        script = '''import signal, sys
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
with open(sys.argv[1]) as ctl, open(sys.argv[2], 'w') as ack:
    while True:
        line = ctl.readline()
        if line:
            ack.write('ack\\n')
            ack.flush()
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            argv = [sys.executable, '-c', script, str(root / 'perf.control'), str(root / 'perf.ack')]
            with patch('harness.perf_command', return_value=argv):
                profiler = Profiler(None, root, os.getpid())
                self.assertIsNone(profiler.process.poll())
                profiler.finish()
                self.assertEqual(profiler.process.returncode, 0)
                self.assertFalse(profiler.fds)
                self.assertTrue((root / 'perf.command.json').exists())
        with tempfile.TemporaryDirectory() as directory:
            with patch('harness.perf_command', return_value=[sys.executable, '-c', 'raise SystemExit(7)']):
                with self.assertRaisesRegex(RuntimeError, 'perf exited before enable acknowledgement: 7'):
                    Profiler(None, Path(directory), os.getpid())

    def test_profiler_trace_lifecycle(self):
        from unittest.mock import Mock
        args = parser().parse_args(['--perf-kind', 'trace', '--perf-host-output', '/external/run'])
        process = Mock(pid=123, returncode=0)
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('harness.sp.Popen', return_value=process), \
                 patch('harness.Path.iterdir', return_value=iter([Path('/host/proc/123/fd/7')])), \
                 patch('harness.os.readlink', return_value='anon_inode:[perf_event]'), \
                 patch('harness.os.mkfifo') as fifo, patch.object(Profiler, 'control') as control:
                profiler = Profiler(args, root, 456)
                self.assertFalse(profiler.fds)
                fifo.assert_not_called()
                self.assertFalse((root / 'perf.control').exists())
                profiler.finish()
                control.assert_not_called()
                import signal
                process.send_signal.assert_called_once_with(signal.SIGINT)
                process.wait.assert_called_once_with(timeout=15)

    def test_trace_readiness_failures(self):
        from unittest.mock import Mock
        profiler = Profiler.__new__(Profiler)
        profiler.process = Mock(pid=123, returncode=7)
        profiler.process.poll.return_value = 7
        with self.assertRaisesRegex(RuntimeError, 'perf trace exited before attachment: 7'):
            profiler.wait_trace_ready()
        profiler.process.poll.return_value = None
        with patch('harness.time.monotonic', side_effect=[0, 0, 16]), \
             patch('harness.Path.iterdir', return_value=iter([])), patch('harness.time.sleep'):
            with self.assertRaisesRegex(RuntimeError, 'perf trace attachment timed out'):
                profiler.wait_trace_ready()

    def test_perf_intentional_sigint(self):
        import signal
        from unittest.mock import Mock
        for code in (0, -signal.SIGINT, 7, -signal.SIGKILL):
            with self.subTest(returncode=code):
                profiler = Profiler.__new__(Profiler)
                profiler.process = Mock(returncode=code)
                profiler.trace = False
                profiler.control = Mock()
                profiler.close = Mock()
                if code in (0, -signal.SIGINT):
                    profiler.finish()
                else:
                    with self.assertRaisesRegex(RuntimeError, 'perf failed'):
                        profiler.finish()
                profiler.control.assert_called_once_with('disable')
                profiler.close.assert_called_once_with()

    def test_perf_nul_acknowledgement(self):
        profiler = Profiler.__new__(Profiler)
        profiler.fds = [10, 11]
        from unittest.mock import Mock
        profiler.process = Mock()
        profiler.process.poll.return_value = None
        with patch('harness.os.write'), patch('harness.select.select', return_value=([11], [], [])):
            for reply in (b'ack\n', b'ack\n\x00'):
                with self.subTest(reply=reply), patch('harness.os.read', return_value=reply):
                    profiler.control('enable')
            with patch('harness.os.read', return_value=b'wrong\n\x00'):
                with self.assertRaisesRegex(RuntimeError, 'Unexpected perf acknowledgement'):
                    profiler.control('enable')

    def test_plan(self):
        args = parser().parse_args(['--output-dir', '/external'])
        self.assertEqual(len(plan(args)), 336)
        args.slow_repeats = 1
        self.assertEqual(len(plan(args)), 252)
        self.assertEqual(len(PROFILES), 8)
        self.assertEqual(BUFFERS[0], 76800)
        self.assertEqual(PROFILES['burst'], ['loss', '5%', '25%'])

    def test_log_level_config(self):
        for options, expected in (([], 1), (['--log-level', '0'], 0), (['--log-level', '5'], 5)):
            args = parser().parse_args(['--output-dir', '/external', *options])
            args.source = Path(__file__).resolve().parents[2]
            self.assertEqual(args.log_level, expected)
            for label in ('client', 'server'):
                config = make_config(args, label, 'clean', 'quic', 76800, 212992)
                self.assertEqual(config['log_level'], expected)
                self.assertEqual(config['quic']['send_buffer_size'], 212992)
        args = parser().parse_args(['--output-dir', '/external', '--link-network', '192.0.2.0/30'])
        args.source = Path(__file__).resolve().parents[2]
        self.assertEqual(make_config(args, 'client', 'clean', 'quic', 1, 1)['remote_addr'], '192.0.2.2')

    def test_diagnostic_profiles(self):
        self.assertEqual(DIAGNOSTIC_PROFILES['delay100-fixed'], ['delay', '100ms'])
        self.assertEqual(DIAGNOSTIC_PROFILES['delay100-jitter'], PROFILES['delay100'])
        self.assertEqual(DIAGNOSTIC_PROFILES['delay100-jitter-ordered'], ['delay', '70ms', 'slot', '1ms', '60ms'])
        for profile in DIAGNOSTIC_PROFILES:
            args = parser().parse_args(['--output-dir', '/external', '--profile', profile,
                                        '--log-level', '5', '--workload', 'A', '--buffer-size', '76800'])
            self.assertEqual(len(plan(args)), 6)
            self.assertEqual(plan(args)[0][0], profile)
        args.source = Path(__file__).resolve().parents[2]
        self.assertEqual(make_config(args, 'server', 'relay-only', 'quic', 76800, 76800)['local_port'], 4434)

    def test_probe_only_options(self):
        args = parser().parse_args(['--profile', 'delay100-jitter-ordered', '--probe-only'])
        self.assertTrue(args.probe_only)
        self.assertEqual(args.profile, 'delay100-jitter-ordered')
        self.assertEqual(args.probe_spacing, 0.001)

        args = parser().parse_args(['--profile', 'delay100-jitter-ordered', '--probe-only', '--probe-spacing', '0.0002'])
        self.assertEqual(args.probe_spacing, 0.0002)

    def test_buffers(self):
        line = 'buffers requested recv=76800 send=212992 actual recv=76800 send=212992'
        self.assertEqual(buffer_log(line, 76800, 212992)['actual_send'], 212992)
        with self.assertRaises(RuntimeError):
            buffer_log(line, 1, 2)

    def test_aggregation(self):
        base = dict(profile='clean', workload='A', mode='quic', recv_buffer=76800,
                    send_buffer=76800, quic_cc='bbr', quic_stats=False, success=True, eagain=2)
        rows = [dict(base, duration_s=n, throughput_mbps=10/n) for n in (1, 2, 3)]
        rows.append(dict(base, success=False))
        result = aggregate(rows)[0]
        self.assertEqual(result['failures'], 1)
        self.assertEqual(result['duration_s'], dict(median=2, min=1, max=3))
        self.assertEqual(result['eagain'], 8)
        self.assertEqual(result['quic_cc'], 'bbr')
        self.assertFalse(result['quic_stats'])
        other = dict(base, quic_cc='cubic', duration_s=4, throughput_mbps=2)
        self.assertEqual(len(aggregate(rows + [other])), 2)
        self.assertEqual(len(digest(50_000_000)), 64)

    def test_quic_cc_stats_options(self):
        args = parser().parse_args(['--output-dir', '/external'])
        self.assertEqual(args.quic_cc, 'bbr')
        self.assertFalse(args.quic_stats)
        self.assertFalse(args.netem_before_handshake)
        enabled = parser().parse_args(['--netem-before-handshake'])
        self.assertTrue(enabled.netem_before_handshake)
        base = dict(profile='clean', workload='A', mode='quic', recv_buffer=76800,
                    send_buffer=76800, success=True, eagain=0, duration_s=1, throughput_mbps=1)
        rows = aggregate([dict(base, netem_before_handshake=False),
                          dict(base, netem_before_handshake=enabled.netem_before_handshake)])
        self.assertEqual([r['netem_before_handshake'] for r in rows], [False, True])
        with self.assertRaises(SystemExit):
            parser().parse_args(['--quic-cc', 'bbrv2'])
        args = parser().parse_args(['--output-dir', '/external', '--quic-cc', 'reno', '--quic-stats'])
        self.assertEqual(args.quic_cc, 'reno')
        self.assertTrue(args.quic_stats)
        server = quic_process_env({}, args, Path('/logs/cell'), 'server', 'quic')
        client = quic_process_env({'TROJAN_QUIC_STATS': '/elsewhere/old.csv'}, args, Path('/logs/cell'), 'client', 'quic')
        self.assertEqual(server['TROJAN_QUIC_CC'], 'reno')
        self.assertEqual(client['TROJAN_QUIC_CC'], 'reno')
        self.assertEqual(server['TROJAN_QUIC_STATS'], '/logs/cell/server.quic_stats.csv')
        self.assertEqual(client['TROJAN_QUIC_STATS'], '/logs/cell/client.quic_stats.csv')
        self.assertNotEqual(server['TROJAN_QUIC_STATS'], client['TROJAN_QUIC_STATS'])
        off = parser().parse_args(['--output-dir', '/external', '--quic-cc', 'cubic'])
        quiet = quic_process_env({'TROJAN_QUIC_STATS': '/elsewhere/old.csv', 'TROJAN_QUIC_CC': 'reno'},
                                 off, Path('/logs/cell'), 'client', 'quic')
        self.assertEqual(quiet['TROJAN_QUIC_CC'], 'cubic')
        self.assertNotIn('TROJAN_QUIC_STATS', quiet)
        tcp = quic_process_env({'TROJAN_QUIC_CC': 'reno', 'TROJAN_QUIC_STATS': '/old.csv'},
                               args, Path('/logs/cell'), 'server', 'tcp')
        self.assertNotIn('TROJAN_QUIC_CC', tcp)
        self.assertNotIn('TROJAN_QUIC_STATS', tcp)


if __name__ == '__main__':
    unittest.main()
