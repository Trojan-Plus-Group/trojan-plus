#!/usr/bin/env python3
"""Container-free checks: python3 tests/netem/test_harness.py."""
import unittest
from pathlib import Path
from harness import BUFFERS, PROFILES, aggregate, buffer_log, digest, make_config, parser, plan


class HarnessTests(unittest.TestCase):
    def test_plan(self):
        args = parser().parse_args(['--output-dir', '/external'])
        self.assertEqual(len(plan(args)), 336)
        args.slow_repeats = 1
        self.assertEqual(len(plan(args)), 252)
        self.assertEqual(len(PROFILES), 8)
        self.assertEqual(BUFFERS[0], 76800)
        self.assertEqual(PROFILES['burst'], ['loss', '5%', '25%'])

    def test_log_level_config(self):
        for options, expected in (([], 1), (['--log-level', '0'], 0)):
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

    def test_buffers(self):
        line = 'buffers requested recv=76800 send=212992 actual recv=76800 send=212992'
        self.assertEqual(buffer_log(line, 76800, 212992)['actual_send'], 212992)
        with self.assertRaises(RuntimeError):
            buffer_log(line, 1, 2)

    def test_aggregation(self):
        base = dict(profile='clean', workload='A', mode='quic', recv_buffer=76800,
                    send_buffer=76800, success=True, eagain=2)
        rows = [dict(base, duration_s=n, throughput_mbps=10/n) for n in (1, 2, 3)]
        rows.append(dict(base, success=False))
        result = aggregate(rows)[0]
        self.assertEqual(result['failures'], 1)
        self.assertEqual(result['duration_s'], dict(median=2, min=1, max=3))
        self.assertEqual(result['eagain'], 8)
        self.assertEqual(len(digest(50_000_000)), 64)


if __name__ == '__main__':
    unittest.main()
