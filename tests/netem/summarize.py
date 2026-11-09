#!/usr/bin/env python3
"""Write external CSV and Markdown reports from retained JSONL measurements."""
import argparse
import csv
import json
from pathlib import Path
from harness import aggregate


def metric(item, key):
    value = item[key]
    if value is None:
        return 'FAIL'
    return f"{value['median']:.3f} [{value['min']:.3f}, {value['max']:.3f}]"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.resolve().is_relative_to(Path(__file__).resolve().parents[2]):
        parser.error('Reports must be outside repository')
    rows = [json.loads(line) for line in args.results.read_text().splitlines() if line.strip()]
    groups = aggregate(rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / 'results.csv').open('w', newline='') as f:
        keys = sorted(set().union(*(row.keys() for row in rows)))
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    text = ['# QUIC buffer matrix', '',
            f'Completed cells: {len(rows)}; passed: {sum(r["success"] for r in rows)}; '
            f'failed: {sum(not r["success"] for r in rows)}. EAGAIN total: {sum(r["eagain"] for r in rows)}.', '',
            'Successful-repeat median [min, max]; failures excluded from medians, included in failure counts. '
            'One-repeat results are not evidence for a default change. Differences smaller than repeat variation are noise. '
            'Inspect JSONL for log levels, actual buffers, CPU/RSS, latency and impairment details. '
            'Do not combine results with different log levels or harness settings.', '',
            '| Profile | Workload/mode | Receive/send bytes | Runs | Mbit/s median [min,max] | Seconds median [min,max] | EAGAIN | Failures |',
            '|---|---|---:|---:|---|---|---:|---:|']
    for item in groups:
        buffer = f"{item['recv_buffer']}/{item['send_buffer']}" if item['mode'] == 'quic' else 'N/A'
        text.append(f"| {item['profile']} | {item['workload']}/{item['mode']} | {buffer} | {item['runs']} | "
                    f"{metric(item, 'throughput_mbps')} | {metric(item, 'duration_s')} | {item['eagain']} | {item['failures']} |")
    (args.output_dir / 'summary.md').write_text('\n'.join(text)+'\n')


if __name__ == '__main__':
    main()
