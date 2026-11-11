#!/usr/bin/env python3
"""Summarize TROJAN_QUIC_STATS CSV using only stdlib.

RTT input is nanoseconds; output is milliseconds. Queue covers unsent
UnackedBuf bytes, not H3 buffers. Stream concurrency is not byte credit.
Buckets use sample counts, not time weighting. Rates use adjacent samples;
mean is duration-weighted, p50 is the median interval rate.
Idle runs cover [first idle sample, next non-idle sample); trailing runs end
at the final sample (right-censored lower bounds, possibly zero duration).
Run duration statistics include these censored observations.
"""
import csv
import io
import math
import statistics
import sys
from pathlib import Path

INFINITE = 18446744073709551615
BUCKETS = ('flow_control_exhausted', 'congestion_limited',
           'application_limited', 'idle_with_work', 'other')
REASONS = ('other', 'ack', 'retry', 'loss', 'application', 'flow')


def _num(row, key):
    value = row.get(key)
    if value is None or value == '':
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f'invalid {key}: {value}')
    # Preserve uint64 sentinel and cumulative counter precision.
    return int(value) if value.isdecimal() else number


def percentile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    index = (len(values) - 1) * fraction
    lo = int(index)
    return values[lo] + (values[math.ceil(index)] - values[lo]) * (index - lo)


def summarize(rows):
    if not rows:
        raise ValueError('empty stats csv')
    counts = dict.fromkeys(BUCKETS, 0)
    buckets = []
    for row in rows:
        cwnd, flight, queue = (_num(row, key) for key in
                               ('cwnd', 'bytes_in_flight', 'app_queue_bytes'))
        conn_credit = _num(row, 'max_data_left')
        stream_credit = _num(row, 'max_stream_data_left')
        if conn_credit == 0 or stream_credit == 0:
            bucket = 'flow_control_exhausted'
        elif cwnd is not None and cwnd > 0 and flight is not None and flight >= .9 * cwnd:
            bucket = 'congestion_limited'
        elif queue == 0:
            bucket = 'application_limited'
        elif (cwnd is not None and flight is not None and flight < .9 * cwnd
              and queue is not None and queue > 0 and conn_credit is not None
              and conn_credit > 0 and (stream_credit is None or stream_credit > 0)):
            bucket = 'idle_with_work'
        else:
            bucket = 'other'
        counts[bucket] += 1
        buckets.append(bucket)
    fractions = {key + '_frac': count / len(rows) for key, count in counts.items()}
    assert math.isclose(sum(fractions.values()), 1.0, abs_tol=1e-12)

    def values(key):
        return [v for row in rows if (v := _num(row, key)) is not None]

    times = values('t_ms')
    if len(times) != len(rows) or any(b <= a for a, b in zip(times, times[1:])):
        raise ValueError('timestamps must be present and strictly increasing; analyze one connection at a time')
    seconds = (times[-1] - times[0]) / 1000
    result = dict(role=','.join(sorted({r.get('role', 'unknown') for r in rows})),
                  samples=len(rows), duration_ms=times[-1] - times[0], **fractions)
    for key in ('cwnd', 'smoothed_rtt', 'latest_rtt'):
        scale = 1e6 if key.endswith('rtt') else 1
        for label, fraction in (('p50', .5), ('p90', .9)):
            value = percentile(values(key), fraction)
            result[f'{key}_{label}' + ('_ms' if scale != 1 else '')] = None if value is None else value / scale
    minima = [v for v in values('min_rtt') if 0 < v < INFINITE]
    min_rtt = min(minima) if minima else None
    result['min_rtt_ms'] = min_rtt / 1e6 if min_rtt else None
    smooth = result['smoothed_rtt_p50_ms']
    result['smoothed_rtt_p50_over_min_rtt'] = smooth / result['min_rtt_ms'] if min_rtt and smooth is not None else None
    thresholds = values('ssthresh')
    finite = [v for v in thresholds if v != INFINITE]
    result['ssthresh'] = 'inf' if thresholds and not finite else ('mixed finite/inf' if len(finite) < len(thresholds) else 'finite')
    result['ssthresh_finite_mean'] = statistics.mean(finite) if finite else None
    rates = []
    sent_delta = rate_seconds = 0
    for a, b, ta, tb in zip(rows, rows[1:], times, times[1:]):
        sa, sb = _num(a, 'bytes_sent'), _num(b, 'bytes_sent')
        if sa is None or sb is None:
            continue
        if sb < sa:
            raise ValueError('bytes_sent counter decreased')
        dt = (tb - ta) / 1000
        rates.append((sb - sa) * 8 / dt / 1e6)
        sent_delta += sb - sa
        rate_seconds += dt
    result['bytes_sent_rate_mean_mbps'] = sent_delta * 8 / rate_seconds / 1e6 if rate_seconds else None
    result['bytes_sent_rate_p50_mbps'] = statistics.median(rates) if rates else None
    def counter_delta(key):
        samples = [_num(row, key) for row in rows]
        present = [v for v in samples if v is not None]
        if any(b < a for a, b in zip(present, present[1:])):
            raise ValueError(f'{key} counter decreased')
        return samples[-1] - samples[0] if all(v is not None for v in samples) else None

    for key in ('zero_len_send', 'stream_data_blocked', 'write_more',
                'retry_arms', 'retry_expires_bytes', 'retry_expires_empty') + tuple(
                    f'{kind}_{reason}' for kind in ('pump', 'data', 'vecs', 'udp_sent')
                    for reason in REASONS):
        delta = counter_delta(key)
        result[key + '_delta'] = delta
        result[key + '_delta_per_s'] = delta / seconds if seconds and delta is not None else None
    retry_sent = result['retry_expires_bytes_delta']
    retry_empty = result['retry_expires_empty_delta']
    retry_total = retry_sent + retry_empty if retry_sent is not None and retry_empty is not None else 0
    result['retry_actual_send_frac'] = retry_sent / retry_total if retry_total else None
    for key in ('open_packet_gap_max_ms', 'zero_write_expiry_ms', 'zero_write_expiry_max_ms'):
        finite = [v for v in values(key) if v < INFINITE]
        result[key + '_last_finite'] = finite[-1] if finite else None
        result[key + '_max_finite'] = max(finite, default=None)

    durations = []
    endings = dict.fromkeys(('unique', 'mixed', 'none', 'unavailable', 'right_censored'), 0)
    unique = dict.fromkeys(REASONS, 0)
    start = None
    for index, bucket in enumerate(buckets):
        if bucket == 'idle_with_work':
            if start is None:
                start = index
        elif start is not None:
            durations.append(times[index] - times[start])
            deltas = []
            for reason in REASONS:
                key = 'udp_sent_' + reason
                before, after = _num(rows[index - 1], key), _num(rows[index], key)
                deltas.append(after - before if before is not None and after is not None else None)
            if any(delta is None for delta in deltas):
                endings['unavailable'] += 1
            else:
                active = [reason for reason, delta in zip(REASONS, deltas) if delta > 0]
                ending = 'unique' if len(active) == 1 else ('mixed' if active else 'none')
                endings[ending] += 1
                if len(active) == 1:
                    unique[active[0]] += 1
            start = None
    if start is not None:
        durations.append(times[-1] - times[start])
        endings['right_censored'] += 1
    result['idle_with_work_runs'] = len(durations)
    result['idle_with_work_run_duration_median_ms'] = percentile(durations, .5)
    result['idle_with_work_run_duration_p90_ms'] = percentile(durations, .9)
    result['idle_with_work_run_duration_max_ms'] = max(durations, default=None)
    result.update({f'idle_ending_{key}_count': value for key, value in endings.items()})
    result.update({f'idle_ending_unique_{key}_count': value for key, value in unique.items()})
    for key in ('pkt_lost', 'bytes_lost'):
        result[key] = max(values(key), default=None)
    dominant = max(counts, key=counts.get)
    result['verdict'] = dominant if counts[dominant] / len(rows) >= .5 else 'no-dominant-limit'
    return result


def format_report(summary):
    lines = []
    for key, value in summary.items():
        text = 'n/a' if value is None else (f'{value:.6f}' if isinstance(value, float) else str(value))
        lines.append(f'{key}: {text}')
    lines.append('download_note: server sends; client application queue is expected to be empty')
    lines.append('idle_with_work_note: data, window and credit available; pacing, CPU or send-loop limit possible, not proven')
    lines.append('idle_run_note: [first idle sample, next non-idle sample); trailing run ends at final sample, right-censored lower bound; duration statistics include censored runs')
    lines.append('idle_ending_note: positive udp_sent_REASON deltas from last idle sample to next non-idle sample; unique/mixed/none describe interval attribution, not exact event resolution or causation; unavailable means missing counters')
    lines.append('retry_actual_send_note: retry_expires_bytes delta / (retry_expires_bytes + retry_expires_empty deltas); fraction of observed expiries sending UDP, not fraction of arms')
    lines.append('gap_expiry_note: open_packet_gap_max_ms is per-sample maximum; zero_write_expiry fields summarize finite aggregate ngtcp2 expiry delays observed at zero writes, not proof of pacing; last_finite skips missing samples')
    return '\n'.join(lines) + '\n'


def load(path):
    with open(path, newline='') as handle:
        return list(csv.DictReader(handle))


def self_check():
    rows = []
    for index in range(5):
        rows.append(dict(t_ms=str(index * 1000), role='server', cwnd='1000',
                         ssthresh=str(INFINITE), bytes_in_flight='100',
                         app_queue_bytes='10', max_data_left='100', max_stream_data_left='100',
                         latest_rtt='2000000', smoothed_rtt='3000000', min_rtt='1000000',
                         bytes_sent=str(index * 1000000), zero_len_send=str(index * 2),
                         stream_data_blocked=str(index * 3), write_more=str(index * 4)))
    rows[0].update(max_data_left='0', bytes_in_flight='1000', app_queue_bytes='0')
    rows[1].update(bytes_in_flight='900', app_queue_bytes='0')
    rows[2]['app_queue_bytes'] = '0'
    rows[4]['bytes_in_flight'] = ''
    summary = summarize(rows)
    assert all(summary[key + '_frac'] == .2 for key in BUCKETS)
    assert summary['ssthresh'] == 'inf' and summary['ssthresh_finite_mean'] is None
    assert summary['bytes_sent_rate_mean_mbps'] == summary['bytes_sent_rate_p50_mbps'] == 8
    assert summary['smoothed_rtt_p50_over_min_rtt'] == 3
    assert summary['zero_len_send_delta_per_s'] == 2
    assert summary['stream_data_blocked_delta_per_s'] == 3
    assert summary['write_more_delta_per_s'] == 4
    assert summary['cwnd_p90'] == 1000 and summary['latest_rtt_p90_ms'] == 2
    rows[0]['ssthresh'] = '100'
    assert summarize(rows)['ssthresh_finite_mean'] == 100
    rows[1]['t_ms'] = '0'
    try:
        summarize(rows)
    except ValueError:
        pass
    else:
        raise AssertionError('duplicate timestamp accepted')
    # Exercise CSV parsing as well as optional counters and sampled transitions.
    synthetic = []
    for index in range(9):
        row = dict(rows[3], t_ms=str(index * 1000),
                   app_queue_bytes='10' if index in (0, 1, 3, 5, 8) else '0',
                   retry_arms=str(index * 3), retry_expires_bytes=str(index),
                   retry_expires_empty=str(index), open_packet_gap_max_ms=str(index / 2),
                   zero_write_expiry_ms='' if index == 8 else str(index / 4),
                   zero_write_expiry_max_ms=str(index / 2))
        for reason in REASONS:
            for kind in ('pump', 'data', 'vecs', 'udp_sent'):
                row[f'{kind}_{reason}'] = str(
                    int(index >= 2) if reason == 'ack' else
                    int(index >= 4) if reason in ('retry', 'application') else 0)
        synthetic.append(row)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(synthetic[0]))
    writer.writeheader()
    writer.writerows(synthetic)
    buffer.seek(0)
    new = summarize(list(csv.DictReader(buffer)))
    assert new['idle_with_work_runs'] == 4
    assert new['idle_with_work_run_duration_median_ms'] == 1000
    assert math.isclose(new['idle_with_work_run_duration_p90_ms'], 1700)
    assert new['idle_with_work_run_duration_max_ms'] == 2000
    assert all(new[f'idle_ending_{key}_count'] == 1
               for key in ('unique', 'mixed', 'none', 'right_censored'))
    assert new['idle_ending_unique_ack_count'] == 1
    assert new['idle_ending_unavailable_count'] == 0
    assert summary['idle_ending_unavailable_count'] == 1
    assert new['retry_arms_delta'] == 24 and new['retry_arms_delta_per_s'] == 3
    assert new['retry_expires_bytes_delta_per_s'] == 1
    assert new['retry_expires_empty_delta_per_s'] == 1
    assert new['retry_actual_send_frac'] == .5
    for kind in ('pump', 'data', 'vecs', 'udp_sent'):
        assert new[f'{kind}_ack_delta'] == 1
        assert new[f'{kind}_ack_delta_per_s'] == .125
    assert new['open_packet_gap_max_ms_max_finite'] == 4
    assert new['zero_write_expiry_ms_last_finite'] == 1.75
    assert new['zero_write_expiry_ms_max_finite'] == 1.75
    assert new['zero_write_expiry_max_ms_max_finite'] == 4
    print('self-check ok: all five exclusive buckets, priority, sentinel, rates, RTT, timestamps, optional CSV counters, idle runs and interval attribution')
    print(format_report(summary), end='')


def main(argv):
    if len(argv) == 2 and argv[1] == '--self-check':
        self_check()
        return 0
    if len(argv) != 2:
        print('usage: analyze_cc.py {--self-check|CSV}', file=sys.stderr)
        return 2
    print(format_report(summarize(load(Path(argv[1])))), end='')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv))
    except (OSError, ValueError, csv.Error) as exc:
        print(f'analyze_cc: {exc}', file=sys.stderr)
        raise SystemExit(1)
