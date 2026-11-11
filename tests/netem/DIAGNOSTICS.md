# Single-variable throughput diagnostics

Sender sampling and `TROJAN_QUIC_CC` selection require an explicit diagnostics build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DTROJAN_QUIC_STATS=ON
cmake --build build --parallel
```

`TROJAN_QUIC_STATS` is a CMake BOOL, default OFF. OFF compiles out sampler state,
reason scopes, CSV code and both environment reads; CC stays hardcoded BBR as on
master. ON retains the runtime `TROJAN_QUIC_STATS` CSV-path switch and diagnostic
`TROJAN_QUIC_CC={bbr,cubic,reno}` selector. CSV format is unchanged. The harness
requires the unique `quic stats: compiled in` binary marker for `--quic-stats` or
explicit `--quic-cc` (including `bbr`), otherwise stops with a rebuild instruction.
Use the direct harness with this build; the standard container runner keeps its
production-default build. Sampling overhead exists only in diagnostics builds.

Diagnostic profiles are separate from the original eight-profile matrix; `--profile all` remains unchanged. Use workload A, buffer 76800, three repeats and both QUIC and TCP controls. Build once and run invocations serially in the same privileged container; never compare competing measurements.

```sh
for level in 0 1 5; do
    python3 /src/tests/netem/harness.py --profile clean --workload A --mode all --repeat 3 --buffer-size 76800 --log-level "$level" --output-dir "/logs/e1-level$level"
done
for profile in delay100-fixed delay100-jitter delay100-jitter-ordered; do
    python3 /src/tests/netem/harness.py --profile "$profile" --workload A --mode all --repeat 3 --buffer-size 76800 --log-level 5 --output-dir "/logs/e2-$profile"
done
python3 /src/tests/netem/harness.py --profile relay-only --workload A --mode all --repeat 3 --buffer-size 76800 --log-level 5 --output-dir /logs/e3-relay-only
```

- `delay100-fixed`: symmetric `delay 100ms`.
- `delay100-jitter`: symmetric `delay 100ms 30ms`, identical to existing `delay100`. Out-of-order arrival observed in ~83% of probe packets.
- `delay100-jitter-ordered`: symmetric `delay 70ms slot 1ms 60ms`. Verified in-order jitter emulation using a fixed delay followed by an ordered slotted release interval. Observed FIFO departure yielded zero reordered packets at the two tested probe rates while maintaining a ~60 ms delay spread centered near 100 ms (matching `delay100-jitter` span without reordering).
- `relay-only`: the same UDP relay path as rebind, but no outage or port change. TCP remains direct. Use E1 clean/OFF as the direct baseline.

Before every diagnostic delay transfer, a 5000-packet UDP train (1200-byte datagrams, default 1 ms apart) crosses client-to-server egress. Sequence numbers and shared-kernel monotonic timestamps measure arrival order and one-way delay min/median/max/spread. Reorder fraction counts sequence numbers below the largest previously received. Probe loss is fatal. This samples one direction and one packet rate; it does not certify all transfer traffic. Packet counters include the probe; payload amplification subtracts pre-transfer qdisc byte counters and uses the root qdisc once, avoiding child double counting. The reject-before-transfer rule triggers immediately if any reordering is detected on an ordered profile.

## Findings

Measured in specific research environments, not universal tuning advice: Linux privileged
container/veth netem transfers and an Android phone clock-cost profile. With the repaired
clock, clock caching gained only about 7-10% in the Linux experiment; the phone spent
about 1% in clock_gettime. No product value justified a clock replacement. A fixed larger
time-loss factor helped synthetic reordering but hurt clean/fixed-delay BBR. Disabling
pacing helped BBR but hurt CUBIC and raised loss. Those research controls and dependency
patches are deliberately absent; clocks, recovery and pacing retain upstream behavior.

## Probe-only validation

To run probe measurements without compiling trojan or launching proxy transfers:

```sh
python3 /src/tests/netem/harness.py --profile delay100-jitter-ordered --probe-only
python3 /src/tests/netem/harness.py --profile delay100-jitter-ordered --probe-only --probe-spacing 0.0002
```

`--probe-only` creates isolated namespaces, configures static neighbor entries to prevent ARP loss, sets up the qdisc, runs the 5000-packet UDP probe (with a 4 MiB socket buffer to prevent burst loss), prints JSON results, and removes the namespaces.

## In-order jitter evaluation

Four candidate families were evaluated across both standard (1.0 ms) and high-rate (0.2 ms) probe packet spacing to replace the earlier failed `pfifo` child qdisc attempt:

| Candidate | Parameters | Spacing | Received / Sent | Reordered (Frac) | Min / Med / Max / Spread (ms) | Verdict |
|---|---|---|---|---|---|---|
| a.1 (Correlation) | `delay 100ms 30ms 99%` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>5000 / 5000 | 4164 (83.3%)<br>4637 (92.7%) | 70 / 101 / 132 / 61 ms<br>70 / 100 / 131 / 61 ms | Rejected: consecutive packets overtake each other |
| a.2 (Correlation) | `delay 100ms 30ms 99.9%` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>5000 / 5000 | 2113 (42.3%)<br>4637 (92.7%) | 70 / 94 / 132 / 62 ms<br>70 / 103 / 135 / 65 ms | Rejected: high reordering remains |
| **b.1 (Slot winner)** | `delay 70ms slot 1ms 60ms` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>5000 / 5000 | **0 (0.0%)**<br>**0 (0.0%)** | 71 / 90 / 132 / 61 ms<br>71 / 103 / 134 / 63 ms | **Accepted**: 0 reordered, 61 ms spread, 100 ms center |
| b.2 (Slot) | `delay 75ms slot 0ms 50ms` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>5000 / 5000 | 0 (0.0%)<br>0 (0.0%) | 76 / 92 / 127 / 51 ms<br>76 / 98 / 127 / 52 ms | Passed, narrower spread than b.1 |
| b.3 (Slot dist) | `slot dist normal 100ms 30ms` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>5000 / 5000 | 0 (0.0%)<br>0 (0.0%) | 3 / 59 / 171 / 168 ms<br>20 / 73 / 133 / 113 ms | Rejected: median delay too low without base delay |
| b.4 (Slot dist) | `delay 70ms slot dist normal 30ms 10ms` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>5000 / 5000 | 0 (0.0%)<br>0 (0.0%) | 71 / 88 / 132 / 60 ms<br>72 / 95 / 120 / 48 ms | Passed: 0 reordered, spread 48-60 ms |
| c.1 (Child stage) | `netem delay 100ms 30ms` + child `tbf 10mbit` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>1608 / 5000 | 4175 (83.5%)<br>1397 (86.9%) | 70 / 101 / 131 / 61 ms<br>71 / 605 / 657 / 586 ms | Rejected: child receives already-reordered packets; drops at 0.2 ms |
| c.2 (Netem rate) | `netem delay 100ms 30ms rate 10mbit` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>1883 / 5000 | 0 (0.0%)<br>0 (0.0%) | 82 / 131 / 148 / 66 ms<br>107 / 871 / 996 / 889 ms | Rejected: choked 48 Mbps train, >3000 packet drops |
| d.1 (Root stage) | `tbf 100mbit` + child `netem slot 1ms 60ms delay 70ms` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>5000 / 5000 | 0 (0.0%)<br>0 (0.0%) | 71 / 90 / 133 / 62 ms<br>73 / 110 / 142 / 68 ms | Passed, but extra complexity over standalone netem |
| d.2 (Slot) | `delay 80ms slot 0ms 40ms` | 1.0 ms<br>0.2 ms | 5000 / 5000<br>5000 / 5000 | 0 (0.0%)<br>0 (0.0%) | 81 / 94 / 122 / 42 ms<br>82 / 99 / 121 / 40 ms | Passed: 0 reordered, ~40 ms spread |

Candidate `b.1` (`delay 70ms slot 1ms 60ms`) is selected: it uses a single standard netem qdisc without child stages, achieves 0 reordered packets under both probe pacing rates, and spans [71 ms, 132 ms] (spread ~61 ms, median ~95-103 ms), mirroring the delay span of `delay100-jitter` ([70 ms, 130 ms]) without packet reordering.

## Transfer metrics

Per-row additions: transfer CPU seconds (startup/probe baseline subtracted), CPU seconds divided by transfer duration, server wire bytes / payload bytes, endpoint log line counts, ALL-only loop-break/retry counts, and INFO loss/retransmit lines if present. CPU sampling has 20 ms and kernel tick granularity; very short TCP transfers are noisy. Wire amplification includes IP/UDP/TCP/QUIC headers and control traffic, so it is an indicator, not an exact retransmission count. Log counts include shutdown. OFF counts are not evidence of zero losses.

When `top` exists, clean QUIC/OFF samples server threads around four seconds after transfer launch (two snapshots, 0.5 s apart); the first snapshot is lifetime-based, the second interval-based. This approximates the midpoint of an eight-second clean transfer, not a general midpoint guarantee. Raw output is retained as `server-threads.log`. Missing `top` does not block measurements. No profiler is required.
