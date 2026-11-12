# QUIC performance investigation

## Summary

Why did this QUIC proxy deliver less throughput and use more CPU than TCP/TLS?
The answer depended on clocksource, packet path, receiver, and network conditions.
No single congestion-control or encryption explanation survived all experiments.

- A slow VM clocksource invalidated early absolute performance comparisons.
- After clock repair, per-datagram kernel work and timer work remained important.
- TCP benefited from large kernel aggregates and in-kernel ACK processing.
- The phone spent most active CPU at kernel boundaries, with substantial idle gaps.
- UDP GSO plus loss-timer coalescing helped the tested phone LAN path considerably.
- ACK thinning, disabled pacing, and relaxed loss detection were unsafe general fixes.
- Clean VM gains varied sharply between experiments; their cause remains unresolved.
- The public long-RTT test reduced CPU, but did not improve throughput.

This tree provides `quic.udp_gso` (default `false`) for server and client endpoints
on Linux and Android with UDP_SEGMENT support, as documented in
[configuration](config.md). The option enables UDP GSO plus timer coalescing.

## Environment and measurement method

### Systems and paths

The controlled Linux environment was a 4-vCPU Linux VM under QEMU.
The repository's [netem harness](../tests/netem/README.md) created two network
namespaces joined by veth, with impairment on both egress directions.
Configured one-way delay therefore contributed twice to nominal RTT.
Clean meant an empty netem qdisc, not absence of host scheduling or socket drops.
The UDP relay used for rebinding added its own work and was not a physical router.

The phone was a Snapdragon 888 Android 14 phone, not rooted, on 5 GHz Wi-Fi.
The phone client used the TUN path; the VM namespace client was not an equivalent
phone kernel, Wi-Fi stack, or TUN implementation.
The public test used a single-vCPU KVM VPS about 300–400 ms RTT away.
These systems establish examples, not hardware-independent QUIC limits.

### Transfer controls and statistics

Runs were serial; competing measurements and builds were prohibited.
Existing host services and background phone load were not eliminated completely.
Paired A/B comparisons interleaved variants and alternated order where supported.
The E2 multi-variant matrix instead rotated variant order across rounds.
Payload length and SHA256 were checked in the main validation matrices.
The symbolized phone-profile series checked HTTP status and length, not SHA256.
A successful transfer is not automatically valid profiling or acceptance evidence.

A paired ratio is treatment throughput divided by its matched baseline throughput.
The reported median of paired ratios need not equal the ratio of two medians.
Bootstrap intervals describe resampling uncertainty within the measured pairs;
they do not remove shared-host drift, instrumentation bias, or path changes.
Few repeats, especially one-repeat impairment cells, cannot establish stable tails.
Failed attempts and partial matrices were retained rather than overwritten.

Payload MB means 1,000,000 bytes unless a buffer size explicitly uses MiB.
Interface counters count skbs, not necessarily on-wire packets under offload.
Reverse traffic is ACK-dominated but also contains control traffic.
Encrypted counters do not provide an exact ACK-only packet count.
Selected syscall totals include relay TCP IO and unsuccessful calls.
They must not be relabelled UDP-only syscall totals.

### Clock, sender state, and CPU accounting

The repaired local VM required `tsc` before and after every measured run.
A different value stopped the sequence rather than silently accepting results.
The public VPS used `kvm-clock`; local guards did not establish remote `tsc`.
Record each machine's clocksource separately and reject unexpected changes.

`TROJAN_QUIC_STATS` is a compile-time diagnostic option, default OFF.
Its sender sampler records idle-with-work, congestion-window limitation,
flow-control blocking, flight/cwnd, RTT and rate quantiles, loss/retransmit deltas,
and loop/wake counters and trigger observations.
These are observations, not an exclusive causal classifier for pacing.
The tracked unsent queue does not cover every higher-layer buffer.
Sampling adds work; use stats-OFF controls before making throughput claims.

VM profiles used perf software CPU sampling and frame-pointer call graphs.
Phone profiles used simpleperf `cpu-clock`, an unstripped matching native library,
and frame-pointer call graphs; hardware cycles were unavailable.
Phone kernel symbols were invisible, so kernel attribution stopped at caller paths.
Self percentages partition sampled CPU; inclusive percentages overlap.
Never add TUN, UDP, ngtcp2, crypto, and kernel inclusive shares together.

Per-run phone CPU came from `/proc` user/system tick deltas at workload boundaries.
Asynchronous thread/process snapshots can skew short-run thread shares.
Profilers and phone samplers running during transfers can perturb scheduling badly.
Compare matched instrumentation and retain unprofiled controls.

## Chronological findings

### 1. Weak-network matrix: UDP buffers were not the main limit

**Question.** Could socket buffers explain poor QUIC throughput under impairment?
The initial matrix covered clean, loss, delay, constrained-rate, burst, outage,
and NAT-rebind profiles, with several workloads and TCP controls.
Buffer values were 76800, 212992, 1048576, and 4194304 bytes.

Of 252 cells, 248 passed; four constrained-rate workload-A cells hit 900-second
deadlines. EAGAIN counts were zero, and larger buffers gave no consistent gain.
Those failures remain failures, not zero-throughput successful measurements.
The outage and rebind tests intentionally overlapped data with a blackout.
Their gates and relay overhead matter when interpreting outliers.

**Conclusion.** Buffer tuning did not resolve the observed gap.
Socket capacity is not the congestion window, and capacity divided by RTT is not
a valid standalone throughput ceiling for this implementation.
**Confidence:** useful negative result for tested sizes and workloads only.
The slow-clock discovery below invalidates these rates as normal-clock baselines.

### 2. Random jitter manufactured severe reordering

**Question.** Was the delay profile testing realistic latency variation or reorder?
A UDP spacing probe showed about 77.82% reordering in the original random-jitter
profile at 1 ms spacing.
A 99%-correlated candidate still produced 83.3% at 1 ms and 92.7% at 0.2 ms.
Correlation was therefore not enough to preserve order.
The selected `delay 70ms slot 1ms 60ms` profile produced zero reorder at both
spacings in the recorded probes.

The inspected ngtcp2 time threshold was
`max(latest_rtt, smoothed_rtt) * 9/8`, with a 1 ms floor and elapsed `>=` comparison.
The packet threshold was dynamic, not a fixed three packets:
`min(256, max(3, cc_bytes_in_flight / max_tx_udp_payload_size / 2))`.
Raising the packet minimum alone did not prevent time-triggered loss declarations.
Increasing the time factor to two helped the artificial-reorder case substantially,
but BBR regressed 19.46% under loss5, 39.96% under fixed delay, and 17.28% on clean.
These early rates were collected under the bad-clock conditions discussed next.

**Conclusion.** Do not generalize a win against extreme synthetic reordering.
Ordered jitter is a separate impairment, not an interchangeable replacement for
random jitter in historical tables.
**Confidence:** strong source/probe support for the loss-detection mechanism;
limited evidence about reorder prevalence on real networks.
The claim that real networks rarely reorder was not established by these tests.

### 3. Clocksource repair changed the investigation

**Question.** Why did early profiles spend most CPU reading time?
The VM had fallen back from `tsc` to `acpi_pm`.
Historical clock measurements were about 8.7 us for MONOTONIC and 9.2 us for
BOOTTIME; the retained C5 profiles attributed 75.44% and 74.94% to `acpi_pm_read`.
A clock read on a hot QUIC path was no longer a small constant cost.

The investigation notes attribute detection to a clocksource-watchdog warning.
The exact warning text was not verified in the investigation notes,
so no reconstructed kernel log is presented as evidence.
The investigation notes record VM boot parameters `clocksource=tsc tsc=reliable`;
independent boot-log confirmation was not found in those notes.
These are laboratory history, not a blanket recommendation to override watchdogs.
A forced unreliable clock can invalidate timekeeping; validate host suitability.

After repair, measured MONOTONIC/BOOTTIME/RAW costs were
21.139/20.784/22.299 ns, rather than microseconds.
The later VM analysis assigned clock/timer self work 4.636/4.234% for BBR and
4.430/3.937% for CUBIC.
Phone BOOTTIME measurements were 44.652, 43.730, and 43.722 ns.
Symbolized phone profiles assigned clocks 0.92%, then 0.88% with logging off.

An experimental fast-clock path still gained 7–10% after VM clock repair,
but was not shipped. Its earlier apparent importance was not portable evidence.
**Conclusion.** Early slow-clock throughput and profiles cannot quantify normal
QUIC cost; clock repair did not remove the packet and timer bottlenecks.
**Confidence:** high for clock-cost distortion; limited for general fast-clock gains.

### 4. Sender idleness did not identify one pacing defect

**Question.** Did a 100 ms retry timer leave the sender asleep with work queued?
The retry experiment recorded 70,975 arms, 21 empty expiries and four productive
expiries. Retry-triggered UDP work was 4/260572, or 0.00154%.
No idle interval was uniquely shown to end because of this fallback.
Tracing itself reduced BBR throughput 47.79% and CUBIC 17.94%.
The fallback remained a recovery safety net, not a demonstrated bulk-rate limit.

Disabling pacing was not a general fix.
With stats OFF, historical BBR throughput changed from 17.541373 to 26.422219
Mbit/s (+50.627995%), but CUBIC changed from 24.514653 to 7.128810
Mbit/s (−70.920210%); loss increased.
These were slow-clock historical measurements, not present clean-path rates.

Later loop traces recorded the following instrumented behavior:

| Run | Loops | Zero-packet loops | Pacing-not-due count % | Pacing-not-due synchronous time % | Pacing rate / actual UDP rate |
|---|---:|---:|---:|---:|---:|
| 1 | 185647 | 151521 | 55.13 | 92.97 | 2.159266669117598 |
| 2 | 204267 | 161688 | 56.47 | 92.87 | 2.128034154331451 |
| 3 | 185276 | 150271 | 55.71 | 92.82 | 2.3029209872556033 |

Single-packet and small multi-packet calls were also frequent.
Exit categories were snapshots, not definitive ngtcp2 return reasons.
Per-loop file writes perturbed throughput; duration measured synchronous loop work,
not requested-versus-actual wake latency. Quantum exhaustion was not isolated.

**Conclusion.** Future pacing deadlines and many unproductive calls coexisted.
Low controller rate and delayed scheduling were not causally separated.
**Confidence:** high for recorded counts; insufficient for a unique pacing diagnosis.

### 5. E1: per-datagram cost remained after clock repair

**Question.** How much work did QUIC require per delivered MB versus TCP?
Three interleaved baseline repeats used 200 MB transfers on the controlled VM.

| Transport | Mbit/s | Server CPU us/MB | Client CPU us/MB | Data skbs/MB | Reverse skbs/MB |
|---|---:|---:|---:|---:|---:|
| QUIC | 338.79 | 17450 | 20600 | 888.39 | 431.30 |
| TCP | 1806.65 | 1200 | 1150 | 29.34 | 17.54 |

QUIC's reverse/data ratio was 0.485, with reverse skbs about 87 bytes on average.
This supports ACK-dominated traffic, not a measured count of ACK-only packets.
TCP's large interface skbs and in-kernel ACK handling change both accounting and
userspace work; qdisc and interface counters must not be interchanged.

Separate syscall-count runs measured selected calls/MB of 2187.700/2416.975
for QUIC server/client, versus 510.785/317.555 for TCP.
Their throughputs were 336.316 and 1810.392 Mbit/s respectively.
`sendmmsg` and `recvmmsg` were zero in these proxy runs.
Counts included failed attempts and the local relay, not only network UDP IO.

#### Kernel-floor experiment

A separate single-thread sender/receiver tool removed QUIC, encryption and relay.
Each case ran for 10 seconds with three repeats on the veth topology.

| Case | Received Mbit/s | Received bytes/call |
|---|---:|---:|
| Plain UDP sendmsg | 1589.84 | 1252.00 |
| UDP batch32 sendmmsg | 1771.44 | 5826.24 |
| UDP GSO plus socket GRO | 33689.02 | 63851.90 |
| TCP | 28386.29 | 60449.32 |

GSO and socket GRO were active and verified on veth; generic GRO was off.
These are aggregate memory-path rates, not physical-link or phone ceilings.
Batching alone improved much less than segmentation plus receive coalescing.
Plain UDP still exceeded QUIC substantially, so syscall entry or packet count
alone could not explain all remaining cost.

#### CPU distribution

| Self CPU % | QUIC server | QUIC client | TCP server | TCP client |
|---|---:|---:|---:|---:|
| Kernel stack/syscalls/scheduler | 44.41 | 42.04 | 43.24 | 32.95 |
| ngtcp2 ACK | 1.00 | 1.09 | 0 | 0 |
| ngtcp2 congestion | 0.23 | 0 | 0 | 0 |
| ngtcp2 loss/rtb | 0.50 | 0.14 | 0 | 0 |
| ngtcp2 other | 9.89 | 14.60 | 0 | 0 |
| ngtcp2 write | 2.53 | 2.89 | 0 | 0 |
| Crypto | 5.02 | 7.67 | 26.49 | 28.32 |
| Relay/other userspace | 16.70 | 12.22 | 9.73 | 12.14 |
| Asio dispatch | 3.33 | 4.11 | 2.16 | 4.05 |
| Userspace clock/timer | 2.22 | 1.15 | 0 | 0 |
| Copies | 0.34 | 0.20 | 0.54 | 0 |
| malloc/free | 2.22 | 1.26 | 2.70 | 5.78 |
| Unresolved userspace | 11.61 | 12.63 | 15.14 | 16.76 |

Inclusive `timerfd_settime` shares were 16.32/13.48% for QUIC server/client,
versus zero for TCP; they overlap the kernel category above.
Inclusive `sendto` was 19.08/21.56%, and `recvfrom` 4.56/3.09% for QUIC.
TCP profiles contained only 185/173 samples, making their percentages coarse.
ngtcp2 categories used symbol-name heuristics; unresolved and inlined work remained.

**Conclusion.** Per-datagram kernel work, userspace transport work and timer churn
all mattered. Encryption was not the dominant measured QUIC category.
**Confidence:** strong for this topology; no exact exclusive causal decomposition.

### 6. E2: three levers interacted, but clean gains did not reproduce

L1 enabled GSO send, L2 socket GRO receive, and L3 loss-timer coalescing.
Five rounds per congestion controller used matching instrumentation.
The following throughput tables retain E2's reported values and paired statistics.

| BBR variant | Median Mbit/s | Paired ratio median | Paired ratio min–max | Range / median % | Server user/sys us/MB | Client user/sys us/MB |
|---|---:|---:|---:|---:|---:|---:|
| base | 340.77 | 1.000 | 1.000–1.000 | 5.70 | 8650/9550 | 12350/9300 |
| L1 | 327.44 | 0.973 | 0.930–0.998 | 4.28 | 8150/10000 | 13100/9300 |
| L2 | 337.61 | 0.995 | 0.955–1.025 | 3.93 | 8900/9550 | 12150/9400 |
| L3 | 453.60 | 1.331 | 1.231–1.540 | 26.47 | 5300/4200 | 4050/5400 |
| L1+L2 | 370.53 | 1.124 | 1.050–1.143 | 4.60 | 7500/8700 | 11900/7350 |
| L1+L2+L3 | 847.96 | 2.466 | 2.430–2.592 | 1.79 | 4400/1450 | 4500/2900 |

| CUBIC variant | Median Mbit/s | Paired ratio median | Paired ratio min–max | Range / median % | Server user/sys us/MB | Client user/sys us/MB |
|---|---:|---:|---:|---:|---:|---:|
| base | 331.87 | 1.000 | 1.000–1.000 | 13.08 | 8500/8700 | 11500/8850 |
| L1 | 331.39 | 1.010 | 0.964–1.110 | 3.47 | 8150/8600 | 12350/9800 |
| L2 | 306.55 | 0.983 | 0.918–1.103 | 12.83 | 8550/8950 | 11700/8900 |
| L3 | 768.62 | 2.335 | 2.283–2.567 | 2.91 | 4050/4100 | 4100/4350 |
| L1+L2 | 384.36 | 1.176 | 1.123–1.303 | 3.37 | 7800/6950 | 11100/7350 |
| L1+L2+L3 | 857.99 | 2.618 | 2.548–2.931 | 5.33 | 4250/1450 | 4350/2850 |

The combined result includes GRO. It is not a GSO-plus-timer-only result.
For BBR, server `timerfd` calls/MB fell from 480.50 at baseline to 52.62 with L3;
client calls fell from 869.89 to 28.80.
GSO alone cut server skbs but did not establish a throughput gain.
GRO alone also failed to beat noise; ordinary datagrams did not become aggregates.

Later clean-path results disagreed with the magnitude of E2's timer gains.
P3's server-only GSO-plus-timer paired ratios were 1.1874 BBR and 1.2369 CUBIC.
Final product measurements gave 0.9890 BBR and 0.9445 CUBIC;
a research-build comparison gave 1.0863.
Different binaries, instrumentation, host state and noise are candidates, not
established explanations. These experiments did not isolate the discrepancy.
**Confidence:** high that E2 measured its stated variants; low for portable clean gains.

### 7. Phone profiles and sender state narrowed, but did not solve, the limit

The later five-run LAN comparison had median QUIC 85.24204478617034 Mbit/s
versus TCP 224.05085058104785 Mbit/s.
Median phone CPU was 0.048 versus 0.0184 seconds/MB.
An earlier series gave QUIC 79.980 versus TCP 297.895 Mbit/s; do not merge them.
Matched server CPU for the later five-run comparison was not verified here.
A separate symbolized QUIC series measured about 43–46% of one VM CPU and
49–55% of one phone CPU during transfer, not sustained full-core saturation.

E3's symbolized phone profile had 68.04% opaque kernel self samples.
TUN-related write was 35.23% inclusive; UDP send 20.86%; clocks 0.92%.
ngtcp2 read/write were 7.13/3.75% inclusive and overlapped other work.
Logging-off E4 remained kernel-heavy at 67.59%, TUN write 34.40%, clocks 0.88%.
Thus visible userspace transport work did not make opaque kernel work disappear.

A sample-timeline analysis found per-second on-CPU shares of
47, 55, 55, 52, 47, 49, 48, 49, 50, and 43%.
Across 9.84 seconds, estimated gaps totalled 4.00 seconds, or 41%.
These are inferred sample gaps, not scheduler-trace proof of blocking causes.
Many small stalls are consistent with the observations; a single long block is
not required to explain partial CPU occupancy.

Three sender-state runs recorded idle-with-work 91.01/93.07/90.36%,
median flight/cwnd 0.396/0.441/0.431, and no flow-control blocking.
Lost/sent counts were 335/87769, 186/87967, and 162/88008.
Socket receive-drop deltas were 340/193/195.
These socket drops and transport loss counters measure different layers.

Thermal status was normal (0), while middle-core median frequency was 710.4 MHz
and big cores commonly ran at 844.8 MHz under observed platform limits.
Temperature was not experimentally varied, so normal status does not prove that
thermal policy had no effect. Frequency limits were observations, not isolated causes.
Phone background load and concurrent sampling produced substantial sensitivity.
**Conclusion:** TUN writes and packet kernel paths are strong candidates, not a
resolved kernel-internal diagnosis. **Confidence:** moderate, with opaque symbols.

### 8. ACK thinning traded clean throughput for impaired-path regressions

Raising the receiver ACK threshold to eight yielded clean paired ratios of
1.607 for BBR and 1.622 for CUBIC in S3.
P2 then tested impairment rather than accepting that clean-path win.
BBR's loss5 ratio was 0.6417 and its phone-like-profile ratio was 0.3288.
On ordered jitter, loss and retransmission ratios were 1.9434 and 1.6619.
Periodic counter deltas were not exact final transport recovery totals.
**Conclusion:** ACK thinning was abandoned; a clean gain did not establish safety.
**Confidence:** strong negative evidence for the tested impaired BBR paths.

### 9. Product GSO-plus-timer validation favored selective use

The product design used ngtcp2 aggregation, not concatenated arbitrary packets.
It retained ciphertext ownership in a FIFO, with four queued 64 KiB aggregates
and five lazily pooled buffers including the current writer.
EAGAIN retained unsent bytes until writable readiness.
Unsupported GSO fell back to identical per-datagram bytes in order.
Timer coalescing tolerated up to 1 ms while preserving an earlier armed timer.
The shared ngtcp2 expiry covers loss/PTO, delayed ACK, pacing and idle; this
tolerance can delay loss/PTO detection, delayed-ACK sending and the pacing
wakeup by at most 1 ms.
The bounded queue and pool addressed research-code ownership and allocation risks.
No receiver GRO or ACK-threshold change was part of this product option.

Research phone LAN validation passed 20 SHA256 transfers, with paired median
1.8657 and nine of ten pairs faster; substantial drift remained visible.
Final product validation also passed 20 transfers, with paired median 2.2365 and
all ten pairs faster. Median throughput rose from 38.8896 to 85.7285 Mbit/s.
Phone CPU fell from 11.2300 to 5.5650 seconds per 100 MB;
server CPU fell from 5.3400 to 2.0300 seconds per 100 MB.
These are matched product-run baselines, not the earlier 85-versus-224 comparison.

The research impairment matrix had 16 download and eight upload cells;
23 of 24 were faster. The slower ordered-jitter upload ratio was 0.7105.
A fresh server-only six-pair retest gave median 1.0107, four wins, and range
0.7225–1.4167. That supports noise as a plausible explanation, not proof of no
smaller regression. Recovery gates also failed in P3; throughput wins alone were
not full production acceptance. Netem seeds differed and GSO changed skb accounting.

The public long-RTT test had eight pairs, median ratio 0.947347, three faster.
Median throughput was 36.726 versus 34.393 Mbit/s.
Server CPU fell from 2.410 to 1.125 seconds; phone CPU from 6.930 to 6.125 seconds.
The post-connect ICMP acceptance gate failed, making this exploratory evidence,
not a fully conforming acceptance result.
**Conclusion:** lower CPU did not guarantee higher throughput; default stayed OFF.
**Confidence:** strong LAN benefit in these pairs, limited public-path generality.

## What did not work or was dropped

- ACK thinning: impaired BBR regressions outweighed clean-path wins.
- Fast clock: much smaller benefit after clock repair; not shipped.
- Disabled pacing: controller-dependent behavior and more loss; not safe generally.
- Larger reorder time factor: synthetic win, normal-path regressions.
- GRO alone: no established clean gain without useful incoming aggregates.
- GSO alone: reduced send work without a reliable independent clean throughput win.
- Logging as the main phone cost: logging-off profiles stayed kernel-heavy.
- Larger UDP buffers: no consistent benefit in the tested matrix; EAGAIN stayed zero.
- Retry-timer removal: no demonstrated throughput bottleneck; retain recovery safety.
- Crypto-only optimization: measured shares did not explain most QUIC CPU cost.

## Superseded and retracted conclusions

- Early slow-clock perf results are not normal-clock cost breakdowns.
  Retain them as evidence of clock distortion, not as current optimization priorities.
- “The server is not the bottleneck” based on idle CPU after transfer is invalid.
  CPU must be sampled during transfer; the historical correction lacks a verified
  matched before/after numeric result in the investigation notes.
- “Clock is the only bottleneck” was false: packet and timer costs remained on `tsc`.
- “The stream flow-control window is insufficient” was not supported by later
  open-credit and no-flow-block observations; socket buffers are a separate limit.
- A historical claim of persistent blocking on one carrier's network was withdrawn.
  The investigation notes describe intermittent dropping of large downlink UDP packets while
  another carrier worked; those notes did not independently verify that account.
  Do not treat it as a measured carrier-wide policy or a permanent protocol block.
- The first E2 interpretation conflated GSO-plus-timer with the GRO-inclusive result.
  Only L1+L2+L3 produced the combined E2 table values above.
- A historical first phone run was reported to have used the TCP host accidentally.
  That is a labelling correction, not QUIC evidence; the original relabelled dataset
  was not independently verified in the investigation notes.
- “Temperature was not the cause” exceeded the test: normal thermal status and
  frequency limits were observed, but thermal causality was not isolated.
- “One slower upload cell was disproved” also exceeds the noisy six-pair retest.
  The appropriate conclusion is uncertainty, not a universal no-regression claim.

## Open questions

- Why did later clean-path runs fail to reproduce E2's large timer gains?
- Which hidden phone kernel operations dominate TUN write and per-packet work?
- How much sender idleness comes from controller decisions versus wake scheduling?
- Would receiver UDP GRO improve clean paths enough to justify parsing complexity?
- What limits the long-RTT path when server CPU falls without throughput rising?
- Would results hold on a different carrier or in a different country?
- How large are long-run tails once background load and thermal policy vary?
- Can equivalent physical-packet impairment remove GSO/netem accounting ambiguity?

Small samples and topology-specific packet aggregation remain major limitations.
No public-path result establishes a universal throughput win or safe new default.

## Reproducing with repository contents

Start with [build instructions](build.md), [configuration](config.md),
[netem usage](../tests/netem/README.md), and
[diagnostic profiles](../tests/netem/DIAGNOSTICS.md).
Initialize submodules and use an external, fresh result directory for each run.
Do not run measurements concurrently or overwrite failed evidence.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DTROJAN_QUIC_STATS=ON
cmake --build build --parallel
python3 tests/netem/harness.py --help
python3 tests/netem/analyze_cc.py --self-check
```

The direct harness accepts `--binary`, `--source`, and `--output-dir`.
Use `--quic-stats` with a diagnostics build; compare stats-OFF controls separately.
The standard container runner builds production defaults, not a sampler build.
Profiles include clean, loss, fixed/ordered delay, constrained rate, burst, outage,
and rebind; inspect `--help` rather than inventing unsupported combinations.
`--probe-only` and `--probe-spacing` test reorder without a transfer.
Use the documented privileged-container setup for network namespaces and qdiscs.

The local clock guard is a shell assertion, run before **and** after each command:

```sh
test "$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource)" = tsc
```

Stop immediately on failure. A passing after-check cannot rescue a failing before-check.
For other hosts, record and validate their expected source separately.
Keep payload, logging level, buffers, binary, sampler state and profile matched.
Alternate A/B order, verify payload SHA256, and record CPU at transfer boundaries.

Set `"udp_gso": true` inside the server's existing `quic` object for the treatment,
and `false` for the control; see [configuration](config.md). Keep the client unchanged.
No standalone partial configuration here replaces the required full server config.

A runnable stdlib calculation for a CSV containing matched `base_mbps,test_mbps`
columns computes the median paired ratio and a percentile bootstrap interval:

```sh
python3 - paired.csv <<'PY'
import csv
import math
import random
import statistics
import sys

with open(sys.argv[1], newline="") as f:
    pairs = [(float(r["base_mbps"]), float(r["test_mbps"]))
             for r in csv.DictReader(f)]
if not pairs or any(not math.isfinite(x) or x <= 0 for p in pairs for x in p):
    raise SystemExit("expected nonempty, finite, positive matched throughputs")
ratios = [b / a for a, b in pairs]
assert statistics.median([2 / 1, 6 / 3, 8 / 4]) == 2
rng = random.Random(0)
medians = sorted(statistics.median(rng.choices(ratios, k=len(ratios)))
                 for _ in range(10000))
print("paired median:", statistics.median(ratios))
print("95% percentile bootstrap:", medians[249], medians[9749])
PY
```

This calculation is an example, not a reconstruction of every interval in the investigation notes.
It cannot correct biased pairing or justify extrapolation from a few measurements.

The following investigation components are **not** part of this repository:
experimental fast-clock, no-pacing and loss-threshold switches; receiver GRO and
ACK-threshold research code; the kernel-floor C tool; phone driver scripts;
and external paired-matrix, loop-trace and product-validation drivers.
Do not infer command-line flags from experiment labels.
Repository tooling supports a grounded new measurement, not a byte-for-byte replay
of every historical experiment without those separately retained artifacts.
