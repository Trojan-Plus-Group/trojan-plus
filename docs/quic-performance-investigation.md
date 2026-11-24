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
- Keeping overdue waits cut clean-path timer churn but regressed delayed uploads.
- The public long-RTT test reduced CPU, but did not improve throughput.

This tree provides `quic.udp_gso` (now defaults to `true`) for server and client endpoints
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

### 10. Timer re-arm reduction (B)

**Question.** Why does timer re-arm work remain with GSO enabled?
Temporary counters on `d70b805` sampled one isolated clean transfer per case,
with GSO on and log level 1. The denominator is decimal payload MB or received
QUIC packets (ngtcp2), not UDP skbs. Last snapshots can omit the teardown tail.

| Case | Base arms/MB client/server | Candidate arms/MB client/server | Base arms/RX packet client/server | Candidate arms/RX packet client/server |
|---|---:|---:|---:|---:|
| tcp_down-socks5 | 161.3/136.5 | 10.5/14.9 | 0.225/0.382 | 0.015/0.041 |
| tcp_down-tun | 164.6/140.1 | 9.7/14.1 | 0.228/0.390 | 0.014/0.039 |
| tcp_up-socks5 | 352.2/395.6 | 38.8/25.8 | 0.788/0.443 | 0.087/0.029 |
| tcp_up-tun | 1576.1/1046.7 | 122.2/98.3 | 2.230/0.721 | 0.174/0.068 |

Earlier requests accounted for 18.2–43.3% of installs, later requests 46.8–50.4%,
and equal requests 7.0–31.5%. A later request only replaced a wait after its
installed deadline had passed. The pump and GSO write sites accounted for
nearly all arms. Most replaced waits were canceled rather than handled.
Aggregate expiry includes pacing, but these counters cannot isolate which
source caused each shift. Moving pacing to a different path was not tested.

**Candidate.** Keep an overdue wait instead of canceling and replacing it.
The pending handler processes current ngtcp2 expiry, clears armed state, and
pumps to recompute the next expiry. Keep future waits for equal/later requests
in both modes, with the existing 1 ms earlier tolerance on GSO and zero off.
Overdue waits add no intentional delay: the handler is already eligible to run.
Those are policy bounds, not guarantees on event-loop dispatch latency.
Early fires with no work increased, but later and equal replacements disappeared.

**Release bench.** Base vs candidate, alternating order, log level 1, back leg
`b0`. Clean: five pairs with GSO on, two off. Impaired: three pairs per profile
with GSO on. TCP bulk uses Mbit/s; TCP latency uses p95 TTFB and UDP latency uses
p95 RTT, both in ms. Brackets show range; ratios are candidate/base by round.
Lower is better only for latency.

**Clean.**

| Front | GSO | Mode | Metric | Base median [range] | Head median [range] | Paired ratios | Median ratio | Base client/server CPU s/GB |
|---|---|---|---|---|---|---|---|---|
| f0 | off | socks5 | tcp_down | 286.689 [281.067, 292.310] | 581.152 [519.996, 642.308] | 2.197, 1.850 | 2.024 | 27.875/21.189 |
| f0 | off | socks5 | tcp_up | 158.878 [156.491, 161.264] | 328.072 [321.346, 334.797] | 1.993, 2.139 | 2.066 | 26.301/50.701 |
| f0 | off | tun | tcp_down | 230.236 [223.958, 236.513] | 488.455 [472.681, 504.229] | 2.251, 1.999 | 2.125 | 33.339/22.694 |
| f0 | off | tun | tcp_up | 88.802 [88.419, 89.185] | 154.443 [153.567, 155.319] | 1.722, 1.757 | 1.739 | 75.833/90.094 |
| f0 | on | socks5 | tcp_down | 538.562 [512.615, 551.933] | 860.003 [807.467, 873.118] | 1.703, 1.607, 1.597, 1.520, 1.538 | 1.597 | 14.836/10.896 |
| f0 | on | socks5 | tcp_up | 204.305 [196.323, 214.591] | 330.046 [296.843, 343.365] | 1.464, 1.622, 1.643, 1.538, 1.667 | 1.622 | 19.260/39.488 |
| f0 | on | tun | tcp_down | 396.686 [365.835, 407.476] | 545.870 [500.815, 580.707] | 1.374, 1.492, 1.229, 1.464, 1.395 | 1.395 | 18.877/11.123 |
| f0 | on | tun | tcp_up | 97.947 [93.135, 101.861] | 159.857 [152.654, 167.992] | 1.688, 1.712, 1.569, 1.633, 1.639 | 1.639 | 69.915/81.636 |

**30 ms RTT.**

| Front | GSO | Mode | Metric | Base median [range] | Head median [range] | Paired ratios | Median ratio | Base client/server CPU s/GB |
|---|---|---|---|---|---|---|---|---|
| f30 | on | socks5 | tcp_down | 104.289 [103.926, 123.815] | 110.779 [105.386, 129.011] | 1.042, 1.014, 1.062 | 1.042 | 37.318/14.356 |
| f30 | on | socks5 | tcp_lat | 35.067 [34.924, 35.197] | 35.534 [34.933, 36.573] | 1.017, 0.992, 1.043 | 1.017 | n/a/n/a |
| f30 | on | socks5 | tcp_up | 82.988 [81.524, 84.247] | 77.012 [75.309, 78.401] | 0.914, 0.962, 0.907 | 0.914 | 22.815/54.608 |
| f30 | on | socks5 | udp_lat | 33.976 [33.962, 34.009] | 33.907 [33.829, 33.949] | 0.998, 0.996, 0.998 | 0.998 | n/a/n/a |
| f30 | on | tun | tcp_down | 117.944 [108.562, 118.597] | 105.837 [101.468, 111.188] | 0.975, 0.938, 0.860 | 0.938 | 40.137/13.596 |
| f30 | on | tun | tcp_lat | 35.053 [34.893, 35.304] | 34.645 [34.521, 35.334] | 1.001, 0.993, 0.985 | 0.993 | n/a/n/a |
| f30 | on | tun | tcp_up | 56.709 [56.148, 57.255] | 36.841 [34.572, 54.653] | 0.973, 0.650, 0.604 | 0.650 | 58.398/57.350 |
| f30 | on | tun | udp_lat | 33.969 [33.953, 34.006] | 33.943 [33.925, 33.958] | 0.998, 1.000, 0.999 | 0.999 | n/a/n/a |

**80 ms RTT with loss.**

| Front | GSO | Mode | Metric | Base median [range] | Head median [range] | Paired ratios | Median ratio | Base client/server CPU s/GB |
|---|---|---|---|---|---|---|---|---|
| f80l1 | on | socks5 | tcp_down | 133.207 [126.891, 134.058] | 162.964 [158.360, 163.698] | 1.221, 1.223, 1.248 | 1.223 | 27.388/15.395 |
| f80l1 | on | socks5 | tcp_lat | 86.744 [86.631, 87.539] | 86.326 [85.943, 86.472] | 0.986, 0.992, 0.997 | 0.992 | n/a/n/a |
| f80l1 | on | socks5 | tcp_up | 32.713 [32.110, 32.820] | 32.817 [32.399, 34.024] | 1.000, 1.040, 1.009 | 1.009 | 27.788/65.535 |
| f80l1 | on | socks5 | udp_lat | 128.686 [116.901, 129.758] | 135.778 [115.763, 137.259] | 0.892, 1.174, 1.055 | 1.055 | n/a/n/a |
| f80l1 | on | tun | tcp_down | 133.122 [132.233, 133.519] | 164.179 [160.682, 165.221] | 1.203, 1.249, 1.233 | 1.233 | 31.879/15.275 |
| f80l1 | on | tun | tcp_lat | 86.545 [86.212, 87.514] | 86.748 [86.129, 87.095] | 0.999, 0.995, 1.002 | 0.999 | n/a/n/a |
| f80l1 | on | tun | tcp_up | 25.611 [24.590, 25.786] | 24.825 [24.797, 24.832] | 0.968, 0.963, 1.010 | 0.968 | 84.181/82.210 |
| f80l1 | on | tun | udp_lat | 107.183 [85.410, 143.003] | 147.337 [135.993, 156.134] | 1.092, 1.592, 1.375 | 1.375 | n/a/n/a |

The 30 ms upload regression appeared in every pair for both modes. TUN UDP
p95 also rose in every 80 ms/loss pair, despite zero missing echoes. No bench
cell reported failure, but a passing transfer does not clear these regressions.

**Safety checks.** Candidate container matrix had all 40 suites exit zero;
recorded PASS/SKIP lists matched the prior matrix. T5 and T22–T25 passed,
as did the S5 server handshake timeout regression. A production-helper test
pinned due-wait retention, exact earlier deadlines without GSO, and reset after
firing; it was part of the rejected candidate, not a product change.

A focused repository netem workload A comparison used two repeats per variant,
with stats enabled to select BBR and CUBIC. All 16 transfers passed SHA256.
Ratios below match repeat numbers, not interleaved netem runs. Loss figures are
last sampled server lost/sent counts, not exact retransmission totals. Netem
seeds varied; ordered jitter can induce transport loss even without random
qdisc drops, so these data do not identify a cause for every loss delta.

| Controller | Profile | Base Mbit/s | Candidate Mbit/s | Ratios by repeat | Server lost/sent base vs candidate |
|---|---|---|---|---|---|
| bbr | loss1 | 191.804, 281.269 | 388.807, 434.968 | 2.027, 1.546 | 2.57%, 3.46% vs 0.94%, 0.96% |
| bbr | delay100-jitter-ordered | 6.465, 6.285 | 6.325, 6.286 | 0.978, 1.000 | 8.30%, 5.72% vs 8.11%, 7.57% |
| cubic | loss1 | 185.995, 164.368 | 358.554, 346.914 | 1.928, 2.111 | 0.97%, 1.05% vs 1.02%, 0.97% |
| cubic | delay100-jitter-ordered | 6.564, 6.479 | 6.845, 6.382 | 1.043, 0.985 | 0.53%, 1.18% vs 0.51%, 0.19% |

| Profile | Base client/server % | Candidate client/server % |
|---|---|---|
| socks5-down | 18.86/20.67 | 0.57/7.40 |
| socks5-up | 22.17/16.88 | 13.07/1.83 |
| tun-down | 14.62/20.20 | 0.51/9.58 |
| tun-up | 24.28/20.15 | 3.17/1.08 |

Matched frame-pointer builds sampled sustained clean transfers. Inclusive
`timerfd_settime` shares overlap other CPU categories and are percentages of
samples, not syscall counts. The large clean throughput gain does not follow
from those shares alone; changes in wake scheduling or packet delivery are
possible contributors, not established causes.

**Conclusion.** Do not ship overdue-wait retention as tested. It removes
measured churn and improves clean throughput but fails the impairment gate.
**Confidence:** strong for the clean improvement and the local 30 ms upload
regression; cause and generality across paths remain unresolved.

## What did not work or was dropped

- Overdue-wait retention: clean gains did not offset delayed-upload regressions.
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
- Which expiry sources drive overdue replacements, and can batching avoid
  those replacements without changing delayed-path send timing?
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
