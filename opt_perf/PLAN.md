# Trojan Plus 代理性能优化迭代计划

## 1. 目标与原则

目标：不损害协议正确性、稳定性和资源安全，提高跨洋高 RTT、弱丢包链路上的 TCP TLS 与 QUIC 单流吞吐。

执行原则：

1. 每次只验证一个假设，禁止同时修改 UDP buffer、QUIC flow control、Session chunk 和双缓冲。
2. 每个 Iteration 均执行“本地修改 → 本地 fulltest → commit → 同步及远端编译 → 三模式 TCP/QUIC smoke”的验证闭环；同步后本地与远端分支名、commit 必须同时一致。
3. **开始任何 Iteration 前必须先重点阅读 [quic_proxy_test_remote/AGENTS.md](../quic_proxy_test_remote/AGENTS.md)**。所有测试命令、远端同步、基线采集、安全规则、Run ID、证据保留、失败迭代和 cleanup 要求均以该文件为准；本计划不重复定义。
4. 性能优化首要判定依据是本地与远程测试服务器之间的原始 TCP/UDP 基线带宽，以及代理路径相对该基线的利用率；禁止脱离同时间窗口基线比较绝对 Mbps。
5. 本地测试或远端 smoke 失败时停止，保留证据并返回本地修改；修复后使用新 commit 和新 Run ID 重跑。
6. 单变量 smoke 通过后，才运行该假设所需的最小 A/B 性能测试。正式性能结论每组至少五个有效样本，只比较 median、P10/P90、aggregate、P50/P95 和失败数。
7. 假设不成立、收益不显著、指标恶化或引入 Bug 时停止该方向，不叠加其他修改。
8. 原始结果只增不改；失败、超时和重试结果全部保留。

### 1.1 每个性能 Iteration 的固定 A/B 闭环

每个单变量优化必须严格按以下顺序执行，禁止只测修改后版本，禁止用历史绝对 Mbps 代替同轮比例对比：

1. 使用修改前代码运行 `quic_proxy_test_remote`，在相邻时间窗口采集 iperf3 TCP/UDP 原始网络基线和代理路径性能数据。
2. 计算修改前代理路径利用率：`修改前代理吞吐中位数 / 修改前同方向原始基线中位数`。
3. 只修改一个性能变量，并先完成本地 Release 并发构建、runner unittest、QUIC 全量、标准 client/forward/pipeline、fallback 和平台适用补充测试。
4. 任一本地构建、测试、内容校验或协议校验失败，立即返回代码修改；修复后从本地完整门禁重新开始，直到全部正确。正确性是性能调优前提，失败版本禁止进入性能测试。
5. 本地门禁全部通过后，使用修改后代码再次运行同规格 `quic_proxy_test_remote`，重新采集相邻时间窗口的 iperf3 TCP/UDP 原始网络基线和代理路径性能数据。
6. 计算修改后代理路径利用率：`修改后代理吞吐中位数 / 修改后同方向原始基线中位数`。
7. 比较修改前后代理路径利用率，而非只比较绝对 Mbps。利用率达到该 Iteration 预设提升阈值且正确性、资源和稳定性无回归，才保留修改；利用率未提升、下降或数据因基线波动而无效，则回退修改并记录结论。
8. 任一远端部署、协议、内容、资源、cleanup 或性能采集步骤失败，保留完整证据并返回代码或测试配置修改；修复后重新执行本地完整门禁，再以新 Run ID 重跑修改后整轮测试。禁止跳过错误继续比较收益。

固定比较式：

```text
修改前利用率 = 修改前代理吞吐中位数 / 修改前同方向 iperf3 基线中位数
修改后利用率 = 修改后代理吞吐中位数 / 修改后同方向 iperf3 基线中位数
利用率变化 = 修改后利用率 / 修改前利用率 - 1
```

TCP TLS 与 QUIC 必须分别使用同协议、同方向、同并发条件的代理数据计算。iperf3 TCP 与 UDP 基线均需采集；解释 QUIC 时重点结合 UDP loss、jitter、drops，不能用不同时间窗口或不同方向的数据拼接比例。

## 2. 首要判定依据：本地到远端原始带宽基线

每个性能 Iteration 必须重点执行并查阅 [quic_proxy_test_remote/AGENTS.md](../quic_proxy_test_remote/AGENTS.md) 中的基线流程。三模式 smoke 用于正确性门禁，不能替代性能基线。

在代理 A/B 前后相邻时间窗口采集：

- iperf3 TCP 正向与反向，至少包含单流；涉及并发优化时补充对应多流。
- iperf3 UDP 正向与反向，记录实际吞吐、loss 和 jitter。
- RTT、路由、测试时间、两端 commit 和构建类型。

每轮必须同时报告：

```text
原始 TCP/UDP 基线中位数
TCP TLS 与 QUIC 吞吐中位数
代理路径利用率 = 代理吞吐中位数 / 同方向原始基线中位数
优化前后代理吞吐变化率
优化前后代理路径利用率变化
```

判定规则：

- 只比较同方向、相邻时间窗口、相同样本和并发条件的数据。
- 原始基线波动明显时，本轮性能结论无效；重新采集，不把公网变化记为代码收益或回退。
- UDP 基线显著弱于 TCP 时，先判断公网 UDP loss、policing 或 MTU，不直接归因 QUIC 实现。
- 代理绝对 Mbps 提升但基线利用率未提升时，不宣布代码优化有效。
- 仅 smoke 通过只能说明功能正确，不能宣布性能提升。

## 3. 已确认事实与待验证假设

### 2.1 已确认事实

- `quic.recv_buffer_size` 与 `quic.send_buffer_size` 默认请求值为 `max_datagram_size * 64`，即 76,800 bytes。
- 每个 QUIC Endpoint 显式设置 UDP receive/send socket buffer，但当前错误码可能被后续 `non_blocking()` 调用覆盖。
- 服务端初始双向 stream credit 为 512 KiB，客户端为 1 MiB；后续 credit 随应用消费扩展，不是静态窗口。
- Session 每个单向 relay 同时只有一次 read 和对应 write；下一次 read 等待上一块 write completion。
- `MAX_BUF_LENGTH` 同时用于 TCP relay、UDP 和 TUN，不能直接全局放大。
- QUIC partial write 使用固定 10 ms timer retry，可能产生调度空洞。

### 2.2 待验证假设

- UDP socket buffer 偏小是否造成内核 UDP drops 或吞吐限制。
- QUIC partial write 的 10 ms retry 是否频繁触发并限制单流吞吐。
- client/server 初始 stream credit 是否在对应上传、下载方向产生 flow-control blocked。
- TCP relay chunk 从 8 KiB 增至 16/32 KiB 是否减少 handler、copy 和 syscall 开销。
- 有界双槽流水线是否能在保持背压、顺序和生命周期正确性的同时提升吞吐。

UDP socket buffer 不是 QUIC congestion window，不能使用 `socket buffer / RTT` 推导单连接吞吐硬上限。异步 write completion 也不等于等待远端 TCP/QUIC ACK。根因必须由运行时观测和单变量 A/B 证明。

## 4. 通用停止条件

出现以下任一情况，立即停止当前 Iteration，按 [quic_proxy_test_remote/AGENTS.md](../quic_proxy_test_remote/AGENTS.md) 的失败闭环处理：

- 本地构建或 fulltest 失败。
- 远端同步、编译或三模式 smoke 失败。
- 内容长度或 hash 不一致。
- 强制 QUIC 发生 TCP fallback。
- crash、deadlock、unexpected reset 或 callback 重入问题。
- TCP TLS 或并发 aggregate 中位数回退超过 5%。
- UDP/kernel drops 明显恶化。
- RSS/PSS 持续线性增长且 cooldown 不回落。
- 单变量假设无数据支持或收益不足预设阈值。

## 5. Iteration 0：基线修正与可观测性

### 4.1 代码范围

不改性能参数，仅增加低开销观测：

- UDP buffer 每次 `set_option()` 使用独立 error code。
- 设置失败打印非致命 WARN。
- 设置后使用 `get_option()` 记录实际 `SO_RCVBUF/SO_SNDBUF`。
- 区分 `non_blocking()` 失败，避免错误码覆盖。
- 后续诊断按需增加累计计数，禁止正式性能轮逐包日志。

观测目标：

- 实际 socket buffer。
- UDP receive/send 错误。
- receive drain loop 触及批次上限次数。
- QUIC flow-control blocked、partial write、10 ms retry 次数。
- Session read size、write latency、source-read idle gap。

### 4.2 验收

- 日常验证闭环全部通过。
- 观测日志不泄露密钥、不逐包刷屏、不显著影响性能。
- 建立可复现基线，修正互相矛盾的绝对吞吐目标。

## 6. Iteration 1：UDP socket buffer 单变量 A/B

候选值：

```text
76,800 B
256 KiB
1 MiB
2 MiB
```

先用 baseline 和一个候选值完成日常验证闭环及五轮 A/B。仅前一个候选值显示改善趋势时测试下一档，不为每档重复无关的全量压力矩阵。

记录请求值、实际内核值、吞吐、CPU、RSS/PSS 和 UDP drops。成立条件：相对基线吞吐中位数提升至少 5%，或明确消除 `RcvbufErrors/SndbufErrors`，且无正确性和资源回归。否则停止扩大并重新规划。

## 7. Iteration 2：QUIC retry 与 flow control

先验证 10 ms partial-write retry：

- 若大量触发，优先改为 ACK、pacing、flow-control unblock 或 socket write opportunity 驱动。
- 若极少触发，不修改 retry 机制，转向 flow-control A/B。

flow-control 分方向测试：

```text
client receive credit: 1 MiB / 2 MiB / 4 MiB
server receive credit: 512 KiB / 1 MiB / 2 MiB
```

上传、下载独立统计。每次只改变一个方向和一个值；先跑日常验证闭环，再做对应方向五轮 A/B。成立条件：blocked/retry 指标明显下降、目标方向吞吐中位数提升至少 10%，且 RSS/PSS 和队列内存无持续增长。

## 8. Iteration 3：拆分并测试 TCP relay chunk

不得直接放大全局 `MAX_BUF_LENGTH`。先拆分：

```cpp
TCP_RELAY_BUF_LENGTH = 8192 / 16384 / 32768;
UDP/TUN limits unchanged;
```

保持单读单写状态机。每个候选值先跑日常验证闭环，再对 TCP TLS、QUIC、pipeline、非 pipeline、上传和下载中的受影响路径做五轮 A/B。

成立条件：目标路径吞吐中位数提升至少 5%，handler/CPU 开销下降，无 UDP/TUN 行为变化。

## 9. Iteration 4：有界双槽流水线

按以下顺序逐项实施，每项独立执行日常验证闭环和对应路径 A/B：

1. `ClientSession` TCP TLS 下载方向。
2. `ClientSession` QUIC 下载方向。
3. Client 上传方向。
4. `ServerSession` 对称路径。
5. Pipeline 兼容路径。

约束：

- 每方向最多一个 write in flight。
- 只允许一个额外 read buffer，形成有界背压。
- 严格保证 write ordering、partial completion、EOF/FIN、half-close、reset 和 destroy 生命周期。
- callback exactly once。
- 首版不引入通用 128/256 KiB watermark queue。

任一子步骤失败，停止后续方向扩展。

## 10. 参数固化与最终验收

仅保留单变量 A/B 已证明有效的修改。先按 [quic_proxy_test_remote/AGENTS.md](../quic_proxy_test_remote/AGENTS.md) 完成日常三模式验证、正式性能矩阵和压力测试。

长稳规则：

- 日常迭代不重复执行长稳。
- 最终发布，或修改连接/流生命周期、发现内存异常时，对关键 QUIC 路径执行一次 30 分钟 active + 10 分钟 cooldown。
- 超过 256 次连接，每分钟记录 RSS/PSS 和 slope，每个样本校验长度与 SHA-256。
- Docker runner 未完整采集逐分钟 RSS/PSS 时，只能验收功能和并发，不能宣布内存长稳通过。

最终指标相对同轮、同方向原始网络基线计算：

- QUIC 单流中位数相对优化前提升至少 20%。
- QUIC 单流达到同方向 iperf3 单流中位数至少 70%。
- TCP TLS 中位数不回退超过 5%。
- 5/10 并发 aggregate 不回退超过 5%。
- 全部内容长度/hash 正确。
- 零 fallback、crash、deadlock、unexpected reset。
- UDP/kernel/interface drops 不恶化。
- Trojan RSS/PSS 无持续线性增长，cooldown 可回落。
- 远端整机峰值内存低于 350 MiB，无 swap storm/OOM。
- cleanup 后无本轮资源残留。

是否 push 由用户另行明确授权。
