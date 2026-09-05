# Trojan Plus 代理性能优化迭代计划

## 1. 目标与原则

目标：在不损害协议正确性、稳定性和资源安全的前提下，提高跨洋高 RTT、弱丢包链路上的 TCP TLS 与 QUIC 单流吞吐。

执行原则：

1. 每次只验证一个假设，禁止把 UDP buffer、QUIC flow control、Session chunk、双缓冲同时修改。
2. 每个 Iteration 必须依次通过代码审查、本地全面功能测试、本地与远端组合的端到端压测、结果复核。远端不重复运行 LinuxFullTest。
3. 假设不成立、收益不显著、指标恶化或引入 Bug 时立即停止，不进入下一 Iteration；保留失败证据并重新规划。
4. 允许为远程同步和阶段检查创建本地 commit；任何情况下不得 push。每个 Iteration 全部通过后再标记为验收完成。
5. TCP TLS 与 QUIC 使用同一 commit、构建类型、证书、密码、目标、样本大小、并发数和相邻时间窗口。
6. 正式性能测试每组至少五个有效样本，只比较 median、P10/P90、aggregate、P50/P95 和失败数，不使用最好结果代替统计。
7. 原始结果只增不改；失败、超时和重试结果全部保留。

## 2. 已确认事实与待验证假设

### 2.1 已确认事实

- `quic.recv_buffer_size` 与 `quic.send_buffer_size` 默认请求值为 `max_datagram_size * 64`，默认等于 76,800 bytes。
- 每个 QUIC Endpoint 显式设置 UDP receive/send socket buffer，但当前错误码可能被后续 `non_blocking()` 调用覆盖。
- 服务端初始双向 stream credit 为 512 KiB，客户端为 1 MiB；后续 credit 会随应用消费扩展，不是完全静态窗口。
- Session 每个单向 relay 同时只有一次 read 和对应 write；下一次 read 等待上一块 write completion。
- `MAX_BUF_LENGTH` 同时用于 TCP relay、UDP 和 TUN，不能直接全局放大。
- QUIC partial write 当前使用固定 10 ms timer retry，可能产生额外调度空洞。

### 2.2 待验证假设

- UDP socket buffer 偏小是否造成内核 UDP drops 或吞吐限制。
- QUIC partial write 的 10 ms retry 是否频繁触发并限制单流吞吐。
- client/server 初始 stream credit 是否在对应上传、下载方向产生 flow-control blocked。
- TCP relay chunk 从 8 KiB 增至 16/32 KiB 是否减少 handler、copy 和 syscall 开销。
- 有界双槽流水线是否能在保持背压、顺序和生命周期正确性的同时提升吞吐。

UDP socket buffer 不是 QUIC congestion window，不能使用 `socket buffer / RTT` 直接推导单连接吞吐硬上限。异步 write completion 也不等于等待远端 TCP/QUIC ACK。所有根因必须由运行时观测和单变量 A/B 证明。

## 3. 统一测试门禁

### 3.1 本地全面测试

每个 Iteration 修改后依次执行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_QUIC=ON
cmake --build build -j 1
python3 -m unittest \
  quic_proxy_test_remote/scripts/test_run.py \
  quic_proxy_test_remote/scripts/test_docker_modes.py
cd tests/LinuxFullTest
python3 -u fulltest_main.py ../../build/trojan -q all
python3 -u fulltest_main.py ../../build/trojan -n
python3 -u fulltest_main.py ../../build/trojan -f
```

Linux 且具备权限时补充：

```bash
sudo python3 fulltest_main.py ../../build/trojan -d 5333
sudo python3 fulltest_main.py ../../build/trojan -t -n -d 5333
```

macOS DNS 测试按 runner 平台保护跳过。测试前确认 `18080`、`18083`、`9080`、`9081` 无用户业务。

本地门禁：全部测试通过；零 crash、deadlock、unexpected reset、内容错误和资源门禁失败。

### 3.2 远程环境确认

全面功能回归仅在本地执行。远端只执行 Release 构建，并与本地客户端组成端到端网络基线、代理压测、长稳、资源监控和 cleanup 验证；远端无需安装或运行 LinuxFullTest 依赖。

每轮组合压测前重新确认：

```text
REMOTE_HOST
SSH_USER
SSH_PORT
REMOTE_REPO
REMOTE_CPU_COUNT
REMOTE_MEMORY
REMOTE_BRANCH
TEST_PORTS
```

保存两端 commit、dirty diff、构建类型、系统与工具版本。两端必须使用同一代码和 Release 构建。远端若为 1 CPU/1 GB，只允许：

```bash
cmake --build build -j 1
```

同步仅使用 git bundle 与 fast-forward。禁止 reset、force 和任何 push；允许创建本地 commit。

### 3.3 远程基础与代理测试矩阵

每个 Iteration 先记录相邻时间窗口的原始网络基线：

- ping 30 次和路由信息。
- iperf3 TCP 正向/反向，1/4/8 streams，每项至少五轮。
- iperf3 UDP 正向/反向，从 10/25/50 Mbit/s 开始；稳定后才测试更高档位。

代理正式矩阵：

| 模式 | TCP 正式 | 强制 QUIC 正式 | TCP 压力 | QUIC 压力 |
|---|---:|---:|---:|---:|
| `client` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/50 MB | 200 请求/50 MB |
| `nat` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/32 并发 | 200 请求/32 并发 |
| `client_tun` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/32 并发 | 200 请求/32 并发 |

每个协议、模式、配置变量使用独立 Run ID。TCP 与强制 QUIC 分开 deploy。强制 QUIC 样本必须满足：

- client/server `debug_disable_tcp=true`。
- 远端 UDP listener 存在，TCP listener 不存在。
- client/server 日志包含 `handshake completed`。
- ALPN 为 `h3`。
- 零 TCP fallback。

最低正确性要求：exit 0、HTTP 200、长度和 SHA-256 完整、零 fallback、零 crash/deadlock/unexpected reset。

资源指标：client/server CPU、RSS/PSS、context switches、UDP errors、interface drops、softnet drops、吞吐、延迟。每组结束后按 metadata 精确清理并验证进程、listener、容器、route、iptables、TUN、namespace、qdisc 无残留。

### 3.4 停止条件

出现以下任一情况立即停止当前 Iteration：

- 本地任一测试失败。
- 远程内容长度或 hash 不一致。
- 强制 QUIC 发生 TCP fallback。
- crash、deadlock、unexpected reset 或 callback 重入问题。
- TCP TLS 或并发 aggregate 中位数回退超过 5%。
- UDP/kernel drops 明显恶化。
- RSS/PSS 持续线性增长且 cooldown 不回落。
- 单变量假设无数据支持或收益不足预设阈值。

停止后保留结果，定位原因，更新计划；禁止带着未知回归继续下一步。

## 4. Iteration 0：基线修正与可观测性

### 4.1 代码范围

不改性能参数，仅增加低开销观测：

- UDP buffer 每次 `set_option()` 使用独立 error code。
- 设置失败打印非致命 WARN。
- 设置后使用 `get_option()` 记录实际 `SO_RCVBUF/SO_SNDBUF`。
- 区分 `non_blocking()` 失败，避免错误码覆盖。
- 后续诊断按需要增加累计计数，禁止正式性能轮逐包日志。

观测目标：

- 实际 socket buffer。
- UDP receive/send 错误。
- receive drain loop 触及批次上限次数。
- QUIC flow-control blocked、partial write、10 ms retry 次数。
- Session read size、write latency、source-read idle gap。

### 4.2 验收

- 本地全面门禁全部通过。
- 远程三模式 TCP/强制 QUIC 正式与压力矩阵通过。
- 观测日志不泄露密钥、不逐包刷屏、不显著影响性能。
- 建立可复现基线，修正原计划中互相矛盾的绝对吞吐目标。

通过后创建 Iteration 0 本地 commit，再进入 Iteration 1。

## 5. Iteration 1：UDP socket buffer 单变量 A/B

仅修改客户端与服务端 UDP socket buffer 配置，候选值：

```text
76,800 B
256 KiB
1 MiB
2 MiB
```

每档执行本地全面门禁和远程矩阵，记录请求值、实际内核值、吞吐、CPU、RSS/PSS、UDP drops。

成立条件：相对基线吞吐中位数提升至少 5%，或明确消除 `RcvbufErrors/SndbufErrors`，且无正确性和资源回归。否则停止扩大并重新规划。

## 6. Iteration 2：QUIC retry 与 flow control

先验证 10 ms partial-write retry：

- 若大量触发，优先改为对应 ACK、pacing、flow-control unblock 或 socket write opportunity 驱动。
- 若极少触发，不修改 retry 机制，转向 flow-control A/B。

flow-control 分方向测试：

```text
client receive credit: 1 MiB / 2 MiB / 4 MiB
server receive credit: 512 KiB / 1 MiB / 2 MiB
```

上传、下载独立统计。成立条件：blocked/retry 指标明显下降且目标方向吞吐中位数提升至少 10%；RSS/PSS 和队列内存无持续增长。

## 7. Iteration 3：拆分并测试 TCP relay chunk

不得直接放大全局 `MAX_BUF_LENGTH`。先拆分：

```cpp
TCP_RELAY_BUF_LENGTH = 8192 / 16384 / 32768;
UDP/TUN limits unchanged;
```

保持单读单写状态机，只验证 chunk 大小。分别测试 TCP TLS、QUIC、pipeline、非 pipeline、上传和下载。

成立条件：目标路径吞吐中位数提升至少 5%，handler/CPU 开销下降，无 UDP/TUN 行为变化。

## 8. Iteration 4：有界双槽流水线

按以下顺序逐项实施，每项均独立执行完整门禁：

1. `ClientSession` TCP TLS 下载方向。
2. `ClientSession` QUIC 下载方向。
3. Client 上传方向。
4. `ServerSession` 对称路径。
5. Pipeline 兼容路径。

约束：

- 每方向最多一个 write in flight。
- 只允许一个额外 read buffer，形成天然有界背压。
- 严格保证 write ordering、partial completion、EOF/FIN、half-close、reset 和 destroy 生命周期。
- callback exactly once。
- 首版不引入通用 128/256 KiB watermark queue。

任一子步骤失败，停止后续方向扩展。

## 9. Iteration 5：参数固化与长稳

仅保留已由单变量 A/B 证明有效的修改。TCP 与 QUIC 分别执行：

- 至少 30 分钟 active。
- 至少 10 分钟 cooldown。
- 超过 256 次连接。
- 每分钟记录 RSS/PSS 和 slope。
- 每个样本校验长度与 SHA-256。

Docker runner 未完整采集逐分钟 RSS/PSS 前，只能验收功能和并发，不能宣布内存长稳通过。

## 10. 最终验收

最终指标相对同轮、同方向原始网络基线计算，不预设与基线矛盾的绝对 Mbps：

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

最终全部通过后创建本地 commit；是否 push 由用户另行明确授权。
