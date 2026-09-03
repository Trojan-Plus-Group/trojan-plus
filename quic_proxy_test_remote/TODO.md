# Trojan Plus QUIC 远程性能调查 TODO

关联计划：[PLAN.md](PLAN.md)

## 使用规则

- 状态只用：`[ ]` 未开始、`[~]` 进行中、`[x]` 完成、`[-]` 跳过、`[!]` 阻塞。
- 同一时间只允许一个任务为 `[~]`。
- 每轮使用独立 `run_id`：`<UTC时间>-<commit短哈希>-r<轮次>`。
- 每轮开始前填写“输入”，结束后填写“结论”和“下一轮唯一变量”。
- 每轮只改变一个变量。代码、配置、网络条件不能同时变化。
- 原始结果只新增，不覆盖；结果统一放入 `results/<run_id>/`。
- 未完成正确性和基线测试前，不修改 QUIC 传输代码。
- 失败结果同样保留，记录命令、退出码、日志和环境。
- 所有跨洋命令设置连接/总超时，最多重试 2 次，间隔 3 秒、10 秒；每次尝试单独保存。
- 单个带宽样本总流量不得超过 50 MB；单项含重试必须在 3 分钟内结束。
- TCP/HTTP 优先按字节限制；UDP 必须满足 `bitrate × duration <= 50 MB`。
- 密码、私钥、TLS keylog 不提交仓库；测试结束删除远端临时凭据。

## 当前状态

- 当前阶段：修复验证。
- 当前轮次：R11。
- 当前基线 commit：`a76cb80`。
- 当前结论：问题已稳定复现并修复；高 RTT + 反向 UDP 5–6% 丢包下，CUBIC 崩速，应用重试退避和 16 KiB 串行读取进一步放大停顿。BBR v2 + 10 ms retry + 256 KiB read + 正确 packet tx time 后，15 MiB QUIC 为 15.14 秒，TCP TLS 为 95.82 秒，SHA-256 正确。
- 下一步：提交修复、清理远端、保留后续长稳和更多网络环境验证任务。
- 阻塞项：无。

## 总门禁

- [x] 原始 TCP/UDP 网络基线完成。
- [x] Trojan TCP TLS 基线完成。
- [x] Trojan QUIC 基线完成，且确认未回退 TCP。
- [x] 固定 byte source 正确性和吞吐测试完成。
- [ ] 单流与多流差异得到量化。
- [~] 客户端和服务端 CPU、RSS、UDP drop 数据：T16 与 R1 已采集，远程长稳待补。
- [x] 至少一个高 RTT 场景可稳定复现问题。
- [x] 根因有实验数据支持，不依赖代码猜测。
- [x] 修复按单变量逐轮验证后组合。
- [x] 本地 QUIC 全量测试通过。
- [ ] 远程短测、并发、长稳和内存门禁通过。
- [ ] 最终结论可由保存的命令和结果复现。

---

# R0：环境与工具准备

## 输入

- Commit：`f8bb047`
- 本地：macOS 26.5，北京。
- 远端：CentOS Stream 10，美国，`172.236.226.35`。
- 远端 SSH：`ssh -p 9922 root@172.236.226.35`。
- 预期代码改动：无。

## 任务

### R0.1 目录与结果规范

- [x] 创建 `quic_proxy_test_remote/PLAN.md`。
- [x] 创建 `quic_proxy_test_remote/TODO.md`。
- [x] 创建 `scripts/`。
- [x] 创建 `results/`，并确保运行结果不被 Git 跟踪。
- [~] 定义 run manifest，已记录 commit、UTC 时间、构建参数和配置 hash；命令与退出码在 R1 runner 补齐。
- [x] 定义结果目录：`metadata/`、`baseline/`、`direct/`、`tcp-tls/`、`quic/`、`logs/`、`captures/`。

### R0.2 远端工具

- [x] 查询并安装 `perf`、`sysstat`。
- [x] 记录安装后版本：`perf-6.12.0-264.el10.x86_64`、`sysstat-12.7.6-4.el10.x86_64`。
- [x] 确认 `pidstat`、`sar`、`nstat` 可用。
- [x] 确认 `tcpdump`、`tc`、`ss`、`iperf3` 可用。
- [x] 不安装 `speedtest`，除非后续公网体验测试确实需要。

### R0.3 网络与端口

- [ ] 确认云防火墙允许 `3443/TCP`。
- [ ] 确认云防火墙允许 `3443/UDP`。
- [ ] 确认云防火墙允许 `5201/TCP`。
- [ ] 确认云防火墙允许 `5201/UDP`。
- [ ] 确认端口当前未被其他进程占用。
- [ ] 测试结束后确认端口释放。

### R0.4 构建一致性

- [x] 保存本地 `git status`、commit、submodule commit。
- [x] 保存远端 `git status`、commit、submodule commit。
- [x] 确认两端使用 Release 构建。
- [x] 完成远端 Release CMake configure/build；R1 runner 负责持久保存后续输出。
- [x] 检查两端 `trojan --version`。
- [x] 确认两端显示 QUIC Support enabled。

### R0.5 临时凭据和配置

- [x] 生成一次性随机 Trojan 密码。
- [x] 生成仅用于本轮测试的证书和私钥，包含远端 IP SAN。
- [x] 创建 `server.json` 模板和运行时配置。
- [x] 创建 `client-quic.json` 模板和运行时配置，SOCKS5 监听 `127.0.0.1:9080`。
- [x] 创建 `client-tcp.json` 模板和运行时配置，SOCKS5 监听 `127.0.0.1:9081`。
- [x] QUIC 配置设置 `debug_disable_tcp: true`。
- [x] 性能配置使用 `log_level: 1`。
- [x] 凭据文件加入忽略规则，不进入 Git diff。
- [ ] 定义远端部署和清理命令，R2 启动 Trojan 前完成。

## R0 验收

- [ ] 两端 commit、构建类型和版本一致。
- [ ] 四个测试端口均可用。
- [ ] 配置可解析，但尚未开始正式性能测试。
- [ ] 所有敏感文件有清理方案。

## R0 结论

- 状态：未完成。
- 证据目录：待创建。
- 阻塞：云防火墙状态未确认。
- 下一轮唯一目标：采集不经过 Trojan 的原始网络基线。

---

# R1：原始网络基线

## 输入

- 代码改动：无。
- 配置改动：无。
- 唯一目标：量化北京到美国的 TCP/UDP 原始能力。

## 任务

### R1.1 路径与延迟

- [ ] `ping` 30 次，保存原始输出。
- [ ] `traceroute`，保存原始输出。
- [ ] 记录 RTT min/avg/max/stddev。
- [ ] 记录 ICMP loss。
- [ ] 检查两端 UTC 时间和 NTP 状态。

### R1.2 iperf3 TCP

每项预热一次、正式五次。TCP 使用总量 `-n 50M`；每次尝试硬超时 170 秒，最多重试 2 次。

- [ ] client 到 server，单流。
- [ ] server 到 client，单流 `-R`。
- [ ] client 到 server，4 流。
- [ ] server 到 client，4 流。
- [ ] client 到 server，8 流。
- [ ] server 到 client，8 流。
- [ ] 保存每轮 JSON。
- [ ] 汇总吞吐、retransmits、cwnd、CPU、P10/中位数/P90。

### R1.3 iperf3 UDP

正向和反向分别测试：

- [ ] 10 Mbit/s。
- [ ] 25 Mbit/s。
- [ ] 50 Mbit/s。
- [ ] 100 Mbit/s。
- [ ] 200 Mbit/s。
- [ ] 保存每轮 JSON。
- [ ] 汇总实际吞吐、loss、jitter、out-of-order。
- [ ] 标记开始出现明显 loss 的目标速率。

### R1.4 系统观测

- [ ] 测试前后保存 `/proc/net/snmp`。
- [ ] 测试前后保存 `/proc/net/softnet_stat`。
- [ ] 测试前后保存 `ip -s link`。
- [ ] 保存 `sar -n DEV,EDEV 1`。
- [ ] 保存 iperf3 client/server CPU。

## R1 验收

- [ ] TCP 正反向结果完整。
- [ ] UDP 正反向结果完整。
- [ ] 至少五轮数据可计算统计值。
- [ ] 能回答 UDP 是否在进入 Trojan 前已经异常。

## R1 决策

- [ ] UDP 明显差于 TCP：创建 R1A，调查云网络、UDP policing、MTU；暂缓改 QUIC。
- [ ] UDP 基线正常：进入 R2。
- [ ] 数据波动过大：在不改变量的条件下追加五轮，不进入下一阶段。

## R1 结论

- 状态：未开始。
- Run ID：待填写。
- TCP 单流中位数：待填写。
- TCP 4/8 流中位数：待填写。
- UDP 可用速率：待填写。
- UDP loss/jitter：待填写。
- 下一轮唯一目标：待 R1 数据决定。

---

# R2：Trojan TCP TLS 与 QUIC 基线

## 输入

- 代码：原始 `f8bb047`。
- QUIC：默认参数，`debug_disable_tcp: true`。
- 日志：`log_level: 1`。
- 唯一变量：传输协议 TCP TLS 或 QUIC。

## 任务

### R2.1 启动验证

- [ ] 启动远端 Trojan server。
- [ ] 确认远端 `3443/TCP` 和 `3443/UDP` 同时监听。
- [ ] 启动本地 TCP client，监听 `9081`。
- [ ] 启动本地 QUIC client，监听 `9080`。
- [ ] 确认 QUIC handshake completed。
- [ ] 确认 ALPN 为预期值。
- [ ] 确认 QUIC 测试没有 TCP fallback。
- [ ] 保存 PID、启动时间和日志路径。

### R2.2 正确性短测

TCP TLS 和 QUIC 分别执行：

- [ ] SOCKS5 hostname 解析成功。
- [ ] 1 MiB 下载成功。
- [ ] 返回长度正确。
- [ ] SHA-256 正确。
- [ ] 错误 URL 返回非零退出码。
- [ ] 客户端断开后 stream 正常关闭。

### R2.3 固定 byte source

- [ ] 在远端 localhost 启动固定 byte source。
- [ ] 1 MiB：TCP/QUIC 各五轮。
- [ ] 10 MiB：TCP/QUIC 各五轮。
- [ ] 25 MiB：TCP/QUIC 各五轮。
- [ ] 50 MiB：TCP/QUIC 各五轮。
- [ ] 轮换执行 TCP、QUIC，避免时间偏差。
- [ ] 每轮校验长度和 SHA-256。
- [ ] 汇总 connect、TTFB、total、goodput。

### R2.4 第三方体验对照

- [ ] Cloudflare 直连，50 MB，五轮。
- [ ] Cloudflare TCP TLS 代理，50 MB，五轮。
- [ ] Cloudflare QUIC 代理，50 MB，五轮。
- [ ] 记录远端出口到 CDN 可能不同，不把该结果作为唯一证据。
- [ ] 检查本地 `speedtest --help` 是否支持 proxy。
- [ ] 仅在明确支持时执行 speedtest TCP/QUIC 对照。

### R2.5 同步观测

- [ ] 本地采集 trojan CPU、RSS、线程数。
- [ ] 远端采集 `pidstat -dur`。
- [ ] 远端采集 `sar -n DEV,EDEV`。
- [ ] 测试前后采集 UDP counters。
- [ ] 保存客户端和服务端日志。

## R2 验收

- [ ] TCP TLS 和 QUIC 使用同一 server、目标、密码和时间窗口。
- [ ] 所有正式下载内容正确。
- [ ] 每组至少五个有效样本。
- [ ] QUIC 慢速可重复，或证明确认当前无法复现。

## R2 决策

- [ ] QUIC 单流已明显慢于 TCP：进入 R3。
- [ ] QUIC 与 TCP 接近：检查原用户场景差异，补充目标网站、方向、并发和时间窗口。
- [ ] TCP 与 QUIC 都慢：调查目标源、CPU 或公网路径，不修改 QUIC。
- [ ] QUIC 无法稳定握手：创建连接专项轮次，不把失败样本算吞吐。

## R2 结论

- 状态：未开始。
- Run ID：待填写。
- TCP 25 MiB 中位数：待填写。
- QUIC 25 MiB 中位数：待填写。
- TCP 50 MiB 中位数：待填写。
- QUIC 50 MiB 中位数：待填写。
- QUIC/TCP 比例：待填写。
- 下一轮唯一目标：并发对照，判断单 stream 限制。

---

# R3：单流与多流对照

## 输入

- 代码、配置、网络条件与 R2 相同。
- 唯一变量：并发 stream 数。
- 每组总量：50 MiB，由所有 stream 平分。

## 任务

TCP TLS 与 QUIC 分别执行：

- [ ] 并发 1。
- [ ] 并发 4。
- [ ] 并发 16。
- [ ] 并发 64。
- [ ] 每组预热一次、正式五次。
- [ ] 校验每个响应长度和 SHA-256。
- [ ] 汇总 aggregate throughput。
- [ ] 汇总每流 P50/P95 完成时间。
- [ ] 记录 stream open failures。
- [ ] 记录客户端/服务端 CPU 和 RSS。
- [ ] 记录 UDP errors 和 interface drops。

## R3 验收

- [ ] 单流和多流样本完整。
- [ ] 总数据量和测试时长可比较。
- [ ] 无内容错误或静默 TCP fallback。

## R3 决策

- [ ] QUIC 单流慢、多流 aggregate 明显提升：H2/H3 优先。
- [ ] 所有并发都慢且有 UDP drop：H1/H4/H5 优先。
- [ ] 所有并发都慢且 CPU 单核满：H5/H6 优先。
- [ ] 100 stream 附近出现 open failure：单独验证 `max_concurrent_streams`，不与吞吐修复混合。

## R3 结论

- 状态：未开始。
- Run ID：待填写。
- 1/4/16/64 stream aggregate：待填写。
- P95：待填写。
- 错误数：待填写。
- 下一轮唯一目标：由观测结果选择 H1–H6 中证据最强者。

---

# R4：系统与短时抓包诊断

## 输入

- 使用 R2/R3 中最稳定的复现场景。
- 代码和配置不变。
- 唯一变化：增加短时观测，不作为正式吞吐分数。

## 任务

- [ ] 客户端抓取 `udp port 3443`，限制时长和文件大小。
- [ ] 服务端抓取 `udp port 3443`，限制时长和文件大小。
- [ ] 保存抓包开始/结束 UTC 时间。
- [ ] 统计 UDP packet size 分布。
- [ ] 统计 packet rate 和吞吐空洞。
- [ ] 确认实际 payload 是否接近 1200、1452 或其他值。
- [ ] 检查 IP fragmentation。
- [ ] 检查 `Udp: RcvbufErrors`、`SndbufErrors`、`InErrors` 增量。
- [ ] 检查 softnet drop/time_squeeze 增量。
- [ ] 检查 trojan 是否单核满载。
- [ ] 用短时 `log_level: 0` 搜索 `STREAM_DATA_BLOCKED`。
- [ ] 搜索 50/100/200/400/800/1600/3000 ms retry 痕迹。
- [ ] 完成后恢复 `log_level: 1`。

## R4 验收

- [ ] 两端观测时间与复现窗口对齐。
- [ ] 性能结果和诊断结果分开保存。
- [ ] 至少排除或支持一个主要假设。

## R4 结论

- 状态：未开始。
- Run ID：待填写。
- 实际 UDP payload：待填写。
- Kernel UDP drop：待填写。
- CPU：待填写。
- flow-control blocked：待填写。
- retry 周期：待填写。
- 下一轮唯一变量：待填写。

---

# R5：无代码配置实验

只执行由 R4 证据支持的分支。未选中的任务保持未开始，不并行尝试。

## R5-A：UDP socket buffer

### 输入

- 唯一变量：客户端和服务端 QUIC socket buffer。
- 值：76,800、256 KiB、1 MiB、4 MiB、16 MiB。

### 任务

- [ ] 保存两端原始 sysctl。
- [ ] 必要时临时提高系统上限。
- [ ] 每个值确认内核实际生效大小。
- [ ] 每个值运行同一单流场景五次。
- [ ] 每个值运行同一并发场景五次。
- [ ] 比较 goodput、CPU、RSS、UDP drop。
- [ ] 测试后恢复原始 sysctl。

### 通过条件

- [ ] 吞吐改善可重复。
- [ ] UDP drop 同步下降。
- [ ] 改善不是仅由时间波动造成。

## R5-B：日志开销

### 输入

- 唯一变量：`log_level` 0、1、2。

### 任务

- [ ] 每个级别运行同一测试五次。
- [ ] 比较吞吐、CPU、日志写入量。
- [ ] 正式基线恢复到 1。

## R5-C：路径 MTU 初筛

### 输入

- 不声称现有 `max_datagram_size` 能改变 ngtcp2 payload。
- 唯一目标：确认真实路径是否出现 fragmentation 或大包异常。

### 任务

- [ ] 用抓包记录实际包长。
- [ ] 执行不分片路径探测。
- [ ] 检查 ICMP Packet Too Big 可见性。
- [ ] 若需改变 QUIC payload，推迟到代码实验轮次。

## R5 结论

- 状态：未开始。
- 选择分支：待填写。
- 最佳值：待填写。
- 相对 baseline 提升：待填写。
- 假设状态：支持 / 否定 / 数据不足。
- 下一轮唯一目标：可控高 RTT 复现或最小观测代码。

---

# R6：可控网络复现

## 安全前置

- [ ] 不在 SSH 默认路径上直接施加无过滤 netem。
- [ ] 保存现有 qdisc。
- [ ] 使用独立接口、namespace 或按测试流量精确分类。
- [ ] 准备自动恢复命令。
- [ ] 每个场景后确认 SSH 正常、qdisc 已恢复。

## 场景

每场景运行 TCP TLS 和 QUIC 单流/4 流对照：

- [ ] 20 ms / 0 loss。
- [ ] 100 ms / 0 loss。
- [ ] 200 ms / 0 loss。
- [ ] 300 ms / 0 loss。
- [ ] 200 ms / 0.01% loss。
- [ ] 200 ms / 0.1% loss。
- [ ] 300 ms / 0.1% loss。
- [ ] 200 ms / 0.5% loss。
- [ ] 200 ms / 1% loss。
- [ ] 必要时增加 10/30 ms jitter。
- [ ] 必要时增加 0.1%/1% reorder。

## R6 验收

- [ ] 至少一个场景稳定复现远程现象。
- [ ] 每场景测试后网络规则恢复。
- [ ] 得到 RTT/loss 与 QUIC/TCP 比例曲线。

## R6 结论

- 状态：未开始。
- 最小复现场景：待填写。
- QUIC 性能拐点：待填写。
- TCP 性能拐点：待填写。
- 下一轮唯一目标：增加最小观测，定位协议或应用停顿。

---

# R7：最小观测代码

按顺序添加；前一项足够定位时停止，不一次加入全部指标。

## R7.1 Socket 指标

- [ ] 输出请求和实际 `SO_RCVBUF`/`SO_SNDBUF`。
- [ ] 统计 rx/tx packets 和 bytes。
- [ ] 统计 `would_block`、`ENOBUFS` 和其他 socket errors。
- [ ] 每连接低频聚合输出。
- [ ] 添加一个最小可运行检查。

## R7.2 Receive/Pump 指标

- [ ] 统计每次 receive drain 数量。
- [ ] 统计命中 64 上限次数。
- [ ] 统计 pump duration。
- [ ] 统计 event-loop callback duration。
- [ ] 添加一个最小可运行检查。

## R7.3 Stream/Retry 指标

- [ ] 统计 queued、accepted、ACKed bytes。
- [ ] 统计 partial write 和 zero-progress。
- [ ] 统计 retry delay histogram。
- [ ] 统计 3000 ms abort。
- [ ] 统计 flow-control blocked duration。
- [ ] 添加一个最小可运行检查。

## R7.4 ngtcp2 指标

- [ ] 调查当前 ngtcp2 API 可取得的 RTT、cwnd、bytes-in-flight、loss、PTO。
- [ ] 优先低频结构化统计；必要时再启用 qlog。
- [ ] qlog 文件不进入 Git。
- [ ] 添加一个最小可运行检查。

## R7 门禁

- [ ] Release 编译通过。
- [ ] 本地 `fulltest_quic.py` 通过。
- [ ] 指标关闭或低频时无明显吞吐回归。
- [ ] 指标数据足以选择一个修复方向。

## R7 结论

- 状态：未开始。
- 新增指标：待填写。
- 主要瓶颈证据：待填写。
- 下一轮唯一修复：待填写。

---

# R8+：单变量修复迭代

每个候选修复复制下面模板，编号依次为 R8、R9、R10。禁止把多个候选修复放进同一轮。

## 候选顺序

仅按证据选择，不按静态猜测排序：

- [ ] Socket buffer 设置、错误检查和实际值验证。
- [ ] non-blocking UDP send 的 `would_block` 队列/重试。
- [ ] stream/connection flow-control window。
- [ ] 应用 retry 与 credit/congestion 事件联动。
- [ ] receive batch 和 pump 公平性。
- [ ] `max_datagram_size` 映射到 ngtcp2 payload。
- [ ] `max_concurrent_streams` 映射到 transport parameters。
- [ ] CUBIC、Reno、BBR v2 对照。

## 修复轮次模板

### 轮次信息

- 轮次：`R__`
- Run ID：待填写。
- 基线 commit：待填写。
- 实验 commit/工作树 hash：待填写。
- 假设：待填写。
- 唯一代码变量：待填写。
- 预期指标变化：待填写。
- 回滚方式：待填写。

### 修改前门禁

- [ ] 基线结果可重现。
- [ ] 复现场景固定。
- [ ] 配置 hash 固定。
- [ ] 除目标变量外无其他工作树改动。

### 修改

- [ ] 实现最小 diff。
- [ ] 不新增无关配置或抽象。
- [ ] 不改变默认行为，除非证据要求且计划明确。
- [ ] 增加一个针对该逻辑的最小可运行检查。
- [ ] 保存 diff。

### 本地验证

- [ ] Release 编译通过。
- [ ] `python3 -u tests/LinuxFullTest/fulltest_quic.py build/trojan` 通过。
- [ ] T16 内存测试通过。
- [ ] 相关单项测试重复至少三次。

### 远程验证

- [ ] 1 MiB 正确性。
- [ ] 25 MiB 单流五轮。
- [ ] 50 MiB steady-state 五轮。
- [ ] 4/16/64 并发，每组总量 50 MiB。
- [ ] 双向传输。
- [ ] 30–60 分钟长稳，循环独立的 25/50 MiB 样本。
- [ ] 停流后观察 RSS 5–10 分钟。
- [ ] 空闲、keepalive、重连。
- [ ] 保存 CPU、RSS、UDP drop、P95 latency。

### 结果判断

- [ ] 吞吐提升达到预期且五轮稳定。
- [ ] 指标变化符合假设。
- [ ] 内容完整性无错误。
- [ ] CPU 无不可接受回归。
- [ ] RSS 无持续线性增长。
- [ ] P95 latency 无不可接受回归。
- [ ] 无 stream open/close/fallback 回归。

### 轮次结论

- 状态：未开始。
- 结果：接受 / 否定 / 数据不足。
- Baseline 中位数：待填写。
- 实验中位数：待填写。
- 相对变化：待填写。
- CPU 变化：待填写。
- RSS 变化：待填写。
- UDP drop 变化：待填写。
- P95 变化：待填写。
- 是否保留修改：待填写。
- 下一轮唯一变量：待填写。

---

# 回归与内存专项

## 功能回归

- [ ] QUIC handshake。
- [ ] SOCKS5 HTTP GET。
- [ ] POST。
- [ ] HTTP/3 fallback。
- [ ] idle timeout。
- [ ] ALPN。
- [ ] TCP fallback。
- [ ] client retry。
- [ ] 大文件和 flow control。
- [ ] DNS failure。
- [ ] 双客户端。
- [ ] 非法输入。
- [ ] server restart/stateless reset。
- [ ] TCP/UDP 双向 close。
- [ ] PING keepalive。

## 内存专项

- [ ] 本地 T16 通过。
- [ ] 远端循环 25/50 MiB 独立样本至少 60 分钟。
- [ ] 每分钟记录 RSS/PSS。
- [ ] 记录 active connection/stream 数。
- [ ] 停流后观察 5–10 分钟。
- [ ] 比较 baseline 与实验版增长斜率。
- [ ] 若持续线性增长，使用 ASan/LSan 或 heap profiler。
- [ ] 不通过提高阈值隐藏增长。

## 性能回归

- [ ] localhost 无明显性能下降。
- [ ] 低 RTT 无明显性能下降。
- [ ] 高 RTT 吞吐提升可重复。
- [ ] 轻微 loss 场景无明显恶化。
- [ ] 单流和 aggregate 均记录。
- [ ] CPU、syscall 和 packet rate 可解释。

---

# 最终验收

- [ ] 根因由至少两类独立证据支持。
- [ ] 修复机制与观测现象一致。
- [ ] 原始网络、TCP TLS、QUIC 三组结果齐全。
- [ ] 修复前后使用同一测试环境和配置。
- [ ] 所有正式样本至少五轮。
- [ ] 1/10/25/50 MiB 内容校验通过，长稳每个样本独立校验。
- [ ] 1/4/16/64 并发通过。
- [ ] 长稳和内存门禁通过。
- [ ] 本地完整 QUIC 测试通过。
- [ ] 无敏感凭据进入 Git。
- [ ] 远端测试服务停止。
- [ ] 临时端口关闭。
- [ ] 临时证书、私钥和 keylog 删除。
- [ ] sysctl、qdisc 和系统配置恢复。
- [ ] 结果目录包含复现命令、配置 hash 和 commit。
- [ ] PLAN.md 与 TODO.md 根据最终事实更新。

---

# 轮次索引

| 轮次 | Run ID | 唯一变量 | 状态 | 结论 | 结果目录 |
|---|---|---|---|---|---|
| R0 | 待填写 | 环境准备 | 未开始 | 待填写 | 待填写 |
| R1 | 待填写 | 原始网络基线 | 未开始 | 待填写 | 待填写 |
| R2 | 待填写 | TCP TLS / QUIC | 未开始 | 待填写 | 待填写 |
| R3 | 待填写 | stream 并发数 | 未开始 | 待填写 | 待填写 |
| R4 | 待填写 | 增加观测 | 未开始 | 待填写 | 待填写 |
| R5 | 待填写 | 配置单变量 | 未开始 | 待填写 | 待填写 |
| R6 | 待填写 | RTT/loss | 未开始 | 待填写 | 待填写 |
| R7 | 待填写 | 最小观测代码 | 未开始 | 待填写 | 待填写 |
| R8+ | 待填写 | 单变量修复 | 未开始 | 待填写 | 待填写 |

# 问题与阻塞记录

| 时间 UTC | 轮次 | 问题 | 影响 | 处理 | 状态 |
|---|---|---|---|---|---|
| 待填写 | R0 | 云防火墙状态未知 | 无法确认测试端口 | 检查控制台并实测 | 阻塞 |

# 假设状态

| 假设 | 当前状态 | 支持证据 | 反对证据 | 下一验证 |
|---|---|---|---|---|
| H1 UDP socket buffer 太小 | 当前不支持 | 默认仅 76,800 bytes | 远端 `UdpRcvbufErrors/SndbufErrors=0` | 后续高并发再验证 |
| H2 单 stream flow control | 次要 | 初始 512 KiB/1 MiB | 15 MiB 修复后 15.14 秒完成 | 后续多流验证 |
| H3 应用 retry 退避 | 支持 | 详细日志 `pdatalen<=0` 319 次；10 ms retry 改善 | 单独修复不足以解决全部问题 | 已修复 |
| H4 UDP send 丢弃 | 当前不支持 | non-blocking `send_to` 无队列 | 详细日志未见 send failure | 后续高并发再验证 |
| H5 event-loop/batch 阻塞 | 数据不足 | 单 io_context、batch 64 | 全量测试与 T16 通过 | 后续压测 |
| H6 CUBIC/MTU | 主因确认 | 反向 UDP loss 5–6%；CUBIC 5 MiB 35.86–46.76 秒 | BBR v2 5 MiB 三轮 8.59/5.45/4.76 秒 | 已切换 BBR v2 |
| H7 配置项未生效 | 静态确认 | 参数解析后未映射 | 未证明影响当前吞吐 | 独立后续修复 |
