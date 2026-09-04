# Trojan Plus QUIC 远程性能调查 TODO

关联计划：[PLAN.md](PLAN.md)

## 使用规则

- 状态只用：`[ ]` 未开始、`[~]` 进行中、`[x]` 完成、`[-]` 跳过、`[!]` 阻塞。
- 原始结果只新增，不覆盖；结果统一放入 `results/<run_id>/`。
- 正式统计必须有五个有效样本；少于五轮只标部分完成。
- 失败、预热失败、命令、退出码、配置和资源原始观测均保留。
- 密码、私钥、TLS keylog 不提交仓库；测试结束恢复网络规则并关闭临时服务。

## 当前状态

- 当前阶段：补全研究性矩阵和最终可复现证据。
- 核心 QUIC 修复 commit：`e3c29a5`。
- 当前工作树：增加 wolfSSL stateful session cache 禁用修复及远程测试工具，尚未提交。
- 当前结论：R2 Cloudflare、R3 五轮并发、R6 指定 netem 场景、R13 30+10 分钟长稳均通过；R8 发现的 TCP 第 257 次连接失败已消除。
- 最终长稳：`20260904T042723Z-e3c29a5-r13`，1459/1459 成功，观测失败 0。
- 本地验证：Release build、normal fulltest、QUIC fulltest 在本会话执行通过；日志尚未持久化到 `results/`。
- 下一步：提交 session cache 修复，补 R1 五轮、R4 抓包、R5 配置矩阵和测试日志证据。
- 阻塞项：无。

## 总门禁

- [~] 原始 TCP/UDP 网络基线：R1 仅一轮，反向 UDP loss 为 3.77–6.22%，不足五轮统计。
- [x] Cloudflare direct/TCP TLS/QUIC 正式基线：各五轮有效，内容正确。
- [x] 1/4/16/64 并发对照：每组 warmup 1 + 正式 5，每组 5 MB，全部零失败。
- [x] 200 ms 0/0.1/1% 与 300 ms 0.1% netem 短测：TCP/QUIC 全部有效。
- [x] netem 安全清理：无遗留 filter、ifb、listener。
- [x] 核心 QUIC 修复已提交为 `e3c29a5`。
- [x] 本地 Release build、normal fulltest、QUIC fulltest 会话执行通过。
- [x] 资源数据：R3 原始观测与 R13 30+10 分钟 RSS/PSS 已保存。
- [x] 远程长稳门禁：R13 共 1459 样本，失败 0，观测失败 0。
- [ ] socket buffer 矩阵。
- [ ] log level 矩阵。
- [ ] MTU payload 代码变更实验。
- [ ] 更多 netem jitter/reorder 场景。
- [x] 修复后完整 30 分钟 active + 10 分钟 cooldown soak。
- [~] 最终结论由持久化命令、配置、commit 和结果复现；本地 fulltest 日志待持久化。

---

# R0：环境与工具准备

- [x] `PLAN.md`、`TODO.md`、`scripts/`、`results/` 和分层结果目录已建立。
- [x] 远端 `perf`、`sysstat`、`pidstat`、`sar`、`nstat`、`tcpdump`、`tc`、`ss`、`iperf3` 可用。
- [x] 两端 Release 构建及 QUIC Support 已确认。
- [x] 一次性密码、测试证书、TCP/QUIC 配置与忽略规则已准备。
- [x] 远端部署、监听和安全清理流程已由后续轮次实际使用。
- 状态：完成后续测试所需准备；早期清单没有独立完整 R0 证据包，不补标为完整审计验收。
- 阻塞：无当前阻塞。

---

# R1：原始网络基线

- [~] Run `20260903T143121Z-85d12be-r1`、`20260903T144643Z-85d12be-r1` 仅形成一轮基线数据。
- [~] TCP/UDP 基线部分完成；样本不足五轮，不能计算正式 P10/中位数/P90。
- [x] 已确认反向 UDP 基线存在 3.77–6.22% loss。
- [ ] 五轮完整 TCP 正反向、1/4/8 流统计。
- [ ] 五轮完整 UDP 正反向速率、loss、jitter 统计。

## R1 结论

- 状态：部分完成。
- Run ID：`20260903T143121Z-85d12be-r1`、`20260903T144643Z-85d12be-r1`。
- 结论：反向 UDP 在进入 Trojan 前已有 3.77–6.22% loss；仅一轮，不能作为稳定分布或正式基线完成证据。

---

# R2：Trojan TCP TLS 与 QUIC 基线

- [x] Cloudflare direct、TCP TLS、QUIC 各五轮正式样本全部有效。
- [x] 正式样本内容和有效性检查通过。
- [x] warmup 零字节失败保留，未混入正式统计。
- [ ] 固定 byte source 的 1/10/25/50 MiB 完整矩阵未完成，不以 Cloudflare 结果替代。
- [ ] speedtest 对照未执行。

## R2 结论

- 状态：Cloudflare 基线完成；R2 全清单部分完成。
- Run ID：`20260904T014605Z-e3c29a5-r2`。
- 中位吞吐：direct `13.11 Mbps`、TCP TLS `5.62 Mbps`、QUIC `6.91 Mbps`。
- 失败说明：warmup 出现零字节失败，证据保留；正式 direct/TCP/QUIC 各五轮均有效。

---

# R3：单流与多流对照

- [x] 并发 1/4/16/64。
- [x] 每组 warmup 1 + 正式 5；每组总量 5 MB。
- [x] TCP TLS 与 QUIC 全部正式样本零失败。
- [x] 资源原始观测已保存。
- [ ] 原计划每组总量 50 MiB 未执行；本轮实际为 5 MB，不能标为原规格完成。
- [ ] 每流 P50/P95 未给出，不补标。

## R3 结论

- 状态：并发短测完成；原 50 MiB 规格未完成。
- Run ID：`20260904T012853Z-e3c29a5-r3`。
- TCP 1/4/16/64 中位吞吐：`5.16/11.36/13.54/15.68 Mbps`。
- QUIC 1/4/16/64 中位吞吐：`5.04/18.57/25.70/25.86 Mbps`。
- 结论：单流接近；QUIC 多流 aggregate 提升明显，16 流后接近平台。

---

# R4：系统与短时抓包诊断

- [ ] 双端限时抓包、UDP packet size、fragmentation、flow-control blocked 和 retry 周期完整清单未执行或无足够持久化证据。
- [x] 后续轮次已保存部分 CPU、RSS、UDP/drop 观测。

## R4 结论

- 状态：部分观测随 R3/R8 保存；独立 R4 未完成。
- 不能补填实际 payload、kernel UDP drop、CPU 饱和或 retry 周期结论。

---

# R5：无代码配置实验

## R5-A：UDP socket buffer

- [ ] 76,800、256 KiB、1 MiB、4 MiB、16 MiB 矩阵未执行。

## R5-B：日志开销

- [ ] `log_level` 0/1/2 矩阵未执行。

## R5-C：路径 MTU 初筛

- [ ] 抓包、不分片路径探测、ICMP Packet Too Big 检查未形成完整证据。
- [ ] 改变 ngtcp2 payload 的 MTU 代码实验未执行。

## R5 结论

- 状态：未完成；研究性项目保留，不因后续结果跳过。

---

# R6：可控网络复现

## 已执行场景

| Run ID | 协议 | netem | 有效 | 时间 |
|---|---|---:|---|---:|
| `20260904T034351Z-e3c29a5-r6` | TCP | 200 ms / 0% | 是 | 5.083 s |
| `20260904T034507Z-e3c29a5-r6` | QUIC | 200 ms / 0% | 是 | 3.190 s |
| `20260904T034621Z-e3c29a5-r6` | TCP | 200 ms / 0.1% | 是 | 6.811 s |
| `20260904T034223Z-e3c29a5-r6` | QUIC | 200 ms / 0.1% | 是 | 2.997 s |
| `20260904T034737Z-e3c29a5-r6` | TCP | 300 ms / 0.1% | 是 | 6.791 s |
| `20260904T034854Z-e3c29a5-r6` | QUIC | 300 ms / 0.1% | 是 | 2.775 s |
| `20260904T035007Z-e3c29a5-r6` | TCP | 200 ms / 1% | 是 | 5.974 s |
| `20260904T035124Z-e3c29a5-r6` | QUIC | 200 ms / 1% | 是 | 3.734 s |

- [x] 上表 TCP/QUIC 样本长度和 SHA-256 均有效。
- [x] 每场景 `cleanup_valid: true`。
- [x] 最终安全检查无 filter、ifb、listener 遗留。
- [ ] 20/100 ms、200 ms 0.01/0.5%、jitter、reorder 未执行。
- [ ] 每场景五轮及 RTT/loss 曲线未完成；上表均为单样本短测。

## R6 结论

- 状态：指定四个网络条件短测完成；完整矩阵和五轮统计未完成。
- 结论：在已测 1 MiB 单样本中 TCP/QUIC 均有效，QUIC 用时均短于 TCP；不能由单样本推导稳定性能曲线。

---

# R7：最小观测代码

- [ ] Socket、receive/pump、stream/retry、ngtcp2 指标清单未按独立 R7 完整实现和验证。
- [x] 核心 QUIC 修复已形成 commit `e3c29a5`，但不倒推标记未留证的 R7 指标。

## R7 结论

- 状态：未完成独立观测门禁。
- 现有性能与正确性结果支持继续修复验证，但不能虚标全部指标已具备。

---

# R8+：修复、长稳与 session reuse

## R8 长稳

- Run ID：`20260904T014858Z-e3c29a5-r8`。
- 条件：30 分钟 active + 10 分钟 cooldown，共 948 样本。
- QUIC：`474/474` 成功。
- TCP：前 256 成功，后 218 失败。
- 发现：wolfSSL session reuse 边界 bug。
- RSS slope：client TCP `30949 B/min`，client QUIC `33831 B/min`，server RSS `56713 B/min`，server PSS `56720 B/min`。
- 状态：失败并转入修复；不能宣布长稳通过或无 leak。
- 结论：QUIC 本轮无观测请求失败，但正 RSS slope 与 TCP 功能失败同时存在；必须修复后长稳重跑。

## R12 验证

- [x] `20260904T035330Z-e3c29a5-r12`：no reuse，`321/321` 成功。
- [x] `20260904T041128Z-e3c29a5-r12`：新 `config.cpp` 禁用 wolfSSL stateful session cache 实验，`308/308` 成功。
- [~] `config.cpp` 修复已验证，尚未提交。
- [x] 修复后 30 分钟 active + 10 分钟 cooldown 完整 soak：`20260904T042723Z-e3c29a5-r13`。
- [x] 1459/1459 样本成功，观测失败 0。
- [x] RSS slope：client TCP `9109 B/min`、client QUIC `11541 B/min`、server RSS `19027 B/min`、server PSS `19040 B/min`。

## R8+ 结论

- 状态：功能与长稳验证完成，等待提交。
- 结论：wolfSSL stateful session cache 禁用后，已跨越 256 连接边界并通过 30+10 分钟长稳；未观察到线性失控增长，但不将 RSS slope 单独等同于严格 leak proof。

---

# 最终验收

- [x] 核心 QUIC 修复 commit 为 `e3c29a5`。
- [x] R2 正式样本、R3 并发样本、R6 指定场景和 R8 soak 原始结果已保存。
- [x] 本地 Release build、normal fulltest、QUIC fulltest 本会话通过。
- [ ] 本地测试日志持久化到 `results/`。
- [ ] R1 至少五轮完整原始网络基线。
- [ ] 修复提交后远端工作树与 commit 一致。
- [x] 修复后完整 30 分钟 soak 与 cooldown 通过。
- [x] R13 未观察到 RSS/PSS 失控增长；不替代 ASan/LSan 严格 leak proof。
- [ ] socket buffer、log level、MTU payload 研究矩阵。
- [ ] 更多 netem jitter/reorder。
- [ ] 结果目录包含最终复现命令、配置 hash、commit 和清理记录。

---

# 轮次索引

| 轮次 | Run ID | 状态 | 结论 | 结果目录 |
|---|---|---|---|---|
| R0 | 多轮 metadata | 部分审计完成 | 环境可用；无独立完整 R0 证据包 | `results/*/metadata/` |
| R1 | `20260903T143121Z-85d12be-r1`、`20260903T144643Z-85d12be-r1` | 部分完成 | 仅一轮；反向 UDP loss 3.77–6.22% | 对应 `results/<run_id>/baseline/` |
| R2 | `20260904T014605Z-e3c29a5-r2` | Cloudflare 基线完成 | 正式各五轮有效；median 13.11/5.62/6.91 Mbps | `results/20260904T014605Z-e3c29a5-r2/cloudflare/` |
| R3 | `20260904T012853Z-e3c29a5-r3` | 短测完成 | 1/4/16/64 全部零失败；每组 5 MB | `results/20260904T012853Z-e3c29a5-r3/concurrency/` |
| R4 | 无独立 run | 部分完成 | 部分资源观测随其他轮次保存 | 见 R3/R8 |
| R5 | 无 | 未完成 | 可选配置与 MTU 研究保留 | 无 |
| R6 | `20260904T034223Z`…`20260904T035124Z` | 指定场景完成 | 四条件 TCP/QUIC 全有效；单样本 | 对应 `results/<run_id>/netem/` |
| R7 | 无独立 run | 未完成 | 不倒推标记观测项 | 无 |
| R8 | `20260904T014858Z-e3c29a5-r8` | 失败 | QUIC 474/474；TCP 256 成功后 218 失败 | `results/20260904T014858Z-e3c29a5-r8/soak/` |
| R12a | `20260904T035330Z-e3c29a5-r12` | 实验通过 | no reuse 321/321 | `results/20260904T035330Z-e3c29a5-r12/soak/` |
| R12b | `20260904T041128Z-e3c29a5-r12` | 实验通过、未提交 | 禁用 stateful session cache 308/308 | `results/20260904T041128Z-e3c29a5-r12/soak/` |
| R13 | `20260904T042723Z-e3c29a5-r13` | 长稳通过 | 30+10 分钟，1459/1459 成功，观测失败 0 | `results/20260904T042723Z-e3c29a5-r13/soak/` |

# 问题与阻塞记录

| 时间 UTC | 轮次 | 问题 | 影响 | 处理 | 状态 |
|---|---|---|---|---|---|
| 2026-09-03 | R1 | 基线仅一轮 | 不能形成正式统计 | 后续补足五轮 | 未完成 |
| 2026-09-04 | R2 | warmup 零字节 | 不影响正式五轮统计，但必须保留 | 已保存失败证据 | 已记录 |
| 2026-09-04 | R8 | TCP 256 次成功后 218 次失败 | 长稳门禁失败 | 定位 wolfSSL session reuse 边界 bug | 修复中 |
| 2026-09-04 | R12 | `config.cpp` session cache 实验未提交 | 远端不是干净 `e3c29a5` | 定稿、提交后重部署 | 阻塞 |
| 2026-09-04 | 本地验证 | 日志未持久化到 `results/` | 不能作为最终可复现证据 | 后续持久化重跑 | 未完成 |

# 假设状态

| 假设 | 当前状态 | 支持证据 | 反对/限制 | 下一验证 |
|---|---|---|---|---|
| H1 UDP socket buffer 太小 | 数据不足 | 原计划值较小 | 未执行 buffer 矩阵；现有短测均有效 | 保留 socket buffer 矩阵 |
| H2 单 stream flow control 是主因 | 不支持为唯一主因 | R3 单流较多流慢 | TCP 同样受并发影响；R3 每组仅 5 MB | 必要时用 50 MiB 重跑 |
| H3 应用 retry/发送调度放大停顿 | 已纳入核心修复 | `e3c29a5` 后 R2/R3/R6 QUIC 有效 | 缺少独立 R7 全指标证据 | 保留修复，不扩大结论 |
| H4 UDP send 丢弃 | 当前不支持 | 反向 UDP 基线 loss 3.77–6.22% | R6 已测样本均正确，无发送失败证据 | 高并发时再采集 socket errors |
| H5 event-loop/batch 阻塞 | 数据不足 | 多流 aggregate 明显提高 | 无独立 R7 指标 | 仅在复现时增加最小观测 |
| H6 高 RTT/loss 下拥塞控制敏感 | 支持但未完成曲线 | R1 反向 UDP loss；R6 四条件均有有效短测 | R6 每条件仅单样本，不能给稳定拐点 | 补五轮及必要 jitter/reorder |
| H7 MTU/payload 映射问题 | 数据不足 | 计划中配置映射疑点 | 无完整抓包/fragmentation 证据 | 保留 MTU payload 研究 |
| H8 wolfSSL session reuse 边界 bug | 强支持 | R8 TCP 256 成功后连续失败；no reuse 321/321；禁用 stateful cache 308/308 | 两个修复实验仍为短时，代码未提交 | 提交修复后完整 soak |
| H9 已无内存泄漏 | 不成立/不可宣布 | R8 QUIC 474/474 无请求失败 | client/server RSS/PSS slope 为正；TCP 功能失败干扰 | 修复后长稳与 cooldown 重测 |
