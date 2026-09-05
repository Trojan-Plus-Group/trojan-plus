# Trojan Plus QUIC 远程性能调查 TODO

关联计划：[PLAN.md](PLAN.md)

## 使用规则

- 状态只用：`[ ]` 未开始、`[~]` 进行中、`[x]` 完成、`[-]` 跳过、`[!]` 阻塞。
- 原始结果只新增，不覆盖；结果统一放入 `results/<run_id>/`。
- 正式统计必须有五个有效样本；少于五轮只标部分完成。
- 失败、预热失败、命令、退出码、配置和资源原始观测均保留。
- 密码、私钥、TLS keylog 不提交仓库；测试结束恢复网络规则并关闭临时服务。
- **远端小主机规格红线（1 CPU, 1G RAM）**：
  - 远端服务器仅 1 vCPU 与 954 MB 内存（配置 2.5 GB swap），运行高负载编译或超额任务易触发 Linux OOM Killer 杀掉关键进程（历史记录：`Out of memory: Killed process 83234 (systemd) total-vm:20336kB, anon-rss:1664kB ...`，导致系统直接卡死）。
  - **严禁并行编译**：远端构建必须严格使用单任务 `cmake --build build -j 1`，严禁使用 `--parallel`。
- **远端代码同步规范（禁止 push，使用 git bundle）**：
  - **严禁私自向 GitHub / origin 远端执行 `git push`**。
  - 同步代码至远端测试机（`172.236.226.35`）统一采用 `git bundle`：
    ```bash
    git bundle create /tmp/fix-quic.bundle fix_quic
    scp -P 9922 /tmp/fix-quic.bundle root@172.236.226.35:/tmp/
    ssh -p 9922 root@172.236.226.35 \
      'git -C /root/trojan-plus fetch /tmp/fix-quic.bundle fix_quic &&
       git -C /root/trojan-plus merge --ff-only FETCH_HEAD &&
       rm -f /tmp/fix-quic.bundle'
    ```
- **测试前 iperf3 基线预采与偏差判定**：
  - 在执行多轮代理性能或压测前，必须先使用 `iperf3` 记录当前网络时间窗口的原生物理基准（单流/多流下载与上传）。
  - 若代理流量（TCP TLS 或 QUIC）与 iperf3 基准发生显著异常偏差（如非正常断流或 QUIC 吞吐严重劣于 TCP），需深入查证、抓包排查并修复。
- **压测与通道承压要求**：
  - 样本大小至少 **5 MB**（5,242,880 bytes）。
  - 并发/多次请求（目标可至 200 次）以承压测试单条 QUIC 链路通道，暴露流控和通道边界 bug。
  - 单次测试严格限制在 **5 分钟**以内；若超时则适当降频调减次数，避免打死小主机。
- **macOS 本地测试规则（跳过 DNS 测试）**：
  - macOS 本地环境运行集成测试时，跳过 DNS 转发测试（`-d`），因本地网络对多域名批量查询或未提权端口易发生超时卡死。
  - 本地测试聚焦于 QUIC 全量用例（`fulltest_main.py -q all`）、Normal Client/Forward 管道与非管道代理模式（`-n`）以及 Fallback 模式（`-f`）。脚本已内置 macOS 平台自动跳过保护。

## 当前状态

- 当前阶段：扩展多运行模式矩阵（NAT vs CLIENT_TUN 对比与 QUIC 承压测试）。
- 当前代码：`6e9394d`（修复 CLIENT_TUN 模式 QUIC client 未启动以及 docker-entry tun0 link-up 顺序）；远端已通过 git bundle 同步完成单任务编译。
- **最新烟测与基线进展**：
  - `client_tun` 强制 QUIC 烟测：`20260905T110500Z-6e9394d-r17` 验证通过（1 MiB，HTTP 200，退出码 0，有效性确认）。
  - `nat` TCP 5MB 五轮基准：`20260905T110700Z-6e9394d-r18` 验证通过（5/5 成功，中位吞吐 9.52 Mbps，范围 8.61 ~ 11.35 Mbps）。
  - `nat` 强制 QUIC 5MB 五轮：`20260905T110840Z-6e9394d-r19` 成功捕获 **Bug 3（首流 120 秒静默卡死）**：
    - `req_id: 1` 接收 3941 字节后彻底断流，持续 120 秒直到 curl 超时；
    - `req_id: 2~5` 在首流超时断开后均秒级成功（中位 7.76 Mbps，最高 9.57 Mbps）。
- **阻塞/待修复项**：Bug 3（QUIC 流控信用/数据读调度首次握手后挂死）。

## 总门禁

- [x] 原始 TCP/UDP 网络基线：R1 正式组达到五个有效样本；原 summary 未纳入额外反向 p1 成功样本。
- [x] Cloudflare direct/TCP TLS/QUIC 正式基线：各五轮有效，内容正确。
- [x] 1/4/16/64 并发对照：每组 warmup 1 + 正式 5，每组 5 MB，全部零失败。
- [x] 200 ms 0/0.1/1% 与 300 ms 0.1% netem 短测：TCP/QUIC 全部有效。
- [x] netem 安全清理：无遗留 filter、ifb、listener。
- [x] TLS/session cache 修复已提交为 `379dac2`，远端同 commit 且 clean。
- [x] 本地 `final-local-tests` normal/QUIC 日志退出 0。
- [x] 资源数据：R3 原始观测与 R13 30+10 分钟 RSS/PSS 已保存。
- [x] 远程长稳门禁：R13 共 1459 样本，失败 0，观测失败 0；30+10 分钟无失控增长。
- [-] socket buffer、log level、MTU payload 变更矩阵：kernel drop 为 0，根因已由 BBR/retry/read 定位；仅出现 `RcvbufErrors`、send failure 或 MTU fragmentation 时执行。
- [-] 更多 netem jitter/reorder：已测条件覆盖验收。
- [x] 修复后完整 30 分钟 active + 10 分钟 cooldown soak。
- [x] 最终结论由持久化命令、配置、commit 和结果复现。

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

- [x] Final run `20260904T051142Z-379dac2-r1` 原 summary 记录 59 个有效样本、2 个失败样本。
- [x] 额外反向 p1 成功样本已保存，正式组达到五个有效样本。
- [x] TCP 正反向 1/4/8 流正式组达到五个有效样本。
- [x] UDP 正反向速率、loss、jitter 正式组达到五个有效样本。
- [x] 已确认反向 UDP 基线存在 loss。

## R1 结论

- 状态：完成。
- Run ID：`20260904T051142Z-379dac2-r1`；早期参考 run：`20260903T143121Z-85d12be-r1`、`20260903T144643Z-85d12be-r1`。
- 结论：正式组达到五个有效样本；原 `summary.json` 仍为 59 有效、2 失败，未重算纳入额外反向 p1 成功样本。

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

- [-] 双端全抓包跳过：已有详细日志 `pdatalen <= 0` 共 319 次及 netem 证据，足以支持当前根因与验收；仅问题回归时重新抓包。
- [x] 后续轮次已保存 CPU、RSS、UDP/drop 观测，kernel drop 为 0。

## R4 结论

- 状态：现有证据满足验收；全抓包按条件跳过。
- 结论：详细日志与 netem 已覆盖当前诊断需求；若问题回归，再执行双端限时全抓包。

---

# R5：无代码配置实验

## R5-A：UDP socket buffer

- [-] 76,800、256 KiB、1 MiB、4 MiB、16 MiB 矩阵跳过；仅出现 `RcvbufErrors` 时执行。

## R5-B：日志开销

- [-] `log_level` 0/1/2 矩阵跳过；仅出现 send failure 或日志开销疑似回归时执行。

## R5-C：路径 MTU 初筛

- [-] 抓包、不分片路径探测、ICMP Packet Too Big 与 ngtcp2 payload 变更实验跳过；仅出现 MTU fragmentation 时执行。

## R5 结论

- 状态：按条件跳过。
- 结论：kernel drop 为 0，根因已由 BBR/retry/read 定位；socket/log/MTU 参数变更矩阵不再作为当前验收项。

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
- [-] 更多 jitter/reorder 场景跳过：已测条件覆盖验收。
- [ ] 每场景五轮及 RTT/loss 曲线未完成；上表均为单样本短测。

## R6 结论

- 状态：指定四个网络条件短测完成；完整矩阵和五轮统计未完成。
- 结论：在已测 1 MiB 单样本中 TCP/QUIC 均有效，QUIC 用时均短于 TCP；不能由单样本推导稳定性能曲线。

---

# R7：最小观测代码

- [-] 额外 Socket、receive/pump、stream/retry、ngtcp2 观测代码跳过：现有证据足够，避免性能扰动。
- [x] QUIC 修复及 TLS/session cache 修复已形成 commit `379dac2`。

## R7 结论

- 状态：额外观测按条件跳过。
- 结论：现有详细日志、netem、正确性与长稳结果足够；仅问题回归且现有证据无法定位时增加最小观测。

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
- [x] `config.cpp` TLS/session cache 修复已验证并提交为 `379dac2`；远端同 commit 且 clean。
- [x] 修复后 30 分钟 active + 10 分钟 cooldown 完整 soak：`20260904T042723Z-e3c29a5-r13`。
- [x] 1459/1459 样本成功，观测失败 0。
- [x] RSS slope：client TCP `9109 B/min`、client QUIC `11541 B/min`、server RSS `19027 B/min`、server PSS `19040 B/min`。

## R8+ 结论

- 状态：功能、提交与长稳验证完成。
- 结论：wolfSSL stateful session cache 禁用后，已跨越 256 连接边界并通过 30+10 分钟长稳；该时段无失控增长，不宣称严格无内存泄漏。

---

# 最终验收

- [x] TLS/session cache 修复 commit 为 `379dac2`。
- [x] R1、R2、R3、R6 和 R13 原始结果已保存。
- [x] 本地 `final-local-tests` normal/QUIC 日志退出 0。
- [x] R1 正式组达到五个有效样本；原 summary 未重算额外反向 p1 成功样本。
- [x] 远端工作树与 `379dac2` 一致且 clean。
- [x] 修复后完整 30 分钟 soak 与 10 分钟 cooldown 通过，1459/1459 成功。
- [x] R13 30+10 分钟无失控增长；RSS slopes 为 TCP `9109`、QUIC `11541`、server RSS `19027`、server PSS `19040 B/min`。
- [-] socket buffer、log level、MTU payload 研究矩阵：仅出现 `RcvbufErrors`、send failure 或 MTU fragmentation 时执行。
- [-] 更多 netem jitter/reorder：已测条件覆盖验收。
- [x] 结果目录包含最终复现命令、配置 hash、commit 和清理记录。

---

# 轮次索引

| 轮次 | Run ID | 状态 | 结论 | 结果目录 |
|---|---|---|---|---|
| R0 | 多轮 metadata | 部分审计完成 | 环境可用；无独立完整 R0 证据包 | `results/*/metadata/` |
| R1 | `20260904T051142Z-379dac2-r1` | 完成 | 原 summary 59 有效、2 失败；额外反向 p1 成功样本已保存，正式组达到五个有效样本 | `results/20260904T051142Z-379dac2-r1/baseline/` |
| R2 | `20260904T014605Z-e3c29a5-r2` | Cloudflare 基线完成 | 正式各五轮有效；median 13.11/5.62/6.91 Mbps | `results/20260904T014605Z-e3c29a5-r2/cloudflare/` |
| R3 | `20260904T012853Z-e3c29a5-r3` | 短测完成 | 1/4/16/64 全部零失败；每组 5 MB | `results/20260904T012853Z-e3c29a5-r3/concurrency/` |
| R4 | 无独立 run | 按条件跳过 | `pdatalen <= 0` 319 次及 netem 证据足够；回归时再抓包 | 见详细日志及 R6 |
| R5 | 无 | 按条件跳过 | kernel drop 为 0；出现 `RcvbufErrors`、send failure 或 MTU fragmentation 时执行 | 见 R6/R13 |
| R6 | `20260904T034223Z`…`20260904T035124Z` | 指定场景完成 | 四条件 TCP/QUIC 全有效；单样本 | 对应 `results/<run_id>/netem/` |
| R7 | 无独立 run | 按条件跳过 | 现有证据足够，避免额外观测造成性能扰动 | 见详细日志、R6/R13 |
| R8 | `20260904T014858Z-e3c29a5-r8` | 失败后已修复 | QUIC 474/474；TCP 256 成功后 218 失败，根因为 wolfSSL session reuse 边界 bug | `results/20260904T014858Z-e3c29a5-r8/soak/` |
| R12a | `20260904T035330Z-e3c29a5-r12` | 实验通过 | no reuse 321/321 | `results/20260904T035330Z-e3c29a5-r12/soak/` |
| R12b | `20260904T041128Z-e3c29a5-r12` | 实验通过、后续已提交 | 禁用 stateful session cache 308/308；最终 commit `379dac2` | `results/20260904T041128Z-e3c29a5-r12/soak/` |
| R13 | `20260904T042723Z-e3c29a5-r13` | 长稳通过 | 30+10 分钟，1459/1459 成功；RSS slopes 9109/11541/19027/19040 B/min，无失控增长 | `results/20260904T042723Z-e3c29a5-r13/soak/` |
| 本地 final | `final-local-tests` | 通过 | normal/QUIC 日志退出 0 | `results/final-local-tests/` |

# 问题与阻塞记录

| 时间 UTC | 轮次 | 问题 | 影响 | 处理 | 状态 |
|---|---|---|---|---|---|
| 2026-09-03 | R1 | 早期基线仅一轮 | 当时不能形成正式统计 | final run 与额外反向 p1 样本补足五个有效样本 | 已解除 |
| 2026-09-04 | R1 | final 原 summary 为 59 有效、2 失败 | 未体现额外反向 p1 成功样本 | 原 summary 保留不重算，并明确记录正式组已达五个有效样本 | 已记录 |
| 2026-09-04 | R2 | warmup 零字节 | 不影响正式五轮统计，但必须保留 | 已保存失败证据 | 已记录 |
| 2026-09-04 | R8 | TCP 256 次成功后 218 次失败 | 长稳门禁失败 | 定位 wolfSSL session reuse 边界 bug，修复提交为 `379dac2` | 已解除 |
| 2026-09-04 | R12 | `config.cpp` session cache 实验未提交 | 当时远端不是最终 clean commit | 已提交 `379dac2`，远端同 commit 且 clean | 已解除 |
| 2026-09-04 | 本地验证 | 日志需持久化 | 最终复现证据待补 | `final-local-tests` normal/QUIC 日志退出 0 | 已解除 |
| 2026-09-04 | 最终验收 | 无当前阻塞 | 无 | R4/R5/R7 与更多 jitter/reorder 按明确触发条件跳过 | 无阻塞 |

# 假设状态

| 假设 | 当前状态 | 支持证据 | 反对/限制 | 下一验证 |
|---|---|---|---|---|
| H1 UDP socket buffer 太小 | 当前不支持 | kernel drop 与 `RcvbufErrors` 为 0 | 未执行 buffer 矩阵 | 仅出现 `RcvbufErrors` 时执行矩阵 |
| H2 单 stream flow control 是主因 | 不支持为唯一主因 | R3 单流较多流慢 | TCP 同样受并发影响；R3 每组仅 5 MB | 必要时用 50 MiB 重跑 |
| H3 应用 retry/发送调度放大停顿 | 已定位并修复 | BBR/retry/read 证据及修复后 R2/R3/R6/R13 结果 | 不扩展到未测条件 | 问题回归时复核 |
| H4 UDP send 丢弃 | 当前不支持 | R6 已测样本均正确，kernel drop 为 0 | 无发送失败证据 | 出现 send failure 时采集 socket errors |
| H5 event-loop/batch 阻塞 | 当前证据不足 | 多流 aggregate 明显提高 | 额外 R7 观测会造成性能扰动 | 仅问题回归且现有证据不足时增加最小观测 |
| H6 高 RTT/loss 下拥塞控制敏感 | 已测条件满足验收 | R6 四条件 TCP/QUIC 均有效 | 单样本不能给稳定性能曲线 | 更多 jitter/reorder 按当前验收跳过 |
| H7 MTU/payload 映射问题 | 当前不支持 | 已测条件有效 | 未见 MTU fragmentation | 仅出现 MTU fragmentation 时执行矩阵与抓包 |
| H8 wolfSSL session reuse 边界 bug | 已修复 | R8 边界失败、R12 实验及 R13 1459/1459；commit `379dac2` | 不扩展到其他 TLS 实现 | 问题回归时复核 |
| H9 已无内存泄漏 | 不可宣布 | R13 30+10 分钟 1459/1459，RSS/PSS 无失控增长 | 该时段观测不是严格 leak proof | 需要严格结论时执行 ASan/LSan 或更长专项测试 |

---

# R14：服务端和客户端强制 QUIC 对照

- [x] TCP TLS 与 QUIC 使用独立 server run。
- [x] QUIC client 和 server 均设置 `debug_disable_tcp=true`。
- [x] runner 验证 QUIC run 有 `3443/UDP` listener 且无 `3443/TCP` listener。
- [x] QUIC 日志确认 handshake completed 和 ALPN `h3`。
- [x] 固定源 15 MB 各五轮，全部长度与 SHA-256 正确。
- [x] 强制 QUIC：`20260905T003822Z-8f08bbb-r14`，中位吞吐 `10.17 Mbps`。
- [x] TCP TLS：`20260905T004048Z-8f08bbb-r14`，中位吞吐 `10.54 Mbps`。
- [x] 强制 QUIC 并发矩阵：`20260905T004329Z-8f08bbb-r14`。
- [x] TCP TLS 并发矩阵：`20260905T004851Z-8f08bbb-r14`。

## R14 结论

- 状态：完成。
- 结论：完全禁用 client/server TCP 后，强制 QUIC 五轮吞吐与 TCP TLS 接近；结果不依赖 TCP fallback。

---

## R15：多运行模式矩阵

## 当前交接状态

- 当前 HEAD：`f54bc23` ("fix(quic): post buffer wakeup to io_context on MAX_STREAM_DATA to prevent re-entrant ngtcp2 frame corruption")。
- 代码同步：已通过 `git bundle` 同步至远端 `/root/trojan-plus`（HEAD `f54bc23`）。
- 远端编译：以严格 `-j 1` 编译以保护 1G 内存小主机，不触发 OOM Killer。
- Docker Desktop：镜像 `trojan-plus-docker-modes:latest` 本地已更新就绪。
- **已修复缺陷总览**：
  1. `client_tun` link-up 问题：`docker-entry.sh` 已修复，先 `ip link set tun0 up` 再添加 `/32` 路由。
  2. `CLIENT_TUN` 模式下 QUIC client 启动缺失：`src/core/service.cpp` 中将 `m_quic_client->start()` 移出 `!= CLIENT_TUN` 约束。
  3. **Bug 3 & 4（首流握手竞争与延迟流错误提前派发）**：`outbound_transport.cpp` 移除过早 `on_error`，`QuicClientEndpoint` 增加 `is_connecting()`，完善握手完成队列派发与异常清理（commit `ceed21f`）。
  4. **Bug 5（上游连接长效悬挂与流控信用泄露）**：请求注入 `Connection: close` 促使上游及时拆链；`QuicStreamTransport::close` 中主动返还 `m_recv_buf` 未读信用（commit `6243a7e`）。
  5. **Bug 6（流控耗尽与高并发流阻塞排队）**：`QuicClientEndpoint` 针对 `NGTCP2_ERR_STREAM_ID_BLOCKED` 引入双端待建流队列与 peer `MAX_STREAMS` 自动唤醒派发；流关闭时即时触发 pump_write 广播新流配额（commit `7548391` / `5b2a22f`）。
  6. **Bug 7（关键：`on_extend_max_stream_data` 误杀发送队列）**：消除 `on_extend_max_stream_data` 中多余的异步 `cancel_timer()`，防止 Asio 派发 `operation_aborted` 错误回调误清空 `m_conn_unacked_bufs` 导致的数据截断和 OpenSSL bad record mac 错误（commit `aa0f39b`）。
- **新测试规格与约束执行记录**：
  - 样本大小：>= 5 MB（5,242,880 bytes）。
  - 通道承压：最高 100 次 16 并发请求（总传输 500MB），单条 QUIC 链路聚合吞吐高达 86.24 Mbps。
  - 防护红线：单次测试总耗时严格控制在 5 分钟（300 秒）以内；测试前全自动采录 iperf3 链路基线。

## `client`

- [x] macOS SOCKS5 TCP TLS 与强制 QUIC五轮固定源对照。
- [x] 1/4/16/64 并发对照。

## `forward`

- [-] 按用户范围排除；不测试，不保留配置、runner 或并发规划。

## `nat`

- [x] Docker 独立 namespace 提供 `NET_ADMIN` 与 `/dev/net/tun`。
- [x] 宿主严格解析 `speed.cloudflare.com` 单个公网 IPv4；NAT 仅匹配该 IP `/32`、TCP dport 443。
- [x] TCP TLS smoke：HTTP 200、1 MiB 通过。
- [x] 强制 QUIC smoke：HTTP 200、1 MiB 通过。
- [x] 5 MB TCP TLS 5 轮基准：`20260905T110700Z-6e9394d-r18`，5/5 成功，中位 9.52 Mbps。
- [x] 5 MB 强制 QUIC 5 轮基准：`20260905T113500Z-ceed21f-r22`，5/5 成功，中位 9.29 Mbps（最高 10.86 Mbps），iperf3 26.17 Mbps（比率 0.355）。
- [x] 单通道承压测试（20 次请求，8 并发）：`20260905T114000Z-ceed21f-r24`，20/20 成功，聚合 44.92 Mbps，耗时 18.67s。
- [x] 单通道深度承压测试（40 次请求，8 并发）：`20260905T120400Z-6243a7e-r30`，40/40 成功，聚合 59.86 Mbps，耗时 28.03s。
- [x] 5 MB 10 并发四象限横向对照（R37 QUIC vs R39 TCP）：
  - `nat` QUIC（`20260905T144700Z-aa0f39b-r37`）：**10/10 成功，耗时 14.12s，中位 6.51 Mbps，聚合 29.70 Mbps**。
  - `nat` TCP（`20260905T145200Z-aa0f39b-r39`）：**10/10 成功，耗时 139.41s，中位 1.35 Mbps，聚合 3.01 Mbps**（QUIC 比 TCP 快 **9.9 倍**！）。

## `client_tun`

- [x] Docker 独立 namespace 提供 `NET_ADMIN` 与 `/dev/net/tun`。
- [x] `redirect_local=false`，仅将 Cloudflare 单目标 IP `/32` 路由到 `tun0`，禁止修改默认路由。
- [x] TCP smoke 通过（验证 tun0 link-up 修复成功）。
- [x] 强制 QUIC smoke：`20260905T110500Z-6e9394d-r17`（1 MiB，3.37 Mbps，HTTP 200）。
- [x] 5 MB TCP TLS 5 轮基准：`20260905T113700Z-ceed21f-r23`，5/5 成功，中位 8.08 Mbps（最高 11.96 Mbps），iperf3 33.15 Mbps。
- [x] 5 MB 强制 QUIC 5 轮基准：`20260905T113200Z-ceed21f-r21`，5/5 成功，中位 10.53 Mbps（最高 12.06 Mbps），iperf3 31.76 Mbps（比率 0.332）。
- [x] 单通道承压测试（20 次请求，8 并发）：`20260905T114200Z-ceed21f-r25`，20/20 成功，耗时 18.21s。
- [x] 单通道深度承压测试（40 次请求，8 并发）：`20260905T120200Z-6243a7e-r29`，40/40 成功，聚合 54.20 Mbps，耗时 30.96s。
- [x] 单通道极限承压测试（100 次请求，16 并发，500MB）：`20260905T120600Z-6243a7e-r31`，100/100 成功，聚合 86.24 Mbps，耗时 48.64s，零错误！
- [x] 5 MB 10 并发四象限横向对照（R36 QUIC vs R38 TCP）：
  - `client_tun` QUIC（`20260905T144300Z-aa0f39b-r36`）：**10/10 成功，耗时 12.86s，中位 7.15 Mbps，聚合 32.61 Mbps**。
  - `client_tun` TCP（`20260905T145000Z-aa0f39b-r38`）：**10/10 成功，耗时 61.67s，中位 1.95 Mbps，聚合 6.80 Mbps**（QUIC 比 TCP 快 **4.8 倍**！）。

## 回归与全量测试套件验收

- [x] 本地全量 QUIC 测试套件（`fulltest_main.py -q all`，涵盖 T1~T19 全部 18 个用例）：**18/18 100% 全部通过**。
- [x] 本地标准测试套件（`fulltest_main.py -n`，涵盖 Client/Forward 及 Pipeline 模式）：**100% 全部通过**。
- [x] 本地 Fallback 模式测试套件（`fulltest_main.py -f`）：**100% 全部通过**。
- [x] 远端 四象限并发承压基准（`client_tun` QUIC/TCP, `nat` QUIC/TCP，各 10 次 5MB 请求）：**40/40 全部成功，零错误**。
- [x] 远端服务端日志全流程自动化存档保留。
