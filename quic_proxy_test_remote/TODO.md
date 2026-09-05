# Trojan Plus QUIC 远程性能调查 TODO

关联计划：[PLAN.md](PLAN.md)

## 使用规则

- 状态只用：`[ ]` 未开始、`[~]` 进行中、`[x]` 完成、`[-]` 跳过、`[!]` 阻塞。
- 原始结果只新增，不覆盖；结果统一放入 `results/<run_id>/`。
- 正式统计必须有五个有效样本；少于五轮只标部分完成。
- 失败、预热失败、命令、退出码、配置和资源原始观测均保留。
- 密码、私钥、TLS keylog 不提交仓库；测试结束恢复网络规则并关闭临时服务。

## 当前状态

- 当前阶段：扩展多运行模式矩阵。
- 当前代码：`8f08bbb`，新增 `debug_disable_tcp=true` 时 client/server TCP 完全禁用；远端为同 commit 且工作树 clean。
- 当前结论：R1 正式组达到五个有效样本，R2 Cloudflare、R3 五轮并发、R6 指定 netem 场景、R13 30+10 分钟长稳均通过；R8 发现的 TCP 第 257 次连接失败已消除。
- 最终长稳：`20260904T042723Z-e3c29a5-r13`，1459/1459 成功，观测失败 0；RSS slopes 为 client TCP `9109 B/min`、client QUIC `11541 B/min`、server RSS `19027 B/min`、server PSS `19040 B/min`。
- R1 final：`20260904T051142Z-379dac2-r1` 原 summary 为 59 有效、2 失败；额外反向 p1 成功样本已保存，正式组达到五个有效样本，但原 summary 未重算。
- 本地验证：`final-local-tests` normal/QUIC 日志均退出 0。
- 阻塞项：无。

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

# R15：多运行模式矩阵

## 当前交接状态

- 当前 HEAD：`17d3b53`；本地工作树有未提交改动。
- 未提交产品改动：彻底删除 `server_tun`/`SERVERT_TUN` 枚举、解析和 service 分支。
- 未提交测试改动：`Dockerfile.template`、`docker-entry.sh`、`scripts/docker_modes.py`、`scripts/test_docker_modes.py`。
- Docker 能力已确认：Linux amd64、`NET_ADMIN`、`/dev/net/tun`、iptables/nftables、远端连通。
- 远端不再开放 `8001`，不再安装或修改远端防火墙；测试目标为 Cloudflare 固定 IPv4。
- 远端早期临时 `nftables` 已卸载，临时 table、listener、process 和部署目录已清理。
- 下一步：修复 `client_tun` 添加 route 前未将 `tun0` link up 的问题。

## `client`

- [x] macOS SOCKS5 TCP TLS 与强制 QUIC五轮固定源对照。
- [x] 1/4/16/64 并发对照。

## `forward`

- [-] 按用户范围排除；不测试，不保留配置、runner 或并发规划。

## `nat`

- [x] Docker 独立 namespace 提供 `NET_ADMIN` 与 `/dev/net/tun`。
- [x] 宿主严格解析 `speed.cloudflare.com` 单个公网 IPv4；NAT 仅匹配该 IP `/32`、TCP dport 443。
- [x] TCP TLS smoke：`20260905T120000Z-17d3b53-r16`，HTTP 200、1 MiB、清理完成。
- [x] 强制 QUIC smoke：`20260905T021733Z-17d3b53-r16`，HTTP 200、1 MiB、清理完成。
- [ ] TCP TLS 与强制 QUIC 各五轮及并发矩阵。

## `client_tun`

- [x] Docker 独立 namespace 提供 `NET_ADMIN` 与 `/dev/net/tun`。
- [~] `redirect_local=false`，仅将 Cloudflare 单目标 IP `/32` 路由到 `tun0`，禁止修改默认路由。
- [!] TCP smoke `20260905T021836Z-17d3b53-r16` 阻塞：添加 `/32` route 时 `Device for nexthop is not up`。
- [ ] 修复顺序：等待 `tun0`，执行 `ip link set tun0 up`，再添加目标 route 并保存 evidence。
- [ ] 完成 TCP TLS 与强制 QUIC smoke、五轮和并发矩阵。

## R15 验收

- [ ] `client`、`nat`、`client_tun` 每种模式均完成 TCP TLS 与强制 QUIC。
- [-] `forward` 按用户范围明确排除。
- [ ] Docker curl exit 0、HTTP 200、`size_download=1048576`、文件大小 1048576；不做 SHA。
- [ ] 强制 QUIC server 仅监听 UDP，日志确认 ALPN `h3`；TCP 使用普通 server。
- [ ] Docker `finally` 清理容器；远端只清理 Trojan server 和临时证书目录。
