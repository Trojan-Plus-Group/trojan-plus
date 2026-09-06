# 性能优化执行记录

## 当前状态

- 当前 Iteration：Iteration 4
- 当前阶段：ClientSession TCP TLS 下载双槽有效 A/B、压力和长稳完成，候选保留
- 总体状态：非 pipeline TCP TLS 下载利用率提升约 6.8%，正确性、资源和 cleanup 无回归
- 下一门禁：为 ClientSession QUIC 下载方向采集独立修改前基线，禁止直接复用 TCP 双槽状态机

## 强制流程

每个 Iteration 必须按顺序完成：

1. 单变量代码修改与自检。
2. 本地 Release 构建。
3. runner unittest。
4. QUIC 全量测试。
5. 标准 client/forward/pipeline 测试。
6. fallback 测试。
7. Linux DNS/TUN 补充测试；macOS 按规则跳过 DNS。
8. 用户确认远程环境参数。
9. git bundle + fast-forward 同步。
10. 远端单线程 Release 构建；不在远端重复运行 LinuxFullTest。
11. 本地与远端组合的原始网络基线。
12. `client`、`nat`、`client_tun` TCP/强制 QUIC 正式与压力测试。
13. 资源、正确性、性能与 cleanup 复核。
14. 全部通过后创建本地 commit。
15. 更新本文件，再进入下一 Iteration。

任何阶段失败：停止当前测试并保留证据，先区分产品代码、测试编排和环境。测试编排或环境失败时修复验证流程并以新 Run ID 重跑，不得直接回退性能候选；产品失败或有效 A/B 未达阈值才回退。禁止跳过未解决错误继续比较收益。

## Iteration 0：基线与可观测性

- [x] UDP receive buffer 设置使用独立 error code。
- [x] UDP send buffer 设置使用独立 error code。
- [x] buffer 设置失败记录非致命 WARN。
- [x] 读取并记录实际 UDP receive/send buffer。
- [x] `non_blocking()` 错误独立处理。
- [ ] 代码格式检查：本机无 `clang-format`，待远端或安装工具后补充。
- [x] Release 构建通过。
- [x] runner unittest 通过：42/42。
- [x] QUIC `-q all` 通过。
- [x] 标准 `-n` 通过。
- [x] fallback `-f` 通过。
- [x] Linux DNS/TUN 补充测试；当前为 macOS，按规则 skip。
- [ ] 远程环境参数已重新确认：默认 host/user/port/repo/CPU/内存/端口已确认；远端分支为 `fix_quic`，与本地 `opt_perf` 不一致，待处理。
- [ ] 远端原始网络基线完成。
- [x] `client` TCP/强制 QUIC smoke 通过：`20260906T020331Z-d2d3c9e-r1`、`20260906T020438Z-d2d3c9e-r2`。
- [x] `nat` TCP/强制 QUIC smoke 通过：`20260906T020543Z-d2d3c9e-r3`、`20260906T020702Z-d2d3c9e-r4`。
- [x] `client_tun` TCP/强制 QUIC smoke 通过：`20260906T020814Z-d2d3c9e-r5`、`20260906T020927Z-d2d3c9e-r6`。
- [ ] 30 分钟 active + 10 分钟 cooldown 长稳通过。
- [ ] cleanup 无残留。
- [ ] 假设与结果复核完成。
- [ ] Iteration 0 本地 commit 已创建。

## Iteration 1：UDP socket buffer A/B

状态：已停止；256 KiB 复测收益不足 5%，1/2 MiB 会被当前 Linux `net.core.rmem_max/wmem_max` 同样截断，不继续扩大。

- [x] 256 KiB 本地构建、45/45 unittest、QUIC all、标准 `-n`、fallback `-f` 通过。
- [x] 双端 `opt_perf@b69192d` 一致，远端 `-j 1` 编译通过。
- [x] 六组 smoke 通过：`r16` 至 `r21`。
- [x] Linux 请求 262,144 B，实际 receive/send buffer 均为 212,992 B。
- [x] 前置基线 `r22`：TCP 单流正向中位数 12.529 Mbps；60/60 有效。
- [x] QUIC `r23`：中位数 14.343 Mbps，但样本 8.683–21.200 Mbps，波动大。
- [x] 后置基线 `r24`：TCP 单流正向中位数 12.605 Mbps；前后仅 +0.6%。
- [x] QUIC 复测 `r25`：中位数 9.738 Mbps；相对 76,800 B 基线 `r9` 的 9.513 Mbps 仅 +2.4%。
- [x] cleanup 无本轮容器、listener 或远端进程残留。
- [x] 默认值已恢复为 76,800 B；双端 `opt_perf@832f396` 一致，六组 smoke `r26` 至 `r31` 通过。

## Iteration 2：QUIC retry 与 flow control

状态：单连接累计计数已完成；10 ms retry 在本地 T12 的 300 KiB 下载中每连接触发 4 次，`STREAM_DATA_BLOCKED` 未触发。1 ms retry 虽通过本地门禁，但没有按固定流程取得修改前后同环境利用率 A/B，判定无有效收益证据并回退至 10 ms；不修改 flow control。

- [x] 增加连接级 `partial_write_retries`、`write_more`、`stream_data_blocked` 累计计数，析构时单行 INFO 输出。
- [x] 10 ms 基线 T12 通过；服务端观察 4 次 partial-write retry，累计固定等待约 40 ms。
- [x] 将 partial-write retry 单变量改为 1 ms；T12 通过，仍触发 4 次，日志间隔约 2 ms。
- [x] 1 ms 候选因缺少修改前后同环境代理路径利用率 A/B，按无有效收益处理并回退至 10 ms。
- [x] 本地 Release 并发构建通过。
- [x] runner unittest 通过：46/46。
- [x] QUIC `-q all`、标准 `-n`、fallback `-f` 通过。
- [x] macOS DNS 按规则跳过。
- [x] 历史远端数据复核：`r9` QUIC 中位数 9.513 Mbps；`r23` 14.343 Mbps；`r25` 9.738 Mbps。同 commit 的 `r23/r25` 波动约 32%，不能用于证明 1 ms 候选收益。
- [x] 1 ms 候选停止，不再补测；后续任何性能候选必须先取得修改前基线与代理利用率，再修改并重测。
- [ ] 依据新固定流程选择下一单变量；完成修改前数据采集前不进入 flow-control 参数 A/B。

## Iteration 3：TCP relay chunk

状态：已完成有效 A/B 并回退。`r36` 确认为测试命令流错误，不用于评价候选；修正验证流程后，16 KiB 候选通过全部 smoke，但 TCP TLS 利用率回退约 48.5%，触发停止条件。

- [x] 修改前原始基线 `20260906T120000Z-87361b3-r32`：60/60 有效；TCP 单流正向中位数 12.635 Mbps。
- [x] 修改前 TCP TLS `r33`：5/5 有效；中位数约 10.840 Mbps，利用率约 85.8%。
- [x] 修改前强制 QUIC `r34`：5/5 有效；中位数约 9.442 Mbps，利用率约 74.7%。
- [x] 拆分 `TCP_RELAY_BUF_LENGTH=16384`，仅替换 Client/Server 四个 relay read；`MAX_BUF_LENGTH=8192` 保持不变。
- [x] 候选本地 Release 并发构建、46/46 unittest、QUIC all、标准 `-n`、fallback `-f` 通过。
- [x] 候选 commit `b084f94`，双端分支 `opt_perf` 与 commit 一致，远端 `-j 1` 构建通过。
- [x] `client` TCP smoke `r35` 通过。
- [x] `client` QUIC smoke `r36` 失败：curl exit 7，`127.0.0.1:8001` 未监听；失败证据完整保留。
- [x] `r36` 归因为测试命令流漏启动 bytesource/server/client，不构成产品失败；PLAN 已增加归因规则。
- [x] 恢复候选 commit `271b34d`；双端一致，远端 `-j 1` 构建通过。
- [x] 正确命令流 smoke 全部通过：client `r41/r42`、nat `r43/r44`、client_tun `r45/r46`；内容/hash、QUIC handshake/ALPN 和 listener 正确。
- [x] 修改后原始基线 `r47`：60/60 有效；TCP 单流正向中位数 12.635 Mbps，与修改前几乎一致。
- [x] 修改后 TCP TLS `r48`：5/5 有效；中位数约 5.581 Mbps，利用率约 44.2%，相对修改前利用率约 -48.5%。
- [x] 修改后强制 QUIC `r49`：5/5 有效；中位数约 9.081 Mbps，利用率约 71.9%，相对修改前利用率约 -3.7%。
- [x] TCP TLS 回退超过 5%，16 KiB 候选判定无效并回退；未继续 32 KiB。
- [x] 回退版本本地 Release、46/46 unittest、QUIC all、标准 `-n`、fallback `-f` 通过。
- [x] 回退 commit `0377e1e` 已同步远端并完成 `-j 1` 构建；双端 `opt_perf@0377e1e` 一致，cleanup 无残留，未 push。

## Iteration 4：有界双槽流水线

状态：第一子步骤完成并保留。仅 `ClientSession` 非 pipeline TCP TLS 下载启用双槽；QUIC、pipeline 和上传路径不变。

- [x] 修改前 `20260906T081358Z-0377e1e-r50`：原始基线 60/60 有效，TCP 正向单流中位数 12.634 Mbps；TCP TLS 5/5 有效，中位数约 10.417 Mbps，利用率约 82.45%。
- [x] 候选使用两个延迟分配的 8 KiB read buffer；最多一个 outbound read、一个 local write in flight、一个待写槽，严格按 read completion 顺序写入。
- [x] outbound EOF/error 等已读取数据排空后销毁；local write error 立即销毁；callback 捕获 session 和对应 buffer 保证生命周期。
- [x] 候选仅在 `status == FORWARD`、非 pipeline、`m_out` 非 QUIC 时启用；QUIC、pipeline、UDP 和上传逻辑未改。
- [x] 本地 Release 并发构建、46/46 unittest、QUIC all、标准 `-n`、fallback `-f` 通过；macOS DNS 按规则跳过。
- [x] 候选 commit `d85fa79`；双端 `opt_perf` 与 commit 一致，远端 `-j 1` 构建通过，未 push。
- [x] 首次 smoke 编排命令因 zsh 不拆分标量 `SPEC` 在 Run ID 校验前失败；无部署、无产品代码执行，不用于产品结论。
- [x] 修正编排后六组 smoke `r57` 至 `r62` 全部通过；HTTP 200、长度/hash、QUIC handshake/ALPN、listener 和 cleanup 正确。
- [x] 修改后 `20260906T084615Z-d85fa79-r63`：原始基线 60/60 有效，TCP 正向单流中位数 12.723 Mbps；TCP TLS 5/5 有效，中位数约 11.207 Mbps，利用率约 88.08%。
- [x] 代理绝对吞吐中位数约 +7.6%，代理路径利用率约 +6.8%，超过 5% 保留门槛。
- [x] TCP 200 请求/50 MB 压力 `r64`：200/200 有效，aggregate 32.691 Mbps，P50 2.466 秒，P95 2.952 秒，失败 0。
- [x] TCP 30 分钟 active + 10 分钟 cooldown `r65`：509/509 样本长度/hash 正确，失败 0；本地 TCP RSS 约 4.38–6.14 MiB 后平台化，远端 RSS 约 11.26–11.32 MiB、PSS 约 9.62–9.70 MiB，cooldown 稳定。
- [x] cleanup 无本轮容器、本地 9080/9081 listener、远端 3443/5201/8001 listener 或测试进程残留。
- [x] QUIC 修改前 `20260906T100047Z-d85fa79-r66`：原始基线 60/60 有效，TCP 正向单流中位数 12.646 Mbps；QUIC 5/5 有效，中位数约 8.294 Mbps，利用率约 65.58%。
- [x] QUIC 候选复用现有两个 8 KiB 下载槽；transport 仍最多一个 pending read，额外 flow-control 消费上限为一个 8 KiB 槽；pipeline 路径不变。
- [x] 候选本地 Release、46/46 unittest、QUIC all、标准 `-n`、fallback `-f` 通过；六组 smoke `r67` 至 `r72` 通过。
- [x] QUIC 修改后 `20260906T102819Z-2bb79cb-r73`：原始基线 60/60 有效，TCP 正向单流中位数 12.663 Mbps；QUIC 5/5 有效，中位数约 9.648 Mbps，利用率约 76.19%；利用率提升约 16.2%。
- [x] 首次 QUIC 200 请求压力 `r74` 仅 103/200 有效，97 个达到 140 秒 attempt timeout；证据保留，未直接作为产品结论。
- [x] 候选 QUIC 30+10 分钟长稳 `r75`：1323/1323 有效，失败 0；本地 QUIC RSS 约 8.26–14.27 MiB，远端 PSS 约 8.12–11.50 MiB。cooldown 未回落到初值，但无持续失败；单凭正 slope 不判泄漏。
- [x] 同规格并发归因夹测：回退前 `r77` 200/200、22.424 Mbps；候选 `r78` 200/200、29.035 Mbps；回退后 `r79` 200/200、28.760 Mbps。`r74` 的大面积超时无法稳定复现，归因瞬时公网或连接状态异常，不归因双槽。
- [x] 夹测显示候选相对相邻后基线并发 aggregate 仅约 +1.0%，不作为并发收益证据；单流利用率有效 A/B 提升约 16.2%，且并发正确性无可复现回归，保留候选。
- [x] 最终候选 commit `f48bfce` 已同步远端并完成 `-j 1` 构建；双端 `opt_perf@f48bfce` 一致，未 push。
- [ ] 下一子步骤：Client 上传方向；修改前先采集独立基线。

## Iteration 5：参数固化与长稳

状态：未开始。


## 结果索引

### 2026-09-06 Iteration 0 smoke

```text
日期：2026-09-06
Iteration：0
Commit/dirty diff：d2d3c9ef262b1a62600a2c1cd892eea4d3ce7764；opt_perf/PLAN.md、opt_perf/TODO.md 有本地文档改动
本地结果：此前 Release、42/42 unittest、QUIC all、标准 -n、fallback -f 通过
远程 Run ID：r1 至 r6，见上述六组记录
基线：未执行；远端分支门禁失败后停止
代理结果：六组 1 MiB smoke 均 exit 0、HTTP 200、长度/hash 正确；QUIC handshake completed，ALPN h3
资源结果：远端 1 vCPU、954 MiB RAM、2.5 GiB swap；-j 1 编译通过
Cleanup：本地无 trojan 容器及 9080/9081 listener；远端无 3443/5201/8001 listener 或本轮进程
结论：停止并重新规划；本地 opt_perf 与远端 fix_quic 分支名不一致，commit 均为 d2d3c9e
```

### 2026-09-06 Iteration 3 TCP relay chunk

```text
日期：2026-09-06
Iteration：3
Commit/dirty diff：候选 b084f94；回退 ff5b1d2；仅 TODO.md 有执行记录改动
本地结果：候选与回退版本均通过 Release、46/46 unittest、QUIC all、标准 -n、fallback -f
远程 Run ID：修改前 r32/r33/r34；候选 smoke r35/r36
基线：TCP 单流正向中位数 12.635 Mbps；TCP TLS 约 10.840 Mbps；QUIC 约 9.442 Mbps
代理结果：r36 为测试命令流错误；修正后六组 smoke 通过。修改后 TCP TLS 约 5.581 Mbps、利用率 44.2%；QUIC 约 9.081 Mbps、利用率 71.9%
资源结果：远端 1 vCPU、954 MiB RAM、2.5 GiB swap；候选 -j 1 编译通过
Cleanup：各成功 run 自清理通过；回退后本地无容器或 9080/9081 listener，远端无 3443/5201/8001 listener 或测试进程
结论：有效 A/B 显示 TCP TLS 利用率约 -48.5%、QUIC 利用率约 -3.7%；16 KiB 候选无效，回退且不测试 32 KiB
```

每次测试完成后记录：

```text
日期：
Iteration：
Commit/dirty diff：
本地结果：
远程 Run ID：
基线：
代理结果：
资源结果：
Cleanup：
结论：通过 / 停止并重新规划
```
