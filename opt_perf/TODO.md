# 性能优化执行记录

## 当前状态

- 当前 Iteration：Iteration 0
- 当前阶段：修复远端同步分支一致性
- 总体状态：进行中；已获授权将远端切换到本地同名 `opt_perf` 分支
- 下一门禁：同步脚本测试、本地完整门禁、远端分支与 commit 双校验

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

任何阶段失败：停止，保留证据，重新规划。禁止跳过失败继续优化。

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

状态：未开始。Iteration 0 未全部通过前禁止开始。

候选值：76,800 B、256 KiB、1 MiB、2 MiB。

## Iteration 2：QUIC retry 与 flow control

状态：未开始。Iteration 1 未完成或重新规划前禁止开始。

## Iteration 3：TCP relay chunk

状态：未开始。禁止直接修改全局 `MAX_BUF_LENGTH`。

## Iteration 4：有界双槽流水线

状态：未开始。每个方向与 transport 独立迭代。

## Iteration 5：参数固化与长稳

状态：未开始。

## 远程环境待确认

```text
REMOTE_HOST=
SSH_USER=
SSH_PORT=
REMOTE_REPO=
REMOTE_CPU_COUNT=
REMOTE_MEMORY=
REMOTE_BRANCH=
TEST_PORTS=
```

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
