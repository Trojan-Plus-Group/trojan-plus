# 性能优化执行记录

## 当前状态

- 当前 Iteration：Iteration 0
- 当前阶段：实施可观测性改造
- 总体状态：进行中
- 下一门禁：本地全面测试

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
10. 远端单线程构建。
11. 原始网络基线。
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
- [ ] 远程环境参数已重新确认。
- [ ] 远端原始网络基线完成。
- [ ] `client` TCP/强制 QUIC 矩阵通过。
- [ ] `nat` TCP/强制 QUIC 矩阵通过。
- [ ] `client_tun` TCP/强制 QUIC 矩阵通过。
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
