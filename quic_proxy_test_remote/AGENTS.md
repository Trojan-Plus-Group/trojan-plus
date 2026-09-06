# 本地多模式连接远端服务器测试指南

本文件仅指导 AI Agent 从本地以 `client`、`nat`、`client_tun` 模式连接远端 Trojan server，对比 TCP TLS 与强制 QUIC。`forward` 不在测试范围。

## 1. 日常验证闭环

用户要求验证一次代码修改时，严格按以下顺序执行：

1. 本地修改代码。
2. 本地 Release 构建并运行相关 fulltest。
3. 本地测试全部通过后提交本轮代码。该提交仅限用户明确要求启动此验证流程时创建；禁止 `git push`。
4. 运行 `python3 quic_proxy_test_remote/scripts/sync_remote.py --jobs 1`，通过 git bundle 将本地当前分支 fast-forward 同步到远端。
5. 同步脚本在远端以 `-j 1` 编译，并验证本地与远端 commit 一致。`-j 1` 仅适用于远端构建；本地构建必须使用并发编译，不得套用远端单线程限制。
6. 依次执行 `client`、`nat`、`client_tun` 的 TCP TLS 与强制 QUIC smoke，共六组。每组使用独立 Run ID，默认 1 MiB、1 请求，不运行 iperf3 和长稳。
7. 六组均满足 exit 0、HTTP 200、字节/hash 完整、QUIC 无 TCP fallback，且 cleanup 无残留后，宣布本轮通过。

失败处理：

- 本地构建或 fulltest 失败：返回步骤 1；不得提交失败版本。
- 远端同步、编译或 smoke 失败：保留失败结果和日志，返回步骤 1；修复后重新跑本地门禁，创建新 commit 和新 Run ID，再同步、编译、重测。
- 禁止覆盖、修改或删除失败结果；禁止仅重试后用成功结果替代首次失败。

当前三模式六组 smoke 实测约 6–7 分钟；本地 fulltest、提交、同步和远端单线程编译耗时另计。此闭环不是最终验收，不包含五轮性能矩阵、200 请求压力或 30+10 分钟长稳。

## 2. 测试前确认

每轮先确认，不得沿用历史值：

```text
REMOTE_HOST
SSH_USER
SSH_PORT
REMOTE_REPO
REMOTE_BRANCH
REMOTE_CPU_COUNT
REMOTE_MEMORY
TEST_PORTS
```

检查本地与远端环境：

```bash
git status --short --branch
git rev-parse HEAD
uname -a
cmake --version
curl --version
iperf3 --version

ssh -p <SSH_PORT> <SSH_USER>@<REMOTE_HOST> \
  'uname -a; nproc; free -h; git -C <REMOTE_REPO> status --short --branch; git -C <REMOTE_REPO> rev-parse HEAD; ss -lntup'
```

本地与远端必须使用同一 commit、同一 Release 构建。工作树非 clean 时保存 diff 到本轮 metadata。

## 3. 安全规则

1. 禁止 `git push`。仅使用 git bundle 将代码 fast-forward 同步到远端。
2. 未经用户明确要求，不得创建 commit。
3. 远端若为 1 CPU/1 GB 小主机，只能使用 `cmake --build build -j 1`；禁止并行编译和并行重负载任务。此单线程规则只适用于远端，禁止用于本地构建；本地必须按可用 CPU 并发编译。
4. 单样本不超过 50 MB，单组不超过 5 分钟；首次失败、超时和重试结果都要保留。
5. 临时密码、私钥、TLS keylog 不得提交；测试结束删除远端临时凭据。
6. 禁止批量 `pkill`、批量删除 `/tmp/trojan-*` 或非本轮容器。仅按 run metadata 中 PID、容器名和远端目录清理。
7. netem 只能精确匹配测试 IP/port，不得修改 SSH 默认路由；执行前保存规则，结束后恢复并验证。
8. `--with-iperf` 默认关闭；仅确认没有其他 iperf3 任务后启用。

## 4. 远端同步与本地门禁

优先使用同步脚本，执行前核对脚本中的 host、user、port、repo：

```bash
python3 quic_proxy_test_remote/scripts/sync_remote.py --status
python3 quic_proxy_test_remote/scripts/sync_remote.py --jobs 1
```

同步脚本默认通过 `git branch --show-current` 获取本地当前分支并同步同名 branch，不得写死项目分支。detached HEAD 时必须显式传入 `--branch <BRANCH>`。同步时必须切换或创建远端同名分支，并在完成后同时校验本地与远端分支名、commit 一致；只允许 fast-forward。远端分支无法安全切换、存在未提交改动或 commit 无法 fast-forward 时停止，不得 reset、force 覆盖或推进其他分支。git bundle 只能包含已提交内容；工作树有产品代码修改时，未经用户明确授权不得自行 commit，也不得声称远端已同步该修改。

修改产品代码或测试执行器后，先运行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_QUIC=ON
cmake --build build --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
python3 -m unittest \
  quic_proxy_test_remote/scripts/test_run.py \
  quic_proxy_test_remote/scripts/test_docker_modes.py
cd tests/LinuxFullTest
python3 -u fulltest_main.py ../../build/trojan -q all
python3 -u fulltest_main.py ../../build/trojan -n
python3 -u fulltest_main.py ../../build/trojan -f
```

macOS 跳过 DNS `-d`。运行前确认测试端口 `18080`、`18083`、`9080`、`9081` 未被用户业务占用。

## 5. Run 与证据

Run ID：

```bash
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD)-r<number>"
```

每个模式、协议、变量使用独立 run。禁止覆盖 `runtime/<run_id>` 或 `results/<run_id>`。短测标记 smoke/partial；正式性能测试至少五个有效样本。

每轮必须保存：commit、dirty diff、配置、命令、退出码、stdout/stderr、监听状态、handshake/ALPN、实际字节数/hash、失败样本、CPU、RSS/PSS、UDP errors、interface drops 和 cleanup 结果。

## 6. 协议有效性

TCP TLS 与强制 QUIC 必须分开部署：

- TCP TLS：client `quic.enabled=false`；server 允许 TCP，远端 TCP listener 存在。
- 强制 QUIC：client/server 均为 `quic.enabled=true`、`debug_disable_tcp=true`；远端 UDP listener 存在，TCP listener 不存在；日志包含 `handshake completed` 和 ALPN `h3`。

出现 TCP fallback、QUIC 握手未完成或 listener 不符合要求时，样本作废。

## 7. `client` 模式

TCP 五轮 5 MiB：

```bash
python3 quic_proxy_test_remote/scripts/run.py prepare --run-id "$RUN_ID"
python3 quic_proxy_test_remote/scripts/run.py trojan-deploy --run-id "$RUN_ID"
python3 quic_proxy_test_remote/scripts/run.py r2 \
  --run-id "$RUN_ID" --protocol tcp --sizes 5242880 --runs 5
```

强制 QUIC 五轮 5 MiB：

```bash
python3 quic_proxy_test_remote/scripts/run.py trojan-deploy \
  --run-id "$RUN_ID" --server-disable-tcp
python3 quic_proxy_test_remote/scripts/run.py r2 \
  --run-id "$RUN_ID" --protocol quic --sizes 5242880 --runs 5
```

200 请求压力，总量固定 50 MB：

```bash
python3 quic_proxy_test_remote/scripts/run.py concurrency \
  --run-id "$RUN_ID" --protocol <tcp|quic> \
  --streams 200 --total-bytes 50000000 --warmup 0 --runs 1
```

同一 deploy 不得使用 `--protocol both`。

## 8. `nat` 与 `client_tun` 模式

前置条件：Docker daemon 可用、`/dev/net/tun` 可访问、本地 `build/trojan` 可执行、远端 binary 已同步构建。

```bash
docker info
test -x build/trojan
```

五轮 5 MiB：

```bash
python3 quic_proxy_test_remote/scripts/docker_modes.py \
  --mode <nat|client_tun> --protocol <tcp|quic> \
  --run-id "$RUN_ID" --size 5242880 \
  --requests 5 --concurrency 5 --watchdog 240
```

200 请求压力，总量 50 MB：

```bash
python3 quic_proxy_test_remote/scripts/docker_modes.py \
  --mode <nat|client_tun> --protocol <tcp|quic> \
  --run-id "$RUN_ID" --size 250000 \
  --requests 200 --concurrency 32 --watchdog 240
```

模式约束：

- `nat`：仅重定向目标公网 IPv4 `/32` 的 TCP 443，不改默认路由。
- `client_tun`：`redirect_local=false`，仅将目标 `/32` 路由到 `tun0`；远端 server 地址不得进入该路由，防止递归。
- 每个容器使用独立 network namespace、`NET_ADMIN`、`/dev/net/tun` 和 watchdog；结束后必须删除。
- Docker image 仅在 `Dockerfile.template` 或 `docker-entry.sh` 内容变化时重建；binary 通过只读 runtime volume 挂载。

## 9. 验收矩阵

| 模式 | TCP TLS | 强制 QUIC | TCP 压力 | QUIC 压力 |
|---|---:|---:|---:|---:|
| `client` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/50 MB | 200 请求/50 MB |
| `nat` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/32 并发 | 200 请求/32 并发 |
| `client_tun` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/32 并发 | 200 请求/32 并发 |

最低要求：exit 0、HTTP 200、长度/hash 完整、零 fallback、零 crash、零 deadlock、零 unexpected reset。

公平对比要求：同一 commit、证书、密码、目标、样本大小和并发数；TCP/QUIC 在相邻时间窗口交替运行；每次只改变一个变量。先记录 iperf3 TCP/UDP 基线，再解释代理吞吐。Cloudflare 只用于入口与体验验证，不作为唯一性能依据。

正式结果报告中比较中位数、P10/P90、aggregate、P50/P95 和失败数，不只报告最佳值。性能轮使用 `log_level` 1 或 2；`log_level: 0` 仅用于短时诊断。

日常多模式验收使用 5 分钟 active + 2 分钟 cooldown；`run.py soak` 已提供 `--minutes`、`--cooldown` 参数，默认值也是 5 和 2：

```bash
python3 quic_proxy_test_remote/scripts/run.py soak \
  --run-id "$RUN_ID" --protocol <tcp|quic> \
  --minutes 5 --cooldown 2
```

仅在最终发布、发现内存异常或修改连接/流生命周期后，对关键 QUIC 路径执行一次 `--minutes 30 --cooldown 10`。默认每 60 秒采集 RSS/PSS，可用 `--soak-sample-interval` 调整。持续线性增长且停流后不回落时，再执行 ASan/LSan 或 heap profiler。仅凭正 slope 不得宣布内存泄漏。

## 10. 时间参数

watchdog、命令超时、连接超时、重试等待、进程轮询和资源采样间隔均有 CLI 参数与默认值，不再依赖不可覆盖的硬编码。参数单位均为秒，`soak --minutes` 和 `--cooldown` 除外。

`scripts/run.py` 的时间参数可放在任一子命令后：

| 参数 | 默认值 | 用途 |
|---|---:|---|
| `--item-timeout` | 170 | 单项含重试总时限 |
| `--retry-delays FIRST SECOND` | `3 10` | 两次重试退避 |
| `--default-attempt-timeout` | 140 | 下载单次尝试时限 |
| `--run-item-attempt-timeout` | 50 | 通用命令单次尝试时限 |
| `--ssh-connect-timeout` | 10 | SSH 建连时限 |
| `--local-port-timeout` | 30 | 本地 listener 启动等待 |
| `--poll-interval` | 0.5 | 本地 listener 轮询间隔 |
| `--remote-start-wait` | 1 | 远端进程启动确认等待 |
| `--remote-stop-polls` | 5 | 远端进程停止轮询次数 |
| `--remote-stop-poll-interval` | 1 | 远端进程停止轮询间隔 |
| `--local-start-stop-timeout` | 5 | 本地启动失败后的停止等待 |
| `--local-stop-timeout` | 10 | 本地进程正常停止等待 |
| `--local-kill-timeout` | 5 | 本地进程强制停止等待 |
| `--lsof-timeout` | 5 | 单次 listener 检查时限 |
| `--short-command-timeout` | 15 | 短命令时限 |
| `--stop-command-timeout` | 20 | 停止命令时限 |
| `--command-timeout` | 30 | 常规命令与观测时限 |
| `--long-command-timeout` | 60 | 长命令时限 |
| `--cloudflare-connect-timeout` | 15 | Cloudflare curl 建连时限 |
| `--cloudflare-max-time` | 170 | Cloudflare curl 总时限 |
| `--cloudflare-retries` | 2 | Cloudflare curl 重试次数 |
| `--cloudflare-retry-delay` | 3 | Cloudflare curl 重试间隔 |
| `--cloudflare-outer-timeout` | 180 | Cloudflare curl 外层进程时限 |
| `--soak-sample-interval` | 60 | soak 资源采样间隔 |
| `--netem-watchdog` | 300 | netem 自动清理 watchdog |

`scripts/docker_modes.py`：

| 参数 | 默认值 | 用途 |
|---|---:|---|
| `--watchdog` | 180 | 容器测试时限 |
| `--watchdog-grace` | 10 | 宿主等待容器的额外时限 |
| `--command-timeout` | 30 | 通用命令与 cleanup 时限 |
| `--ssh-connect-timeout` | 10 | SSH 建连时限 |
| `--iperf-stop-timeout` | 10 | iperf3 停止时限 |
| `--iperf-start-timeout` | 15 | iperf3 启动时限 |
| `--iperf-client-timeout` | 15 | iperf3 client 时限 |
| `--image-build-timeout` | 300 | Docker image 构建时限 |
| `--image-inspect-timeout` | 30 | Docker image 检查时限 |
| `--scp-timeout` | 180 | binary 下载时限 |
| `--server-log-scp-timeout` | 15 | server log 下载时限 |
| `--progress-interval` | 5 | 容器进度轮询间隔 |

`scripts/sync_remote.py`：

| 参数 | 默认值 | 用途 |
|---|---:|---|
| `--connect-timeout` | 10 | SSH 建连时限 |
| `--command-timeout` | 120 | 默认命令时限 |
| `--status-timeout` | 30 | 远端状态查询时限 |
| `--bundle-timeout` | 120 | bundle 创建时限；未指定时跟随 `--command-timeout` |
| `--transfer-timeout` | 120 | bundle 上传时限；未指定时跟随 `--command-timeout` |
| `--sync-timeout` | 60 | 远端 fetch/merge 时限 |
| `--cleanup-timeout` | 15 | 失败清理时限 |
| `--build-timeout` | 600 | 远端单线程构建时限 |

默认值适合当前 30 Mbps 跨洋链路。只有已保存失败证据且确认属于网络延迟时才增大超时；不得通过放宽 watchdog 掩盖 deadlock。使用 `--help` 查看当前脚本实际参数。

## 11. 失败处理

失败样本不得删除或并入成功统计。依次检查：

1. curl exit、HTTP code、实际字节、SHA-256。
2. client/server handshake、ALPN、listener 和 fallback。
3. 首流是否早于 DNS resolve 或 QUIC handshake 完成。
4. stream open 是否出现 `NGTCP2_ERR_STREAM_ID_BLOCKED`，pending queue 是否 drain。
5. `UnackedBuf` callback 是否 exactly once，timer cancel 是否误删发送队列。
6. stream close 是否返还 flow-control credit 并发送 `STOP_SENDING`。
7. loss/PTO timer、UDP socket errors、kernel drops 和 CPU 饱和情况。
8. 区分公网/CDN 波动、测试工具错误与产品错误。

修复后先跑本地完整门禁，再使用新 commit、新 run ID 重跑失败组。

## 12. Cleanup 门禁

本地：

```bash
docker ps -a --filter 'name=trojan-' --format '{{.Names}} {{.Status}}'
lsof -nP -iTCP:9080 -sTCP:LISTEN
lsof -nP -iTCP:9081 -sTCP:LISTEN
```

远端：

```bash
ssh -p <SSH_PORT> <SSH_USER>@<REMOTE_HOST> \
  "ss -lntup | grep -E ':(3443|5201|8001) ' || true; pgrep -af '<REMOTE_REPO>/build/trojan|iperf3 -s -p 5201|bytesource.py' || true"
```

期望无本轮容器、listener、进程、route、iptables、TUN、namespace 或临时私钥遗留。远端临时目录仅按 `results/<run_id>/metadata/trojan-deploy.json` 中 `remote_dir` 精确删除。
