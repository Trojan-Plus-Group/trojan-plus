# QUIC 本地与远程测试指南

本文件适用于 `quic_proxy_test_remote/`。进入此目录执行调查、基准、远程部署、Docker NAT/TUN 或压力测试时，先阅读本文件，再按需查阅 [PLAN.md](PLAN.md) 与 [TODO.md](TODO.md)。

## 1. 文档职责

- `AGENTS.md`：当前可执行工作流、安全规则、验收门禁。
- `PLAN.md`：设计、历史 Bug、实验假设、历次结果与结论。
- `TODO.md`：历史轮次索引、完成状态、未完成项目；内容可能陈旧，不得把其中旧 HEAD、主机或结果当作当前事实。
- `scripts/run.py`：`client` 模式、基线、并发、soak、netem 执行器。
- `scripts/docker_modes.py`：Linux Docker namespace 内 `nat`、`client_tun` 执行器。
- `results/`：只增不改的原始证据。

## 2. 每轮先重新发现环境

远端主机可能变化。开始前必须向用户确认或从当前任务配置取得以下值：

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

当前脚本仍可能包含历史默认值 `172.236.226.35`、`root`、`9922`、`/root/trojan-plus`。它们不是永久配置。若主机变化，先统一修改或参数化 `scripts/run.py`、`scripts/docker_modes.py`、`scripts/sync_remote.py`，再运行测试；禁止只改一处导致部署、SCP、SSH 指向不同主机。

每轮保存并核对：

```bash
git status --short --branch
git rev-parse HEAD
uname -a
cmake --version
iperf3 --version
curl --version
```

远端补充：

```bash
uname -a
nproc
free -h
git -C <REMOTE_REPO> status --short --branch
git -C <REMOTE_REPO> rev-parse HEAD
ss -lntup
```

本地和远端必须使用同一 commit、同一构建类型。工作树脏时在 metadata 保存 diff；不要把脏代码描述成可复现 commit。

## 3. 不可违反的安全规则

1. 允许为远程同步、阶段检查和验收创建本地 `git commit`；任何情况下不得 `git push`。
2. 禁止向 GitHub/origin push。远端同步使用 git bundle 和 fast-forward。
3. 远端若是 1 CPU/1 GB 小主机，只能：

   ```bash
   cmake --build build -j 1
   ```

   禁止 `--parallel`、`-j > 1`、并行编译或多个重负载任务同时运行。
4. 单个样本不超过 50 MB；单组不超过 5 分钟。失败和首次超时必须保存，不能用重试成功覆盖。
5. 临时密码、私钥、TLS keylog 不提交。结束后停止服务、删除远端临时私钥并核对端口。
6. netem 只按测试 IP/port 精确分类；禁止在 SSH 默认路由上盲目添加 qdisc。应用前保存规则，结束后恢复并验证。
7. `--with-iperf` 只在确认远端没有其他 iperf3 任务时使用。执行器可能停止远端 iperf3 server；默认不要启用。
8. 不得批量 `pkill`、批量删除 `/tmp/trojan-*` 或删除非本轮容器。按 run metadata 中 PID、container name、remote directory 精确清理。

## 4. Git bundle 同步

优先使用：

```bash
python3 quic_proxy_test_remote/scripts/sync_remote.py --status
python3 quic_proxy_test_remote/scripts/sync_remote.py --branch <BRANCH> --jobs 1
```

脚本调用前先检查其中 host/user/port/repo 与本轮环境一致。手工等价流程：

```bash
git bundle create /tmp/<branch>.bundle refs/heads/<branch>
scp -P <SSH_PORT> /tmp/<branch>.bundle <SSH_USER>@<REMOTE_HOST>:/tmp/
ssh -p <SSH_PORT> <SSH_USER>@<REMOTE_HOST> \
  'git -C <REMOTE_REPO> fetch /tmp/<branch>.bundle <branch> && git -C <REMOTE_REPO> merge --ff-only FETCH_HEAD && rm -f /tmp/<branch>.bundle'
```

只允许 fast-forward。远端不一致时停止并调查，不得 reset/force 覆盖。

## 5. 本地完整门禁

修改 QUIC、session、transport、runner 后依次执行：

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

macOS 跳过 DNS `-d`；脚本已有平台保护。Linux DNS/TUN 测试需要 root 时按根目录 `AGENTS.md` 执行。顶层 CTest 当前可能报告 `No tests were found`，不能替代上述集成测试。

测试脚本使用固定端口并可能清理占用进程。运行前确认 `18080`、`18083`、`9080`、`9081` 没有用户业务。

## 6. Run ID 与证据

Run ID 格式：

```text
YYYYMMDDTHHMMSSZ-<7至40位小写commit>-r<number>
```

示例：

```bash
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(git rev-parse --short HEAD)-r55"
```

每个协议、模式、配置变量使用独立 run。禁止覆盖已有 `runtime/<run_id>` 或 `results/<run_id>`。正式性能统计至少五个有效样本；短测必须标为 smoke/partial。

必须保存：commit、dirty diff、配置、命令、退出码、stdout/stderr、监听状态、handshake/ALPN、字节数/hash、失败样本、资源观测和 cleanup。

## 7. `client` TCP/强制 QUIC 对比

TCP 和强制 QUIC 必须分开 deploy：

```bash
python3 quic_proxy_test_remote/scripts/run.py prepare --run-id "$RUN_ID"
python3 quic_proxy_test_remote/scripts/run.py trojan-deploy --run-id "$RUN_ID"
```

TCP 五轮 5 MiB：

```bash
python3 quic_proxy_test_remote/scripts/run.py r2 \
  --run-id "$RUN_ID" --protocol tcp --sizes 5242880 --runs 5
```

强制 QUIC deploy 必须禁用 server TCP：

```bash
python3 quic_proxy_test_remote/scripts/run.py trojan-deploy \
  --run-id "$RUN_ID" --server-disable-tcp
python3 quic_proxy_test_remote/scripts/run.py r2 \
  --run-id "$RUN_ID" --protocol quic --sizes 5242880 --runs 5
```

强制 QUIC 样本必须满足：client/server `debug_disable_tcp=true`、远端 UDP listener 存在、TCP listener 不存在、日志含 `handshake completed` 与 ALPN `h3`。否则样本作废。

200 流压力，总量固定 50 MB：

```bash
python3 quic_proxy_test_remote/scripts/run.py concurrency \
  --run-id "$RUN_ID" --protocol <tcp|quic> \
  --streams 200 --total-bytes 50000000 --warmup 0 --runs 1
```

不要在同一 deploy 中使用 `--protocol both`；TCP server 与强制 QUIC server 的 listener 条件互斥。

## 8. Docker `nat` 与 `client_tun`

前置条件：Docker daemon 可用、`/dev/net/tun` 可访问、远端 binary 已同步构建。

```bash
docker info
test -x build/trojan
```

执行器每轮会：prepare、deploy、SCP 远端 binary、渲染配置、启动远端 server、运行隔离容器、保存结果、删除容器、停止 server、删除本轮远端临时目录。

Docker image `trojan-plus-docker-modes` 使用 `Dockerfile.template` 与 `docker-entry.sh` 内容 SHA-256 label 缓存。输入未变必须显示：

```text
Reusing Docker image trojan-plus-docker-modes (...)
```

只有这两个输入变化才允许重建。Trojan binary 通过只读 runtime volume 挂载，不应因 binary/commit 变化重建 image。

五个 5 MiB 正式样本：

```bash
python3 quic_proxy_test_remote/scripts/docker_modes.py \
  --mode <nat|client_tun> --protocol <tcp|quic> \
  --run-id "$RUN_ID" --size 5242880 \
  --requests 5 --concurrency 5 --watchdog 240
```

200 请求压力，总量 50 MB，最多 32 个活动请求：

```bash
python3 quic_proxy_test_remote/scripts/docker_modes.py \
  --mode <nat|client_tun> --protocol <tcp|quic> \
  --run-id "$RUN_ID" --size 250000 \
  --requests 200 --concurrency 32 --watchdog 240
```

执行器每 5 秒输出进度。晚高峰低吞吐不是死锁；只要 elapsed 增长、容器存活且 watchdog 未到，应继续等待。无进度输出、CPU 异常或超时才调查。

模式约束：

- `nat`：仅重定向目标公网 IPv4 `/32`、TCP dport 443；不改默认路由。
- `client_tun`：`redirect_local=false`；仅目标 `/32` 路由到 `tun0`；Trojan server 地址不得落入目标路由，防止递归。
- `forward`：当前范围明确排除，除非用户重新纳入。

## 9. 公平对比原则

1. TCP TLS 与 QUIC 使用同一 commit、证书、密码、目标、样本大小、并发数和相邻时间窗口。
2. 路径按 TCP/QUIC 交替测试，降低公网波动；晚高峰结果注明时间窗口。
3. 每次只改变一个变量。
4. 先记录 iperf3 TCP/UDP 原始基线，再解释代理吞吐；第三方 Cloudflare 只作体验/多模式入口验证，不是唯一根因证据。
5. 固定 byte source 用于 Trojan 主链路吞吐与 SHA-256 正确性；Cloudflare CDN 结果受节点选择影响。
6. 比较中位数、P10/P90、aggregate、P50/P95、失败数，不只报最好结果。
7. 详细 `log_level: 0` 只用于短诊断；性能轮用 1 或 2。

## 10. 推荐验收矩阵

| 模式 | TCP 五轮 | QUIC 五轮 | TCP 压力 | QUIC 压力 |
|---|---:|---:|---:|---:|
| `client` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/50 MB | 200 请求/50 MB |
| `nat` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/32 并发 | 200 请求/32 并发 |
| `client_tun` | 5 × 5 MiB | 5 × 5 MiB | 200 请求/32 并发 | 200 请求/32 并发 |

最低正确性要求：exit 0、HTTP 200、长度/hash 完整、零 fallback、零 crash/deadlock/unexpected reset。

资源门禁另需 CPU、RSS/PSS、UDP errors、interface drops。Docker runner 当前未完整采集逐分钟 RSS/PSS；没有这些数据时，只能宣布功能/并发/cleanup 通过，不能宣布长稳内存门禁完成。

严格长稳使用 `run.py soak`，至少 30 分钟 active + 10 分钟 cooldown，保存每分钟 RSS/PSS 和 slope。正 slope 不等于 leak；持续线性增长且停流不回落时再用 ASan/LSan 或 heap profiler。

## 11. 失败处理

失败样本立即保留并检查：

1. curl exit、HTTP code、实际字节、SHA-256。
2. client/server handshake、ALPN、listener 与 fallback。
3. 首流是否发生在 endpoint resolve/QUIC handshake 前。
4. stream open 是否 `NGTCP2_ERR_STREAM_ID_BLOCKED`，pending queue 是否 drain。
5. `UnackedBuf` callback 是否 exactly once，timer cancel 是否误删发送队列。
6. stream close 是否返还 credit 并发送 `STOP_SENDING`。
7. loss/PTO timer、UDP socket errors、kernel drops、CPU 是否饱和。
8. 失败是公网/CDN 波动、工具错误还是产品错误。

修复后先跑本地完整门禁，再用新 commit、新 run ID 重跑失败组。原失败目录保留，不修改、不删除、不并入成功统计。

## 12. Cleanup 门禁

每组后检查本地：

```bash
docker ps -a --filter 'name=trojan-' --format '{{.Names}} {{.Status}}'
lsof -nP -iTCP:9080 -sTCP:LISTEN
lsof -nP -iTCP:9081 -sTCP:LISTEN
```

远端使用本轮 host/user/port：

```bash
ssh -p <SSH_PORT> <SSH_USER>@<REMOTE_HOST> \
  "ss -lntup | grep -E ':(3443|5201|8001) ' || true; pgrep -af '<REMOTE_REPO>/build/trojan|iperf3 -s -p 5201|bytesource.py' || true"
```

期望无本轮容器、listener 或进程。远端临时目录只按 `results/<run_id>/metadata/trojan-deploy.json` 中 `remote_dir` 精确删除。

## 13. 已知历史教训

- Bug 3/4：endpoint 握手/resolve 中首流必须排队，不能误走 TCP 或提前 error。
- Bug 5：关闭未读 stream 必须返还缓存 credit，并停止 read side。
- Bug 6/8：ACK、MAX_STREAM_DATA、timer cancel 与发送队列存在重入风险；callback 必须 exactly once。
- Bug 7：stream credit 暂时耗尽必须等待 `MAX_STREAMS`，fatal open error 不得永久排队。
- wolfSSL stateful session cache 曾在约 256 次连接边界失败；长稳必须跨越该边界。
- Docker 命令长时间无输出曾被误认为卡死；执行器必须保留进度心跳。
- Docker image 不得每轮重建；只按 Dockerfile/entry 内容变化重建。
