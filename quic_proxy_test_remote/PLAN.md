# Trojan Plus QUIC 远程性能调查计划

## 1. 目标

在不先猜测代码根因的前提下，建立可重复、可对照、可观测的北京客户端到美国服务器测试环境，回答以下问题：

1. 客户端与服务器间 TCP、UDP 原始网络能力分别是多少。
2. 直连、Trojan TCP TLS、Trojan QUIC 三种路径的吞吐、延迟、CPU 和内存差异是多少。
3. QUIC 慢发生在公网 UDP、QUIC 拥塞控制、流控、socket buffer、应用层重试，还是目标网站路径。
4. 修复后是否提升吞吐，且不引入正确性、延迟、内存泄漏和并发回归。

首轮只建立环境和采集基线。未获得证据前不修改 QUIC 实现。

## 2. 已确认环境

### 本地客户端

- 系统：macOS 26.5。
- 仓库：`fix_quic` 分支，提交 `f8bb047 fix compiling error for gcc14`。
- 可用工具：`cmake`、`iperf3`、`speedtest`、`curl`、`python3`、`tcpdump`。
- 工作目录：`/Users/tianzhizhi/Documents/trojan-project/trojan-plus`。

### 远程服务器

- SSH：`ssh -p 9922 root@172.236.226.35`。
- 系统：CentOS Stream 10，Linux 6.12。
- 仓库：`/root/trojan-plus`，同为 `fix_quic@f8bb047`，工作树干净。
- `/root/trojan-plus/build/trojan` 已存在，版本 `10.3.0`，QUIC 已启用。
- 可用工具：`cmake`、`make`、`gcc`、`g++`、`iperf3`、`curl`、`python3`、`ss`、`tcpdump`、`tc`。
- 缺少：`speedtest`、`perf`。
- `firewalld` 未运行。
- 当前无 `3443`、`5201` 监听。
- UDP socket 系统上限：

```text
net.core.rmem_max = 212992
net.core.wmem_max = 212992
net.core.rmem_default = 212992
net.core.wmem_default = 212992
```

执行阶段允许安装诊断工具、临时开放测试端口。仍需确认云防火墙允许：

- `3443/TCP`
- `3443/UDP`
- `5201/TCP`
- `5201/UDP`

## 3. 现有测试覆盖与缺口

`tests/LinuxFullTest/fulltest_quic.py` 已覆盖握手、SOCKS5、并发 stream、POST、HTTP/3 fallback、idle timeout、ALPN、TCP fallback、连接重试、大文件、DNS 失败、双客户端、错误输入、负载/RSS、server restart、TCP/UDP close、keepalive。

现有测试不足以诊断跨洋吞吐：

- 全部运行在 localhost。
- 大文件测试仅约 300 KiB。
- 无 TCP/QUIC 同条件 A/B。
- 无 RTT、loss、jitter、reordering、MTU 和 UDP policing 场景。
- 无 cwnd、bytes-in-flight、PTO、重传和 kernel UDP drop 指标。
- T16 只做 RSS 百分比比较，不是严格 leak test。
- `log_level: 0` 产生逐 ACK、逐 buffer 日志，会污染性能结果。

## 4. 静态调查发现：待验证假设

以下只是实验假设，不作为修复结论。

### H1：UDP socket buffer 太小

配置默认值位于 `src/core/config.cpp:229`：

```text
max_datagram_size = 1200
recv_buffer_size = 1200 * 64 = 76800
send_buffer_size = 1200 * 64 = 76800
```

socket 设置位于 `src/quic/quic_endpoint.cpp:70`。默认约 75 KiB，远小于典型跨洋高带宽链路 BDP。代码也未读取内核实际生效值。

### H2：单 stream 流控窗口限制高 RTT 吞吐

QUIC transport parameters 位于 `src/quic/quic_connection.cpp:374` 和 `src/quic/quic_connection.cpp:484`：

- server bidi stream：512 KiB。
- client bidi stream：1 MiB。
- connection：32 MiB。

例如 RTT 200 ms 时，512 KiB/RTT 仅约 20 Mbit/s。动态扩窗可能缓解，必须通过单流和多流对照验证。

### H3：应用发送重试退避产生吞吐空洞

`src/quic/quic_connection.cpp:704` 的重试从 50 ms 指数增长至 3000 ms。高 RTT、丢包或拥塞下可能出现 50/100/200/400/800/1600/3000 ms 周期停顿。

### H4：非阻塞 UDP 发送失败后直接丢 packet

`src/quic/quic_endpoint.cpp:163` 使用同步 `send_to`。socket 为 non-blocking；`would_block`/`ENOBUFS` 只记录警告，没有发送队列和异步重试。

### H5：receive batch 或单事件循环阻塞

`src/quic/quic_endpoint.cpp:92` 每次 readiness 最多读取 64 个 datagram，再统一 pump write。全部 UDP、QUIC、TCP upstream、timer 和日志共用单个 `io_context`。高 PPS 或详细日志可能拖延 ACK、PTO 和 TCP I/O。

### H6：拥塞控制或路径 MTU

ngtcp2 当前默认使用 CUBIC。应用未暴露拥塞算法、initial RTT、ACK threshold 或 pacing 配置。

`quic.max_datagram_size=1200` 没有设置 ngtcp2 `max_tx_udp_payload_size`；ngtcp2 默认仍可能发送 1452-byte payload。需要捕包确认实际包长并排除 MTU black hole。

### H7：配置项未生效

- `quic.max_concurrent_streams` 被解析，但 transport parameters 仍硬编码为 server 1000、client 100。
- `quic.max_datagram_size` 只用于默认 socket buffer 计算，没有映射到 ngtcp2 payload 设置。

这两项需后续独立修复，但未必是当前单流慢速根因。

## 5. 目录设计

所有新增脚本、配置模板和结果放在：

```text
quic_proxy_test_remote/
├── PLAN.md
├── client-quic.json
├── client-tcp.json
├── server.json
├── scripts/
└── results/
    └── <UTC时间>-<commit>-<run-id>/
        ├── metadata/
        ├── baseline/
        ├── direct/
        ├── tcp-tls/
        ├── quic/
        ├── logs/
        └── captures/
```

除 `PLAN.md` 外，其余文件按执行阶段逐步建立。结果目录使用 UTC 时间和 Git commit，禁止覆盖历史结果。

不要复制现有公开测试密码作为公网服务凭据。执行时生成一次性随机密码和临时测试证书；测试结束停止服务并删除远端私钥。

## 6. 测试原则

1. 客户端和服务端固定同一 commit、同一构建类型。
2. 直连、TCP TLS、QUIC 在同一时间窗口交替运行，降低公网波动影响。
3. 每组预热一次，正式运行至少五次；记录中位数、P10、P90，不只看最好结果。
4. 固定测试方向、文件大小、并发数、持续时间和日志级别。
5. 吞吐基准使用 `log_level: 1` 或 `2`；短时诊断才使用 `log_level: 0`。
6. QUIC 配置保持 `debug_disable_tcp: true`，防止测速静默回退 TCP。
7. 每次测试前确认 QUIC handshake 日志、进程 PID、监听端口和 Git commit。
8. 同时采集客户端和服务端指标；单边日志不足以定位公网 UDP 丢包。
9. 每次只改变一个变量。
10. 修改代码后先跑本地完整 QUIC 测试，再跑远程短测、压力和长稳测试。
11. 北京到美国链路质量较差；所有跨洋命令设置明确连接/总超时，并允许最多 2 次有限重试，重试间隔使用 3 秒、10 秒退避。
12. 单个带宽测试样本传输总量不得超过 50 MB，单项包含重试必须在 3 分钟内结束。
13. 超时、断流和重试均作为结果保存，不用重试后的成功样本覆盖首次失败。
14. 优先按字节数限制 TCP/HTTP 测试；UDP 按 `bitrate × duration <= 50 MB` 计算时长。

## 7. 阶段 0：准备与安全检查

### 7.1 保存元数据

两端记录：

```bash
uname -a
git status --short --branch
git rev-parse HEAD
cmake --version
iperf3 --version
curl --version
```

远端补充：

```bash
ip addr
ip route
ss -lntup
sysctl net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default
```

检查两端 UTC 时间误差。跨主机日志分析要求 NTP 正常。

### 7.2 安装诊断工具

CentOS 10 先查询包名，再安装最小集合：

```bash
dnf install -y perf sysstat
```

如果仓库无对应包，记录失败，不替换系统组件。`speedtest` 不是首轮必要依赖；公网测速以 iperf3 和固定 HTTP byte source 为主。

### 7.3 确认端口

远端启动前：

```bash
ss -lntup | grep -E ':(3443|5201)\b'
```

从本地验证 TCP 端口；UDP 不能只依赖端口扫描，必须通过 iperf3 UDP 和 QUIC handshake 验证。

测试服务只在测试窗口运行。完成后停止进程，确认端口释放。

## 8. 阶段 1：原始网络基线

### 8.1 RTT 与路径

本地执行：

```bash
ping -c 30 172.236.226.35
traceroute 172.236.226.35
```

记录 min/avg/max/stddev、丢包率和路由跳数。若 ICMP 被禁，记录该事实，不把 ICMP 失败等同于 UDP 失败。

### 8.2 iperf3 TCP

远端：

```bash
iperf3 -s -p 5201 --one-off
```

本地正向与反向，每项至少五轮。使用 `-n 50M` 限制每个样本总量，外层命令设置 170 秒硬超时和最多 2 次重试：

```bash
iperf3 -c 172.236.226.35 -p 5201 -n 50M -O 2 --get-server-output --json
iperf3 -c 172.236.226.35 -p 5201 -n 50M -O 2 -R --get-server-output --json
```

补充 1、4、8 并行流。`-n 50M` 是全部 stream 合计总量，不是每 stream 50 MB：

```bash
iperf3 -c 172.236.226.35 -p 5201 -n 50M -O 2 -P 4 --get-server-output --json
iperf3 -c 172.236.226.35 -p 5201 -n 50M -O 2 -P 8 --get-server-output --json
```

记录吞吐、retransmits、cwnd 和 CPU。单流慢、多流快通常指向单流拥塞窗口或 RTT 限制。

### 8.3 iperf3 UDP

iperf3 UDP 服务控制通道仍使用 TCP 5201，因此云防火墙需要同时允许 TCP/UDP 5201。

逐级探测 10、25、50、100、200 Mbit/s。每档动态限制时长，确保理论发送量不超过 50 MB：10M/25M/50M 使用 20/12/8 秒，100M/200M 使用 4/2 秒。弱链路首轮优先 10M、25M、50M；高档仅在低档稳定后执行：

```bash
iperf3 -c 172.236.226.35 -p 5201 -u -b 10M -t 20 -O 2 --get-server-output --json
iperf3 -c 172.236.226.35 -p 5201 -u -b 25M -t 12 -O 2 --get-server-output --json
iperf3 -c 172.236.226.35 -p 5201 -u -b 50M -t 8 -O 2 --get-server-output --json
iperf3 -c 172.236.226.35 -p 5201 -u -b 100M -t 4 --get-server-output --json
iperf3 -c 172.236.226.35 -p 5201 -u -b 200M -t 2 --get-server-output --json
```

再测反向 `-R`。记录实际吞吐、loss、jitter、out-of-order。不要用 UDP 发送目标速率作为实际带宽。

判断：

- UDP 基线已显著差于 TCP：先调查网络、云厂商和 UDP policing。
- UDP 基线正常但 QUIC 慢：重点转向 QUIC 栈、流控、socket drop 和应用层重试。

## 9. 阶段 2：部署 Trojan 对照环境

### 9.1 构建

两端使用同一命令和同一 commit。优先复用项目当前构建方式；执行前保存完整 CMake 输出。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_QUIC=ON
cmake --build build --parallel
./build/trojan --version
```

不先运行 `fulltest_quic.py` 到远端共享端口，因为它会生成文件并杀死占用测试端口的进程。

### 9.2 服务端配置

以 `quic_proxy_test/server.json` 为骨架：

- `run_type: server`
- `local_addr: 0.0.0.0`
- `local_port: 3443`
- 一次性随机密码
- 临时证书和私钥
- `quic.enabled: true`
- 首轮保持其余 QUIC 默认值
- 性能轮 `log_level: 1`

服务端同一端口监听 TCP TLS 和 UDP QUIC，可供两个客户端配置做 A/B。

### 9.3 客户端配置

建立两份配置：

- `client-quic.json`：本地 SOCKS5 `127.0.0.1:9080`，`remote_addr: 172.236.226.35`，`quic.enabled: true`，`debug_disable_tcp: true`。
- `client-tcp.json`：本地 SOCKS5 `127.0.0.1:9081`，同一远端和密码，`quic.enabled: false`。

客户端使用临时 CA 证书校验。测试 IP 与证书身份不匹配时，可在封闭测试中暂时关闭 hostname 校验，但保留证书链校验，并在结果元数据中记录。

### 9.4 启动验证

远端：

```bash
./build/trojan -c quic_proxy_test_remote/server.json -l quic_proxy_test_remote/server.log
```

本地分别启动 TCP 和 QUIC 客户端，日志独立保存。验证：

```bash
lsof -nP -iTCP:9080 -sTCP:LISTEN
lsof -nP -iTCP:9081 -sTCP:LISTEN
```

服务端验证：

```bash
ss -lntup | grep ':3443'
```

QUIC 日志必须明确出现 handshake completed 和 ALPN；任何未握手或 TCP fallback 的结果作废。

## 10. 阶段 3：SOCKS5 功能和公网速度 A/B

### 10.1 curl 命令修正

带 `&` 的 URL 必须整体引用。SOCKS5 hostname 解析使用 `--socks5-hostname` 或 `--proxy socks5h://...`。

```bash
curl --fail --show-error --location \
  --socks5-hostname 127.0.0.1:9080 \
  --output /dev/null \
  --write-out 'http=%{http_code} bytes=%{size_download} speed=%{speed_download}B/s connect=%{time_connect}s starttransfer=%{time_starttransfer}s total=%{time_total}s\n' \
  'https://speed.cloudflare.com/__down?bytes=104857600'
```

TCP TLS 对照只改 SOCKS5 端口为 `9081`。直连去掉 proxy 参数。

Cloudflare 属于第三方动态目标，结果会受 CDN 节点选择影响。它适合用户体验验证，不作为唯一根因证据。

### 10.2 speedtest

先确认本地版本参数：

```bash
speedtest --help
```

只有当前版本明确支持 `--proxy` 时再执行：

```bash
speedtest --proxy=socks5://127.0.0.1:9080
speedtest --proxy=socks5://127.0.0.1:9081
```

若不支持 SOCKS5，不替换成不透明第三方工具；使用 curl 和自建固定 byte source。

### 10.3 自建固定 HTTP byte source

在远端仅绑定 localhost 的 HTTP 服务生成固定长度响应，再由 Trojan server 访问。这样流量路径为：

```text
本地测速客户端 -> SOCKS5 -> Trojan TCP/QUIC -> 远端 localhost HTTP byte source
```

该方式消除远端到第三方 CDN 的波动，是 Trojan 吞吐主测试。下载大小：

- 1 MiB：观察启动与握手。
- 10 MiB：观察 slow start。
- 25 MiB：常规吞吐。
- 50 MiB：单样本 steady-state 上限。

长稳和内存测试通过循环 25/50 MiB 独立样本实现；每个样本单独记录，不创建超过 50 MB 的单次传输。

每个大小按直连公网目标、TCP TLS、QUIC 顺序轮换至少五次。校验返回长度和 SHA-256，禁止只测速度不测完整性。

注意：本地无法“直连”远端 localhost byte source。原始链路直连基线由 iperf3 提供；公网 URL 的直连只用于第三方体验对照。

### 10.4 并发矩阵

固定总数据量，测试并发 1、4、16、64：

- 单流吞吐。
- aggregate throughput。
- 每流完成时间 P50/P95。
- 错误数和内容校验失败数。

若单流 QUIC 慢而多流 aggregate 接近 TCP，优先验证 stream flow-control 或单流发送调度。

## 11. 阶段 4：同步观测

每次正式测试同时采集：

### 客户端

- trojan CPU、RSS、线程数、context switches。
- 接口 packet/drop/error。
- SOCKS5 请求耗时与吞吐。
- QUIC/TCP 客户端日志。
- 必要时短时 `tcpdump`。

### 服务端

```bash
pidstat -dur -p <trojan-pid> 1
ss -u -m
nstat -az
sar -n DEV,EDEV 1
```

测试前后保存：

```bash
cat /proc/net/snmp
cat /proc/net/softnet_stat
ip -s link
```

重点比较：

- `Udp: InErrors`
- `Udp: RcvbufErrors`
- `Udp: SndbufErrors`
- NIC RX/TX dropped
- softnet dropped/time_squeeze
- trojan CPU 是否单核满载
- RSS 是否持续增长

### 抓包

只在短时诊断轮抓包，避免磁盘 I/O 污染长测速：

```bash
tcpdump -i any -nn -s 128 -w <run-id>-quic.pcap 'udp port 3443'
```

记录包长分布、packet rate、明显重传/乱序和吞吐空洞。TLS keylog 属于敏感材料；仅在必要时短期生成，不提交仓库，不上传公共位置，完成后删除。

## 12. 阶段 5：不改代码的变量实验

基线稳定后，每次只改一个变量。

### 12.1 日志开销

- `log_level: 0`
- `log_level: 1`
- `log_level: 2`

若 level 0 显著慢，只说明详细日志污染 benchmark，不代表生产路径根因。

### 12.2 UDP socket buffer

客户端和服务端同时测试：

- 76,800 bytes（当前默认）
- 256 KiB
- 1 MiB
- 4 MiB
- 16 MiB

先临时提高远端和本地系统上限，再设置应用配置。每次记录 `getsockopt` 或 `ss -u -m` 可见的实际值；不能只记录请求值。

判断：buffer 增大后 kernel UDP drop 和 PTO 降低、吞吐提升，则 H1 得到支持。

### 12.3 单流与多流

- 1、4、16、64 stream。
- 每组总量固定 50 MiB，由并发 stream 平分，避免并发数增加时总流量失控。

判断：多流显著绕过单流上限，则重点验证 flow-control window 和每 stream producer 调度。

### 12.4 包大小与 MTU

先用抓包确认实际 UDP payload。后续若增加最小实验配置，再对比 1200、1350、1452。未建立有效映射前，不通过现有 `max_datagram_size` 值声称已改变发送 payload。

## 13. 阶段 6：可控网络实验

真实跨洋结果确认后，在本机或独立 Linux 测试机使用 `tc netem` 复现，不直接在 SSH 默认路由上盲目加规则，避免断开远端管理连接。

矩阵：

- RTT：20、100、200、300 ms。
- loss：0、0.01%、0.1%、0.5%、1%。
- jitter：0、10、30 ms。
- reorder：0、0.1%、1%。
- bandwidth：25、50、100、500 Mbit/s。

每次只组合必要变量，先测：

1. 200 ms / 0 loss。
2. 200 ms / 0.1% loss。
3. 300 ms / 0.1% loss。
4. 200 ms / 1% loss。

管理 SSH 与测试流量必须按 IP/port 精确分类。应用规则前保存现有 qdisc；测试后恢复并验证。

## 14. 阶段 7：最小观测代码

如果阶段 1–6 仍不能定位，再添加低频结构化指标，不先改传输行为。

优先顺序：

1. 输出 `SO_RCVBUF`/`SO_SNDBUF` 实际值及 socket send/receive error 计数。
2. 统计 rx/tx packets、bytes、receive drain 命中 64 上限次数。
3. 统计 `would_block`、`ENOBUFS` 和其他 `send_to` 错误。
4. 统计 stream queue bytes、partial write、zero-progress、retry delay 和 3000 ms abort。
5. 统计 flow-control blocked 次数和持续时间。
6. 启用 ngtcp2 qlog，或低频输出 RTT、cwnd、bytes-in-flight、loss、PTO。
7. 统计 event-loop callback/pump duration。

指标按连接每秒或每数秒聚合，禁止逐 packet INFO 日志。

## 15. 阶段 8：根据证据做单变量修复

可能实验分支按证据选择，不同时修改：

1. socket buffer 设置、错误检查与实际值日志。
2. non-blocking UDP send 的 `would_block` 重试/队列。
3. stream/connection flow-control window。
4. 应用层 retry 与 QUIC credit/congestion 事件联动。
5. receive batch 和 pump 公平性。
6. `max_datagram_size` 正确映射到 ngtcp2。
7. `max_concurrent_streams` 正确映射到 transport parameters。
8. CUBIC、Reno、BBR v2 对照。

每个实验版本都必须保留原始 baseline，使用同一测试矩阵验证。若指标不支持假设，撤销该实验，不叠加更多改动。

## 16. 每次代码修改后的门禁

### 本地功能门禁

```bash
python3 -u tests/LinuxFullTest/fulltest_quic.py build/trojan
```

随后运行项目已有完整 lint/typecheck/build/test 命令。C++ 项目当前未发现独立 typecheck；以 CMake Release 编译和现有测试脚本为准。

### 远程门禁

1. 1 MiB 正确性短测。
2. 50 MiB 单流 A/B。
3. 4/16/64 并发，每组总量 50 MiB。
4. 双向传输。
5. 30–60 分钟 steady-state，循环独立的 25/50 MiB 样本。
6. 空闲、keepalive、重连。
7. 进程 CPU/RSS、UDP drop、错误日志。

### 内存门禁

- 本地复跑 T16。
- 远端持续循环独立的 25/50 MiB 样本；单样本不得超过 50 MB。
- 采集每分钟 RSS/PSS，而非只取测试首尾。
- 停流后观察至少 5–10 分钟回落。
- 若 RSS 持续线性增长，再用 ASan/LSan 或 heap profiler 定位；不要只扩大 T16 百分比阈值。

## 17. 首轮执行顺序

1. 创建配置模板、结果目录和一次性凭据。
2. 确认云防火墙与 TCP/UDP 端口。
3. 跑 ping/traceroute、iperf3 TCP/UDP 双向基线。
4. 启动远端 Trojan server。
5. 启动本地 TCP TLS 与 QUIC 两个 SOCKS5 client。
6. 验证握手、协议和内容正确性。
7. 跑固定 byte source：1 MiB、10 MiB、25 MiB、50 MiB。
8. 跑直连公网、TCP TLS、QUIC 的 Cloudflare curl 体验对照。
9. 跑并发 1/4/16/64。
10. 同步采集 CPU、RSS、UDP errors、接口 drops 和短时抓包。
11. 汇总结果，先判断公网 UDP 是否异常。
12. 只选择证据最强的一个变量进入下一轮。

## 18. 首轮判定表

| 现象 | 优先方向 |
|---|---|
| iperf3 UDP 明显差于 TCP | 云网络、UDP policing、路径丢包、MTU |
| iperf3 UDP 正常，QUIC 单流慢，多流快 | stream flow control、producer/retry 调度 |
| QUIC 与 TCP 都慢 | 目标源、客户端、服务端 CPU 或链路基线 |
| QUIC 伴随 `RcvbufErrors` | socket buffer、event-loop receive drain |
| QUIC 伴随 `SndbufErrors`/`would_block` | UDP send queue 和错误处理 |
| 吞吐出现指数间隔空洞 | 50–3000 ms 应用 retry |
| CPU 单核满、packet rate 高 | packet size、同步 syscall、日志、event loop |
| 1200 正常、1452 异常 | 路径 MTU/fragmentation |
| 修改 buffer 无效果且无 kernel drop | 不继续扩大 buffer，转向 flow/congestion/retry |
| RSS 停流后不回落并持续增长 | leak 专项分析 |

## 19. 多运行模式对比

### 19.1 覆盖范围

客户端模式矩阵统一连接同一远端 `server`，使用同一证书、密码、目标 byte source、样本大小和网络时间窗口：

| 模式 | 本地平台 | 请求入口 | TCP TLS | 强制 QUIC | 状态 |
|---|---|---|---|---|---|
| `client` | macOS/Linux | SOCKS5 | 必测 | 必测 | 已具备 |
| `nat` | Linux Docker namespace | 精确透明 TCP | 必测 | 必测 | 待测 |
| `client_tun` | Linux Docker namespace | 单目标 `/32` TUN 路由 | 必测 | 必测 | 待测 |
| `forward` | - | - | - | - | [-] 按用户范围排除，不测试、不规划 |

`server` 是三个客户端模式共同远端，不作为客户端吞吐模式。范围仅包含 `client`、`nat`、`client_tun`；`forward` 明确排除。Linux 模式使用独立 Docker network namespace、`NET_ADMIN` 和 `/dev/net/tun`。

### 19.2 强制 QUIC 规则

TCP TLS 与 QUIC 分为独立 server run：

- TCP TLS：client 使用 `quic.enabled=false`，server 使用 `debug_disable_tcp=false`；远端 `3443/TCP` listener 必须存在。
- 强制 QUIC：client 和 server 均设置 `quic.enabled=true`、`debug_disable_tcp=true`；远端 `3443/UDP` listener 必须存在，`3443/TCP` listener 必须不存在。
- 每个 QUIC run 必须保存 handshake completed、ALPN `h3` 和 listener 验证。
- 任何 TCP listener 存在、TCP fallback 或未完成 QUIC handshake 的 QUIC 样本作废。

### 19.3 Docker `nat` 与 `client_tun`

宿主先将 `speed.cloudflare.com` 严格解析为单个公网 IPv4，并传入容器。容器固定请求 `https://speed.cloudflare.com/__down?bytes=1048576`，curl 使用 `--resolve speed.cloudflare.com:443:<IP>`：

- `nat`：容器内 NAT 规则仅匹配目标 `<IP>/32`、TCP、dport 443，并重定向到本地 NAT listener。
- `client_tun`：`redirect_local=false`，仅将目标 `<IP>/32` 路由到 `tun0`，不修改默认路由。
- Trojan server `172.236.226.35:3443` 不匹配目标路由，保持自然直连，避免递归。
- 目标请求由 Trojan server 正常连接 Cloudflare；远端不启动或访问 8001，不安装或修改 iptables/nft。
- 每个容器使用独立 network namespace、`NET_ADMIN`、`/dev/net/tun` 和 watchdog；`finally` 强制删除容器。
- 远端只停止 Trojan server 并删除临时证书目录，无远端防火墙清理。

### 19.4 当前执行状态与交接

截至 `2026-09-05`：

- `client` 强制 QUIC/TCP TLS 固定源五轮和并发矩阵已完成，见 R14。
- `forward` 按用户范围排除；曾完成的临时结果不纳入最终多模式验收。
- Docker Desktop 能力已确认：Linux amd64、`NET_ADMIN`、`/dev/net/tun`、iptables/nftables 和远端网络可用。
- Docker NAT TCP smoke 已通过：`20260905T120000Z-17d3b53-r16`，Cloudflare 1 MiB，HTTP 200、大小正确、清理完成。
- Docker NAT 强制 QUIC smoke 已通过：`20260905T021733Z-17d3b53-r16`，Cloudflare 1 MiB，HTTP 200、大小正确、清理完成。
- Docker `client_tun` TCP smoke `20260905T021836Z-17d3b53-r16` 未完成，错误为 `Device for nexthop is not up`。下一步应在 `docker-entry.sh` 中等待 `tun0` 后先执行 `ip link set tun0 up`，再添加目标 `/32` route，并保存 `ip -s link` 与 route evidence。
- `client_tun` 强制 QUIC 尚未执行。
- 远端不使用或开放 `8001`；Docker NAT/TUN 目标统一为固定 Cloudflare IPv4 + `--resolve`。
- 远端曾为早期 8001 方案临时安装 `nftables`，已卸载；临时 nft table、8001 listener、Trojan process 和部署目录均已清理。
- 产品 `server_tun` 已按用户要求从代码删除；当前删除改动尚未提交。
- 当前本地工作树包含 Docker harness、`server_tun` 删除和本节文档更新，尚未提交。当前 HEAD 为 `17d3b53`。

下一 session 顺序：

1. 修复 `client_tun` 的 `tun0` link-up/route 顺序。
2. 跑 `client_tun` TCP TLS 和强制 QUIC smoke。
3. 将 NAT/client_tun 每种 transport 扩展到五轮，再按需增加 1/4/16/64 并发。
4. 运行 Release、normal、Docker TUN、QUIC 回归。
5. 检查远端无 `3443/8001/5201` listener、无临时部署；提交本地 `fix_quic`，再 fast-forward 同步远端。

### 19.5 多模式验收

每种可运行模式至少满足：

- TCP TLS 与强制 QUIC 各五个有效正式样本。
- 1/4/16/64 并发无失败。
- 单组总量不超过 50 MB，单项含重试不超过 3 分钟。
- Docker Cloudflare 样本要求 curl exit 0、HTTP 200、`size_download=1048576` 且文件大小为 1048576；不做 SHA。
- QUIC server 无 TCP listener，日志确认 ALPN `h3`；TCP 使用普通 server。
- CPU、RSS/PSS、UDP errors 和 cleanup 证据完整。
- Linux NAT/TUN 容器销毁后无容器、route、iptables、TUN 或 namespace 遗留。

## 20. 完成标准

修复只有同时满足以下条件才可接受：

- 远程 QUIC 单流和 aggregate throughput 有稳定、可重复提升。
- 与原始网络能力及 TCP TLS 差距得到量化解释。
- 1/10/25/50 MiB 内容完整性无错误，长稳循环中每个样本独立校验。
- 1/4/16/64 并发无 stream open、close 或 fallback 回归。
- localhost 全量 QUIC 测试通过。
- 跨洋短测、长稳、空闲恢复和双向传输通过。
- CPU、RSS、UDP drops、P95 延迟不出现不可接受回归。
- 测试结果、命令、配置、commit 和环境参数可复现。
