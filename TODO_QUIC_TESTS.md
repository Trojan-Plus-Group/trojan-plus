# QUIC 测试覆盖缺口 TODO

## 工作流程规范

**每修复一个缺口条目后，必须执行以下步骤，直到全部测试通过才能算完成：**

1. 修改测试代码或实现代码
2. 重新编译（如果修改了 C++ 源码）：`cd build && make -j$(sysctl -n hw.ncpu)`
3. 运行完整 QUIC 测试套件：`python3 fulltest_main.py ../../build/trojan -q`
4. 如果有测试失败，分析原因并修复代码（测试代码或实现代码均可能需要改），重回第 2 步
5. 所有测试通过后，将对应条目标记为 `[x] ✅ 已修复`

---

## 如何单独运行 QUIC 测试

```bash
cd tests/LinuxFullTest/

# 运行前先生成测试文件（如果还没有）
python3 fulltest_main.py /path/to/build/trojan -g

# 仅运行 QUIC 相关测试（使用 -q 参数）
python3 fulltest_main.py /path/to/build/trojan -q

# macOS 示例
python3 -m pip install PySocks psutil dnspython --break-system-packages
python3 fulltest_main.py ../../build/trojan -g
python3 fulltest_main.py ../../build/trojan -q
```

`-q` 参数对应 `fulltest_main.py` 第 425 行，最终调用 `fulltest_quic.main(binary_path)`，
运行 `tests/LinuxFullTest/fulltest_quic.py` 中定义的 7 个测试用例（T1–T5、T7、T8）。

---

## 现有测试用例（已覆盖）

| 编号 | 函数 | 内容 |
|------|------|------|
| T1 | `test_e2e_basic_proxy` | QUIC 握手 + HTTP GET 代理，字节级内容比对 |
| T2 | `test_e2e_multistream` | 单连接上 8 个并发双向流 |
| T3 | `test_e2e_post_data` | HTTP POST 数据通过 QUIC 代理传输 |
| T4 | `test_h3_upstream_fallback` | 非 Trojan 流量转发到 UDP h3_upstream |
| T5 | `test_idle_timeout` | 空闲超时触发 `NGTCP2_ERR_IDLE_CLOSE` |
| T6 | `test_h3_upstream_unconfigured_drop` | `h3_upstream=""` 时非 Trojan 流量被优雅丢弃，服务端不崩溃 |
| T7 | `test_alpn_negotiation` | ALPN 令牌出现在日志中（两端都验证） |
| T8 | `test_quic_disabled` | `quic.enabled=false` 回退 TLS 并验证数据完整性 |
| T9 | `test_client_retry_no_server` | `retry_connect_timeout_ms>0` 触发重连日志；`=0` 时不重连 |
| T10 | `test_prefer_quic_false` | `prefer_quic=false` 时数据走 TLS，服务端无 QuicProxySession |
| T11 | `test_tcp_target_unreachable` | TCP 目标不可达时会话正常销毁，不挂起 |
| T12 | `test_large_file_transfer` | 300 KB 文件传输，触发 256 KB 流窗口回压重试路径 |
| T13 | `test_h3_upstream_dns_failure` | h3_upstream 主机名 DNS 失败 → 记录错误，服务端不崩溃 |
| T14 | `test_multiple_quic_connections` | 两个独立客户端同时连接同一服务端，验证 CID 路由表并发正确性 |

---

## 待修复：测试覆盖缺口

### 🔴 严重（核心功能路径未覆盖）

#### [x] T6 测试用例缺失 ✅ 已修复
- **修复**：新增 `test_h3_upstream_unconfigured_drop`，测试 `h3_upstream=""` 时非 Trojan 流量被优雅丢弃。
- **验证点**：服务端日志出现 `"h3_upstream not configured, dropping"`，且服务端进程未崩溃。
- **相关文件**：`tests/LinuxFullTest/fulltest_quic.py`

#### [x] h3_upstream 响应回路未验证 ✅ 已修复
- **测试修复**：T4 现在捕获 `http_get_via_socks5` 的返回值，并断言响应体包含 `"H3 Upstream Fallback!"`；
  同时新增对 mock 日志 `"sent response"` 的检查，确保 UDP 响应已发出。
- **实现 bug 一并修复**（两次迭代）：
  - **第一阶段**（2026-05-06）：`QuicProxySession::on_stream_data()`
    在 `m_upstream_forwarding=true` 但 UDP socket 尚未打开时（DNS resolve 异步进行中），
    会对未开启的 socket 调用 `send_to()` 导致数据静默丢失。修复：在
    `m_udp_socket.is_open()` 为 false 时跳过发送，保留 `m_recv_buf` 内容，
    等 resolve 回调就绪后统一发送。
  - **第二阶段**（2026-05-06）：T4 在完整测试套件中偶发失败。
    根因：客户端 QUIC stream FIN 先于 h3mock UDP 响应到达，`on_stream_close()`
    调用 `destroy()` 关闭 UDP socket，导致响应丢失。
    修复：新增 `m_waiting_h3_response` 和 `m_stream_fin_received` 标志。
    `on_stream_close()` 检测到正在等待 h3_upstream 响应时延迟 destroy；
    `udp_read()` 收到 UDP 响应后若检测到 `m_stream_fin_received=true` 才真正 destroy。
    同时 Windows WSAECONNRESET（10054）在 `udp_read()` 中被正确处理——
    若错误伴随有效数据（`bytes > 0`），仍处理数据后重试 receive，不破坏连接。
- **相关文件**：`src/quic/quic_session.cpp`（T4），`src/quic/quic_session.h`，
  `tests/LinuxFullTest/fulltest_quic.py`（T4），`tests/LinuxFullTest/fulltest_quic_h3mock.py`

#### [x] h3_upstream 未配置时的 drop 路径 ✅ 已修复（由 T6 覆盖）
- **修复**：T6（`test_h3_upstream_unconfigured_drop`）完整覆盖此路径：
  服务端 `h3_upstream=""`，客户端使用错误密码触发 `forward_to_h3_upstream()`，
  验证服务端日志出现 `"h3_upstream not configured, dropping"` 且进程未崩溃。
- **相关文件**：`src/quic/quic_session.cpp:136`，`tests/LinuxFullTest/fulltest_quic.py`（T6）

#### [ ] 无 CRLF fallback（kMaxPasswordLineBytes 边界）
- **问题**：`QuicProxySession::try_parse_request()`（`src/quic/quic_session.cpp:91`）
  当缓冲区超过 `kMaxPasswordLineBytes`（= `Config::MAX_PASSWORD_LENGTH` = 128 字节）
  且没有 `\r\n` 时，会 fallback 到 h3_upstream（或 drop）。这个边界从未被触发测试。
- **为何暂跳过**：测试需要向服务端的 QUIC 流直接注入超过 128 字节的无换行裸字节。
  现有 Python 测试框架通过正常 trojan 客户端转发，客户端始终会插入正确的 `\r\n`。
  实现此测试需要 Python 层的 QUIC 库（如 `aioquic`）直接发送原始 QUIC 流数据，
  或修改测试客户端支持"原始字节注入"模式。
- **建议后续修复**：引入 `aioquic` 依赖后，新增 T15：直接建立 QUIC 连接并发送
  129+ 字节的无换行数据，验证服务端日志出现 `"no CRLF in"` 并正确 fallback。

---

### 🟠 重要（可靠性相关）

#### [x] 客户端断线重连逻辑（DNS 失败路径）✅ 已修复（T9 覆盖 retry_ms>0 和 =0 分支）
- **修复**：T9（`test_client_retry_no_server`）使用不可解析的 `.invalid` 主机名触发
  DNS 失败 → `mark_unreachable()`。分两部分验证：Part A `retry_ms=500` 应见
  `"retrying QUIC connection"` 日志；Part B `retry_ms=0` 必须不出现该日志。
- **相关文件**：`src/quic/quic_client_endpoint.cpp:112`，`tests/LinuxFullTest/fulltest_quic.py`（T9）
- **仍未覆盖**：启动后关闭服务端再重启、验证客户端重新建立连接（T_RECONNECT）——
  需要实现连接断开后自动重连逻辑，当前代码中 `mark_unreachable` 只在连接建立阶段调用。

#### [x] `prefer_quic: false` 的传输路径选择 ✅ 已修复（T10 覆盖）
- **修复**：T10（`test_prefer_quic_false`）配置 `enabled=true, prefer_quic=false`，
  发送 HTTP GET，验证：① 数据正确返回（TLS 路径有效）；
  ② 服务端日志中无 `QuicProxySession: stream \d+ opened`（代理请求未走 QUIC 流）。
- **相关文件**：`src/quic/outbound_transport.cpp:323`，`tests/LinuxFullTest/fulltest_quic.py`（T10）

#### [x] TCP 目标不可达时的会话清理 ✅ 已修复（T11 覆盖）
- **修复**：T11（`test_tcp_target_unreachable`）请求目标为 `127.0.0.1:DEAD_TARGET_PORT`，
  服务端 `connect_target()` 收到 connection-refused → `destroy()`。
  验证：① 服务端日志出现 `"target unreachable|connect.*failed"`；
  ② 客户端不挂起（12 秒内失败）；③ 服务端进程存活。
- **相关文件**：`src/quic/quic_session.cpp:259`，`tests/LinuxFullTest/fulltest_quic.py`（T11）

#### [x] 流控背压（大文件传输）✅ 已修复（T12 覆盖）
- **修复**：T12（`test_large_file_transfer`）在 `html/` 目录生成 300 KB 测试文件
  （`quic_large_test.bin`，超过 256 KB 流窗口），通过 QUIC 传输并进行字节级比对。
  若 `flush_tcp_read_buf()` 的重试路径有问题，内容会不完整或传输会超时。
- **相关文件**：`src/quic/quic_session.cpp:361`，`tests/LinuxFullTest/fulltest_quic.py`（T12）

---

### 🟡 次要（边界场景）

#### [x] 多个独立 QUIC 连接并发 ✅ 已修复（T14 覆盖）
- **修复**：T14（`test_multiple_quic_connections`）启动两个独立的 trojan 客户端进程
  （分别监听 SOCKS5 端口 10621 和 10622），同时发起请求，两者并发传输不同文件，
  字节级验证，确认 `m_conns` 路由表正确处理多个并发连接 ID。
- **相关文件**：`src/quic/quic_server_endpoint.cpp`，`tests/LinuxFullTest/fulltest_quic.py`（T14）

#### [x] DNS 解析失败路径 ✅ 已修复（T9 + T13 覆盖）
- **修复**：
  - T9 覆盖 `QuicClientEndpoint::connect_to_server()` DNS 失败 → `mark_unreachable()`。
  - T13（`test_h3_upstream_dns_failure`）：`h3_upstream` 配置为不可解析主机名，
    错误密码触发 `forward_to_h3_upstream()` → DNS 失败 → `destroy()`。
    验证服务端日志 `"h3_upstream UDP resolve failed"` 且进程存活。
- **相关文件**：`src/quic/quic_client_endpoint.cpp:62`，`src/quic/quic_session.cpp:176`，`tests/LinuxFullTest/fulltest_quic.py`（T9, T13）

#### [ ] IPv6 端点
- **问题**：`fill_sockaddr_union()`（`src/quic/quic_connection.cpp:34`）和
  `pump_write()`（`src/quic/quic_connection.cpp:414`）均有 IPv6 分支，
  但所有测试仅使用 `127.0.0.1`。

#### [ ] `max_concurrent_streams` 上限强制
- **问题**：transport params 设置了 `initial_max_streams_bidi = 100`，
  但没有测试逼近或超过这个上限，验证服务端能正确拒绝第 101 个流。

#### [ ] 连接 ID 轮换后的路由
- **问题**：`on_new_connection_id_cb`（`src/quic/quic_server_endpoint.cpp:139`）
  正确地把新 CID 插入路由表，但没有测试明确触发 CID 轮换后发送数据，
  验证后续包依然路由到正确连接。

---

## 参考文件位置

| 文件 | 说明 |
|------|------|
| `tests/LinuxFullTest/fulltest_quic.py` | QUIC 集成测试主文件 |
| `tests/LinuxFullTest/fulltest_quic_h3mock.py` | h3_upstream UDP Mock 服务端 |
| `tests/LinuxFullTest/fulltest_main.py` | 测试入口，`-q` 参数在第 425 行 |
| `tests/LinuxFullTest/config/quic_server_config.json` | 服务端基础配置 |
| `tests/LinuxFullTest/config/quic_client_config.json` | 客户端基础配置 |
| `src/quic/quic_session.cpp` | `QuicProxySession` 实现，含认证/h3_upstream逻辑 |
| `src/quic/quic_connection.cpp` | ngtcp2 封装，含握手/流控/定时器 |
| `src/quic/quic_client_endpoint.cpp` | 客户端端点，含断线重连逻辑 |
| `src/quic/quic_server_endpoint.cpp` | 服务端端点，含 CID 路由表 |
