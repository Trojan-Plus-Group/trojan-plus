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
- **实现 bug 一并修复**：测试过程中发现 `QuicProxySession::on_stream_data()`
  在 `m_upstream_forwarding=true` 但 UDP socket 尚未打开时（DNS resolve 异步进行中），
  会对未开启的 socket 调用 `send_to()` 导致数据静默丢失，`m_recv_buf` 被提前清空，
  使 resolve 回调发送空数据。修复：在 `m_udp_socket.is_open()` 为 false 时跳过发送，
  保留 `m_recv_buf` 内容，等 resolve 回调就绪后统一发送。
- **相关文件**：`src/quic/quic_session.cpp:61`，`tests/LinuxFullTest/fulltest_quic.py`（T4）

#### [x] h3_upstream 未配置时的 drop 路径 ✅ 已修复（由 T6 覆盖）
- **修复**：T6（`test_h3_upstream_unconfigured_drop`）完整覆盖此路径：
  服务端 `h3_upstream=""`，客户端使用错误密码触发 `forward_to_h3_upstream()`，
  验证服务端日志出现 `"h3_upstream not configured, dropping"` 且进程未崩溃。
- **相关文件**：`src/quic/quic_session.cpp:136`，`tests/LinuxFullTest/fulltest_quic.py`（T6）

#### [ ] 512 字节无 CRLF fallback
- **问题**：`QuicProxySession::try_parse_request()`（`src/quic/quic_session.cpp:87`）
  当缓冲区超过 512 字节且没有 `\r\n` 时，会 fallback 到 h3_upstream（或 drop）。
  这个边界从未被触发测试。
- **建议修复**：新增测试：发送 513 字节无换行的随机数据到 QUIC 代理，验证服务端正确处理。

---

### 🟠 重要（可靠性相关）

#### [ ] 客户端断线重连逻辑
- **问题**：`QuicClientEndpoint::mark_unreachable()`（`src/quic/quic_client_endpoint.cpp:112`）
  在连接失败后启动 `retry_connect_timeout_ms` 定时器重连，配置值为 500ms，
  但从未有测试模拟服务端不可达后验证客户端会重连。
  `retry_connect_timeout_ms=0` 时跳过重试的特殊路径同样未测试。
- **建议修复**：
  - 新增 T_RETRY：先不启动服务端，只启动客户端，等待重连失败日志；
  - 新增 T_RECONNECT：启动后关闭服务端再重启，验证客户端重新建立 QUIC 连接。

#### [ ] `prefer_quic: false` 的传输路径选择
- **问题**：所有测试都使用 `prefer_quic: true`。T8 测试了 `enabled: false`，
  但没有测试 `enabled: true, prefer_quic: false` 的情况，
  此时应该走 TLS 传输而非 QUIC。
- **建议修复**：新增测试：配置 `prefer_quic: false`，发送请求，验证日志中无 `QuicConnection` 字样。

#### [ ] TCP 目标不可达时的会话清理
- **问题**：`QuicProxySession::connect_target()`（`src/quic/quic_session.cpp:221`）
  在 TCP 连接失败时调用 `destroy()`，但没有测试验证这条路径下 QUIC 流是否被正确关闭
  （是否向客户端发送 FIN）。
- **建议修复**：新增测试：配置 `remote_port` 指向一个不存在的端口，发送请求，验证不挂起。

#### [ ] 流控背压（大文件传输）
- **问题**：`QuicProxySession::flush_tcp_read_buf()`（`src/quic/quic_session.cpp:343`）
  在 `send_stream_data()` 返回 `NGTCP2_ERR_STREAM_DATA_BLOCKED` 时有 5ms 重试逻辑。
  QUIC 流窗口为 256KB（`initial_max_stream_data_bidi_*`），但没有任何测试故意发送
  超过窗口大小的数据来触发重试路径。
- **建议修复**：在 T2 或新增测试中使用 > 256KB 的文件，验证大文件能完整传输。

---

### 🟡 次要（边界场景）

#### [ ] 多个独立 QUIC 连接并发
- **问题**：T2 测试了单连接上多流，但从未测试多个客户端进程同时连接同一服务端，
  验证 `QuicServerEndpoint::m_conns` 路由表的并发插入/查找正确性。

#### [ ] DNS 解析失败路径
- **问题**：
  - `QuicClientEndpoint::connect_to_server()`（`src/quic/quic_client_endpoint.cpp:52`）
    DNS 失败 → `mark_unreachable()`：未测试。
  - `QuicProxySession::forward_to_h3_upstream()`（`src/quic/quic_session.cpp:154`）
    UDP 解析失败 → `destroy()`：未测试。

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
