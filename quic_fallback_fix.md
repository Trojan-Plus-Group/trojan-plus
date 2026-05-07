# QUIC Fallback (H3 → HTTP/1.1) 修复 TODO

> 背景：`QuicProxySession::try_parse_request` 判断非 Trojan 流量后 fallback 到 HTTP/1.1 upstream。
> 当前实现存在多个影响正确性和安全性的问题。本文件按修复优先级分阶段列出。

---

## 阶段一：致命 Bug（必须最先修复，不修则整条 fallback 路径不可用）

### 1.1 修复 `nghttp3_rcbuf_decref` 未配对 incref 的 UAF 问题

- **文件**：`src/quic/quic_session.cpp`，`cb_recv_header` 回调
- **问题**：在未调用 `nghttp3_rcbuf_incref` 的情况下直接调用 `nghttp3_rcbuf_decref(name)` 和 `nghttp3_rcbuf_decref(value)`，导致引用计数提前归零。nghttp3 后续再释放同一块内存时触发 double-free 或 UAF（use-after-free）。
- **修复方案**：
  - [ ] 删除 `cb_recv_header` 中的 `nghttp3_rcbuf_decref(name)` 和 `nghttp3_rcbuf_decref(value)` 两行。
  - [ ] 如果未来需要异步保留 rcbuf 内容，改为先 `nghttp3_rcbuf_incref`，使用完毕后再 `nghttp3_rcbuf_decref`。
  - [ ] 回归验证：用 ASan 或 valgrind 跑一次带 H3 fallback 的请求，确认无 heap-use-after-free 报告。

---

### 1.2 在 `on_stream_data` forwarding 分支补充 FIN 标记保存

- **文件**：`src/quic/quic_session.cpp`，`on_stream_data` 函数约第 60–68 行
- **问题**：当 `m_upstream_forwarding=true` 且 `m_h3_handler==nullptr`（TCP 还未连上）时，若此刻 `on_stream_data(..., fin=true)` 到来，`fin` 标志被静默丢弃，仅靠后续 `on_stream_close` 补救，但不同 `QuicConnection` 实现中不保证 1:1 触发。
- **修复方案**：
  - [ ] 在 `on_stream_data` 的 `if (m_upstream_forwarding)` 分支最开始补加：
    ```cpp
    if (fin) m_stream_fin_received = true;
    ```
  - [ ] 验证：模拟 TCP 连接延迟场景，客户端发单包带 FIN 的请求，确认 FIN 被正确透传到 nginx。

---

## 阶段二：协议转换正确性（伪头部转换）

### 2.1 过滤 HTTP/3 禁止的"逐跳头部"（高危：可触发 HTTP Request Smuggling）

- **文件**：`src/quic/quic_session.cpp`，`cb_recv_header` 回调
- **问题**：RFC 9114 §4.2 明确禁止 HTTP/3 请求中携带 `Connection`、`Keep-Alive`、`Proxy-Connection`、`Transfer-Encoding`、`Upgrade`。当前代码将所有常规头无过滤透传，恶意客户端构造 `Transfer-Encoding: chunked` + `Content-Length: 0` 后可对下游 nginx（或其后串联的 fastcgi/uwsgi）发起 HTTP Request Smuggling 攻击。
- **修复方案**：
  - [ ] 在 `cb_recv_header` 的常规头处理分支（`else` 块）中，添加黑名单过滤：
    ```cpp
    static const std::initializer_list<std::string_view> kForbiddenH3Headers = {
        "connection", "keep-alive", "proxy-connection",
        "transfer-encoding", "upgrade"
    };
    // name_str 已是小写（H3 规范要求），直接比较即可
    for (auto& h : kForbiddenH3Headers) {
        if (name_str == h) return 0;  // 静默丢弃
    }
    ```
  - [ ] 同时过滤掉常规 `host` 头（H3 客户端不该发，但万一有则会与 `:authority` 产生重复 Host，见 2.3）。
  - [ ] 验证：用 curl --http3 发带 `Connection: keep-alive` 的请求，确认 nginx 端收到的头中不含该字段。

---

### 2.2 修复请求体缺少 HTTP/1.1 帧边界（POST/PUT 必现失败）

- **文件**：`src/quic/quic_session.cpp`，`cb_end_headers` 和 `cb_recv_data`
- **问题**：HTTP/1.1 请求体必须由 `Content-Length` 或 `Transfer-Encoding: chunked` 框定；当前代码直接透传 DATA frame 字节，无任何帧化处理。若客户端 H3 请求本身没有 `Content-Length`，nginx 对 POST/PUT 会返回 411 Length Required 或将 body 误判为下一个 HTTP 请求（走私面）。
- **修复方案（推荐：chunked 包裹）**：
  - [ ] 在 `cb_end_headers` 中，若方法为非幂等方法（`POST`/`PUT`/`PATCH`），且常规头中没有 `Content-Length`，则追加 `Transfer-Encoding: chunked\r\n`，并设置一个内部标志 `m_chunked_body = true`。
  - [ ] 在 `cb_recv_data` 中，若 `m_chunked_body`，将每块数据用 chunked 格式包裹后再调 `m_write_cb`：
    ```
    {hex_len}\r\n{data}\r\n
    ```
  - [ ] 在 `cb_end_stream` 中，若 `m_chunked_body`，发送终止块 `0\r\n\r\n`（之后再发 FIN）。
  - [ ] 备选方案（简单但需要缓冲）：缓冲全部 body，在 `cb_end_stream` 时补写 `Content-Length`，然后一次性发送。仅适合小 body，不推荐。
  - [ ] 验证：用 curl --http3 发 POST 带 body 的请求，确认 nginx 端正确收到请求体并返回 200/201。

---

### 2.3 去重 `Host` 头（`:authority` 与常规 `host` 冲突）

- **文件**：`src/quic/quic_session.cpp`，`cb_recv_header` 和 `cb_end_headers`
- **问题**：`cb_end_headers` 中无条件追加 `Host: {m_authority}`，若客户端同时携带了常规 `host` 头，且 2.1 中的过滤未覆盖它，nginx 会收到两个 `Host`，行为未定义。
- **修复方案**：
  - [ ] 在 2.1 的黑名单过滤中增加 `"host"` 字段（强制以 `:authority` 为准）。
  - [ ] 验证：检查 nginx access log 中 Host 字段无重复。

---

### 2.4 补充必备伪头部校验

- **文件**：`src/quic/quic_session.cpp`，`cb_end_headers`
- **问题**：`cb_end_headers` 时没有验证 `:method` / `:path` / `:scheme` 是否存在，缺失时会拼出 `" / HTTP/1.1\r\n"` 等残缺起始行。
- **修复方案**：
  - [ ] 在 `cb_end_headers` 开头添加校验：
    ```cpp
    if (handler->m_method.empty() || handler->m_path.empty()) {
        // 返回错误码通知 nghttp3 终止解析
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    ```
  - [ ] 伪头部重复出现时（`cb_recv_header` 中赋值前先检查是否已有值），同样返回 `NGHTTP3_ERR_CALLBACK_FAILURE`。
  - [ ] 验证：发缺少 `:method` 的畸形 H3 请求，确认 session 优雅关闭而不是发送残缺 HTTP/1.1。

---

### 2.5 处理 `CONNECT` 方法的特殊转换

- **文件**：`src/quic/quic_session.cpp`，`cb_end_headers`
- **问题**：`CONNECT` 方法在 HTTP/3 中没有 `:path` 和 `:scheme`，目标为 `:authority`。当前代码会拼出 `"CONNECT  HTTP/1.1\r\n"`（path 为空），是非法格式。
- **修复方案**：
  - [ ] 在 `cb_end_headers` 中对 `CONNECT` 单独分支：
    ```cpp
    if (handler->m_method == "CONNECT") {
        if (handler->m_authority.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        handler->m_http1_request =
            "CONNECT " + handler->m_authority + " HTTP/1.1\r\n"
            "Host: " + handler->m_authority + "\r\n"
            "Connection: close\r\n\r\n";
    }
    ```
  - [ ] 注意 `CONNECT` 一般对应隧道语义，考虑是否需要在 fallback 路径直接拒绝（nginx non-TLS HTTP 服务器通常不处理 CONNECT），文档化决策。

---

### 2.6 头部值 CRLF 注入防御

- **文件**：`src/quic/quic_session.cpp`，`cb_recv_header`
- **问题**：虽然 nghttp3 通常拒绝含 `\r\n` 的头值，但作为纵深防御，应在写入 `m_regular_headers` 前主动检测。
- **修复方案**：
  - [ ] 在 `m_regular_headers += ...` 之前添加：
    ```cpp
    if (value_str.find_first_of("\r\n\0"sv) != tp::string::npos) {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    ```
  - [ ] 对 `m_method`、`m_path`、`m_authority` 赋值处同样添加检测（尤其 path，防止请求行注入）。

---

### 2.7 修复 `cb_end_stream` 与 `cb_stream_close` 双重发送 FIN

- **文件**：`src/quic/quic_session.cpp`，`cb_end_stream` 和 `cb_stream_close`
- **问题**：两个回调都调用 `m_write_cb(tp::string(), true)`，nghttp3 对同一流通常会顺序触发二者，导致 FIN 被入队两次，`do_tcp_write` 调用 `shutdown(SHUT_WR)` 两次（幂等但语义混乱，也多触发一次空 write_to_target）。
- **修复方案**：
  - [ ] 在 `H3UpstreamHandler` 中添加 `bool m_fin_sent{false}` 标志。
  - [ ] 在 `cb_end_stream` 中发送 FIN 并设置 `m_fin_sent = true`。
  - [ ] 在 `cb_stream_close` 中先检查 `m_fin_sent`，若已发则跳过。

---

## 阶段三：nghttp3 初始化与多路复用架构重构（根本问题）

> 注意：此阶段改动量最大，建议单独开分支，充分测试。

### 3.1 补全 nghttp3 服务端初始化（绑定 control / QPACK 流）

- **文件**：`src/quic/quic_session.cpp`，`H3UpstreamHandler` 构造函数
- **问题**：当前只调用 `nghttp3_conn_server_new` 而未绑定任何单向流，导致：
  - nghttp3 无法接收客户端的 control frame（settings 等）；
  - QPACK 动态表无法工作（已设 `qpack_max_dtable_capacity = 4096`）；
  - 任何真实 HTTP/3 客户端发来的 QPACK 编码头都会解码失败，退化为 raw 字节转发。
- **预备调研**：
  - [ ] 阅读 nghttp3 `examples/` 目录中的 server 示例，明确 `nghttp3_conn_bind_control_stream` 和 `nghttp3_conn_bind_qpack_streams` 的调用时机和所需 stream id 来源。
  - [ ] 确认 `QuicConnection` 侧如何分配单向流 id（ngtcp2 的 `ngtcp2_conn_open_unidirectional_stream`）。
- **修复方案**：
  - [ ] 在 `H3UpstreamHandler` 构造函数中，`nghttp3_conn_server_new` 成功后继续调用：
    ```cpp
    int64_t ctrl_id, qpack_enc_id, qpack_dec_id;
    // 由 QuicConnection 分配或由 H3UpstreamHandler 接受外部传入
    nghttp3_conn_bind_control_stream(conn, ctrl_id);
    nghttp3_conn_bind_qpack_streams(conn, qpack_enc_id, qpack_dec_id);
    ```
  - [ ] 注意：这些 id 需要 QuicConnection 实际打开对应的 QUIC 单向流，否则发送数据时会崩。

---

### 3.2 将 nghttp3 实例上提到 `QuicConnection` 级别（多路复用根本修复）

- **文件**：`src/quic/quic_connection.h/.cpp`，`src/quic/quic_session.h/.cpp`
- **问题**：当前每个 `QuicProxySession`（每条流）持有独立的 `nghttp3_conn`，这与 HTTP/3 协议模型不符：
  - 一个 QUIC 连接对应一个 HTTP/3 连接，共享一个 nghttp3 实例；
  - 客户端的 control stream、QPACK encoder/decoder stream 会被路由到**不同的** `QuicProxySession`，各自创建独立 nghttp3 实例，彼此状态完全隔离，QPACK 动态表永远不同步；
  - 实测效果：所有真实 H3 客户端均退化到 `m_valid=false` 的 raw 字节 fallback，HTTP/3 解码形同虚设。
- **重构方案**（建议分步实施）：

  **步骤 a**：在 `QuicConnection` 中增加一个共享 nghttp3 实例
  - [ ] `QuicConnection` 新增成员 `std::unique_ptr<nghttp3_conn, ...> m_h3_conn`，在连接建立后初始化（含 control/QPACK 流绑定）。
  - [ ] `QuicConnection` 负责接收所有 unidirectional stream 数据并 feed 进 `m_h3_conn`，根据 nghttp3 回调路由到对应的 `QuicProxySession`。

  **步骤 b**：`H3UpstreamHandler` 接收已解码的 request 事件而非原始字节
  - [ ] 将 `H3UpstreamHandler` 改为纯粹的"H3 事件 → HTTP/1.1 字符串"转换器，接口从 `feed_stream_data(raw_bytes)` 改为 `on_begin_headers()`、`on_header(name, value)`、`on_end_headers(fin)`、`on_data(chunk)`、`on_end_stream()`。
  - [ ] 删除 `H3UpstreamHandler` 中对 `nghttp3_conn` 的持有（nghttp3 上移到 `QuicConnection`）。

  **步骤 c**：处理 unidirectional stream 路由
  - [ ] 在 `QuicConnection::on_stream_data` 中，对 unidirectional stream（`stream_id & 0x2 != 0`）全部 feed 进共享 nghttp3 实例，不再分发给 `QuicProxySession`。
  - [ ] 对 bidirectional stream（`stream_id & 0x3 == 0`），先让 trojan 协议尝试解析，失败后再通过共享 nghttp3 解码并创建对应 `QuicProxySession`。

  - [ ] 完成后，删除 `H3UpstreamHandler::m_conn`（nghttp3_conn unique_ptr）及其构造/析构逻辑。

---

## 阶段四：资源管理与健壮性

### 4.1 为 h3_upstream TCP 连接添加超时

- **文件**：`src/quic/quic_session.cpp`，`forward_to_h3_upstream`
- **问题**：`async_connect` 没有 deadline，上游不可达时 QUIC stream 及 session 资源最长泄漏 60–120s（内核 SYN 重传超时）。
- **修复方案**：
  - [ ] 在 `async_resolve`/`async_connect` 之前，启动 `m_write_timer`（已有此成员）设置超时（建议 10s）：
    ```cpp
    m_write_timer.expires_after(std::chrono::seconds(10));
    m_write_timer.async_wait([this, self](const boost::system::error_code& ec) {
        if (!ec && !m_destroyed && !m_tcp_socket.is_open()) {
            _log_with_date_time("h3_upstream connect timeout", Log::WARN);
            destroy();
        }
    });
    ```
  - [ ] TCP 连接成功后 cancel timer。

---

### 4.2 h3_upstream DNS 缓存（避免每流重复解析）

- **文件**：`src/quic/quic_connection.h/.cpp`
- **问题**：每个 fallback 流都独立调 `async_resolve`，高并发下（一个 QUIC 连接多流同时 fallback）会向 DNS 发大量重复查询并创建大量 TCP 连接。
- **修复方案**：
  - [ ] 在 `QuicConnection` 中缓存已解析的 `h3_upstream` endpoints（`boost::asio::ip::tcp::resolver::results_type`），TTL 30s（用 steady_timer 过期）。
  - [ ] `QuicProxySession` 通过 `QuicConnection` 获取缓存的 endpoints，仅在缓存缺失或过期时才重新解析。

---

### 4.3 限制单连接 fallback 流数量（防止上游 DoS 放大）

- **文件**：`src/quic/quic_connection.h/.cpp`
- **问题**：当前没有限制，恶意客户端可在一个 QUIC 连接上开大量流触发大量 fallback TCP 连接，放大攻击上游 nginx。
- **修复方案**：
  - [ ] 在 `QuicConnection` 中维护 `m_active_fallback_count` 计数器。
  - [ ] 超过阈值（如 `m_config.get_quic().max_fallback_streams`，默认 32）时，新 fallback 请求直接 destroy。

---

## 验收标准（所有阶段完成后）

- [ ] ASan/valgrind 下跑完整 fallback 流程，无 heap-use-after-free / double-free 报告。
- [ ] `curl --http3 https://server/ -v` 发 GET、POST（带 body）、带自定义头的请求，均能正确到达 nginx 并返回预期响应。
- [ ] `curl --http3` 发带 `Connection: keep-alive`、`Transfer-Encoding: chunked` 头的请求，nginx 端收到的头中**不含**这些字段。
- [ ] 发缺少 `:method` 或 `:path` 的畸形 H3 请求，session 优雅关闭，无 crash，日志有明确错误信息。
- [ ] 模拟 nginx 不可达，10s 内 session 超时销毁，无资源泄漏。
- [ ] 高并发场景（100 个流同时 fallback），DNS 解析不超过 1 次/30s，TCP 连接数不超过 `max_fallback_streams`。
