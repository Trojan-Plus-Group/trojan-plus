# 重构方案：每个 QuicConnection 共享一个 nghttp3_conn

## Context

当前 [quic_session_upstream.cpp:36-58](trojan-plus/src/quic/quic_session_upstream.cpp#L36) 在每个 `QuicUpstreamHandler` 构造函数中都新建一个独立的 `nghttp3_conn`。这违反了 nghttp3 的设计：

- **stream_id 命名空间**是 QUIC connection 级的，nghttp3 把多 stream 视为同一 connection 内的多路复用单元。
- **QPACK 动态表 (dynamic table)** 是 connection 级的，跨 stream 共享头部压缩条目。每流独立 `nghttp3_conn` 会让动态表无法共享，第二个 stream 引用前一个 stream 写入动态表的条目时会触发 QPACK 解码失败。
- **控制流 (control stream)** 与 SETTINGS 帧也是 connection 级的。

目标是抽象 `QuicToHttp3Connect` 管理类，每个 `QuicConnection` 持有一个（懒加载），所有 `QuicUpstreamHandler` 通过 `stream_id` 注册到该管理类，nghttp3 回调按 `stream_id` 路由到对应 handler。

---

## 设计要点（已与用户确认）

1. **归属**：每个 `QuicConnection` 一个 `QuicToHttp3Connect`，作为 `std::unique_ptr` 成员持有；不放在 `QuicServerEndpoint`。
2. **懒加载**：`QuicProxySession::forward_to_h1_upstream` 第一次需要 H3 时通过 `QuicConnection::get_or_create_h3()` 创建。
3. **职责拆分**：
   - `QuicToHttp3Connect`：拥有 `nghttp3_conn`、6 个静态回调、按 stream_id 路由解码事件。
   - `QuicUpstreamHandler`：保留 TCP socket 生命周期、写队列、H3→H1 转换（chunked / CONNECT / 头部）；新增 `on_h3_*` 实例方法接收已解码事件。

---

## 1. 新增文件 `src/quic/quic_to_http3_connect.{h,cpp}`

### 类骨架

```cpp
// quic_to_http3_connect.h
#ifndef _QUIC_TO_HTTP3_CONNECT_H_
#define _QUIC_TO_HTTP3_CONNECT_H_

#include <cstdint>
#include <memory>
#include <nghttp3/nghttp3.h>

#include "mem/memallocator.h"

class QuicConnection;
class QuicUpstreamHandler;

class QuicToHttp3Connect {
  public:
    explicit QuicToHttp3Connect(QuicConnection& owner);
    ~QuicToHttp3Connect();

    QuicToHttp3Connect(const QuicToHttp3Connect&)            = delete;
    QuicToHttp3Connect& operator=(const QuicToHttp3Connect&) = delete;

    [[nodiscard]] bool init();                       // 调用 nghttp3_conn_server_new
    [[nodiscard]] bool is_valid() const { return m_conn != nullptr; }

    void register_stream(int64_t stream_id, QuicUpstreamHandler* handler);
    void unregister_stream(int64_t stream_id);

    // 把 QUIC stream 字节喂给 nghttp3。返回 nghttp3 消费字节数或负的错误码。
    nghttp3_ssize feed_stream_data(int64_t stream_id, const uint8_t* data,
                                   std::size_t len, bool fin);

  private:
    QuicUpstreamHandler* find_handler(int64_t stream_id);

    static int cb_begin_headers(nghttp3_conn*, int64_t, void*, void*);
    static int cb_recv_header(nghttp3_conn*, int64_t, int32_t,
                              nghttp3_rcbuf*, nghttp3_rcbuf*, uint8_t,
                              void*, void*);
    static int cb_end_headers(nghttp3_conn*, int64_t, int, void*, void*);
    static int cb_recv_data(nghttp3_conn*, int64_t, const uint8_t*,
                            std::size_t, void*, void*);
    static int cb_end_stream(nghttp3_conn*, int64_t, void*, void*);
    static int cb_stream_close(nghttp3_conn*, int64_t, uint64_t, void*, void*);

    QuicConnection& m_owner;
    nghttp3_conn* m_conn{nullptr};
    tp::unordered_map<int64_t, QuicUpstreamHandler*> m_streams;
};

#endif
```

### 注册表使用裸指针而非 weak_ptr 的理由

- 全程单 io_context，无并发；handler 销毁与回调都在同一线程串行执行。
- `QuicConnection::m_stream_handlers` 已经持有 `shared_ptr<QuicStreamHandler>`，强引用唯一，再加 `weak_ptr` 是重复簿记。
- 协议保证：`QuicUpstreamHandler::destroy()` 必须在自己被释放前调用 `unregister_stream`（见 §3）。
- 性能上避免每次回调都做一次 lock 的原子操作。

### 回调示例（其余 5 个同模式）

```cpp
int QuicToHttp3Connect::cb_recv_header(
    nghttp3_conn*, int64_t stream_id, int32_t,
    nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t,
    void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto* h    = self->find_handler(stream_id);
    if (!h) return 0;
    auto nb = nghttp3_rcbuf_get_buf(name);
    auto vb = nghttp3_rcbuf_get_buf(value);
    return h->on_h3_header(
        tp::string(reinterpret_cast<char*>(nb.base), nb.len),
        tp::string(reinterpret_cast<char*>(vb.base), vb.len));
}
```

`init()` 中放置 [quic_session_upstream.cpp:44-49](trojan-plus/src/quic/quic_session_upstream.cpp#L44) 现有的 `nghttp3_settings`（`max_field_section_size`、`qpack_max_dtable_capacity = 4096`、`qpack_encoder_max_dtable_capacity = 4096`、`qpack_blocked_streams = 100`）。`nghttp3_conn_server_new` 的 user_data 传 `this`。

---

## 2. `QuicConnection` 改动

### 头文件 [quic_connection.h](trojan-plus/src/quic/quic_connection.h)

仅添加前向声明，不引入 nghttp3 头：

```cpp
class QuicToHttp3Connect; // fwd

// public:
QuicToHttp3Connect& get_or_create_h3();
QuicToHttp3Connect* h3_if_exists() const { return m_h3.get(); }

// private（声明顺序很重要，见下文）:
tp::unordered_map<int64_t, std::shared_ptr<QuicStreamHandler>> m_stream_handlers;
std::unique_ptr<QuicToHttp3Connect> m_h3;     // 声明在 m_stream_handlers 之后，先析构
tp::vector<uint8_t> m_write_buf;
```

`unique_ptr<incomplete>` 要求 `~QuicConnection` 在 .cpp 中定义；当前 [quic_connection.cpp:163](trojan-plus/src/quic/quic_connection.cpp#L163) 已经是 out-of-line。

### 实现 [quic_connection.cpp](trojan-plus/src/quic/quic_connection.cpp)

```cpp
#include "quic_to_http3_connect.h"

QuicToHttp3Connect& QuicConnection::get_or_create_h3() {
    if (!m_h3) {
        m_h3 = std::make_unique<QuicToHttp3Connect>(*this);
        m_h3->init();
    }
    return *m_h3;
}
```

### `set_stream_handler` 的防御性增强

为防止覆盖式赋值漏掉 unregister，在 `set_stream_handler` 内部先调用 `m_h3 ? m_h3->unregister_stream(stream_id) : void()`，再写入新 shared_ptr。这把"`m_streams` 中的裸指针必有对应 `m_stream_handlers` 中的 shared_ptr"做成结构性不变量。

### 析构顺序

成员销毁顺序按声明逆序，故 `m_h3` 先于 `m_stream_handlers` 析构。`~QuicToHttp3Connect` 内 `nghttp3_conn_del` 可能触发剩余 stream 的 close 回调；此时 `m_streams` 仍由 m_h3 自己持有但即将清空，`find_handler` 返回 null 即可，无 UAF。`m_stream_handlers` 的 shared_ptr 在 m_h3 析构后才释放，handler 仍是活的。

---

## 3. `QuicUpstreamHandler` 重构

### 头文件 [quic_session_upstream.h](trojan-plus/src/quic/quic_session_upstream.h)

**删除**：
- `m_conn`（`unique_ptr<nghttp3_conn>`，line 63）
- 6 个 `cb_*` 静态方法声明（line 46-51）
- `<nghttp3/nghttp3.h>` 头（移到 .cpp）

**新增 public 方法**（被 `QuicToHttp3Connect` 回调）：

```cpp
int on_h3_begin_headers();
int on_h3_header(const tp::string& name, const tp::string& value);
int on_h3_end_headers(bool fin);
int on_h3_data(const uint8_t* data, std::size_t len);
int on_h3_end_stream();
int on_h3_stream_close(uint64_t app_error_code);
```

返回 `int` 兼容 nghttp3 回调约定（0 OK，负值 = `NGHTTP3_ERR_CALLBACK_FAILURE`），由管理类透传给 nghttp3。

### 实现 [quic_session_upstream.cpp](trojan-plus/src/quic/quic_session_upstream.cpp)

**构造函数**：删除 [lines 36-58](trojan-plus/src/quic/quic_session_upstream.cpp#L36) 整段 callbacks/settings/`nghttp3_conn_server_new`。`m_valid` 默认 `true`，由调用方在确认 h3 manager 可用后维持。

**`on_stream_data`** 改为委托：

```cpp
void QuicUpstreamHandler::on_stream_data(const uint8_t* data, size_t len, bool fin) {
    auto locked_conn = m_conn_ptr.lock();
    if (!locked_conn || locked_conn->is_closed()) return;

    if (!m_valid) {
        if (len > 0) write_to_upstream(tp::string(reinterpret_cast<const char*>(data), len), false);
        if (fin)     write_to_upstream(tp::string(), true);
        return;
    }

    auto& h3 = locked_conn->get_or_create_h3();
    auto consumed = h3.feed_stream_data(m_stream_id, data, len, fin);
    if (consumed < 0 || (size_t)consumed < len) {
        m_valid = false; // 该流降级为 raw 透传
        if (len > 0) write_to_upstream(tp::string(reinterpret_cast<const char*>(data), len), false);
        if (fin)     write_to_upstream(tp::string(), true);
    }
}
```

**6 个旧静态回调的方法体迁移到对应实例方法**：原本 `auto* handler = static_cast<QuicUpstreamHandler*>(user_data); handler->...` 的代码段删去 cast，直接 `this->...`。chunked 编码、CONNECT 处理、`Host:`/`Connection: close` 头部拼装、fin 处理等逻辑（[lines 262-406](trojan-plus/src/quic/quic_session_upstream.cpp#L262)）保持不变。

**`destroy()`** 改动 [line 134](trojan-plus/src/quic/quic_session_upstream.cpp#L134)：

```cpp
void QuicUpstreamHandler::destroy() {
    if (m_destroyed) return;
    m_destroyed = true;

    auto locked_conn = m_conn_ptr.lock();
    if (locked_conn) {
        // 必须在 remove_stream_handler 之前 unregister，避免任何挂起回调触及悬空裸指针
        if (auto* h3 = locked_conn->h3_if_exists()) {
            h3->unregister_stream(m_stream_id);
        }
    }

    m_resolver.cancel();
    boost::system::error_code ec;
    if (m_tcp_socket.is_open()) {
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
        ec = m_tcp_socket.close(ec);
    }
    if (locked_conn) {
        locked_conn->remove_stream_handler(m_stream_id);
    }
}
```

### 降级策略

- 单 stream 帧损坏 → `feed_stream_data` 返回负值 → 该 handler `m_valid=false`，本流走 raw 透传，不影响同 connection 其它流。
- `nghttp3_conn_server_new` 失败（OOM）→ 整个 connection 不可用 → 在 `forward_to_h1_upstream` 处检测 `!h3.is_valid()`，记录错误并 destroy 该 stream（见 §4）。

---

## 4. `QuicProxySession::forward_to_h1_upstream` 改动

替换 [quic_session.cpp:187-207](trojan-plus/src/quic/quic_session.cpp#L187) 段：

```cpp
auto locked_conn = m_conn.lock();
if (!locked_conn) return;

auto& h3 = locked_conn->get_or_create_h3();
if (!h3.is_valid()) {
    _log_with_date_time("QuicProxySession: h3 manager init failed, dropping stream "
                        + tp::to_string(m_stream_id), Log::ERROR);
    destroy();
    return;
}

auto h3_handler = TP_MAKE_SHARED(QuicUpstreamHandler, locked_conn, m_stream_id,
                                 m_config, m_io_ctx, host, port_str);

// 顺序关键：先注册到 h3，再换 stream handler，保证后续 feed 的回调能查到
h3.register_stream(m_stream_id, h3_handler.get());
locked_conn->set_stream_handler(m_stream_id, h3_handler);

if (!m_recv_buf.empty()) {
    h3_handler->on_stream_data(
        reinterpret_cast<const uint8_t*>(m_recv_buf.data()),
        m_recv_buf.size(), fin);
    m_recv_buf.clear();
} else if (fin) {
    h3_handler->on_stream_data(nullptr, 0, true);
}

h3_handler->start();
```

---

## 5. 生命周期 / 线程安全

全程单 io_context、单线程串行，无锁需求。关键不变量：

1. **回调期间 handler 销毁安全**：`feed_stream_data` 同步驱动一系列 nghttp3 回调；若某回调内调用 `destroy()`，`unregister_stream` 立刻把裸指针从 `m_streams` 移除，后续同次喂数据中其他 nghttp3 事件查不到 handler 返回 0，安全。
2. **unregister 必须先于 remove_stream_handler**：`destroy()` 已遵循此顺序。
3. **QuicConnection 析构**：`m_h3` 是其 unique_ptr 成员，绑定生命周期，不可能先销毁。`QuicUpstreamHandler` 持的 `weak_ptr<QuicConnection>` 在 connection 销毁后 lock 失败，自然短路。
4. **set_stream_handler 覆盖语义**：QuicConnection 内部在赋值前先 `unregister_stream`，保证 `m_streams` 与 `m_stream_handlers` 一致。

---

## 6. CMakeLists.txt

在 [trojan-plus/CMakeLists.txt](trojan-plus/CMakeLists.txt) 现有 `src/quic/quic_*.cpp` 列表（约 line 262 附近）追加：

```cmake
src/quic/quic_to_http3_connect.cpp
```

无新链接依赖：nghttp3 已被 `quic_session_upstream.cpp` 引入。

---

## 待修改文件清单

- 新增 `trojan-plus/src/quic/quic_to_http3_connect.h`
- 新增 `trojan-plus/src/quic/quic_to_http3_connect.cpp`
- 修改 `trojan-plus/src/quic/quic_connection.h`（fwd 声明、`m_h3` 成员、`get_or_create_h3` / `h3_if_exists` 方法、声明顺序调整、`set_stream_handler` 增强签名）
- 修改 `trojan-plus/src/quic/quic_connection.cpp`（include、方法实现、`set_stream_handler` 内 unregister）
- 修改 `trojan-plus/src/quic/quic_session_upstream.h`（移除 nghttp3 成员/静态回调，新增 `on_h3_*` 接口）
- 修改 `trojan-plus/src/quic/quic_session_upstream.cpp`（构造函数瘦身、`on_stream_data` 委托、`destroy` 调用 unregister、回调方法体迁移）
- 修改 `trojan-plus/src/quic/quic_session.cpp`（`forward_to_h1_upstream` 走新流程）
- 修改 `trojan-plus/CMakeLists.txt`

---

## 7. 验证方案

### 编译

```powershell
cd trojan-plus; mkdir build; cd build; cmake ..; cmake --build . --config Release
```

注意：`unique_ptr<QuicToHttp3Connect>` 的 deleter 要求析构点能见完整类型，`~QuicConnection` 已在 .cpp 中定义；如果出现 "use of undefined type"，确认 .cpp 已 include `quic_to_http3_connect.h`。

### 单流冒烟

启动 server，配置 `h1_stream` 指向真实 H1.1 后端：

```bash
curl --http3 -k https://localhost:443/                           # 简单 GET
curl --http3 -k -X POST --data-binary @big.bin https://localhost:443/upload  # chunked POST
curl --http3 -k -p -x https://localhost:443 https://example.com/ # CONNECT
```

任一路径头部或 chunked 转换出错都会被上游以 400 返回。

### 多流复用（重构核心目的）

```bash
curl --http3 -k --parallel \
  https://localhost:443/path/a \
  https://localhost:443/path/b
```

修复前并发流可能因第二个流引用首个流写入 QPACK 动态表的条目而解码失败；修复后应同时成功。

### 全量回归

```bash
sudo python3 trojan-plus/tests/LinuxFullTest/fulltest_main.py /path/to/build/trojan -g -d 5333
```

### ASAN 生命周期检查

debug + AddressSanitizer 构建，跑大量并发短连接（`curl --max-time 1` 中断），验证 `QuicToHttp3Connect::find_handler` 与 `~QuicConnection` 期间触发的 `cb_stream_close` 无 use-after-free。
