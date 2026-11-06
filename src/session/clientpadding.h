#pragma once

#include "core/log.h"
#include "core/utils.h"
#include "proto/padding.h"
#include "proto/trojanrequest.h"
#include "quic/outbound_transport.h"
#include <memory>
#include <mutex>
#include <new>

// Process-wide capability memory; session state itself stays on its event loop.
class ClientPadding {
    static tp::map<tp::string, bool>& capabilities() {
        static tp::map<tp::string, bool> memo;
        return memo;
    }
    static std::mutex& mutex() {
        static std::mutex lock;
        return lock;
    }
    tp::string key;
    tp::string header;
    tp::string replay;
    static constexpr size_t replay_limit = 64 * 1024;
    bool retryable{true};
    s2::Encoder encoder;
    s2::Decoder decoder;
    bool active{false};
    bool retried{false};
    bool received_data{false};

    void remember(bool supported) {
        std::lock_guard<std::mutex> lock(mutex());
        auto& memo = capabilities();
        auto it = memo.find(key);
        if (it == memo.end() || it->second != supported) {
            memo[key] = supported;
            Log::log_with_date_time("S2 capability " + key + (supported ? " padded" : " legacy"), Log::INFO);
        }
    }

  public:
    bool enabled() const { return active; }
    void begin(const tp::string& host, uint16_t port, bool enable, uint32_t budget, uint32_t flush_limit = 8) {
        key = format_host_port(host, port);
        std::lock_guard<std::mutex> lock(mutex());
        auto it = capabilities().find(key);
        active = enable && !retried && (it == capabilities().end() || it->second);
        encoder = s2::Encoder(budget, flush_limit);
        decoder = s2::Decoder();
    }
    bool encode(std::string_view data, bool request, tp::vector<tp::string>& flushes) {
        tp::string prefix;
        if (request && active) {
            TrojanRequest req;
            const int length = req.parse(data);
            if (length <= 0 || req.command != TrojanRequest::CONNECT) return false;
            header.assign(data.data(), length);
            prefix = header;
            prefix[prefix.find("\r\n") + 2] = TrojanRequest::CONNECT_PADDED;
            data.remove_prefix(length);
        }
        if (!active) {
            flushes.emplace_back(data.data(), data.size());
            return true;
        }
        if (!decoder.saw_data() && !received_data && retryable && !data.empty()) {
            if (data.size() > replay_limit - replay.size()) {
                tp::string().swap(replay);
                retryable = false;
                Log::log_with_date_time("S2 replay cap reached (64 KiB); legacy retry disabled for " + key, Log::INFO);
            } else {
                replay.append(data.data(), data.size());
            }
        }
        auto result = encoder.encode(data, {prefix.data(), prefix.size()});
        if (!result.success) return false;
        flushes = std::move(result.flushes);
        return true;
    }
    bool decode(std::string_view data, tp::string& plain) {
        if (!active) {
            plain.assign(data.data(), data.size());
            return true;
        }
        auto result = decoder.decode(data);
        if (decoder.saw_data() || (result.success && !result.data.empty())) {
            received_data = true;
            tp::string().swap(replay);
            header.clear();
            if (result.success) remember(true);
        }
        if (!result.success) return false;
        plain = std::move(result.data);
        return true;
    }
    bool fallback(tp::string& request) {
        if (!active || retried || decoder.saw_data() || received_data) return false;
        remember(false);
        active = false;
        retried = true;
        if (!retryable) return false;
        try {
            request = std::move(header);
            request.append(replay);
        } catch (const std::bad_alloc&) {
            return false;
        }
        tp::string().swap(replay);
        return true;
    }
};

// Keep each padding flush as its own transport write and retain all buffers until completion.
inline void client_padding_write(std::shared_ptr<OutboundTransport> out, tp::vector<tp::string> flushes,
                                OutboundTransport::IoHandler handler) {
    struct Write : std::enable_shared_from_this<Write> {
        std::shared_ptr<OutboundTransport> out;
        tp::vector<tp::string> flushes;
        OutboundTransport::IoHandler handler;
        size_t next{0};
        size_t sent{0};
        void run() {
            if (next == flushes.size()) {
                handler({}, sent);
                return;
            }
            auto buf = TP_MAKE_SHARED(ReadBufWithGuard);
            streambuf_append(*buf, flushes[next++]);
            auto self = shared_from_this();
            out->async_write(buf, [self, buf](boost::system::error_code ec, size_t length) {
                self->sent += length;
                if (ec) self->handler(ec, self->sent);
                else self->run();
            });
        }
    };
    auto write = TP_MAKE_SHARED(Write);
    write->out = std::move(out);
    write->flushes = std::move(flushes);
    write->handler = std::move(handler);
    write->run();
}
