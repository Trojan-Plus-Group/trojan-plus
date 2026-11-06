#pragma once

#include "core/log.h"
#include "core/utils.h"
#include "proto/padding.h"
#include "proto/trojanrequest.h"
#include "quic/outbound_transport.h"
#include <cstdio>
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
    std::unique_ptr<std::FILE, decltype(&std::fclose)> replay{nullptr, &std::fclose};
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
    void begin(const tp::string& host, uint16_t port, bool enable, uint32_t budget) {
        key = format_host_port(host, port);
        std::lock_guard<std::mutex> lock(mutex());
        auto it = capabilities().find(key);
        active = enable && !retried && (it == capabilities().end() || it->second);
        encoder = s2::Encoder(budget);
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
        if (!decoder.saw_data() && !received_data && !data.empty()) {
            if (!replay) replay.reset(std::tmpfile());
            if (!replay || std::fwrite(data.data(), 1, data.size(), replay.get()) != data.size()) return false;
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
            replay.reset();
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
        try {
            request = std::move(header);
            if (replay) {
                if (std::fflush(replay.get()) != 0 || std::fseek(replay.get(), 0, SEEK_SET) != 0) return false;
                char chunk[8192];
                for (;;) {
                    const size_t length = std::fread(chunk, 1, sizeof(chunk), replay.get());
                    request.append(chunk, length);
                    if (length != sizeof(chunk)) {
                        if (std::ferror(replay.get())) return false;
                        break;
                    }
                }
            }
        } catch (const std::bad_alloc&) {
            return false;
        }
        replay.reset();
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
