/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "outbound_transport.h"

#include <chrono>
#include <cstring>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <memory>

#include "core/config.h"
#include "core/log.h"
#include "mem/memallocator.h"
#include "quic_client_endpoint.h"

// ─────────────────────────────────────────────────────────────
// TlsOutboundTransport – wraps boost::asio::ssl::stream<tcp::socket>
// ─────────────────────────────────────────────────────────────

class TlsOutboundTransport
    : public OutboundTransport,
      public std::enable_shared_from_this<TlsOutboundTransport> {
  public:
    using SSLSocket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

    TlsOutboundTransport(boost::asio::io_context&       io_ctx,
                         boost::asio::ssl::context&     ssl_ctx,
                         const Config&                  config,
                         boost::asio::ip::tcp::endpoint in_ep)
        : m_socket(io_ctx, ssl_ctx),
          m_resolver(io_ctx),
          m_config(config),
          m_in_ep(std::move(in_ep)),
          m_io_ctx(io_ctx) {}

    void async_connect(const tp::string& host, uint16_t port,
                       std::function<void()> on_success,
                       std::function<void()> on_error) override {
        // Apply SNI and session-reuse settings before the handshake.
        m_config.prepare_ssl_reuse(m_socket);

        auto self = shared_from_this();
        m_resolver.async_resolve(
            std::string(host.c_str()), std::to_string(port),
            [this, self, host, port,
             on_success = std::move(on_success),
             on_error   = std::move(on_error)](
                boost::system::error_code ec,
                boost::asio::ip::tcp::resolver::results_type results) mutable {
                if (ec) {
                    _log_with_endpoint(m_in_ep,
                        "TlsOutboundTransport: resolve " + host + " failed: " +
                            tp::string(ec.message().c_str()),
                        Log::WARN);
                    on_error();
                    return;
                }
                boost::asio::async_connect(
                    m_socket.next_layer(), results,
                    [this, self, host, port,
                     on_success = std::move(on_success),
                     on_error   = std::move(on_error)](
                        boost::system::error_code ec,
                        boost::asio::ip::tcp::endpoint /*ep*/) mutable {
                        if (ec) {
                            _log_with_endpoint(m_in_ep,
                                "TlsOutboundTransport: connect " + host + ':' +
                                    tp::to_string(port) + " failed: " +
                                    tp::string(ec.message().c_str()),
                                Log::WARN);
                            on_error();
                            return;
                        }
                        m_socket.async_handshake(
                            boost::asio::ssl::stream_base::client,
                            [this, self,
                             on_success = std::move(on_success),
                             on_error   = std::move(on_error)](
                                boost::system::error_code ec) mutable {
                                if (ec) {
                                    _log_with_endpoint(m_in_ep,
                                        "TlsOutboundTransport: SSL handshake failed: " +
                                            tp::string(ec.message().c_str()),
                                        Log::WARN);
                                    on_error();
                                    return;
                                }
                                _log_with_endpoint(m_in_ep, "tunnel established");
                                on_success();
                            });
                    });
            });
    }

    void async_read_some(boost::asio::mutable_buffer buf, IoHandler handler) override {
        m_socket.async_read_some(buf, std::move(handler));
    }

    void async_write(std::string_view data, IoHandler handler) override {
        // Caller captures the backing buffer in the handler closure to keep it alive.
        boost::asio::async_write(
            m_socket,
            boost::asio::buffer(data.data(), data.size()),
            std::move(handler));
    }

    void cancel() override {
        boost::system::error_code ec;
        m_resolver.cancel();
        if (m_socket.next_layer().is_open()) {
            m_socket.next_layer().cancel(ec);
        }
    }

    void close() override {
        if (!m_socket.next_layer().is_open()) {
            return;
        }
        auto self  = shared_from_this();
        auto timer = TP_MAKE_SHARED(boost::asio::steady_timer, m_io_ctx);
        auto done  = TP_MAKE_SHARED(bool, false);

        auto shutdown_cb = [self, timer, done](boost::system::error_code) {
            if (*done) return;
            *done = true;
            timer->cancel();
            boost::system::error_code ec;
            self->m_socket.next_layer().shutdown(
                boost::asio::ip::tcp::socket::shutdown_both, ec);
            self->m_socket.next_layer().close(ec);
        };

        boost::system::error_code ec;
        m_socket.next_layer().cancel(ec);
        m_socket.async_shutdown(tp::bind_mem_alloc(shutdown_cb));
        timer->expires_after(
            std::chrono::seconds(m_config.get_ssl().ssl_shutdown_wait_time));
        timer->async_wait(tp::bind_mem_alloc(shutdown_cb));
    }

    bool is_via_quic() const override { return false; }

  private:
    SSLSocket                       m_socket;
    boost::asio::ip::tcp::resolver  m_resolver;
    const Config&                   m_config;
    boost::asio::ip::tcp::endpoint  m_in_ep;
    boost::asio::io_context&        m_io_ctx;
};

// ─────────────────────────────────────────────────────────────
// QuicStreamTransport – wraps a single QUIC bidi stream
// ─────────────────────────────────────────────────────────────

class QuicStreamTransport : public OutboundTransport,
                          public std::enable_shared_from_this<QuicStreamTransport> {
  public:
    QuicStreamTransport(boost::asio::io_context& io_ctx,
                        std::shared_ptr<QuicClientEndpoint>      endpoint)
        : m_io_ctx(io_ctx), m_endpoint(endpoint), m_write_timer(io_ctx) {}

    // host/port are the trojan server coordinates but ignored here – the QUIC
    // connection to the server is already maintained by QuicClientEndpoint.
    void async_connect(const tp::string& /*host*/, uint16_t /*port*/,
                       std::function<void()> on_success,
                       std::function<void()> on_error) override {
        auto ep = m_endpoint.lock();
        if (!ep) {
            boost::asio::post(m_io_ctx, std::move(on_error));
            return;
        }

        // Register data handler before opening the stream so we never miss data.
        // We use a sentinel stream_id = -2 until the real sid is assigned.
        auto self = shared_from_this();
        auto sid  = ep->open_bidi_stream(
            [this, self, on_success = std::move(on_success),
             on_error_deferred = on_error](int64_t sid) mutable {
                auto ep = m_endpoint.lock();
                if (sid < 0 || !ep) {
                    // Endpoint returned failure inside the deferred callback.
                    boost::asio::post(m_io_ctx, std::move(on_error_deferred));
                    return;
                }
                m_stream_id = sid;
                ep->set_stream_data_handler(
                    sid, [this, self](const uint8_t* data, std::size_t len, bool fin) {
                        on_data(data, len, fin);
                    });
                // Post to avoid potential re-entrancy if called synchronously.
                boost::asio::post(m_io_ctx, std::move(on_success));
            });

        // If open_bidi_stream returned -1 immediately (endpoint not connected
        // and nothing was deferred), fire the error callback now.
        if (sid < 0 && !ep->is_connected()) {
            boost::asio::post(m_io_ctx, std::move(on_error));
        }
    }

    void async_read_some(boost::asio::mutable_buffer buf, IoHandler handler) override {
        if (!m_recv_buf.empty()) {
            std::size_t n = std::min(m_recv_buf.size(), buf.size());
            std::memcpy(buf.data(), m_recv_buf.data(), n);
            m_recv_buf.erase(0, n);

            auto ep = m_endpoint.lock();
            if (!ep) {
                boost::asio::post(m_io_ctx, tp::bind_mem_alloc([handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::broken_pipe, 0);
                }));
                return;
            }
            ep->extend_window(m_stream_id, n);

            boost::asio::post(m_io_ctx, tp::bind_mem_alloc([handler = std::move(handler), n]() mutable {
                handler({}, n);
            }));
        } else if (m_fin_received) {
            boost::asio::post(m_io_ctx, tp::bind_mem_alloc([handler = std::move(handler)]() mutable {
                handler(boost::asio::error::eof, 0);
            }));
        } else {
            m_pending_buf     = buf;
            m_pending_handler = std::move(handler);
            m_has_pending     = true;
        }
    }

    void async_write(std::string_view data, IoHandler handler) override {
        auto buf = TP_MAKE_SHARED(tp::string, data);
        do_write(buf, 0, std::move(handler));
    }

    void do_write(std::shared_ptr<tp::string> buf, std::size_t offset, IoHandler handler) {
        if (offset >= buf->size()) {
            boost::asio::post(m_io_ctx, tp::bind_mem_alloc([handler = std::move(handler), len = buf->size()]() mutable {
                handler({}, len);
            }));
            return;
        }

        auto ep = m_endpoint.lock();
        if (!ep) {
            boost::asio::post(m_io_ctx, tp::bind_mem_alloc([handler = std::move(handler)]() mutable {
                handler(boost::asio::error::broken_pipe, 0);
            }));
            return;
        }

        int64_t written = ep->send_stream_data(
            m_stream_id,
            reinterpret_cast<const uint8_t*>(buf->data() + offset),
            buf->size() - offset,
            false);

        if (written < 0) {
            boost::asio::post(m_io_ctx, tp::bind_mem_alloc([handler = std::move(handler)]() mutable {
                handler(boost::asio::error::broken_pipe, 0);
            }));
            return;
        }

        offset += written;
        if (offset < buf->size()) {
            m_write_timer.expires_after(std::chrono::milliseconds(50));
            m_write_timer.async_wait([this, self = shared_from_this(), buf, offset, h = std::move(handler)]
                                    (const boost::system::error_code& ec) mutable {
                if (!ec) {
                    do_write(buf, offset, std::move(h));
                } else {
                    h(ec, 0);
                }
            });
        } else {
            boost::asio::post(m_io_ctx, tp::bind_mem_alloc([handler = std::move(handler), len = buf->size()]() mutable {
                handler({}, len);
            }));
        }
    }

    void cancel() override {
        m_has_pending     = false;
        m_pending_handler = {};
    }

    void close() override {
        if (auto ep = m_endpoint.lock()) {
            if (m_stream_id >= 0) {
                ep->remove_stream_data_handler(m_stream_id);
                ep->send_stream_data(m_stream_id, nullptr, 0, true);
            }
        }
    }

    bool is_via_quic() const override { return true; }

  private:
    void on_data(const uint8_t* data, std::size_t len, bool fin) {
        m_fin_received = fin;

        if (m_has_pending) {
            m_has_pending       = false;
            std::size_t n       = std::min(len, m_pending_buf.size());
            std::memcpy(m_pending_buf.data(), data, n);
            auto ep = m_endpoint.lock();
            if (!ep) {
                boost::asio::post(m_io_ctx, tp::bind_mem_alloc([handler = std::move(m_pending_handler)]() mutable {
                    handler(boost::asio::error::broken_pipe, 0);
                }));
                return;
            }
            ep->extend_window(m_stream_id, n);

            if (n < len) {
                m_recv_buf.append(reinterpret_cast<const char*>(data + n), len - n);
            }
            auto h = std::move(m_pending_handler);
            h({}, n);
        } else {
            m_recv_buf.append(reinterpret_cast<const char*>(data), len);
        }
    }

    boost::asio::io_context& m_io_ctx;
    std::weak_ptr<QuicClientEndpoint> m_endpoint;
    int64_t                  m_stream_id{-1};

    tp::string               m_recv_buf;
    boost::asio::mutable_buffer m_pending_buf{};
    IoHandler                m_pending_handler;
    bool                     m_has_pending{false};
    bool                     m_fin_received{false};
    boost::asio::steady_timer m_write_timer;
};

// ─────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────

std::shared_ptr<OutboundTransport> create_outbound_transport(
    boost::asio::io_context&       io_ctx,
    boost::asio::ssl::context&     ssl_ctx,
    const Config&                  config,
    boost::asio::ip::tcp::endpoint in_ep,
    std::shared_ptr<QuicClientEndpoint> quic_client) {

#ifdef ENABLE_QUIC
    if (quic_client != nullptr &&
        config.get_quic().enabled &&
        quic_client->is_connected()) {
        return TP_MAKE_SHARED(QuicStreamTransport, io_ctx, quic_client);
    }
#endif

    return TP_MAKE_SHARED(TlsOutboundTransport, io_ctx, ssl_ctx, config, std::move(in_ep));
}
