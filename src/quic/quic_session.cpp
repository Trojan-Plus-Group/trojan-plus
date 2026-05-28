/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_session.h"
#include "quic_connection.h"
#include "quic_session_upstream.h"
#include "quic_to_http3_connect.h"
#include <cstddef>
#include <memory>
#include <string_view>
#include <initializer_list>

#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>

#include "core/config.h"
#include "core/log.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include "quic_connection.h"

// Reuse the same upper bound as the password hash storage in Config.
static constexpr std::size_t kMaxPasswordLineBytes = Config::MAX_PASSWORD_LENGTH;

QuicProxySession::QuicProxySession(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                                   const Config& config, boost::asio::io_context& io_ctx)
    : m_conn(conn),
      m_stream_id(stream_id),
      m_config(config),
      m_io_ctx(io_ctx),
      m_tcp_socket(io_ctx),
      m_resolver(io_ctx),
      m_udp_socket(io_ctx),
      m_udp_resolver(io_ctx),
      m_write_timer(io_ctx) {
    m_quic_recv_buf.reserve(kQuicRecvBufReserveSize);
}

QuicProxySession::~QuicProxySession() = default;

void QuicProxySession::start() {
    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) + " opened",
                        Log::INFO);
}

void QuicProxySession::on_stream_data(const uint8_t* data, std::size_t len, bool fin) {
    if (m_destroyed) {
        return;
    }
    
    if (!m_request_parsed) {
        m_quic_recv_buf.append(reinterpret_cast<const char*>(data), len);
        try_parse_request(m_quic_recv_buf,  fin);
        if(m_request_parsed){
            tp::string().swap(m_quic_recv_buf); // release memory
        }
    } else {
        if (m_is_udp) {
            m_udp_data_buf.append(reinterpret_cast<const char*>(data), len);
            if (fin) m_udp_fin_received = true;
            out_udp_sent();
        } else {
            write_to_target(tp::string(reinterpret_cast<const char*>(data), len), fin);
        }
    }
}

void QuicProxySession::on_stream_close() {
    destroy();
}

void QuicProxySession::try_parse_request(std::string_view data, bool fin) {
    if (!data.empty()) {
        char first_char = data[0];
        bool is_valid_hex = (first_char >= '0' && first_char <= '9') ||
                            (first_char >= 'a' && first_char <= 'f');
        if (!is_valid_hex) {
            _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                    " first byte not hex (" + tp::to_string((int)first_char) + "), falling back to h1_stream",
                                Log::INFO);
            forward_to_h1_upstream(data, fin);
            return;
        }
    }

    // Wait for at least the first CRLF (end of password) before deciding if it's Trojan.
    // This avoids premature fallback to h1_stream if the password is split across packets.
    size_t first_crlf = data.find("\r\n");
    if (first_crlf == tp::string::npos) {
        if (data.length() > kMaxPasswordLineBytes || fin) {
            _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                    " no CRLF in " + tp::to_string(kMaxPasswordLineBytes) +
                                    " bytes" + tp::to_string(fin ? " (fin)" : "") + ", falling back to h1_stream",
                                Log::WARN);
            forward_to_h1_upstream(data, fin);
        }
        return;
    }
    if (first_crlf > kMaxPasswordLineBytes) {
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " password line exceeds " + tp::to_string(kMaxPasswordLineBytes) +
                                " bytes, falling back to h1_stream",
                            Log::WARN);
        forward_to_h1_upstream(data, fin);
        return;
    }

    TrojanRequest req;
    int parsed = req.parse(data);
    if (parsed == -1) {
        // If it has a CRLF but still fails to parse as Trojan, it's definitely non-trojan.
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " parse failed, forwarding to h1_stream",
                            Log::INFO);
        forward_to_h1_upstream(data, fin);
        return;
    }
    if (parsed == 0) {
        // Need more bytes.
        return;
    }

    auto it = m_config.get_password().find(req.password);
    if (it == m_config.get_password().end()) {
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " invalid password, forwarding to h1_stream",
                            Log::WARN);
        // m_quic_recv_buf still holds the original raw bytes (not yet consumed), forward verbatim.
        forward_to_h1_upstream(data, fin);
        return;
    }

    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                            " authenticated as " + it->second + " → " + req.address.address +
                            ":" + tp::to_string(req.address.port) + " payload_len=" +
                            tp::to_string(req.payload.length()),
                        Log::INFO);

    m_request_parsed = true;

    if (auto c = m_conn.lock()){
        c->set_conn_type(QuicConnection::ConnType::proxy);
        const size_t password_len = data.size() - req.payload.length();
        c->stream_extend_window(m_stream_id, password_len);
    }
    
    if (req.command == TrojanRequest::UDP_ASSOCIATE) {
        m_is_udp = true;
        // 2048 is greater than MTU 
        m_udp_pending_stream_data.reserve(2048);
        m_udp_recv_buf.resize(kTcpBufSize, '\0');
        if (!req.payload.empty()) {
            m_udp_data_buf.append(req.payload.data(), req.payload.length());
            out_udp_sent();
        }

    }else{
        m_tcp_buf.resize(kTcpBufSize, '\0');
        if (!req.payload.empty()) {
            write_to_target(tp::string(req.payload.data(), req.payload.length()), fin);
        }
        
        connect_target(tp::string(req.address.address), req.address.port);
    }
}

void QuicProxySession::forward_to_h1_upstream(std::string_view data, bool fin) {

    m_request_parsed = true;

    auto locked_conn = m_conn.lock();
    if (!locked_conn) return;

    if (locked_conn->conn_type() == QuicConnection::ConnType::proxy) {
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " unexpected fallback on proxy connection, resetting stream",
                            Log::WARN);
        destroy(true, NGHTTP3_H3_INTERNAL_ERROR);
        return;
    }

    if (!locked_conn->forward_to_h1_upstream(m_stream_id,
                                            reinterpret_cast<const uint8_t*>(data.data()),
                                            data.size(), fin)) {
        destroy(true, NGHTTP3_H3_INTERNAL_ERROR);
    }
}

void QuicProxySession::connect_target(const tp::string& host, uint16_t port) {
    auto self = this->shared_from_this();
    m_resolver.async_resolve(
        host, tp::to_string(port).c_str(),
        [this, self, host, port](const boost::system::error_code& ec,
                                 boost::asio::ip::tcp::resolver::results_type results) {
            if (ec || m_destroyed) {
                if (ec) {
                    _log_with_date_time("QuicProxySession: resolve failed: " +
                                            tp::string(ec.message().c_str()),
                                        Log::WARN);
                }
                destroy();
                return;
            }
            boost::asio::async_connect(
                m_tcp_socket, results,
                [this, self, host, port](const boost::system::error_code& ec2,
                                         [[maybe_unused]] const boost::asio::ip::tcp::endpoint& ep) {
                    if (ec2 || m_destroyed) {
                        _log_with_date_time(
                            "QuicProxySession: target unreachable (" + host + ":" +
                                tp::to_string(port) + "), dropping client: " +
                                tp::string(ec2.message().c_str()),
                            Log::ERROR);
                        destroy();
                        return;
                    }
                    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                            " connected to " + host + ":" + tp::to_string(port),
                                        Log::INFO);

                    // Forward any data that arrived while TCP was connecting.
                    if (!m_is_writing_to_tcp && m_tcp_socket.is_open()) {
                        do_tcp_write();
                    }
                    tcp_read();
                });
        });
}

void QuicProxySession::write_to_target(tp::string data, bool fin) {
    if (data.empty() && !fin) {
        return;
    }
    m_tcp_write_queue.push_back({std::move(data), fin});
    if (!m_is_writing_to_tcp && m_tcp_socket.is_open()) {
        do_tcp_write();
    }
}

void QuicProxySession::do_tcp_write() {
    if (m_destroyed || !m_tcp_socket.is_open() || m_tcp_write_queue.empty()) {
        m_is_writing_to_tcp = false;
        return;
    }

    m_is_writing_to_tcp = true;
    auto self = this->shared_from_this();
    auto& front = m_tcp_write_queue.front();

    // If we only have a FIN (no data), handle it immediately.
    if (front.data.empty() && front.fin) {
        boost::system::error_code ec;
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec);
        m_tcp_write_queue.pop_front();
        do_tcp_write();
        return;
    }

    auto buf = TP_MAKE_SHARED(tp::string, std::move(front.data));
    bool fin = front.fin;
    m_tcp_write_queue.pop_front();

    boost::asio::async_write(
        m_tcp_socket, boost::asio::buffer(*buf),
        [this, self, buf, fin](const boost::system::error_code& ec, std::size_t sent) {
            if (m_destroyed) {
                return;
            }
            if (ec) {
                destroy();
                return;
            }

            if(auto c = m_conn.lock()){
                c->stream_extend_window(m_stream_id, sent);
            }

            // If we received a FIN from QUIC, we should shut down the TCP send side
            // after all data is written.
            if (fin) {
                boost::system::error_code ec2;
                ec2 = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec2);
            }
            do_tcp_write();
        });
}

void QuicProxySession::tcp_read() {
    if (m_destroyed || !m_tcp_socket.is_open()) {
        return;
    }
    auto self = this->shared_from_this();
    m_tcp_socket.async_read_some(
        boost::asio::buffer(&m_tcp_buf[0], kTcpBufSize),
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            if (m_destroyed) {
                return;
            }
            if (ec) {
                if (ec != boost::asio::error::eof) {
                    _log_with_date_time("QuicProxySession: tcp read: " +
                                            tp::string(ec.message().c_str()),
                                        Log::WARN);
                }
                auto locked_conn = m_conn.lock();
                if (locked_conn && !locked_conn->is_closed()) {
                    locked_conn->send_stream_data(m_stream_id, nullptr, 0, true);
                    locked_conn->on_pump_write();
                }
                destroy();
                return;
            }
            auto locked_conn = m_conn.lock();
            if (locked_conn && !locked_conn->is_closed()) {
                flush_tcp_read_buf(0, bytes);
            }
        });
}

void QuicProxySession::flush_tcp_read_buf(std::size_t offset, std::size_t bytes) {
    auto locked_conn = m_conn.lock();
    if (m_destroyed || !locked_conn || locked_conn->is_closed()) {
        return;
    }

    int64_t written = locked_conn->send_stream_data(m_stream_id,
                                               reinterpret_cast<const uint8_t*>(m_tcp_buf.data() + offset),
                                               bytes - offset, false);
    if (written < 0) {
        destroy();
        return;
    }

    if (written > 0) {
        locked_conn->on_pump_write();
    }

    offset += written;
    if (offset < bytes) {
        m_tcp_pending_offset = offset;
        m_tcp_pending_bytes = bytes;
        m_tcp_write_blocked = true;

        uint32_t delay_ms = (written > 0) ? 5 : 100;
        m_write_timer.expires_after(std::chrono::milliseconds(delay_ms));
        auto self = this->shared_from_this();
        m_write_timer.async_wait([this, self](const boost::system::error_code& ec) {
            if (!ec) {
                m_tcp_write_blocked = false;
                flush_tcp_read_buf(m_tcp_pending_offset, m_tcp_pending_bytes);
            }
        });
    } else {
        m_tcp_write_blocked = false;
        m_tcp_pending_offset = 0;
        m_tcp_pending_bytes = 0;
        tcp_read();
    }
}
 
void QuicProxySession::on_connection_pump() {
    if (m_destroyed) return;
    if (m_is_udp) {
        if (!m_udp_pending_stream_data.empty() && !m_udp_write_pending) {
            m_udp_write_pending = true;
            auto self = shared_from_this();
            boost::asio::post(m_io_ctx, [this, self]() {
                if (m_destroyed) return;
                m_udp_write_pending = false;
                m_write_timer.cancel();
                flush_udp_stream_data(0);
            });
        }
    } else {
        if (m_tcp_write_blocked && !m_tcp_write_pending) {
            m_tcp_write_pending = true;
            auto self = shared_from_this();
            boost::asio::post(m_io_ctx, [this, self]() {
                if (m_destroyed) return;
                m_tcp_write_pending = false;
                if (m_tcp_write_blocked) {
                    m_tcp_write_blocked = false;
                    m_write_timer.cancel();
                    flush_tcp_read_buf(m_tcp_pending_offset, m_tcp_pending_bytes);
                }
            });
        }
    }
}

void QuicProxySession::destroy(bool reset, uint64_t app_error_code) {
    if (m_destroyed) {
        return;
    }
    m_destroyed = true;
    m_resolver.cancel();
    m_udp_resolver.cancel();
    boost::system::error_code ec;
    if (m_tcp_socket.is_open()) {
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
        ec = m_tcp_socket.close(ec);
    }
    if (m_udp_socket.is_open()) {
        ec = m_udp_socket.cancel(ec);
        ec = m_udp_socket.close(ec);
    }
    auto locked_conn = m_conn.lock();
    if (locked_conn && !locked_conn->is_closed()) {
        locked_conn->remove_stream_handler(m_stream_id);
        if (reset) {
            locked_conn->reset_stream(m_stream_id, app_error_code);
            locked_conn->on_pump_write();
        } else {
            locked_conn->send_stream_data(m_stream_id, nullptr, true, nullptr);
        }
    }
    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) + " closed",
                        Log::INFO);
}

void QuicProxySession::out_udp_sent() {
    if (m_destroyed || !m_is_udp) return;

    if (m_udp_data_buf.empty()) {
        if (m_udp_fin_received) destroy();
        return;
    }

    UDPPacket packet;
    size_t packet_len = 0;
    bool is_packet_valid = packet.parse(std::string_view(m_udp_data_buf.data(), m_udp_data_buf.size()), packet_len);
    if (!is_packet_valid) {
        if (m_udp_data_buf.size() > 65535) { // Drop stream if packet too large
            _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) + " UDP packet too long", Log::ERROR);
            destroy();
        }
        return;
    }

    auto cb = [this](const UDPPacket& packet, size_t packet_len, const boost::asio::ip::udp::endpoint& dst_endpoint) {
        if (!m_udp_socket.is_open()) {
            auto protocol = dst_endpoint.protocol();
            boost::system::error_code ec;
            m_udp_socket.open(protocol, ec);
            if (ec) {
                _log_with_date_time("open : " + tp::string(ec.message().c_str()), Log::ERROR);
                destroy();
                return;
            }
            m_udp_socket.bind(boost::asio::ip::udp::endpoint(protocol, 0), ec);
            if (ec) {
                _log_with_date_time("bind : " + tp::string(ec.message().c_str()), Log::ERROR);
                destroy();
                return;
            }
            m_udp_socket.non_blocking(true, ec);
            if(ec){
                _log_with_date_time("set_option: " + tp::string(ec.message().c_str()), Log::ERROR);
                return;
            }
            udp_read();
        }

        out_udp_async_write(packet.payload, dst_endpoint);
        m_udp_data_buf.erase(0, packet_len);
    };

    if (packet.address.address_type == SOCKS5Address::DOMAINNAME) {
        auto self = shared_from_this();
        auto payload_tmp_buf = TP_MAKE_SHARED(tp::string, packet.payload);
        packet.payload = *payload_tmp_buf;
        
        m_udp_resolver.async_resolve(packet.address.address, tp::to_string(packet.address.port),
            [this, self, cb, payload_tmp_buf, packet, packet_len](const boost::system::error_code& error, const boost::asio::ip::udp::resolver::results_type& results) {
                if (error || m_destroyed || results.empty()) {
                    destroy();
                    return;
                }
                auto iterator = results.begin();
                if (m_config.get_tcp().prefer_ipv4) {
                    for (auto it = results.begin(); it != results.end(); ++it) {
                        if (it->endpoint().address().is_v4()) {
                            iterator = it;
                            break;
                        }
                    }
                }
                auto dst_endpoint = boost::asio::ip::udp::endpoint(iterator->endpoint().address(), packet.address.port);
                cb(packet, packet_len, dst_endpoint);
            });
    } else {
        boost::system::error_code ec;
        auto dst_endpoint = boost::asio::ip::udp::endpoint(
            boost::asio::ip::make_address(packet.address.address, ec), packet.address.port);
        if (ec) {
            destroy();
            return;
        }
        cb(packet, packet_len, dst_endpoint);
    }
}

void QuicProxySession::out_udp_async_write(const std::string_view& data, const boost::asio::ip::udp::endpoint& endpoint) {
    if (m_destroyed || !m_udp_socket.is_open()) return;

    auto self = shared_from_this();
    auto data_copy = TP_MAKE_SHARED(tp::string, data);

    m_udp_socket.async_send_to(boost::asio::buffer(*data_copy), endpoint,
        [this, self, data_copy](const boost::system::error_code& ec, std::size_t sent) {
            if (m_destroyed) return;
            if (ec) {
                destroy();
                return;
            }
            if(auto c = m_conn.lock()){
                c->stream_extend_window(m_stream_id, sent);
            }
            out_udp_sent();
        });
}

void QuicProxySession::udp_read() {
    if (m_destroyed || !m_udp_socket.is_open()) return;

    auto self = shared_from_this();
    m_udp_socket.async_receive_from(boost::asio::buffer(&m_udp_recv_buf[0], kTcpBufSize), m_udp_remote_endpoint,
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            if (m_destroyed) return;
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    _log_with_date_time("QuicProxySession: udp read error: " + tp::string(ec.message().c_str()), Log::WARN);
                }
                destroy();
                return;
            }

            tp::streambuf buf;
            UDPPacket::generate(buf, m_udp_remote_endpoint, std::string_view(m_udp_recv_buf.data(), bytes));
            
            bool was_empty = m_udp_pending_stream_data.empty();
            m_udp_pending_stream_data.append(streambuf_to_string_view(buf));
            if (was_empty) {
                flush_udp_stream_data(0);
            }
        });
}

void QuicProxySession::flush_udp_stream_data(std::size_t offset) {
    auto locked_conn = m_conn.lock();
    if (m_destroyed || !locked_conn || locked_conn->is_closed() || m_udp_pending_stream_data.empty()) {
        return;
    }

    int64_t written = locked_conn->send_stream_data(m_stream_id,
                                               reinterpret_cast<const uint8_t*>(m_udp_pending_stream_data.data() + offset),
                                               m_udp_pending_stream_data.size() - offset, false);
    if (written < 0) {
        destroy();
        return;
    }

    offset += written;
    if (offset > 0) {
        m_udp_pending_stream_data.erase(0, offset);
        offset = 0;
    }

    if (written > 0) {
        locked_conn->on_pump_write(); // erase before pump so on_connection_pump re-entry sees empty buf
    }

    if (!m_udp_pending_stream_data.empty()) {
        uint32_t delay_ms = (written > 0) ? 5 : 100;
        m_write_timer.expires_after(std::chrono::milliseconds(delay_ms));
        auto self = this->shared_from_this();
        m_write_timer.async_wait([this, self](const boost::system::error_code& ec) {
            if (!ec) {
                flush_udp_stream_data(0);
            }
        });
    }else{
        udp_read();
    }
}
