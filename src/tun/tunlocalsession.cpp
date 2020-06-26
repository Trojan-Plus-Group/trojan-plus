/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing
 * for more experimental features.
 * Copyright (C) 2020 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tun/tunlocalsession.h"
#include "core/service.h"
#include "core/utils.h"
#include "tun/udplocalforwarder.h"

using namespace std;
using namespace boost::asio::ip;

TUNLocalSession::TUNLocalSession(Service* _service, bool is_udp)
    : TUNSession(_service, is_udp), m_resolver(_service->get_io_context()), m_tcp_socket(_service->get_io_context()) {
    if (!is_udp) {
        m_sending_data_cache.set_is_connected_func([this]() { return !m_destroyed && m_connected; });
        m_sending_data_cache.set_async_writer([this](const boost::asio::streambuf& data, SentHandler&& handler) {
            auto self = shared_from_this();
            boost::asio::async_write(
              m_tcp_socket, data.data(), [this, self, handler](const boost::system::error_code error, size_t length) {
                  udp_timer_async_wait();
                  if (error) {
                      output_debug_info_ec(error);
                      destroy();
                  }

                  get_stat().inc_sent_len(length);
                  handler(error);
              });
        });
    }
}

void TUNLocalSession::start() {
    if (is_udp_forward_session()) {
        m_udp_forwarder = make_shared<UDPLocalForwarder>(
          get_service(), m_local_addr_udp, m_remote_addr_udp,
          [this](const udp::endpoint&, const string_view& data) {
              if (m_write_to_lwip(this, (string_view*)&data) < 0) {
                  output_debug_info();
                  destroy();
              }
          },
          false);

        m_udp_forwarder->set_destroy_callback([this]() {
            output_debug_info();
            destroy();
        });

        if (m_udp_forwarder->start(streambuf_to_string_view(m_send_buf))) {
            m_connected = true;
        } else {
            output_debug_info();
            destroy();
        }
    } else {
        // TODO tcp connected
        auto self = shared_from_this();
        connect_out_socket(this, m_remote_addr.address().to_string(), to_string(m_remote_addr.port()), m_resolver,
          m_tcp_socket, m_local_addr_udp, [this, self]() {
              out_async_send_impl(streambuf_to_string_view(m_send_buf), [this](boost::system::error_code ec) {
                  if (ec) {
                      output_debug_info_ec(ec);
                      destroy();
                      return;
                  }
                  if (!m_wait_connected_handler.empty()) {
                      for (auto& h : m_wait_connected_handler) {
                          h(boost::system::error_code());
                      }
                      m_wait_connected_handler.clear();
                  }
                  out_async_read();
              });
          });
    }
}

void TUNLocalSession::recv_buf_consume(uint16_t _length) {
    assert(!is_udp_forward_session());
    m_recv_buf.consume(_length);

    if (m_recv_buf.size() == 0) {
        out_async_read();
    }
}

void TUNLocalSession::recv_buf_ack_sent(uint16_t _length) {
    assert(!is_udp_forward_session());
    m_recv_buf_ack_length -= _length;
}

void TUNLocalSession::out_async_read() {
    if (!is_udp_forward_session()) {
        m_recv_buf.begin_read(__FILE__, __LINE__);
        auto self = shared_from_this();
        m_tcp_socket.async_read_some(m_recv_buf.prepare(Session::MAX_BUF_LENGTH),
          [this, self](const boost::system::error_code error, size_t length) {
              m_recv_buf.end_read();
              if (error) {
                  output_debug_info_ec(error);
                  destroy();
                  return;
              }
              m_recv_buf.commit(length);
              get_stat().inc_recv_len(length);

              m_recv_buf_ack_length += length;

              if (m_write_to_lwip(this, nullptr) < 0) {
                  output_debug_info();
                  destroy();
              }
          });
    }
}

void TUNLocalSession::out_async_send_impl(const std::string_view& data_to_send, SentHandler&& _handler) {
    if (is_udp_forward_session()) {
        if (m_udp_forwarder->process(m_local_addr_udp, data_to_send)) {
            _handler(boost::system::error_code());
        } else {
            _handler(boost::asio::error::broken_pipe);
        }
    } else {
        m_sending_data_cache.push_data(
          [&](boost::asio::streambuf& buf) { streambuf_append(buf, data_to_send); }, move(_handler));
    }
}

void TUNLocalSession::out_async_send(const uint8_t* _data, size_t _length, SentHandler&& _handler) {
    if (!m_connected) {
        if (m_send_buf.size() < numeric_limits<uint16_t>::max()) {
            streambuf_append(m_send_buf, _data, _length);
            m_wait_connected_handler.emplace_back(_handler);
        } else {
            output_debug_info();
            destroy();
        }
    } else {
        out_async_send_impl(streambuf_to_string_view(m_send_buf), move(_handler));
    }
}

void TUNLocalSession::destroy(bool /*= false*/) {
    if (m_destroyed) {
        return;
    }
    m_destroyed = true;

    auto note_str = "TUNLocalSession  disconnected, " + get_stat().to_string();
    if (is_udp_forward_session()) {
        _log_with_endpoint(m_local_addr_udp, note_str, Log::INFO);
    } else {
        _log_with_endpoint(m_local_addr, note_str, Log::INFO);
    }

    m_wait_ack_handler.clear();

    // TODO TCP socket close

    if (!m_close_from_tundev_flag) {
        m_close_cb(this);
    }
}

bool TUNLocalSession::try_to_process_udp(const boost::asio::ip::udp::endpoint& _local,
  const boost::asio::ip::udp::endpoint& _remote, const uint8_t* payload, size_t payload_length) {
    if (is_udp_forward_session()) {
        if (_local == m_local_addr_udp && _remote == m_remote_addr_udp) {
            return m_udp_forwarder->process(_local, string_view((const char*)payload, payload_length));
        }
    }

    return false;
}