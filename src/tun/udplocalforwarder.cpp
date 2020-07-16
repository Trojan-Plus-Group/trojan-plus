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

#include "tun/udplocalforwarder.h"
#include "core/service.h"
#include "session/session.h"

using namespace std;
using namespace boost::asio::ip;

UDPLocalForwarder::UDPLocalForwarder(Service* service, udp::endpoint local_src, udp::endpoint remote_dst,
  UDPForwardSession::UDPWriter&& writer, bool is_dns)
    : Session(service, service->get_config()),
      m_service(service),
      m_writer(move(writer)),
      m_local_src(move(local_src)),
      m_remote_dst(move(remote_dst)),
      m_udp_socket(service->get_io_context()),
      m_is_dns(is_dns) {

    _guard;
    set_udp_forward_session(true);
    _unguard;
}

UDPLocalForwarder::~UDPLocalForwarder() {}
void UDPLocalForwarder::start() {
    _guard;
    auto protocol = m_remote_dst.protocol();
    boost::system::error_code ec;
    m_udp_socket.open(protocol, ec);
    if (ec) {
        output_debug_info_ec(ec);
        destroy();
        return;
    }

    set_udp_send_recv_buf((int)m_udp_socket.native_handle(),
      m_is_dns ? m_service->get_config().get_dns().udp_socket_buf : m_service->get_config().get_udp_socket_buf());

    android_protect_socket((int)m_udp_socket.native_handle());

    m_udp_socket.bind(udp::endpoint(protocol, 0), ec);
    if (ec) {
        output_debug_info_ec(ec);
        destroy();
        return;
    }

    udp_timer_async_wait();

    _log_with_endpoint(m_local_src,
      "UDP local forwarder to [" + m_remote_dst.address().to_string() + ":" + to_string(m_remote_dst.port()) +
        "] started",
      Log::INFO);

    async_read();

    _unguard;
}

bool UDPLocalForwarder::process(const udp::endpoint& endpoint, const string_view& data) {
    _guard;
    if (endpoint != m_local_src) {
        return false;
    }

    return write_to(data);

    _unguard;
}

bool UDPLocalForwarder::write_to(const std::string_view& data) {
    _guard;
    if (is_destroyed()) {
        return false;
    }

    if (m_is_dns) {
        _log_with_endpoint_ALL(m_local_src, "[dns] --> [" + m_remote_dst.address().to_string() + ":" +
                                              to_string(m_remote_dst.port()) + "] length: " + to_string(data.length()));
    }

    boost::system::error_code ec;
    m_udp_socket.send_to(boost::asio::buffer(data), m_remote_dst, 0, ec);
    if (ec) {
        output_debug_info_ec(ec);
        destroy();
        return false;
    }

    m_stat.inc_sent_len(data.length());
    return true;
    _unguard;
}

void UDPLocalForwarder::async_read() {
    _guard;
    udp_timer_async_wait();

    const auto prepare_size =
      m_is_dns ? m_service->get_config().get_dns().udp_recv_buf : m_service->get_config().get_udp_recv_buf();

    m_read_buf.begin_read(__FILE__, __LINE__);
    m_read_buf.consume_all();

    auto self = shared_from_this();
    m_udp_socket.async_receive_from(
      m_read_buf.prepare(prepare_size), m_remote_dst, [this, self](boost::system::error_code ec, size_t length) {
          _guard;
          m_read_buf.end_read();

          if (ec) {
              output_debug_info_ec(ec);
              destroy();
          } else {
              m_read_buf.commit(length);
              m_stat.inc_recv_len(length);
              m_writer(m_local_src, m_read_buf);

              async_read();
          }
          _unguard;
      });
    _unguard;
}

void UDPLocalForwarder::destroy(bool) {
    _guard;

    if (m_destroyed) {
        return;
    }
    m_destroyed = true;

    _log_with_endpoint(m_local_src,
      "UDP local forwarder to [" + m_remote_dst.address().to_string() + ":" + to_string(m_remote_dst.port()) +
        "] disconnected, " + m_stat.to_string(),
      Log::INFO);

    udp_timer_cancel();

    if (m_udp_socket.is_open()) {
        boost::system::error_code ec;
        m_udp_socket.cancel(ec);
        m_udp_socket.close();
    }

    if (m_destroy_cb) {
        m_destroy_cb();
        m_destroy_cb = nullptr;
    }

    _unguard;
}
