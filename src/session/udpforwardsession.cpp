/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing
 * for more experimental features.
 * Copyright (C) 2017-2020  The Trojan Authors.
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

#include "udpforwardsession.h"

#include <stdexcept>
#include <utility>

#include "core/service.h"
#include "core/utils.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include "ssl/sslsession.h"
#include "mem/memallocator.h"

using namespace boost::asio::ip;
using namespace boost::asio::ssl;

UDPForwardSession::UDPForwardSession(Service* _service, const Config& config, context& ssl_context,
  const udp::endpoint& endpoint, const std::pair<tp::string, uint16_t>& targetdst, UDPWriter in_write, bool nat,
  bool dns)
    : SocketSession(_service, config),
      status(CONNECT),
      in_write(std::move(in_write)),
      out_socket(_service->get_io_context(), ssl_context),
      udp_target_socket(_service->get_io_context()),
      is_nat(nat),
      is_dns(dns) {

    set_session_name("UDPForwardSession");
    udp_recv_endpoint = endpoint;
    out_udp_endpoint  = udp::endpoint(boost::asio::ip::make_address(targetdst.first), targetdst.second);
    set_in_endpoint(tcp::endpoint(endpoint.address(), endpoint.port()));
    set_udp_forward_session(true);
    get_pipeline_component().allocate_session_id();
}

UDPForwardSession::~UDPForwardSession() { get_pipeline_component().free_session_id(); }

int UDPForwardSession::get_udp_timer_timeout_val() const {
    return is_dns ? get_config().get_dns().udp_timeout : SocketSession::get_udp_timer_timeout_val();
}

tcp::socket& UDPForwardSession::accept_socket() {
    throw std::logic_error(tp::string("accept_socket does not exist in UDPForwardSession").c_str());
}
void UDPForwardSession::start() { throw std::logic_error(tp::string("start does not exist in UDPForwardSession").c_str()); }

void UDPForwardSession::start_udp(const std::string_view& data) {
    udp_timer_async_wait();

    auto self = shared_from_this();
    auto cb   = [this, self]() {
        if (is_nat) {
            udp_target_socket.open(out_udp_endpoint.protocol());
            bool is_ipv4 = out_udp_endpoint.protocol().family() == boost::asio::ip::tcp::v6().family();
            if (prepare_nat_udp_target_bind((int)udp_target_socket.native_handle(), is_ipv4, out_udp_endpoint,
                  get_config().get_udp_socket_buf())) {
                udp_target_socket.bind(out_udp_endpoint);
            } else {
                destroy();
                return;
            }
        }

        status = FORWARDING;
        out_async_read();

        out_async_write(streambuf_to_string_view(out_write_buf));
        out_write_buf.consume(out_write_buf.size());
    };

    out_write_buf.consume(out_write_buf.size());
    streambuf_append(out_write_buf, TrojanRequest::generate(get_config().get_password().cbegin()->first,
                                      out_udp_endpoint.address().to_string().c_str(), out_udp_endpoint.port(), false));
    process(udp_recv_endpoint, data);

    _log_with_endpoint(udp_recv_endpoint,
      "session_id: " + tp::to_string(get_session_id()) + " forwarding UDP packets to " +
        out_udp_endpoint.address().to_string() + ':' + tp::to_string(out_udp_endpoint.port()) + " via " +
        get_config().get_remote_addr() + ':' + tp::to_string(get_config().get_remote_port()),
      Log::INFO);

    if (get_pipeline_component().is_using_pipeline()) {
        cb();
    } else {
        get_config().prepare_ssl_reuse(out_socket);
        connect_remote_server_ssl(self, get_config().get_remote_addr(), tp::to_string(get_config().get_remote_port()),
          get_resolver(), out_socket, udp_recv_endpoint, cb);
    }
}

bool UDPForwardSession::process(const udp::endpoint& endpoint, const std::string_view& data) {
    if (endpoint != udp_recv_endpoint) {
        return false;
    }
    in_recv(data);
    return true;
}

void UDPForwardSession::out_async_read() {
    if (get_pipeline_component().is_using_pipeline()) {
        get_pipeline_component().get_pipeline_data_cache().async_read(
          [this](const std::string_view& data, size_t) { out_recv(data); });
    } else {
        out_read_buf.begin_read(__FILE__, __LINE__);
        out_read_buf.consume_all();
        auto self = shared_from_this();
        out_socket.async_read_some(
          out_read_buf.prepare(MAX_BUF_LENGTH), tp::bind_mem_alloc([this, self](const boost::system::error_code error, size_t length) {
              out_read_buf.end_read();
              if (error) {
                  destroy();
                  return;
              }
              out_read_buf.commit(length);
              out_recv(out_read_buf);
          }));
    }
}

void UDPForwardSession::out_async_write(const std::string_view& data) {
    auto self = shared_from_this();
    if (get_pipeline_component().is_using_pipeline()) {
        get_service()->session_async_send_to_pipeline(
          *this, PipelineRequest::DATA, data, tp::bind_mem_alloc([this, self](const boost::system::error_code error) {
              if (error) {
                  destroy();
                  return;
              }
              out_sent();
          }));
    } else {
        auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
        boost::asio::async_write(
          out_socket, data_copy->data(), tp::bind_mem_alloc([this, self, data_copy](const boost::system::error_code error, size_t) {
              get_service()->get_sending_data_allocator().free(data_copy);
              if (error) {
                  destroy();
                  return;
              }
              out_sent();
          }));
    }
}

void UDPForwardSession::in_recv(const std::string_view& data) {
    if (status == DESTROY) {
        return;
    }

    udp_timer_async_wait();

    size_t length = data.length();
    get_stat().inc_sent_len(length);

    _log_with_endpoint(
      udp_recv_endpoint, "session_id: " + tp::to_string(get_session_id()) + " sent a UDP packet of length " +
                           tp::to_string(length) + " bytes to " + out_udp_endpoint.address().to_string() + ':' +
                           tp::to_string(out_udp_endpoint.port()) + " sent_len: " + tp::to_string(get_stat().get_sent_len()));

    UDPPacket::generate(out_write_buf, out_udp_endpoint.address().to_string().c_str(), out_udp_endpoint.port(), data);
    if (status == FORWARD) {
        status = FORWARDING;
        out_async_write(streambuf_to_string_view(out_write_buf));
        out_write_buf.consume(out_write_buf.size());
    }
}

void UDPForwardSession::out_recv(const std::string_view& data) {
    if (status == FORWARD || status == FORWARDING) {
        udp_timer_async_wait();
        streambuf_append(udp_data_buf, data);
        for (;;) {
            UDPPacket packet;
            size_t packet_len    = 0;
            bool is_packet_valid = packet.parse(streambuf_to_string_view(udp_data_buf), packet_len);
            if (!is_packet_valid) {
                if (udp_data_buf.size() > MAX_BUF_LENGTH) {
                    _log_with_endpoint(udp_recv_endpoint,
                      "session_id: " + tp::to_string(get_session_id()) + " UDP packet too long", Log::ERROR);
                    destroy();
                    return;
                }
                break;
            }
            _log_with_endpoint(udp_recv_endpoint, "session_id: " + tp::to_string(get_session_id()) +
                                                    " received a UDP packet of length " + tp::to_string(packet.length) +
                                                    " bytes from " + packet.address.address + ':' +
                                                    tp::to_string(packet.address.port));

            if (is_nat) {
                boost::system::error_code ec;
                udp_target_socket.send_to(
                  boost::asio::buffer(packet.payload.data(), packet.payload.length()), udp_recv_endpoint, 0, ec);
                if (ec == boost::asio::error::no_permission) {
                    _log_with_endpoint(
                      udp_recv_endpoint, "[udp] dropped a packet due to firewall policy or rate limit");
                } else if (ec) {
                    output_debug_info_ec(ec);
                    destroy();
                    return;
                }
            } else {
                in_write(udp_recv_endpoint, packet.payload);
            }

            udp_data_buf.consume(packet_len);
            get_stat().inc_recv_len(packet.length);
        }
        out_async_read();
    }
}

void UDPForwardSession::out_sent() {
    if (status == FORWARDING) {
        if (out_write_buf.size() == 0) {
            status = FORWARD;
        } else {
            out_async_write(streambuf_to_string_view(out_write_buf));
            out_write_buf.consume(out_write_buf.size());
        }
    }
}

void UDPForwardSession::destroy(bool pipeline_call /*= false*/) {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;

    _log_with_endpoint(udp_recv_endpoint,
      "session_id: " + tp::to_string(get_session_id()) + " disconnected, " + get_stat().to_string(), Log::INFO);

    get_resolver().cancel();

    udp_timer_cancel();
    if (udp_target_socket.is_open()) {
        boost::system::error_code ec;
        udp_target_socket.cancel(ec);
        udp_target_socket.close();
    }

    shutdown_ssl_socket(this, out_socket);

    if (!pipeline_call && get_pipeline_component().is_using_pipeline()) {
        get_service()->session_destroy_in_pipeline(*this);
    }
}
