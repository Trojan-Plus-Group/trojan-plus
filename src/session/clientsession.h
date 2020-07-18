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

#ifndef _CLIENTSESSION_H_
#define _CLIENTSESSION_H_

#include <boost/asio/ssl.hpp>
#include <string_view>

#include "core/pipeline.h"
#include "core/utils.h"
#include "socketsession.h"

class Service;
class ClientSession : public SocketSession {
  protected:
    enum Status { HANDSHAKE, REQUEST, CONNECT, FORWARD, UDP_FORWARD, INVALID, DESTROY };

  private:
    Status status;
    bool first_packet_recv;
    boost::asio::ip::tcp::socket in_socket;
    SSLSocket out_socket;
    boost::asio::ip::udp::socket udp_socket;
    boost::asio::ip::udp::endpoint udp_recv_endpoint;

    boost::asio::streambuf udp_recv_buf;
    boost::asio::streambuf udp_send_buf;

    ReadBufWithGuard in_read_buf;
    ReadBufWithGuard out_read_buf;
    ReadBufWithGuard udp_read_buf;

    boost::asio::streambuf out_write_buf;
    boost::asio::streambuf udp_data_buf;

  protected:
    void in_async_read();
    void in_async_write(const std::string_view& data, size_t ack_count = 0);
    void out_async_read();
    void out_async_write(const std::string_view& data);
    void out_sent();
    void udp_async_read();
    void udp_async_write(const std::string_view& data, const boost::asio::ip::udp::endpoint& endpoint);
    void udp_recv(const std::string_view& data, const boost::asio::ip::udp::endpoint& endpoint);
    void udp_sent();
    void out_recv(const std::string_view& data, size_t ack_count = 0);

    virtual void in_recv(const std::string_view& data);
    virtual void in_sent();

    bool prepare_session();
    void request_remote();

    _define_simple_getter_setter(Status, status) _define_simple_getter_setter(bool, first_packet_recv);
    _define_getter(boost::asio::ip::tcp::socket&, in_socket) _define_getter(boost::asio::streambuf&, out_write_buf);

  public:
    ClientSession(Service* _service, const Config& config, boost::asio::ssl::context& ssl_context);
    ~ClientSession() override;

    boost::asio::ip::tcp::socket& accept_socket() override;
    void start() override;
    void destroy(bool pipeline_call = false) override;

    void recv_ack_cmd(size_t ack_count) override;
};

#endif // _CLIENTSESSION_H_
