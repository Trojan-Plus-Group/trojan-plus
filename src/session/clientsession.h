/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
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

#include "socketsession.h"
#include "core/pipeline.h"

class Service;
class ClientSession : public SocketSession {
protected:
    enum Status {
        HANDSHAKE,
        REQUEST,
        CONNECT,
        FORWARD,
        UDP_FORWARD,
        INVALID,
        DESTROY
    } status;
    bool first_packet_recv;
    boost::asio::ip::tcp::socket in_socket;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> out_socket;
    boost::asio::streambuf udp_recv_buf;
    boost::asio::streambuf udp_send_buf;

    void in_async_read();
    void in_async_write(const std::string_view &data);
    void out_async_read();
    void out_async_write(const std::string_view &data);
    void out_sent();
    void udp_async_read();
    void udp_async_write(const std::string_view &data, const boost::asio::ip::udp::endpoint &endpoint);
    void udp_recv(const std::string_view &data, const boost::asio::ip::udp::endpoint &endpoint);
    void udp_sent();
    void out_recv(const std::string_view &data);

    virtual void in_recv(const std::string_view &data);
    virtual void in_sent();

    bool prepare_session();
    void request_remote();
public:
    ClientSession(Service* _service, const Config& config, boost::asio::ssl::context &ssl_context);
    ~ClientSession();
    boost::asio::ip::tcp::socket &accept_socket() override;
    void start() override;
    void destroy(bool pipeline_call = false) override;
    
    void recv_ack_cmd() override;
};

#endif // _CLIENTSESSION_H_
