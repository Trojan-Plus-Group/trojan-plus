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

#ifndef _SERVERSESSION_H_
#define _SERVERSESSION_H_

#include "session.h"
#include <boost/asio/ssl.hpp>
#include "pipelinesession.h"
#include "core/authenticator.h"

class ServerSession : public Session {
private:
    enum Status {
        HANDSHAKE,
        FORWARD,
        UDP_FORWARD,
        DESTROY
    } status;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>in_socket;
    boost::asio::ip::tcp::socket out_socket;
    boost::asio::ip::udp::resolver udp_resolver;
    Authenticator *auth;
    std::string auth_password;
    const std::string &plain_http_response;
    
    void in_async_read();
    void in_async_write(const std::string &data);
    void in_sent();
    void out_async_read();
    void out_async_write(const std::string &data);
    void out_recv(const std::string &data);
    void out_sent();
    void udp_async_read();
    void udp_async_write(const std::string &data, const boost::asio::ip::udp::endpoint &endpoint);
    void udp_recv(const std::string &data, const boost::asio::ip::udp::endpoint &endpoint);
    void udp_sent();

    std::weak_ptr<Session> pipeline;
    bool use_pipeline;
    bool has_queried_out;
public:
    ServerSession(const Config &config, boost::asio::io_context &io_context, boost::asio::ssl::context &ssl_context, Authenticator *auth, const std::string &plain_http_response);
    void set_use_pipeline(std::weak_ptr<Session> pipeline);
    boost::asio::ip::tcp::socket& accept_socket();
    void start();
    void destroy(bool pipeline_call = false);
    void in_recv(const std::string &data);
    bool is_destoryed()const{ return status == DESTROY; }

    std::weak_ptr<Session> get_pipeline(){ return pipeline; }
};

#endif // _SERVERSESSION_H_
