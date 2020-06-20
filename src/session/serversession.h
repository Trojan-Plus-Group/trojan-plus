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

#ifndef _SERVERSESSION_H_
#define _SERVERSESSION_H_

#include <string_view>
#include <boost/asio/ssl.hpp>

#include "socketsession.h"
#include "pipelinesession.h"
#include "core/authenticator.h"
#include "core/pipeline.h"
#include "core/utils.h"

class Service;
class ServerSession : public SocketSession {
private:
    enum Status {
        HANDSHAKE,
        FORWARD,
        UDP_FORWARD,
        DESTROY
    } status;

    ReadBufWithGuard in_read_buf;
    ReadBufWithGuard out_read_buf;
    ReadBufWithGuard udp_read_buf;

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>in_socket;
    boost::asio::ip::tcp::socket out_socket;
    boost::asio::ip::udp::socket udp_socket;
    boost::asio::ip::udp::endpoint out_udp_endpoint;
    
    boost::asio::streambuf out_write_buf;
    boost::asio::streambuf udp_data_buf;

    boost::asio::ip::udp::resolver udp_resolver;
    boost::asio::ip::udp::endpoint udp_associate_endpoint;
    
    std::shared_ptr<Authenticator> auth;
    std::string auth_password;
    const std::string &plain_http_response;

    using PipelineSessionRef = std::weak_ptr<Session>;
    PipelineSessionRef pipeline_session;
    bool has_queried_out;
    
    void in_async_read();
    void in_async_write(const std::string_view &data);
    void in_sent();
    void in_recv(const std::string_view &data);
    
    void out_async_write(const std::string_view &data);
    void out_recv(const std::string_view &data);
    void out_sent();
    void out_udp_async_read();
    void out_udp_async_write(const std::string_view &data, const boost::asio::ip::udp::endpoint &endpoint);
    void out_udp_recv(const std::string_view &data, const boost::asio::ip::udp::endpoint &endpoint);
    void out_udp_sent();
public:
    ServerSession(Service* _service, const Config& config, boost::asio::ssl::context &ssl_context, 
        std::shared_ptr<Authenticator> auth, const std::string &plain_http_response);

    boost::asio::ip::tcp::socket &accept_socket() override;
    void start() override;
    void destroy(bool pipeline_call = false) override;
    void out_async_read();

    void set_pipeline_session(const std::shared_ptr<Session>& _session){
        static_assert(std::is_same<PipelineSessionRef, std::weak_ptr<Session>>::value, 
            "Pipeline session ref type must be weak_ptr");
        pipeline_session = _session;
    }
    bool is_destoryed() const { return status == DESTROY; }
};

#endif // _SERVERSESSION_H_
