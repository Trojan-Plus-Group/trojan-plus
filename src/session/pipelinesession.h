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

#ifndef _PIPELINEESSION_H_
#define _PIPELINEESSION_H_

#include <list>
#include <string_view>
#include <boost/asio/ssl.hpp>

#include "session.h"
#include "socketsession.h"
#include "serversession.h"
#include "proto/pipelinerequest.h"
#include "core/authenticator.h"
#include "core/utils.h"
#include "pipelinecomponent.h"


class icmpd;
class Service;
class ServerSession;
class PipelineSession : public SocketSession {
    typedef std::list<std::shared_ptr<ServerSession>> SessionsList;

    enum Status {
        HANDSHAKE,
        STREAMING,
        DESTROY
    } status;


    std::shared_ptr<Authenticator> auth;
    std::string auth_password;
    const std::string &plain_http_response;
    
    SessionsList sessions;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> live_socket;
    boost::asio::steady_timer gc_timer;
    SendDataCache sending_data_cache;    
    boost::asio::ssl::context& ssl_context;

    std::shared_ptr<icmpd> icmp_processor;

    ReadBufWithGuard in_read_buf;

    void timer_async_wait();
    void process_streaming_data();

    void in_async_read();
    void in_recv(const std::string_view& data);
    void in_send(PipelineRequest::Command cmd, ServerSession& session, const std::string_view& session_data, SentHandler&& sent_handler);
    bool find_and_process_session(PipelineComponent::SessionIdType session_id, std::function<void(SessionsList::iterator&)>&& processor);
public:
    PipelineSession(Service* _service, const Config& config, boost::asio::ssl::context &ssl_context, 
        std::shared_ptr<Authenticator> auth, const std::string &plain_http_response);
    void destroy(bool pipeline_call = false) final;

    boost::asio::ip::tcp::socket& accept_socket() final;
    void start() final;

    void session_write_ack(ServerSession& session, SentHandler&& sent_handler);
    void session_write_data(ServerSession& session, const std::string_view& session_data, SentHandler&& sent_handler);
    void session_write_icmp(const std::string_view& data, SentHandler&& sent_handler);
    void remove_session_after_destroy(ServerSession& session);

    void set_icmpd(std::shared_ptr<icmpd> icmp) { icmp_processor = std::move(icmp); }
};

#endif // _PIPELINEESSION_H_