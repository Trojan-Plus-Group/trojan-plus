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

#ifndef _SERVICE_H_
#define _SERVICE_H_

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/version.hpp>
#include <functional>
#include <list>
#include <string>

#include "authenticator.h"
#include "core/icmpd.h"
#include "core/pipeline.h"
#include "session/session.h"
#include "session/udpforwardsession.h"

class Pipeline;
class icmpd;
class Service {
  private:
    typedef std::list<std::weak_ptr<Pipeline>> PipelineList;

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor socket_acceptor;
    boost::asio::ssl::context ssl_context;
    std::shared_ptr<Authenticator> auth;
    std::string plain_http_response;
    boost::asio::ip::udp::socket udp_socket;
    std::list<std::weak_ptr<UDPForwardSession>> udp_sessions;
    ReadBufWithGuard udp_read_buf;
    boost::asio::ip::udp::endpoint udp_recv_endpoint;

    void async_accept();
    void udp_async_read();

    PipelineList pipelines;
    size_t pipeline_select_idx;
    void prepare_pipelines();

    std::shared_ptr<icmpd> icmp_processor;
    void prepare_icmpd(Config& config, bool is_ipv4);

    SendingDataAllocator m_sending_data_allocator;

    const Config& config;

  public:
    explicit Service(Config& config, bool test = false);
    ~Service();

    [[nodiscard]] const Config& get_config() const { return config; }

    void run();
    void stop();

    boost::asio::io_context& get_io_context() { return io_context; }
    boost::asio::ssl::context& get_ssl_context() { return ssl_context; }

    void reload_cert();

    void start_session(const std::shared_ptr<Session>& session, SentHandler&& started_handler);

    void session_async_send_to_pipeline(Session& session, PipelineRequest::Command cmd, const std::string_view& data,
      SentHandler&& sent_handler, size_t ack_count = 0);
    void session_async_send_to_pipeline_icmp(const std::string_view& data, SentHandler&& sent_handler);
    void session_destroy_in_pipeline(Session& session);

    [[nodiscard]] bool is_use_pipeline() const { return config.get_experimental().pipeline_num > 0; }
    Pipeline* search_default_pipeline();

    SendingDataAllocator& get_sending_data_allocator() { return m_sending_data_allocator; }
};
#endif // _SERVICE_H_
