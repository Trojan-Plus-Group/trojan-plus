/*
 * This file is part of the trojan plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Plust Group Authors.
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

#ifndef _PIPELINE_H_
#define _PIPELINE_H_

#include <memory>
#include <list>
#include <functional>
#include <time.h>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/streambuf.hpp>

#include "proto/pipelinerequest.h"
#include "core/config.h"
#include "session/socketsession.h"
#include "core/icmpd.h"

class Service;
class Pipeline : public std::enable_shared_from_this<Pipeline> {
private:

    enum {
        MAX_BUF_LENGTH = 8192,
        STAT_SENT_DATA_SPEED_INTERVAL = 5
    };

    static uint32_t s_pipeline_id_counter;

    Service* service;
    SendDataCache sending_data_cache;
    bool destroyed;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>out_socket;
    bool connected;
    boost::asio::streambuf out_read_buf;
    bool out_read_buf_guard;
    boost::asio::ip::tcp::resolver resolver; 
    std::list<std::shared_ptr<Session>> sessions;
    uint32_t pipeline_id;
    std::shared_ptr<icmpd> icmp_processor;
    boost::asio::ip::tcp::endpoint out_socket_endpoint;

    void out_async_recv();
public:

    Pipeline(Service* _service, const Config& config, boost::asio::ssl::context& ssl_context);
    void start();
    void destroy();
    const Config& config;

    Service* get_service() { return service; }

    void session_start(Session& session,  SentHandler&& started_handler);
    void session_async_send_cmd(PipelineRequest::Command cmd, Session& session, const std::string_view& send_data, SentHandler&& sent_handler);
    void session_async_send_icmp(const std::string_view& send_data, SentHandler&& sent_handler);
    void session_destroyed(Session& session);

    inline bool is_connected()const { return connected; }
    bool is_in_pipeline(Session& session);
    
    uint32_t get_pipeline_id()const{ return pipeline_id; }

    void set_icmpd(std::shared_ptr<icmpd> icmp){ icmp_processor = icmp; }
    boost::asio::ip::tcp::endpoint get_out_socket_endpoint() const { return out_socket_endpoint;}
};

#endif // _PIPELINE_H_
