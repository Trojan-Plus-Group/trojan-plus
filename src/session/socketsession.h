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

#ifndef _SOCKET_SESSION_HPP_
#define _SOCKET_SESSION_HPP_

#include <ctime>
#include <set>
#include <memory>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <boost/asio/streambuf.hpp>

#include "core/config.h"
#include "session.h"

class Service;
class SocketSession : public Session {
protected:    
    boost::asio::streambuf in_read_buf;
    boost::asio::streambuf out_read_buf;
    boost::asio::streambuf udp_read_buf;

    bool in_read_buf_guard;
    bool out_read_buf_guard;
    bool udp_read_buf_guard;

    boost::asio::steady_timer udp_gc_timer;

    uint64_t recv_len;
    uint64_t sent_len;
    time_t start_time{};
    boost::asio::streambuf out_write_buf;
    boost::asio::streambuf udp_data_buf;
    boost::asio::ip::tcp::resolver resolver;
    
    boost::asio::ip::udp::socket udp_socket;
    boost::asio::ip::udp::endpoint udp_recv_endpoint;
    boost::asio::ip::udp::endpoint out_udp_endpoint;
    
    void udp_timer_async_wait();
public:
    SocketSession(Service* _service, const Config& config);

    virtual boost::asio::ip::tcp::socket& accept_socket() = 0;

    boost::asio::ip::tcp::endpoint in_endpoint;
};

#endif //_SOCKET_SESSION_HPP_