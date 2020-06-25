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
    boost::asio::steady_timer udp_gc_timer;
    
    boost::asio::ip::tcp::resolver resolver;
    boost::asio::ip::tcp::endpoint in_endpoint;

protected: 

    virtual int get_udp_timer_timeout_val() const;
    void udp_timer_async_wait();
    void udp_timer_cancel();

    _define_getter(boost::asio::ip::tcp::resolver&, resolver)
    
public:
    SocketSession(Service* _service, const Config& config);
    virtual boost::asio::ip::tcp::socket& accept_socket() = 0;

    _define_simple_getter_setter(const boost::asio::ip::tcp::endpoint&, in_endpoint)
};

#endif //_SOCKET_SESSION_HPP_