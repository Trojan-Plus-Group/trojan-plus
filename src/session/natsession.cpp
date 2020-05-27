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

#include "natsession.h"
#include "proto/trojanrequest.h"
#include "ssl/sslsession.h"

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

NATSession::NATSession(Service* _service, context &ssl_context) :
    ClientSession(_service, ssl_context){
    status = CONNECT;
}

pair<string, uint16_t> NATSession::get_target_endpoint() {
    return recv_target_endpoint(in_socket.native_handle());
}

void NATSession::start() {
    if (prepare_session()) {
        auto target_endpoint = get_target_endpoint();
        string &target_addr = target_endpoint.first;
        uint16_t target_port = target_endpoint.second;
        if (target_port == 0) {
            destroy();
            return;
        }
        _log_with_endpoint(in_endpoint, "forwarding to " + target_addr + ':' + to_string(target_port) + " via " + config.remote_addr + ':' + to_string(config.remote_port), Log::INFO);
        out_write_buf = TrojanRequest::generate(config.password.cbegin()->first, target_addr, target_port, true);
        
        request_remote();
    }
}

void NATSession::in_recv(const string &data) {
    if (status == CONNECT) {
        sent_len += data.length();
        first_packet_recv = true;
        out_write_buf += data;
    } else if (status == FORWARD) {
        sent_len += data.length();
        out_async_write(data);
    }
}

void NATSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    }
}
