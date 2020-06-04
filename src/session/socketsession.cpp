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

#include "socketsession.h"
#include "core/service.h"

using namespace std;
SocketSession::SocketSession(Service* _service, const Config& config) : 
    Session(_service, config),
    in_read_buf_guard(false),
    out_read_buf_guard(false),
    udp_read_buf_guard(false),
    recv_len(0),
    sent_len(0),
    resolver(_service->get_io_context()),
    udp_socket(_service->get_io_context()){
}
