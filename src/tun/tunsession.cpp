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

#include "tunsession.h"
#include "core/service.h"

using namespace boost::asio::ip;
TUNSession::TUNSession(Service* _service, bool _is_udp) : Session(_service, _service->get_config()) {
    _guard;
    set_session_name("TUNSession");
    set_udp_forward_session(_is_udp);
    _unguard;
}

TUNSession::~TUNSession() = default;

udp::endpoint TUNSession::get_redirect_local_remote_addr(bool output_log /*= false*/) const {
    _guard;
    auto remote_addr = m_remote_addr_udp;
    remote_addr.address(make_address_v4(LOCALHOST_IP_ADDRESS));
    if (output_log) {
        _log_with_date_time(m_remote_addr_udp.address().to_string() + " redirect to local for test");
    }

    return remote_addr;
    _unguard;
}
