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

#include "forwardsession.h"
#include "mem/memallocator.h"
using namespace boost::asio::ssl;

ForwardSession::ForwardSession(Service* _service, const Config& config, context& ssl_context)
    : NATSession(_service, config, ssl_context) {
    set_session_name("ForwardSession");
}

std::pair<tp::string, uint16_t> ForwardSession::get_target_endpoint() {
    return std::make_pair(get_config().get_target_addr(), get_config().get_target_port());
}
