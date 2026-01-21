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

#include "socks5address.h"
#include <cstdio>

#include "core/utils.h"

using namespace boost::asio::ip;

bool SOCKS5Address::parse(const std::string_view& data, size_t& address_len) {
    _guard;

    if (data.length() == 0 || (data[0] != IPv4 && data[0] != DOMAINNAME && data[0] != IPv6)) {
        return false;
    }
    address_type = static_cast<AddressType>(data[0]);
    switch (address_type) {
        case IPv4: {
            if (data.length() > 4 + 2) {
                address = std::to_string(uint8_t(data[1])) + '.' + std::to_string(uint8_t(data[2])) + '.' +
                          std::to_string(uint8_t(data[3])) + '.' + std::to_string(uint8_t(data[4]));
                port        = (uint8_t(data[5]) << one_byte_shift_8_bits) | uint8_t(data[6]);
                address_len = 1 + 4 + 2;
                return true;
            }
            break;
        }
        case DOMAINNAME: {
            uint8_t domain_len = data[1];
            if (domain_len == 0) {
                // invalid domain len
                break;
            }
            if (data.length() > (unsigned int)(1 + domain_len + 2)) {
                address     = data.substr(2, domain_len);
                port        = (uint8_t(data[domain_len + 2]) << one_byte_shift_8_bits) | uint8_t(data[domain_len + 3]);
                address_len = 1 + 1 + domain_len + 2;
                return true;
            }
            break;
        }
        case IPv6: {
            if (data.length() > 16 + 2) {
                char t[40];
                sprintf(t, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", uint8_t(data[1]),
                  uint8_t(data[2]), uint8_t(data[3]), uint8_t(data[4]), uint8_t(data[5]), uint8_t(data[6]),
                  uint8_t(data[7]), uint8_t(data[8]), uint8_t(data[9]), uint8_t(data[10]), uint8_t(data[11]),
                  uint8_t(data[12]), uint8_t(data[13]), uint8_t(data[14]), uint8_t(data[15]), uint8_t(data[16]));
                address     = t;
                port        = (uint8_t(data[17]) << one_byte_shift_8_bits) | uint8_t(data[18]);
                address_len = 1 + 16 + 2;
                return true;
            }
            break;
        }
    }
    return false;

    _unguard;
}

static const std::string unspecified_address("\x01\x00\x00\x00\x00\x00\x00", 7);

void SOCKS5Address::generate(boost::asio::streambuf& buf, const udp::endpoint& endpoint) {
    if (endpoint.address().is_unspecified()) {
        streambuf_append(buf, unspecified_address);
        return;
    }

    if (endpoint.address().is_v4()) {
        streambuf_append(buf, '\x01');
        auto ip = endpoint.address().to_v4().to_bytes();
        streambuf_append(buf, ip.data(), ip.size());
    }
    if (endpoint.address().is_v6()) {
        streambuf_append(buf, '\x04');
        auto ip = endpoint.address().to_v6().to_bytes();
        streambuf_append(buf, ip.data(), ip.size());
    }
    streambuf_append(buf, char(uint8_t(endpoint.port() >> one_byte_shift_8_bits)));
    streambuf_append(buf, char(uint8_t(endpoint.port() & one_byte_mask_0xFF)));
}
