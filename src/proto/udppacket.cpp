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

#include "udppacket.h"

#include "core/utils.h"

using namespace std;
using namespace boost::asio::ip;

bool UDPPacket::parse(const string_view& data, size_t& udp_packet_len) {
    _guard;

    if (data.length() <= 0) {
        return false;
    }
    size_t address_len = 0;
    bool is_addr_valid = address.parse(data, address_len);
    if (!is_addr_valid || data.length() < address_len + 2) {
        return false;
    }
    length = (uint8_t(data[address_len]) << one_byte_shift_8_bits) | uint8_t(data[address_len + 1]);
    if (data.length() < address_len + 4 + length || data.substr(address_len + 2, 2) != "\r\n") {
        return false;
    }
    payload        = data.substr(address_len + 4, length);
    udp_packet_len = address_len + 4 + length;
    return true;

    _unguard;
}

boost::asio::streambuf& UDPPacket::generate(
  boost::asio::streambuf& buf, const udp::endpoint& endpoint, const string_view& payload) {
    _guard;

    SOCKS5Address::generate(buf, endpoint);
    streambuf_append(buf, char(uint8_t(payload.length() >> one_byte_shift_8_bits)));
    streambuf_append(buf, char(uint8_t(payload.length() & one_byte_mask_0xFF)));
    streambuf_append(buf, "\r\n");
    streambuf_append(buf, payload);
    return buf;

    _unguard;
}

boost::asio::streambuf& UDPPacket::generate(
  boost::asio::streambuf& buf, const string& domainname, uint16_t port, const string_view& payload) {
    _guard;

    streambuf_append(buf, '\x03');
    streambuf_append(buf, char(uint8_t(domainname.length())));
    streambuf_append(buf, domainname);
    streambuf_append(buf, char(uint8_t(port >> one_byte_shift_8_bits)));
    streambuf_append(buf, char(uint8_t(port & one_byte_mask_0xFF)));
    streambuf_append(buf, char(uint8_t(payload.length() >> one_byte_shift_8_bits)));
    streambuf_append(buf, char(uint8_t(payload.length() & one_byte_mask_0xFF)));
    streambuf_append(buf, "\r\n");
    streambuf_append(buf, payload);
    return buf;

    _unguard;
}
