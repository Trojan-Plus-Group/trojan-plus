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

#include <boost/asio/ip/address_v6.hpp>

#include "core/utils.h"
#include "mem/memallocator.h"

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
                address = tp::to_string(uint8_t(data[1])) + '.' + tp::to_string(uint8_t(data[2])) + '.' +
                          tp::to_string(uint8_t(data[3])) + '.' + tp::to_string(uint8_t(data[4]));
                port        = (uint8_t(data[5]) << one_byte_shift_8_bits) | uint8_t(data[6]);
                address_len = 1 + 4 + 2;
                return true;
            }
            break;
        }
        case DOMAINNAME: {
            if (data.length() < 2) {
                break;
            }
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
                address_v6::bytes_type bytes{};
                for (int i = 0; i < 16; ++i) {
                    bytes[static_cast<size_t>(i)] = static_cast<unsigned char>(data[1 + i]);
                }
                // address_v6::to_string() is the standard compressed form (::1, not 0000:…:0001).
                address     = address_v6(bytes).to_string().c_str();
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

static void append_port(tp::string& out, uint16_t port) {
    out += char(uint8_t(port >> one_byte_shift_8_bits));
    out += char(uint8_t(port & one_byte_mask_0xFF));
}

static tp::string encode_domain(const tp::string& host, uint16_t port) {
    tp::string ret;
    ret += '\x03';
    ret += char(uint8_t(host.length()));
    ret += host;
    append_port(ret, port);
    return ret;
}

static tp::string encode_v4_bytes(const address_v4::bytes_type& bytes, uint16_t port) {
    tp::string ret;
    ret += '\x01';
    ret.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    append_port(ret, port);
    return ret;
}

void SOCKS5Address::generate(tp::streambuf& buf, const udp::endpoint& endpoint) {
    // to_string() keeps a zone id (fe80::1%eth0). encode() then chooses ATYP.
    // Unspecified addresses keep their family and port: :: is ATYP 4, 0.0.0.0 is ATYP 1.
    const tp::string host(endpoint.address().to_string().c_str());
    streambuf_append(buf, encode(host, endpoint.port()));
}

tp::string SOCKS5Address::encode(const tp::string& host, uint16_t port) {
    // ATYP 4 has no zone. make_address() also accepts an unknown interface
    // name and stores scope_id 0, so a '%' in the original text is enough to
    // keep the literal as a domain. The peer resolver still sees the zone.
    if (host.find('%') != tp::string::npos) {
        return encode_domain(host, port);
    }

    boost::system::error_code ec;
    const auto addr = make_address(host.c_str(), ec);
    if (ec) {
        return encode_domain(host, port);
    }
    if (addr.is_v6() && addr.to_v6().scope_id() != 0) {
        return encode_domain(host, port);
    }
    if (addr.is_v4()) {
        return encode_v4_bytes(addr.to_v4().to_bytes(), port);
    }
    if (addr.is_v6() && addr.to_v6().is_v4_mapped()) {
        return encode_v4_bytes(make_address_v4(v4_mapped, addr.to_v6()).to_bytes(), port);
    }
    if (addr.is_v6()) {
        tp::string ret;
        ret += '\x04';
        const auto bytes = addr.to_v6().to_bytes();
        ret.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        append_port(ret, port);
        return ret;
    }
    return encode_domain(host, port);
}
