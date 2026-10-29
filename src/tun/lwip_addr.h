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

#ifndef _TROJAN_LWIP_ADDR_H_
#define _TROJAN_LWIP_ADDR_H_

#include <cstring>

#include <boost/asio/ip/address.hpp>
#include <lwip/ip_addr.h>
#include <misc/byteorder.h>

// lwIP stores an IPv4 address in network order. Boost's to_uint()/from host
// order is the same conversion the IPv4 TUN path already uses.
// An IPv4-mapped IPv6 address is unwrapped so TrojanRequest encoding emits
// ATYP 1. Other IPv6 addresses stay IPv6 and encode as ATYP 4.
inline boost::asio::ip::address address_from_lwip(const ip_addr_t& ip) {
    using namespace boost::asio::ip;
#if LWIP_IPV6
    if (IP_IS_V6_VAL(ip)) {
        address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), ip.u_addr.ip6.addr, bytes.size());
        const address_v6 v6(bytes);
        if (v6.is_v4_mapped()) {
            return make_address_v4(v4_mapped, v6);
        }
        return v6;
    }
#else
    (void)ip;
#endif
    return make_address_v4(static_cast<address_v4::uint_type>(ntoh32(ip.u_addr.ip4.addr)));
}

#endif // _TROJAN_LWIP_ADDR_H_
