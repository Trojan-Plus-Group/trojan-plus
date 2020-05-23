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

#ifndef IPV6_HEADER_HPP
#define IPV6_HEADER_HPP

#include <iostream>
#include <algorithm>
#include <boost/asio/ip/address_v4.hpp>

// Packet header for IPv4.
//
// The wire format of an IPv4 header is:
// https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header

namespace trojan{
    
class ipv6_header {
public:
    enum {
        HEADER_FIXED_LENGTH = 40,
    };

    ipv6_header() { clear(); }
    void clear() { std::fill(rep_, rep_ + sizeof(rep_), 0); }
    const unsigned char* raw(){ return rep_; }

    unsigned char version() const { return (rep_[0] >> 4) & 0xF; }
    unsigned short payload_length() const { return decode(4, 5); }

    friend std::istream &operator>>(std::istream &is, ipv6_header &header) {
        is.read(reinterpret_cast<char *>(header.rep_), HEADER_FIXED_LENGTH);
        return is;
    }

private:
    unsigned short decode(int a, int b) const {
        return (rep_[a] << 8) + rep_[b];
    }

    void encode(int a, int b, unsigned short n) {
        rep_[a] = static_cast<unsigned char>(n >> 8);
        rep_[b] = static_cast<unsigned char>(n & 0xFF);
    }

    unsigned char rep_[HEADER_FIXED_LENGTH];
};

}

#endif  // IPV6_HEADER_HPP