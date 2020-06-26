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

#ifndef _TROJAN_DNS_HEADER_HPP
#define _TROJAN_DNS_HEADER_HPP

#include <array>
#include <cstdint>
#include <gsl/gsl>
#include <iostream>
#include <sstream>

#include "core/utils.h"

namespace trojan {

#define _test_case(hdr, func, val, val_type)                                                                           \
    do {                                                                                                               \
        hdr.func((val_type)(val));                                                                                     \
        if ((val_type)(val) != hdr.func()) {                                                                           \
            throw std::runtime_error("Error: " #func " is not same!!!");                                               \
        }                                                                                                              \
    } while (false)

#define _test_case_call_assert(hdr, func, val, val_type)                                                               \
    do {                                                                                                               \
        if ((val_type)(val) != hdr.func()) {                                                                           \
            throw std::runtime_error("Error: " #func " final value is not correct!!");                                 \
        }                                                                                                              \
    } while (false)

#define _test_case_assert(exp, exp1)                                                                                   \
    do {                                                                                                               \
        if ((exp) != (exp1)) {                                                                                         \
            throw std::runtime_error(                                                                                  \
              "test_cases failed, [" #exp "==" + std::to_string(exp) + "] is not equal [" #exp1 "]");                  \
        }                                                                                                              \
    } while (false)

#define _test_case_assert_str(exp, exp1)                                                                               \
    do {                                                                                                               \
        if ((exp) != (exp1)) {                                                                                         \
            throw std::runtime_error("test_cases failed, [" #exp "==" + (exp) + "] is not equal [" #exp1 "]");         \
        }                                                                                                              \
    } while (false)

//
// https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
//
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|  Opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   QDCOUNT                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   ANCOUNT                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   NSCOUNT                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   ARCOUNT                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
class dns_header {
  public:
    enum {
        DNS_HEADER_LENGTH = 12,

        QR_QUERY   = 0,
        QR_RESPONE = 1,

        RCODE_NO_ERROR_CONDITION = 0,
        RCODE_FORMAT_ERROR       = 1,
        RCODE_SERVER_FAILURE     = 2,
        RCODE_NAME_ERROR         = 3,
        RCODE_NOT_IMPLEMENTED    = 4,
        RCODE_REFUSED            = 5,

        // for dns question and answer type
        // full type: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
        QTYPE_A_RECORD     = 1,
        QTYPE_NS_RECORD    = 2,
        QTYPE_CNAME_RECORD = 5,
        QTYPE_SOA          = 6,
        QTYPE_WKS          = 11,
        QTYPE_PTR          = 12,
        QTYPE_HINFO        = 13,
        QTYPE_MAIL_SERVER  = 15,
        QTYPE_AAAA_RECORD  = 28,
        QTYPE_AXFR         = 252,
        QTYPE_ANY          = 255,

        QCLASS_INTERNET = 1,
    };

    static const char label_split_char  = '.';
    static const uint8_t label_ptr_sign = 0xc0;

  private:
    std::array<uint8_t, DNS_HEADER_LENGTH> rep_{};

    [[nodiscard]] inline uint16_t decode(int a, int b) const { return (rep_[a] << one_byte_shift_8_bits) + rep_[b]; }

    inline void encode(int a, int b, uint16_t n) {
        rep_[a] = static_cast<uint8_t>(n >> one_byte_shift_8_bits);
        rep_[b] = static_cast<uint8_t>(n & one_byte_mask_0xFF);
    }

  public:
    [[nodiscard]] inline uint16_t ID() const { return decode(0, 1); }

    [[nodiscard]] inline uint8_t QR() const { return rep_[2] >> 7; }
    [[nodiscard]] inline uint8_t Opcode() const { return (rep_[2] >> 3) & half_byte_mask_0xF; }
    [[nodiscard]] inline uint8_t AA() const { return (rep_[2] >> 2) & 0x1; }
    [[nodiscard]] inline uint8_t TC() const { return (rep_[2] >> 1) & 0x1; }
    [[nodiscard]] inline uint8_t RD() const { return (rep_[2] & 0x1); }
    [[nodiscard]] inline uint8_t RA() const { return (rep_[3] >> 7); }

    [[nodiscard]] inline uint8_t Z() const { return (rep_[3] >> half_byte_shift_4_bits) & 0x7; }
    [[nodiscard]] inline uint8_t RCODE() const { return (rep_[3] & half_byte_mask_0xF); }

    [[nodiscard]] inline uint16_t QDCOUNT() const { return decode(4, 5); }
    [[nodiscard]] inline uint16_t ANCOUNT() const { return decode(6, 7); }
    [[nodiscard]] inline uint16_t NSCOUNT() const { return decode(8, 9); }
    [[nodiscard]] inline uint16_t ARCOUNT() const { return decode(10, 11); }

    inline void ID(uint16_t v) { encode(0, 1, v); }

    inline void QR(uint8_t v) {
        if (v == 0)
            rep_[2] &= 0x7F;
        else
            rep_[2] |= 0x80;
    }
    inline void Opcode(uint8_t v) { rep_[2] = ((v & half_byte_mask_0xF) << 3) + (rep_[2] & (0x80 + 0x7)); }
    inline void AA(uint8_t v) {
        if (v == 0)
            rep_[2] &= (~0x4);
        else
            rep_[2] |= 0x4;
    }
    inline void TC(uint8_t v) {
        if (v == 0)
            rep_[2] &= (~0x2);
        else
            rep_[2] |= 0x2;
    }
    inline void RD(uint8_t v) {
        if (v == 0)
            rep_[2] &= (~0x1);
        else
            rep_[2] |= 0x1;
    }
    inline void RA(uint8_t v) {
        if (v == 0)
            rep_[2] &= (~0x80);
        else
            rep_[3] |= 0x80;
    }

    inline void Z(uint8_t v) {
        rep_[3] = ((v & 0x7) << half_byte_shift_4_bits) + (rep_[3] & (0x80 + half_byte_mask_0xF));
    }
    inline void RCODE(uint8_t v) { rep_[3] = (v & half_byte_mask_0xF) + (rep_[3] & 0xF0); }

    inline void QDCOUNT(uint16_t v) { encode(4, 5, v); }
    inline void ANCOUNT(uint16_t v) { encode(6, 7, v); }
    inline void NSCOUNT(uint16_t v) { encode(8, 9, v); }
    inline void ARCOUNT(uint16_t v) { encode(10, 11, v); }

    inline friend std::istream& operator>>(std::istream& is, dns_header& header) {
        is.read((char*)(header.rep_.data()), header.rep_.max_size());
        return is;
    }

    inline friend std::ostream& operator<<(std::ostream& os, const dns_header& header) {
        os.write((const char*)(header.rep_.data()), header.rep_.max_size());
        return os;
    }

    static std::istream& read_label(std::istream& is, std::string& name);
    static std::ostream& write_label(std::ostream& os, const std::string& name);

    static void test_cases();
};

// dns question format
//
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                    QNAME                      /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QTYPE                      |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QCLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

class dns_question {
  public:
    enum {
        MAX_QNAME_LENGTH = 512,

    };

  private:
    std::string QNAME;
    uint16_t QTYPE;
    uint16_t QCLASS;

  public:
    _define_simple_getter_setter(const std::string&, QNAME);
    _define_simple_getter_setter(uint16_t, QTYPE);
    _define_simple_getter_setter(uint16_t, QCLASS);

    [[nodiscard]] inline static uint16_t decode(std::istream& is) {
        if (!is) {
            return 0;
        }

        is >> std::noskipws;

        uint8_t high, low;
        if (!(is >> high)) {
            return 0;
        }

        if (!(is >> low)) {
            return 0;
        }

        return (uint16_t(high) << one_byte_shift_8_bits) + low;
    }

    [[nodiscard]] inline static uint32_t decode32(std::istream& is) {
        if (!is) {
            return 0;
        }
        auto high = dns_question::decode(is);
        auto low  = dns_question::decode(is);

        return is ? (((uint32_t)high) << two_bytes_shift_16_bits | low) : 0;
    }

    inline static void encode(std::ostream& os, uint16_t n) {
        os << static_cast<uint8_t>(n >> one_byte_shift_8_bits);
        os << static_cast<uint8_t>(n & one_byte_mask_0xFF);
    }
    friend std::istream& operator>>(std::istream& is, dns_question& header) {
        if (dns_header::read_label(is, header.QNAME)) {
            header.QTYPE  = decode(is);
            header.QCLASS = decode(is);
        }
        return is;
    }

    friend std::ostream& operator<<(std::ostream& os, const dns_question& header) {
        dns_header::write_label(os, header.QNAME);
        encode(os, header.QTYPE);
        encode(os, header.QCLASS);
        return os;
    }

    static void test_case(const char* domain, uint16_t qtype, uint16_t qclass);
    static void test_cases();
};

// dns answer
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                    NAME                       /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    TYPE                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    CLASS                      |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     TTL                       |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                    RDATA                      /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

class dns_answer {
  public:
    enum {
        MAX_RD_LENGTH = 512,
    };

    using answer = struct {
        std::string NAME;
        uint16_t TYPE;
        uint16_t CLASS;
        uint32_t TTL;
        std::string RD;
        std::string A;
        std::string AAAA;
    };

  private:
    dns_header header;
    std::vector<dns_question> questions;
    std::vector<answer> answers;
    std::vector<answer> authorities;
    std::vector<answer> additionals;

    static std::istream& read_answer(std::istream& is, answer& an);

  public:
    _define_getter_const(const dns_header&, header) _define_getter_const(const std::vector<dns_question>&, questions);
    _define_getter_const(const std::vector<answer>&, answers);
    _define_getter_const(const std::vector<answer>&, authorities);
    _define_getter_const(const std::vector<answer>&, additionals);

    friend std::istream& operator>>(std::istream& is, dns_answer& answer);
    static void test_cases();
};

} // namespace trojan
#endif //_TROJAN_DNS_HEADER_HPP