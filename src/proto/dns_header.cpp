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

#include "proto/dns_header.h"


namespace trojan {

void dns_header::test_cases() {
    dns_header hdr;

    _test_case(hdr, ID, 123456, uint16_t);
    _test_case(hdr, ID, 123, uint16_t);
    _test_case(hdr, QR, 1, uint8_t);
    _test_case(hdr, QR, 0, uint8_t);
    _test_case(hdr, Opcode, 1, uint8_t);
    _test_case(hdr, Opcode, 0, uint8_t);
    _test_case(hdr, Opcode, 7, uint8_t);
    _test_case(hdr, AA, 0, uint8_t);
    _test_case(hdr, AA, 1, uint8_t);
    _test_case(hdr, TC, 0, uint8_t);
    _test_case(hdr, TC, 1, uint8_t);
    _test_case(hdr, RD, 0, uint8_t);
    _test_case(hdr, RD, 1, uint8_t);
    _test_case(hdr, RA, 0, uint8_t);
    _test_case(hdr, RA, 1, uint8_t);
    _test_case(hdr, Z, 1, uint8_t);
    _test_case(hdr, Z, 0, uint8_t);
    _test_case(hdr, Z, 7, uint8_t);
    _test_case(hdr, RCODE, 1, uint8_t);
    _test_case(hdr, RCODE, 0, uint8_t);
    _test_case(hdr, RCODE, 7, uint8_t);
    _test_case(hdr, QDCOUNT, 123456, uint16_t);
    _test_case(hdr, QDCOUNT, 123, uint16_t);
    _test_case(hdr, ANCOUNT, 123456, uint16_t);
    _test_case(hdr, ANCOUNT, 123, uint16_t);
    _test_case(hdr, NSCOUNT, 123456, uint16_t);
    _test_case(hdr, NSCOUNT, 123, uint16_t);
    _test_case(hdr, ARCOUNT, 123456, uint16_t);
    _test_case(hdr, ARCOUNT, 123, uint16_t);

    // test
    _test_case_call_assert(hdr, ID, 123, uint16_t);
    _test_case_call_assert(hdr, QR, 0, uint8_t);
    _test_case_call_assert(hdr, Opcode, 7, uint8_t);
    _test_case_call_assert(hdr, AA, 1, uint8_t);
    _test_case_call_assert(hdr, TC, 1, uint8_t);
    _test_case_call_assert(hdr, RD, 1, uint8_t);
    _test_case_call_assert(hdr, RA, 1, uint8_t);
    _test_case_call_assert(hdr, Z, 7, uint8_t);
    _test_case_call_assert(hdr, RCODE, 7, uint8_t);
    _test_case_call_assert(hdr, QDCOUNT, 123, uint16_t);
    _test_case_call_assert(hdr, ANCOUNT, 123, uint16_t);
    _test_case_call_assert(hdr, NSCOUNT, 123, uint16_t);
    _test_case_call_assert(hdr, ARCOUNT, 123, uint16_t);
};

std::istream& dns_header::read_label(std::istream& is, std::string& name) {
    _guard;

    is >> std::noskipws;

    uint8_t sign;
    if (!(is >> sign)) {
        return is;
    }
    if ((sign & 0xc0) != 0) {
        uint8_t low;
        if (!(is >> low)) {
            return is;
        }
        uint16_t ptr = uint16_t(sign & 0x3f) + uint16_t(low);

        auto curr = is.tellg();
        is.seekg(ptr);
        read_label(is, name);

        is.seekg(curr);

        return is;
    }

    if (sign == 0) {
        return is;
    }

    char buf[std::numeric_limits<uint8_t>::max()];
    is.read((char*)buf, sign);

    if (!name.empty()) {
        name.append(1, label_split_char);
    }

    name.append(buf, sign);

    read_label(is, name);
    return is;

    _unguard;
}

std::ostream& dns_header::write_label(std::ostream& os, const std::string& name) {
    _guard;

    const char* data      = name.c_str();
    const size_t data_len = name.length();

    uint8_t start_write_len = 0;
    const char* start_write = data;

    for (size_t i = 0; i < data_len; i++) {
        if (data[i] == label_split_char) {
            os << start_write_len;
            os.write(start_write, start_write_len);

            start_write_len = 0;
            start_write     = data + i + 1;
        } else {
            start_write_len++;
        }
    }

    if (start_write_len > 0) {
        os << (uint8_t)start_write_len;
        os.write(start_write, start_write_len);
    }

    os << (uint8_t)0;
    return os;
    _unguard;
}

void dns_question::test_case(const char* domain, uint16_t qtype, uint16_t qclass) {
    std::ostringstream os;
    dns_question question;
    question.set_QNAME(domain);
    question.set_QTYPE(qtype);
    question.set_QCLASS(qclass);

    os << question;

    std::istringstream is(os.str());
    dns_question question1;
    is >> question1;

    _test_case_assert_str(question.get_QNAME(), question1.get_QNAME());
    _test_case_assert(question.get_QTYPE(), question1.get_QTYPE());
    _test_case_assert(question.get_QCLASS(), question1.get_QCLASS());
}

void dns_question::test_cases() {
    test_case("", 0, 0);
    test_case("", 1, 1);
    test_case("", 123, 112);

    test_case("", 0, 0);
    test_case("", 1, 1);
    test_case("", std::numeric_limits<uint16_t>::max(), std::numeric_limits<uint16_t>::max());

    test_case("ab", 0, 0);
    test_case("ab", 1, 1);
    test_case("ab", 123, 112);

    test_case("ab", 0, 0);
    test_case("ab", 1, 1);
    test_case("ab", std::numeric_limits<uint16_t>::max(), std::numeric_limits<uint16_t>::max());

    test_case("ab.cd", 0, 0);
    test_case("ab.cd", 1, 1);
    test_case("ab.cd", 123, 112);

    test_case("ab.cd", 0, 0);
    test_case("ab.cd", 1, 1);
    test_case("ab.cd", std::numeric_limits<uint16_t>::max(), std::numeric_limits<uint16_t>::max());

    test_case("ab.cd.com", 0, 0);
    test_case("ab.cd.com", 1, 1);
    test_case("ab.cd.com", 123, 112);

    test_case("ab.cd.com", 0, 0);
    test_case("ab.cd.com", 1, 1);
    test_case("ab.cd.com", std::numeric_limits<uint16_t>::max(), std::numeric_limits<uint16_t>::max());

    test_case("ab.cd12.com", 0, 0);
    test_case("ab.c33d.com", 1, 1);
    test_case("ab.22cd.com", std::numeric_limits<uint16_t>::max(), std::numeric_limits<uint16_t>::max());

    std::string test_data("\x6c\xad\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x03\x77\x77\x77\x05\x62\x61\x69\x64\x75\x03\x63"
                     "\x6f\x6d\x00\x00\x1c\x00\x01",
      31);
    std::istringstream is(test_data);

    dns_header header;
    is >> header;

    _test_case_assert(header.QDCOUNT(), 1);
    _test_case_assert(header.QR(), dns_header::QR_QUERY);

    dns_question qt;
    is >> qt;

    _test_case_assert_str(qt.get_QNAME(), "www.baidu.com");
    _test_case_assert(qt.get_QTYPE(), dns_header::QTYPE_AAAA_RECORD);
    _test_case_assert(qt.get_QCLASS(), dns_header::QCLASS_INTERNET);
}

std::istream& dns_answer::read_answer(std::istream& is, answer& an) {
    _guard;

    if (!dns_header::read_label(is, an.NAME)) {
        return is;
    }

    an.TYPE         = dns_question::decode(is);
    an.CLASS        = dns_question::decode(is);
    an.TTL          = dns_question::decode32(is);
    uint16_t length = dns_question::decode(is);
    if (an.TYPE == dns_header::QTYPE_CNAME_RECORD) {
        dns_header::read_label(is, an.RD);
    } else {
        uint8_t c;
        while (length-- > 0) {
            if (is >> c) {
                an.RD += c;
            } else {
                break;
            }
        }
    }

    if (is) {
        if (an.TYPE == dns_header::QTYPE_A_RECORD) {
            an.A     = parse_uint32(0, an.RD);
            an.A_str = boost::asio::ip::make_address_v4(an.A).to_string();
        } else if (an.TYPE == dns_header::QTYPE_AAAA_RECORD) {
            std::copy(an.RD.data(), an.RD.data() + an.AAAA.max_size(), an.AAAA.begin());
            an.AAAA_str = boost::asio::ip::make_address_v6(an.AAAA).to_string();
        }
    }

    return is;
    _unguard;
}

std::istream& operator>>(std::istream& is, dns_answer& answer) {
    _guard;
    is >> std::noskipws;
    is >> answer.header;
    const auto question_count   = answer.header.QDCOUNT();
    const auto answer_count     = answer.header.ANCOUNT();
    const auto anthority_count  = answer.header.NSCOUNT();
    const auto anditional_count = answer.header.ARCOUNT();

    for (int i = 0; i < question_count; i++) {
        if (is) {
            dns_question q;
            is >> q;
            answer.questions.emplace_back(q);
        }
    }

    for (int i = 0; i < answer_count; i++) {
        if (is) {
            dns_answer::answer an{};
            dns_answer::read_answer(is, an);
            answer.answers.emplace_back(an);
        }
    }

    for (int i = 0; i < anthority_count; i++) {
        if (is) {
            dns_answer::answer an{};
            dns_answer::read_answer(is, an);
            answer.authorities.emplace_back(an);
        }
    }

    for (int i = 0; i < anditional_count; i++) {
        if (is) {
            dns_answer::answer an{};
            dns_answer::read_answer(is, an);
            answer.additionals.emplace_back(an);
        }
    }
    return is;
    _unguard;
}

void dns_answer::test_cases() {
    {
        std::string test_data(
          "\x73\x47\x81\x80\x00\x01\x00\x03\x00\x00\x00\x01\x03\x77\x77\x77\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00"
          "\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x02\x20\x00\x0f\x03\x77\x77\x77\x01\x61\x06\x73\x68\x69\x66"
          "\x65\x6e\xc0\x16\xc0\x2b\x00\x01\x00\x01\x00\x00\x00\x29\x00\x04\xb4\x65\x31\x0c\xc0\x2b\x00\x01\x00\x01\x00"
          "\x00\x00\x29\x00\x04\xb4\x65\x31\x0b\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x00",
          135);
        std::istringstream is(test_data);

        dns_answer answer;
        is >> std::noskipws >> answer;

        _test_case_assert(answer.get_questions().size(), 1);
        _test_case_assert_str(answer.get_questions()[0].get_QNAME(), "www.baidu.com");
        _test_case_assert(answer.get_questions()[0].get_QTYPE(), dns_header::QTYPE_A_RECORD);
        _test_case_assert(answer.get_questions()[0].get_QCLASS(), dns_header::QCLASS_INTERNET);

        _test_case_assert(answer.get_answers().size(), 3);

        _test_case_assert(answer.get_answers()[0].TYPE, dns_header::QTYPE_CNAME_RECORD);
        _test_case_assert(answer.get_answers()[0].CLASS, dns_header::QCLASS_INTERNET);
        _test_case_assert(answer.get_answers()[0].TTL, 0x220);
        _test_case_assert_str(answer.get_answers()[0].NAME, "www.baidu.com");
        _test_case_assert_str(answer.get_answers()[0].RD, "www.a.shifen.com");

        _test_case_assert(answer.get_answers()[1].TYPE, dns_header::QTYPE_A_RECORD);
        _test_case_assert(answer.get_answers()[1].CLASS, dns_header::QCLASS_INTERNET);
        _test_case_assert(answer.get_answers()[1].TTL, 0x29);
        _test_case_assert_str(answer.get_answers()[1].NAME, "www.a.shifen.com");
        _test_case_assert_str(answer.get_answers()[1].A_str, "180.101.49.12");

        _test_case_assert(answer.get_answers()[2].TYPE, dns_header::QTYPE_A_RECORD);
        _test_case_assert(answer.get_answers()[2].CLASS, dns_header::QCLASS_INTERNET);
        _test_case_assert(answer.get_answers()[2].TTL, 0x29);
        _test_case_assert_str(answer.get_answers()[2].NAME, "www.a.shifen.com");
        _test_case_assert_str(answer.get_answers()[2].A_str, "180.101.49.11");
    }

    {
        std::string test_data(
          "\x6c\xad\x81\x80\x00\x01\x00\x01\x00\x01\x00\x01\x03\x77\x77\x77\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00"
          "\x00\x1c\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x41\x00\x0f\x03\x77\x77\x77\x01\x61\x06\x73\x68\x69\x66"
          "\x65\x6e\xc0\x16\xc0\x2f\x00\x06\x00\x01\x00\x00\x01\x1d\x00\x2d\x03\x6e\x73\x31\xc0\x2f\x10\x62\x61\x69\x64"
          "\x75\x5f\x64\x6e\x73\x5f\x6d\x61\x73\x74\x65\x72\xc0\x10\x77\x94\xcb\x07\x00\x00\x00\x05\x00\x00\x00\x05\x00"
          "\x27\x8d\x00\x00\x00\x0e\x10\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x00",
          126);
        std::istringstream is(test_data);

        dns_answer answer;
        is >> std::noskipws >> answer;

        _test_case_assert(answer.get_header().QDCOUNT(), 1);
        _test_case_assert(answer.get_header().ANCOUNT(), 1);
        _test_case_assert(answer.get_header().NSCOUNT(), 1);
        _test_case_assert(answer.get_header().ARCOUNT(), 1);

        _test_case_assert(answer.get_header().QR(), dns_header::QR_RESPONE);

        _test_case_assert(answer.get_questions().size(), 1);
        _test_case_assert_str(answer.get_questions()[0].get_QNAME(), "www.baidu.com");
        _test_case_assert(answer.get_questions()[0].get_QTYPE(), dns_header::QTYPE_AAAA_RECORD);
        _test_case_assert(answer.get_questions()[0].get_QCLASS(), dns_header::QCLASS_INTERNET);

        _test_case_assert(answer.get_answers().size(), 1);

        _test_case_assert(answer.get_answers()[0].TYPE, dns_header::QTYPE_CNAME_RECORD);
        _test_case_assert(answer.get_answers()[0].CLASS, dns_header::QCLASS_INTERNET);
        _test_case_assert(answer.get_answers()[0].TTL, 0x41);
        _test_case_assert_str(answer.get_answers()[0].NAME, "www.baidu.com");
        _test_case_assert_str(answer.get_answers()[0].RD, "www.a.shifen.com");

        _test_case_assert(answer.get_authorities().size(), 1);

        _test_case_assert(answer.get_authorities()[0].TYPE, dns_header::QTYPE_SOA);
        _test_case_assert(answer.get_authorities()[0].CLASS, dns_header::QCLASS_INTERNET);
        _test_case_assert(answer.get_authorities()[0].TTL, 0x11d);
        _test_case_assert_str(answer.get_authorities()[0].NAME, "a.shifen.com");

        _test_case_assert(answer.get_additionals().size(), 1);

        _test_case_assert(
          answer.get_additionals()[0].TYPE, 41); // OPT: http://www.networksorcery.com/enp/rfc/rfc2671.txt
        _test_case_assert(answer.get_additionals()[0].CLASS, 0x200);
        _test_case_assert(answer.get_additionals()[0].TTL, 0);
        _test_case_assert_str(answer.get_additionals()[0].NAME, "");
    }
}

} // namespace trojan