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

#include "utils.h"

#include <fstream>
#include <gsl/gsl>

#ifdef __ANDROID__
#include <jni.h>
#include <signal.h>
#endif //__ANDROID__

#include "core/service.h"
#include "core/version.h"
#include "log.h"

using namespace std;
using namespace boost::asio::ip;

size_t streambuf_append(boost::asio::streambuf& target, const boost::asio::streambuf& append_buf) {
    _guard;
    if (append_buf.size() == 0) {
        return 0;
    }

    auto copied = boost::asio::buffer_copy(target.prepare(append_buf.size()), append_buf.data());
    target.commit(copied);
    return copied;
    _unguard;
}

size_t streambuf_append(
  boost::asio::streambuf& target, const boost::asio::streambuf& append_buf, size_t start, size_t n) {
    _guard;
    if (start >= append_buf.size()) {
        return 0;
    }

    if ((start + n) > append_buf.size()) {
        return 0;
    }

    auto* dest      = boost::asio::buffer_cast<uint8_t*>(target.prepare(n));
    const auto* src = boost::asio::buffer_cast<const uint8_t*>(append_buf.data()) + start;
    memcpy(dest, src, n);
    target.commit(n);
    return n;

    _unguard;
}

size_t streambuf_append(boost::asio::streambuf& target, const char* append_str) {
    _guard;
    if (append_str == nullptr) {
        return 0;
    }

    auto length = strlen(append_str);
    if (length == 0) {
        return 0;
    }

    auto copied = boost::asio::buffer_copy(target.prepare(length), boost::asio::buffer(append_str, length));
    target.commit(copied);
    return copied;
    _unguard;
}

size_t streambuf_append(boost::asio::streambuf& target, const uint8_t* append_data, size_t append_length) {
    _guard;

    if (append_data == nullptr || append_length == 0) {
        return 0;
    }

    auto copied =
      boost::asio::buffer_copy(target.prepare(append_length), boost::asio::buffer(append_data, append_length));
    target.commit(copied);
    return copied;
    _unguard;
}

size_t streambuf_append(boost::asio::streambuf& target, char append_char) {
    _guard;
    const size_t char_length = sizeof(char);
    auto cp = gsl::span<char>(boost::asio::buffer_cast<char*>(target.prepare(char_length)), char_length);
    cp[0]   = append_char;
    target.commit(char_length);
    return char_length;
    _unguard;
}

size_t streambuf_append(boost::asio::streambuf& target, const std::string_view& append_data) {
    _guard;

    if (append_data.empty()) {
        return 0;
    }

    auto copied = boost::asio::buffer_copy(
      target.prepare(append_data.length()), boost::asio::buffer(append_data.data(), append_data.length()));
    target.commit(copied);
    return copied;
    _unguard;
}

size_t streambuf_append(boost::asio::streambuf& target, const std::string& append_data) {
    _guard;
    if (append_data.empty()) {
        return 0;
    }

    auto copied = boost::asio::buffer_copy(target.prepare(append_data.length()), boost::asio::buffer(append_data));
    target.commit(copied);
    return copied;
    _unguard;
}

std::string_view streambuf_to_string_view(const boost::asio::streambuf& target) {
    _guard;
    return std::string_view(boost::asio::buffer_cast<const char*>(target.data()), target.size());
    _unguard;
}

unsigned short get_checksum(const std::string_view& str) {
    _guard;

    unsigned int sum = 0;
    // clang-tidy advice failed:
    // compiling error in MSVC if change it into type "const auto*", error message:
    //  cannot deduce type for 'const auto *' from 'std::_String_view_iterator<_Traits>'
    auto body_iter = str.cbegin();
    while (body_iter != str.cend()) {
        sum += (static_cast<uint8_t>(*body_iter++) << one_byte_shift_8_bits);
        if (body_iter != str.end()) {
            sum += static_cast<uint8_t>(*body_iter++);
        }
    }

    return static_cast<unsigned short>(sum);
    _unguard;
}

unsigned short get_checksum(const std::string& str) { return get_checksum(string_view(str)); }

unsigned short get_checksum(const boost::asio::streambuf& buf) { return get_checksum(streambuf_to_string_view(buf)); }

int get_hashCode(const std::string& str) {
    _guard;
    const int hash_code_magic_number = 31;
    int h                            = 0;
    for (auto c : str) {
        h = hash_code_magic_number * h + c;
    }
    return h;
    _unguard;
}

void write_data_to_file(int id, const std::string& tag, const std::string_view& data) {
    _guard;
    ofstream file(tag + "_" + to_string(id) + ".data", std::ofstream::out | std::ofstream::app);
    file << data;
    file.close();
    _unguard;
}

SendDataCache::SendDataCache() : is_async_sending(false), destroyed(false) {
    _guard;
    is_connected = []() { return true; };

    current_recv_handler = &handler_queue;
    current_recv_queue   = &data_queue;
    _unguard;
}

void SendDataCache::swap_recv() {
    _guard;
    if (current_recv_handler == &handler_queue) {
        current_recv_handler = &handler_queue_other;
        current_recv_queue   = &data_queue_other;
    } else {
        current_recv_handler = &handler_queue;
        current_recv_queue   = &data_queue;
    }
    _unguard;
}

void SendDataCache::destroy() {
    _guard;
    if (destroyed) {
        return;
    }
    destroyed = true;

    for (auto& handler : handler_queue_other) {
        handler(boost::asio::error::broken_pipe);
    }
    handler_queue_other.clear();

    for (auto& handler : handler_queue) {
        handler(boost::asio::error::broken_pipe);
    }
    handler_queue.clear();
    _unguard;
}

void SendDataCache::set_async_writer(AsyncWriter&& writer) { async_writer = std::move(writer); }

void SendDataCache::set_is_connected_func(ConnectionFunc&& func) { is_connected = std::move(func); }

void SendDataCache::insert_data(const std::string_view& data) {
    _guard;
    if (destroyed) {
        return;
    }

    boost::asio::streambuf copy_data_queue;
    streambuf_append(copy_data_queue, *current_recv_queue);
    current_recv_queue->consume(current_recv_queue->size());

    streambuf_append(*current_recv_queue, data);
    streambuf_append(*current_recv_queue, copy_data_queue);

    async_send();
    _unguard;
}

void SendDataCache::push_data(PushDataHandler&& push, SentHandler&& handler) {
    _guard;
    if (destroyed) {
        handler(boost::asio::error::broken_pipe);
        return;
    }

    push(*current_recv_queue);

    current_recv_handler->emplace_back(std::move(handler));
    async_send();
    _unguard;
}

void SendDataCache::async_send() {
    _guard;
    if (current_recv_queue->size() == 0 || !is_connected() || is_async_sending || destroyed) {
        return;
    }

    is_async_sending = true;

    auto* sending_handler = current_recv_handler;
    auto* sending_data    = current_recv_queue;

    swap_recv();

    async_writer(*sending_data, [this, sending_handler, sending_data](const boost::system::error_code ec) {
        _guard;
        for (auto& handler : *sending_handler) {
            handler(ec);
        }
        sending_handler->clear();
        sending_data->consume(sending_data->size());

        // above "sending_handler[i](ec);" might call this async_send function back loop,
        // so we must set is_async_sending as false after it
        is_async_sending = false;

        if (!ec) {
            async_send();
        }
        _unguard;
    });
    _unguard;
}

DomainMatcher::DomainLinkData* DomainMatcher::insert_domain_seg(
  std::vector<DomainLinkData>& list, const std::string& seg) {
    _guard;
    DomainLinkData* link = nullptr;

    auto it = std::find_if(list.begin(), list.end(), [&](const DomainLinkData& d) { return seg == d.suffix; });

    if (it == list.end()) {
        DomainLinkData data{seg};
        list.emplace_back(data);

        link = &(list[list.size() - 1]);
    } else {
        link = &(*it);
    }

    return link;
    _unguard;
}

const DomainMatcher::DomainLinkData* DomainMatcher::find_domain_seg(
  const std::vector<DomainLinkData>& list, const std::string& seg) {
    _guard;
    const DomainLinkData* link = nullptr;

    // it's binary_search
    DomainLinkData cmp(seg);
    auto it = std::lower_bound(list.cbegin(), list.cend(), cmp,
      [](const DomainLinkData& a, const DomainLinkData& b) { return a.suffix < b.suffix; });

    if (it != list.cend() && !(seg < it->suffix)) {
        link = &(*it);
    }

    return link;
    _unguard;
}

void DomainMatcher::parse_line(const std::string& line) {
    _guard;
    if (line.empty()) {
        return;
    }

    std::string seg;
    DomainLinkData* link = nullptr;

    for (int r = (int)line.length() - 1; r >= 0; r--) {
        if (line[r] == '.') {
            link = insert_domain_seg(link == nullptr ? domains : link->prefix, seg);
            seg.clear();
            continue;
        }

        seg.insert(seg.begin(), line[r]);
    }

    if (!seg.empty()) {
        insert_domain_seg(link == nullptr ? domains : link->prefix, seg);
    }
    _unguard;
}

bool DomainMatcher::load_from_stream(std::istream& is, size_t& loaded_count) {
    _guard;
    loaded_count = 0;
    if (!is) {
        return false;
    }

    const size_t max_domain_length = 256;
    is >> std::noskipws;

    std::string line;
    line.reserve(max_domain_length);
    char a;
    while (is >> a) {
        if (a == '\n') {
            if (!line.empty()) {
                loaded_count++;
                parse_line(line);
                line.clear();
            }
        }

        if ((a >= 'a' && a <= 'z') || (a >= 'A' && a <= 'Z') || (a >= '0' && a <= '9') || a == '-' || a == '.') {
            line += a;
        }
    }

    if (!line.empty()) {
        loaded_count++;
        parse_line(line);
    }

    std::sort(domains.begin(), domains.end());
    for (auto& d : domains) {
        std::sort(d.prefix.begin(), d.prefix.end());
    }

    return true;
    _unguard;
}
bool DomainMatcher::load_from_file(const std::string& filename, size_t& loaded_count) {
    _guard;
    std::ifstream f(filename);
    return load_from_stream(f, loaded_count);
    _unguard;
}

bool DomainMatcher::is_match(const std::string& domain) const {
    _guard;

    if (domain.empty()) {
        return false;
    }

    std::string seg;
    const DomainLinkData* link = nullptr;

    size_t domain_level = 1;
    for (int r = (int)domain.length() - 1; r >= 0; r--) {
        if (domain[r] == '.') {
            bool is_top = link == nullptr ? true : link->is_top;
            link        = find_domain_seg(link == nullptr ? domains : link->prefix, seg);

            if (link == nullptr) {
                if (is_top) {
                    // xxx.com.cn
                    //     ^
                    return false;
                } else {
                    return domain_level > 2;
                }
            }

            domain_level++;
            seg.clear();
            continue;
        }

        seg.insert(seg.begin(), domain[r]);
    }

    if (domain_level == 1) {
        link = find_domain_seg(domains, domain);
        if (link != nullptr) {
            return link->prefix.empty();
        }
        return false;
    }

    if (link->prefix.empty()) {
        return true;
    }

    link = find_domain_seg(link->prefix, seg);
    return link != nullptr && link->prefix.empty();
    _unguard;
}

void DomainMatcher::test_cases() {

    std::string gfw_list("singledomain-in-gfw\n \
		google.com\n \
		facebook.com\n \
		twitter.com\n \
		api.others.com\n \
		some.com.cn\n \
		");

    std::istringstream is(gfw_list);

    size_t count = 0;
    DomainMatcher matcher;
    matcher.load_from_stream(is, count);

    _test_case_assert(count, 6);

    _test_case_assert(matcher.is_match("com"), false);
    _test_case_assert(matcher.is_match("singledomain"), false);
    _test_case_assert(matcher.is_match("singledomain-in-gfw"), true);
    _test_case_assert(matcher.is_match("www.baidu.com"), false);
    _test_case_assert(matcher.is_match("aa.www.baidu.com"), false);
    _test_case_assert(matcher.is_match("android.clients.google.com"), true);
    _test_case_assert(matcher.is_match("facebook.com"), true);
    _test_case_assert(matcher.is_match("api.facebook.com"), true);
    _test_case_assert(matcher.is_match("route.api.facebook.com"), true);
    _test_case_assert(matcher.is_match("www.jd.com"), false);
    _test_case_assert(matcher.is_match("jd.com"), false);
    _test_case_assert(matcher.is_match("h5.china.com.cn"), false);
    _test_case_assert(matcher.is_match("h5.some.com.cn"), true);
    _test_case_assert(matcher.is_match("some.com.cn"), true);

    _test_case_assert(matcher.is_match("others.com"), false);
    _test_case_assert(matcher.is_match("www.others.com"), false);
    _test_case_assert(matcher.is_match("api.others.com"), true);
    _test_case_assert(matcher.is_match("www.api.others.com"), true);
}
// clang-format off
static const uint32_t mask_values[] = {
  0,
  0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
  0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
  0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
  0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
  0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
  0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
  0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0,
  0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
};
// clang-format on

uint32_t IPv4Matcher::get_ip_value(const std::string& ip_str) {
    _guard;

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address_v4(ip_str, ec);
    return ec ? 0 : addr.to_uint();

    _unguard;
}

bool IPv4Matcher::load_from_stream(std::istream& is, const std::string& filename, size_t& loaded_count) {
    _guard;

    loaded_count                  = 0;
    const uint32_t max_mask_value = std::numeric_limits<uint32_t>::digits;

    for (std::string line; std::getline(is, line);) {
        line.erase(std::remove(line.begin(), line.end(), ' '), line.end());
        if (!line.empty()) {
            size_t pos = line.find('/');
            if (pos != std::string::npos) {
                auto net      = line.substr(0, pos);
                auto mask_str = line.substr(pos + 1);
                uint32_t mask = 0;
                auto addr     = get_ip_value(net);
                if (addr == 0 || !safe_atov(mask_str, mask) || mask == 0 || mask > max_mask_value) {
                    std::string error_msg("[tun] error load '");
                    error_msg += (line);
                    error_msg += "' from ";
                    error_msg += filename;
                    _log_with_date_time(error_msg, Log::ERROR);
                    continue;
                }
                auto it = subnet.find(mask);
                if (it == subnet.end()) {
                    IPList l;
                    l.emplace_back(addr);
                    subnet.emplace(mask, l);
                } else {
                    it->second.emplace_back(addr);
                }
                loaded_count++;
            } else {
                auto addr = get_ip_value(line);
                if (addr == 0) {
                    std::string error_msg("[tun] error load '");
                    error_msg += (line);
                    error_msg += "' from ";
                    error_msg += filename;
                    _log_with_date_time(error_msg, Log::ERROR);
                    continue;
                }
                ips.emplace_back(addr);
                loaded_count++;
            }
        }
    }

    for (auto it : subnet) {
        sort(it.second.begin(), it.second.end());
    }
    sort(ips.begin(), ips.end());

    return true;

    _unguard;
}

bool IPv4Matcher::load_from_file(const std::string& filename, size_t& loaded_count) {
    _guard;

    std::ifstream f(filename);
    return load_from_stream(f, filename, loaded_count);

    _unguard;
}

bool IPv4Matcher::is_match(uint32_t ip) const {
    _guard;
    if (!ips.empty() && binary_search(ips.cbegin(), ips.cend(), ip)) {
        return true;
    }

    for (const auto& sub : subnet) {
        uint32_t net = ip & gsl::at(mask_values, sub.first);
        if (binary_search(sub.second.cbegin(), sub.second.cend(), net)) {
            return true;
        }
    }

    return false;
    _unguard;
}

void IPv4Matcher::test_cases() {

    size_t load_count = 0;
    IPv4Matcher matcher;
    matcher.load_from_file("china_mainland_ips.txt", load_count);

    _test_case_assert(matcher.is_match(get_ip_value("172.217.5.68")), false);
    _test_case_assert(matcher.is_match(get_ip_value("104.244.42.65")), false);
    _test_case_assert(matcher.is_match(get_ip_value("31.13.70.36")), false);

    _test_case_assert(matcher.is_match(get_ip_value("180.101.49.11")), true);
    _test_case_assert(matcher.is_match(get_ip_value("101.227.95.3")), true);
    _test_case_assert(matcher.is_match(get_ip_value("180.153.93.117")), true);
    _test_case_assert(matcher.is_match(get_ip_value("180.163.198.33")), true);
}

bool set_udp_send_recv_buf(int fd, int buf_size) {
    _guard;
    if (buf_size > 0) {

        int size = buf_size;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
#ifndef _WIN32
              &size,
#else
              (const char*)&size,
#endif
              sizeof(size)) != 0) {
            _log_with_date_time("[udp] setsockopt SO_RCVBUF failed!", Log::ERROR);
            return false;
        }

        size = buf_size;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
#ifndef _WIN32
              &size,
#else
              (const char*)&size,
#endif
              sizeof(size)) != 0) {
            _log_with_date_time("[udp] setsockopt SO_SNDBUF failed!", Log::ERROR);
            return false;
        }
    }

    return true;
    _unguard;
}

udp::endpoint make_udp_endpoint_safe(const std::string& address, uint16_t port, boost::system::error_code& ec) {
    _guard;
    auto endpoint =
      udp::endpoint(make_address((address == "0" || address.length() == 0) ? "127.0.0.1" : address.c_str(), ec), port);
    if (ec) {
        return udp::endpoint();
    }
    return endpoint;

    _unguard;
}

FILE_LOCK_HANDLE get_file_lock(const char* filename) {
    _guard;

#ifndef _WIN32
    int lock = open(filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (lock == 0) {
        return -1;
    }

    if (flock(lock, LOCK_EX | LOCK_NB) != 0) {
        close(lock);
        return -1;
    }

    return lock;
#else
    auto hFile = CreateFileA(filename, // name of the write
      GENERIC_WRITE,                   // open for writing
      0,                               // do not share
      NULL,                            // default security
      CREATE_ALWAYS,                   // create new file only
      FILE_ATTRIBUTE_NORMAL,           // normal file
      NULL);                           // no attr. template

    if (hFile == INVALID_LOCK_HANDLE) {
        _log_with_date_time(
          "CreateFileA " + string(filename) + " failed, LastError : " + to_string(::GetLastError()), Log::ERROR);
    }
    return hFile;
#endif

    _unguard;
}

void close_file_lock(FILE_LOCK_HANDLE& file_fd) {
    _guard;

    if (file_fd != INVALID_LOCK_HANDLE) {
#ifndef _WIN32
        close(file_fd);
#else
        CloseHandle(file_fd);
#endif
        file_fd = INVALID_LOCK_HANDLE;
    }

    _unguard;
}

#ifndef _WIN32 // nat mode does not support in windows platform
// copied from shadowsocks-libev udpreplay.c
static int get_dstaddr(struct msghdr* msg, struct sockaddr_storage* dstaddr) {
    _guard;

    struct cmsghdr* cmsg = nullptr;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            dstaddr->ss_family = AF_INET;
            return 0;
        }

        if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
            memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            dstaddr->ss_family = AF_INET6;
            return 0;
        }
    }

    return 1;

    _unguard;
}

static int get_ttl(struct msghdr* msg) {
    _guard;

    struct cmsghdr* cmsg = nullptr;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
            return *(int*)CMSG_DATA(cmsg);
        }

        if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
            return *(int*)CMSG_DATA(cmsg);
        }
    }

    return -1;
    _unguard;
}

static pair<string, uint16_t> get_addr(struct sockaddr_storage addr) {
    _guard;

    const int buf_size = 256;
    char buf[buf_size]{};

    if (addr.ss_family == AF_INET) {
        auto* sa = (sockaddr_in*)&addr;
        if (inet_ntop(AF_INET, &(sa->sin_addr), (char*)buf, buf_size) != nullptr) {
            return make_pair(buf, ntohs(sa->sin_port));
        }
    } else {
        auto* sa = (sockaddr_in6*)&addr;
        if (inet_ntop(AF_INET6, &(sa->sin6_addr), (char*)buf, buf_size) != nullptr) {
            return make_pair(buf, ntohs(sa->sin6_port));
        }
    }

    return make_pair("", 0);
    _unguard;
}

std::pair<std::string, uint16_t> recv_target_endpoint(int _fd, bool use_tproxy) {
    _guard;

#ifdef ENABLE_NAT
    // Taken from
    // https://github.com/shadowsocks/shadowsocks-libev/blob/31dd81649d4c7f40daab46afc73eb0f03c517aa3/src/redir.c#L111
    sockaddr_storage destaddr;
    memset(&destaddr, 0, sizeof(sockaddr_storage));
    socklen_t socklen = sizeof(destaddr);

    int error = 0;
    if (use_tproxy) {
        error = getsockname(_fd, (sockaddr*)&destaddr, &socklen);
        _log_with_date_time("recv_target_endpoint + getsockname error " + to_string(error), Log::INFO);
    } else {
        error = getsockopt(_fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &destaddr, &socklen);
        if (error) {
            error = getsockopt(_fd, SOL_IP, SO_ORIGINAL_DST, &destaddr, &socklen);
        }

        _log_with_date_time("recv_target_endpoint + getsockopt error " + to_string(error), Log::INFO);
    }

    if (error) {
        return make_pair("", 0);
    }

    char ipstr[INET6_ADDRSTRLEN];
    uint16_t port;
    if (destaddr.ss_family == AF_INET) {
        auto* sa = (sockaddr_in*)&destaddr;
        inet_ntop(AF_INET, &(sa->sin_addr), ipstr, INET_ADDRSTRLEN);
        port = ntohs(sa->sin_port);
    } else {
        auto* sa = (sockaddr_in6*)&destaddr;
        inet_ntop(AF_INET6, &(sa->sin6_addr), ipstr, INET6_ADDRSTRLEN);
        port = ntohs(sa->sin6_port);
    }
    return make_pair(ipstr, port);
#else  // ENABLE_NAT
    return make_pair(use_tproxy ? "" : "0", (uint16_t)_fd);
#endif // ENABLE_NAT

    _unguard;
}

// copied from shadowsocks-libev udpreplay.c
// it works if in NAT mode
pair<string, uint16_t> recv_tproxy_udp_msg(
  int fd, boost::asio::ip::udp::endpoint& target_endpoint, char* buf, int& buf_len, int& ttl) {
    _guard;

    const size_t max_control_buffer_size = 64;
    struct sockaddr_storage src_addr {};

    char control_buffer[max_control_buffer_size]{};
    struct msghdr msg {};
    struct iovec iov[1]{};
    struct sockaddr_storage dst_addr {};

    msg.msg_name    = &src_addr;
    msg.msg_namelen = sizeof(struct sockaddr_storage);

    msg.msg_control    = (void*)control_buffer;
    msg.msg_controllen = max_control_buffer_size;

    const int packet_size = DEFAULT_PACKET_SIZE;
    const int buf_size    = DEFAULT_PACKET_SIZE * 2;

    iov[0].iov_base = buf;
    iov[0].iov_len  = buf_size;
    msg.msg_iov     = (struct iovec*)iov;
    msg.msg_iovlen  = 1;

    buf_len = recvmsg(fd, &msg, 0);
    if (buf_len == -1) {
        _log_with_date_time("[udp] server_recvmsg failed!", Log::FATAL);
    } else {
        if (buf_len > packet_size) {
            _log_with_date_time(string("[udp] UDP server_recv_recvmsg fragmentation, MTU at least be: ") +
                                  to_string(buf_len + PACKET_HEADER_SIZE),
              Log::INFO);
        }

        ttl = get_ttl(&msg);
        if (get_dstaddr(&msg, &dst_addr) != 0) {
            _log_with_date_time("[udp] unable to get dest addr!", Log::FATAL);
        } else {
            auto target_dst = get_addr(dst_addr);
            auto src_dst    = get_addr(src_addr);
            target_endpoint.address(boost::asio::ip::make_address(src_dst.first));
            target_endpoint.port(src_dst.second);
            return target_dst;
        }
    }

    return make_pair("", 0);

    _unguard;
}

bool prepare_transparent_socket(int fd, bool is_ipv4) {
    int opt = 1;
    int sol = is_ipv4 ? SOL_IP : SOL_IPV6;

    if (setsockopt(fd, sol, IP_TRANSPARENT, &opt, sizeof(opt)) != 0) {
        _log_with_date_time("setsockopt fd [" + to_string(fd) + "] IP_TRANSPARENT failed!", Log::FATAL);
        return false;
    }

    return true;
}

bool prepare_nat_udp_bind(int fd, bool is_ipv4, bool recv_ttl) {
    _guard;

    int opt     = 1;
    int sol     = is_ipv4 ? SOL_IP : SOL_IPV6;
    int ip_recv = is_ipv4 ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;

    if (!prepare_transparent_socket(fd, is_ipv4)) {
        _log_with_date_time("[udp] setsockopt IP_TRANSPARENT failed!", Log::FATAL);
        return false;
    }

    if (setsockopt(fd, sol, ip_recv, &opt, sizeof(opt)) != 0) {
        _log_with_date_time("[udp] setsockopt IP_RECVORIGDSTADDR failed!", Log::FATAL);
        return false;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        _log_with_date_time("[udp] setsockopt SO_REUSEADDR failed!", Log::FATAL);
        return false;
    }

    if (recv_ttl) {
        if (setsockopt(fd, sol, is_ipv4 ? IP_RECVTTL : IPV6_RECVHOPLIMIT, &opt, sizeof(opt)) != 0) {
            _log_with_date_time("[udp] setsockopt IP_RECVOPTS/IPV6_RECVHOPLIMIT failed!", Log::ERROR);
        }
    }

    return true;
    _unguard;
}

bool prepare_nat_udp_target_bind(
  int fd, bool is_ipv4, const boost::asio::ip::udp::endpoint& udp_target_endpoint, int buf_size) {
    _guard;
    int opt = 1;
    int sol = is_ipv4 ? SOL_IPV6 : SOL_IP;
    if (setsockopt(fd, sol, IP_TRANSPARENT, &opt, sizeof(opt)) != 0) {
        _log_with_endpoint(udp_target_endpoint, "[udp] setsockopt IP_TRANSPARENT failed!", Log::FATAL);
        return false;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        _log_with_endpoint(udp_target_endpoint, "[udp] setsockopt SO_REUSEADDR failed!", Log::FATAL);
        return false;
    }

    if (buf_size > 0) {
        set_udp_send_recv_buf(fd, buf_size);
    }

    return true;
    _unguard;
}

#else

std::pair<std::string, uint16_t> recv_target_endpoint(int _native_fd, bool use_tproxy) {
    throw runtime_error("NAT is not supported in Windows");
}

std::pair<std::string, uint16_t> recv_tproxy_udp_msg(
  int fd, boost::asio::ip::udp::endpoint& target_endpoint, char* buf, int& buf_len, int& ttl) {
    throw runtime_error("NAT is not supported in Windows");
}

bool prepare_transparent_socket(int fd, bool is_ipv4) { throw runtime_error("NAT is not supported in Windows"); }

bool prepare_nat_udp_bind(int fd, bool is_ipv4, bool recv_ttl) {
    throw runtime_error("NAT is not supported in Windows");
}

bool prepare_nat_udp_target_bind(
  int fd, bool is_ipv4, const boost::asio::ip::udp::endpoint& udp_target_endpoint, int buf_size) {
    throw runtime_error("NAT is not supported in Windows");
}

#endif // _WIN32

#ifdef __ANDROID__

int main(int argc, const char* argv[]);

extern "C" {

JNIEnv* g_android_java_env              = NULL;
jclass g_android_java_service_class     = NULL;
jmethodID g_android_java_protect_socket = NULL;

JNIEXPORT void JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_runMain(
  JNIEnv* env, jclass service_class, jstring configPath) {
    g_android_java_env           = env;
    g_android_java_service_class = service_class;
    g_android_java_protect_socket =
      g_android_java_env->GetStaticMethodID(g_android_java_service_class, "protectSocket", "(I)V");

    const char* path   = g_android_java_env->GetStringUTFChars(configPath, 0);
    const char* args[] = {"trojan", "-c", path};
    main(3, args);
    g_android_java_env            = NULL;
    g_android_java_service_class  = NULL;
    g_android_java_protect_socket = NULL;
}

JNIEXPORT void JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_stopMain(JNIEnv*, jclass) { raise(SIGUSR2); }

JNIEXPORT jstring JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_getVersion(JNIEnv* env, jclass) {
    return env->NewStringUTF(Version::get_version().c_str());
}

} // extern "C"

void android_protect_socket(int fd) {
    if (g_android_java_env != NULL && g_android_java_service_class != NULL && g_android_java_protect_socket != NULL) {
        g_android_java_env->CallStaticVoidMethod(g_android_java_service_class, g_android_java_protect_socket, fd);
    }
}
#else

void android_protect_socket(int) {}
#endif