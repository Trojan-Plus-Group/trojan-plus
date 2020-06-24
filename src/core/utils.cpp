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
#include <signal.h>
#include <jni.h>
#endif //__ANDROID__

#include "log.h"
#include "core/service.h"

using namespace std;
using namespace boost::asio::ip;

size_t streambuf_append(boost::asio::streambuf& target, const boost::asio::streambuf& append_buf){
    if(append_buf.size() == 0){
        return 0;
    }

    auto copied = boost::asio::buffer_copy(target.prepare(append_buf.size()), append_buf.data());
    target.commit(copied);
    return copied;
}

size_t streambuf_append(boost::asio::streambuf& target, const boost::asio::streambuf& append_buf, size_t start, size_t n){
    if(start >= append_buf.size()){
        return 0;
    }

    if((start + n) > append_buf.size()){
        return 0;
    }

    auto* dest = boost::asio::buffer_cast<uint8_t*>(target.prepare(n));
    const auto* src = boost::asio::buffer_cast<const uint8_t*>(append_buf.data()) + start;
    memcpy(dest, src, n);
    target.commit(n);
    return n;
}

size_t streambuf_append(boost::asio::streambuf& target, const char* append_str){
    if(append_str == nullptr){
        return 0;
    }

    auto length = strlen(append_str);
    if(length == 0){
        return 0;
    }

    auto copied = boost::asio::buffer_copy(target.prepare(length), boost::asio::buffer(append_str, length));
    target.commit(copied);
    return copied;
}

size_t streambuf_append(boost::asio::streambuf& target, const uint8_t* append_data, size_t append_length){
    if(append_data == nullptr || append_length == 0){
        return 0;
    }

    auto copied = boost::asio::buffer_copy(target.prepare(append_length), boost::asio::buffer(append_data, append_length));
    target.commit(copied);
    return copied;
}

size_t streambuf_append(boost::asio::streambuf& target, char append_char){
    const size_t char_length = sizeof(char);
    auto cp = gsl::span<char>(boost::asio::buffer_cast<char*>(target.prepare(char_length)), char_length);
    cp[0] = append_char;
    target.commit(char_length);
    return char_length;
}

size_t streambuf_append(boost::asio::streambuf& target, const std::string_view& append_data){
    if(append_data.empty()){
        return 0;
    }

    auto copied = boost::asio::buffer_copy(target.prepare(append_data.length()), boost::asio::buffer(append_data.data(), append_data.length()));
    target.commit(copied);
    return copied;
}

size_t streambuf_append(boost::asio::streambuf& target, const std::string& append_data){
    if(append_data.empty()){
        return 0;
    }

    auto copied = boost::asio::buffer_copy(target.prepare(append_data.length()), boost::asio::buffer(append_data));
    target.commit(copied);
    return copied;
}

std::string_view streambuf_to_string_view(const boost::asio::streambuf& target){
    return std::string_view(boost::asio::buffer_cast<const char*>(target.data()), target.size());
}


unsigned short get_checksum(const std::string_view& str){
    unsigned int sum = 0;
    // clang-tidy advice failed:
    // compiling error in MSVC if change it into type "const auto*", error message: 
    //  cannot deduce type for 'const auto *' from 'std::_String_view_iterator<_Traits>'
    auto body_iter = str.cbegin(); 
    while (body_iter != str.cend()) {
        sum += (static_cast<uint8_t>(*body_iter++) << one_byte_shift_8_bits);
        if (body_iter != str.end()){
            sum += static_cast<uint8_t>(*body_iter++);
        }
    }

    return static_cast<unsigned short>(sum);
}

unsigned short get_checksum(const std::string& str){
    return get_checksum(string_view(str));
}

unsigned short get_checksum(const boost::asio::streambuf& buf){
    return get_checksum(streambuf_to_string_view(buf));
}

int get_hashCode(const std::string& str) {
    const int hash_code_magic_number = 31;
    int h = 0;
    for (auto c : str) {
        h = hash_code_magic_number * h + c;
    }
    return h;
}

void write_data_to_file(int id, const std::string& tag, const std::string_view& data){
    ofstream file(tag + "_" + to_string(id) + ".data", std::ofstream::out | std::ofstream::app);
    file << data;
    file.close();
}

SendDataCache::SendDataCache() : is_async_sending(false), destroyed(false) {
    is_connected = []() { return true; };

    current_recv_handler = &handler_queue;
    current_recv_queue = &data_queue;
}

void SendDataCache::swap_recv(){
    if(current_recv_handler == &handler_queue){
        current_recv_handler = &handler_queue_other;
        current_recv_queue = &data_queue_other;
    }else{
        current_recv_handler = &handler_queue;
        current_recv_queue = &data_queue;
    }
}

SendDataCache::~SendDataCache() {
    destroyed = true;

    for (auto& handler : handler_queue_other) {
        handler(boost::asio::error::broken_pipe);
    }
    handler_queue_other.clear();

    for (auto& handler : handler_queue) {
        handler(boost::asio::error::broken_pipe);
    }
    handler_queue.clear();
}

void SendDataCache::set_async_writer(AsyncWriter&& writer) {
    async_writer = std::move(writer);
}

void SendDataCache::set_is_connected_func(ConnectionFunc&& func) {
    is_connected = std::move(func);
}

void SendDataCache::insert_data(const std::string_view& data) {

    boost::asio::streambuf copy_data_queue;
    streambuf_append(copy_data_queue, *current_recv_queue);
    current_recv_queue->consume(current_recv_queue->size());

    streambuf_append(*current_recv_queue, data);
    streambuf_append(*current_recv_queue, copy_data_queue);

    async_send();
}

void SendDataCache::push_data(PushDataHandler&& push, SentHandler&& handler) {
    push(*current_recv_queue);

    current_recv_handler->emplace_back(std::move(handler));
    async_send();
}

void SendDataCache::async_send() {
    if (current_recv_queue->size() == 0 || !is_connected() || is_async_sending || destroyed) {
        return;
    }

    is_async_sending = true;

    auto* sending_handler = current_recv_handler;
    auto* sending_data = current_recv_queue;

    swap_recv();

    async_writer(*sending_data, [this, sending_handler, sending_data](const boost::system::error_code ec) {
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
    });
}

bool set_udp_send_recv_buf(int fd, int buf_size){
    if(buf_size > 0){
        
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
}

udp::endpoint make_udp_endpoint_safe(const std::string& address, uint16_t port, boost::system::error_code& ec){
    auto endpoint = udp::endpoint(make_address((address == "0" || address.length() == 0) ? "127.0.0.1" : address.c_str(), ec), port);
    if(ec){
        return udp::endpoint();
    }
    return endpoint;
}

int get_file_lock(const char* filename){
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
    return -1;
#endif
}

#ifndef _WIN32  // nat mode does not support in windows platform
// copied from shadowsocks-libev udpreplay.c
static int get_dstaddr(struct msghdr *msg, struct sockaddr_storage *dstaddr) {
    struct cmsghdr *cmsg = nullptr;
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
}

static int get_ttl(struct msghdr *msg) {
    struct cmsghdr *cmsg = nullptr;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
            return *(int *)CMSG_DATA(cmsg);
        }
        
        if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
            return *(int *)CMSG_DATA(cmsg);
        }
    }

    return -1;
}

static pair<string, uint16_t> get_addr(struct sockaddr_storage addr) {
    const int buf_size = 256;
    char buf[buf_size]{};

    if (addr.ss_family == AF_INET) {
        auto *sa = (sockaddr_in *)&addr;
        if (inet_ntop(AF_INET, &(sa->sin_addr), (char*)buf, buf_size) != nullptr) {
            return make_pair(buf, ntohs(sa->sin_port));
        }
    } else {
        auto *sa = (sockaddr_in6 *)&addr;
        if (inet_ntop(AF_INET6, &(sa->sin6_addr), (char*)buf, buf_size) != nullptr) {
            return make_pair(buf, ntohs(sa->sin6_port));
        }
    }

    return make_pair("", 0);
}

std::pair<std::string, uint16_t> recv_target_endpoint(int _fd){
#ifdef ENABLE_NAT
    // Taken from https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.1/src/redir.c.
    sockaddr_storage destaddr;
    memset(&destaddr, 0, sizeof(sockaddr_storage));
    socklen_t socklen = sizeof(destaddr);
    int error = getsockopt(_fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &destaddr, &socklen);
    if (error) {
        error = getsockopt(_fd, SOL_IP, SO_ORIGINAL_DST, &destaddr, &socklen);
        if (error) {
            return make_pair("", 0);
        }
    }
    char ipstr[INET6_ADDRSTRLEN];
    uint16_t port;
    if (destaddr.ss_family == AF_INET) {
        auto *sa = (sockaddr_in*) &destaddr;
        inet_ntop(AF_INET, &(sa->sin_addr), ipstr, INET_ADDRSTRLEN);
        port = ntohs(sa->sin_port);
    } else {
        auto *sa = (sockaddr_in6*) &destaddr;
        inet_ntop(AF_INET6, &(sa->sin6_addr), ipstr, INET6_ADDRSTRLEN);
        port = ntohs(sa->sin6_port);
    }
    return make_pair(ipstr, port);
#else // ENABLE_NAT
    return make_pair("", (uint16_t)_fd);
#endif // ENABLE_NAT
}

// copied from shadowsocks-libev udpreplay.c
// it works if in NAT mode
pair<string, uint16_t> recv_tproxy_udp_msg(int fd, boost::asio::ip::udp::endpoint& target_endpoint, char *buf, int &buf_len, int &ttl) {
    const size_t max_control_buffer_size = 64;
    struct sockaddr_storage src_addr{};

    char control_buffer[max_control_buffer_size]{};
    struct msghdr msg{};
    struct iovec iov[1]{};
    struct sockaddr_storage dst_addr{};

    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    
    msg.msg_control = (void*)control_buffer;
    msg.msg_controllen = max_control_buffer_size;

    const int packet_size = DEFAULT_PACKET_SIZE;
    const int buf_size = DEFAULT_PACKET_SIZE * 2;

    iov[0].iov_base = buf;
    iov[0].iov_len = buf_size;
    msg.msg_iov = (struct iovec*)iov;
    msg.msg_iovlen = 1;

    buf_len = recvmsg(fd, &msg, 0);
    if (buf_len == -1) {
        _log_with_date_time("[udp] server_recvmsg failed!", Log::FATAL);
    } else {
        if (buf_len > packet_size) {
            _log_with_date_time(string("[udp] UDP server_recv_recvmsg fragmentation, MTU at least be: ") + to_string(buf_len + PACKET_HEADER_SIZE), Log::INFO);
        }

        ttl = get_ttl(&msg);
        if (get_dstaddr(&msg, &dst_addr) != 0) {
            _log_with_date_time("[udp] unable to get dest addr!", Log::FATAL);
        } else {
            auto target_dst = get_addr(dst_addr);
            auto src_dst = get_addr(src_addr);
            target_endpoint.address(boost::asio::ip::make_address(src_dst.first));
            target_endpoint.port(src_dst.second);
            return target_dst;
        }
    }

    return make_pair("", 0);
}

bool prepare_nat_udp_bind(int fd, bool is_ipv4, bool recv_ttl) {
    
    int opt = 1;
    int sol = is_ipv4 ? SOL_IP : SOL_IPV6;
    int ip_recv = is_ipv4 ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;

    if (setsockopt(fd, sol, IP_TRANSPARENT, &opt, sizeof(opt)) != 0) {
        _log_with_date_time("[udp] setsockopt IP_TRANSPARENT failed!", Log::FATAL);
        return false;
    }

    if (setsockopt(fd, sol, ip_recv, &opt, sizeof(opt)) != 0 ) {
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
}

bool prepare_nat_udp_target_bind(int fd, bool is_ipv4, const boost::asio::ip::udp::endpoint &udp_target_endpoint, int buf_size) {
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

    if(buf_size > 0){
        set_udp_send_recv_buf(fd, buf_size);
    }

    return true;
}

#else

std::pair<std::string, uint16_t> recv_target_endpoint(int _native_fd){
    throw runtime_error("NAT is not supported in Windows");
}

std::pair<std::string, uint16_t> recv_tproxy_udp_msg(int fd, boost::asio::ip::udp::endpoint& target_endpoint, char* buf, int& buf_len, int& ttl){
    throw runtime_error("NAT is not supported in Windows");
}

bool prepare_nat_udp_bind(int fd, bool is_ipv4, bool recv_ttl){
    throw runtime_error("NAT is not supported in Windows");
}

bool prepare_nat_udp_target_bind(int fd, bool is_ipv4, const boost::asio::ip::udp::endpoint& udp_target_endpoint, int buf_size) {
    throw runtime_error("NAT is not supported in Windows");
}

#endif  // _WIN32


#ifdef __ANDROID__

int main(int argc, const char *argv[]);

extern "C" {

JNIEnv* g_android_java_env = NULL;
jclass g_android_java_service_class = NULL;
jmethodID g_android_java_protect_socket = NULL;

JNIEXPORT void JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_runMain (JNIEnv *env, jclass, jstring configPath){
    g_android_java_env = env;

    const char* path = g_android_java_env->GetStringUTFChars(configPath, 0);
    const char* args[]={
        "trojan",
        "-c",
        path
    };
    main(3, args);    
    g_android_java_env = NULL;
    g_android_java_service_class = NULL;
    g_android_java_protect_socket = NULL;
}

JNIEXPORT void JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_stopMain (JNIEnv *, jclass){
    if(g_android_java_env != NULL){
        raise(SIGUSR2);
    }    
}

}

void android_protect_socket(int fd){
    if(g_android_java_env){
        if(g_android_java_protect_socket == NULL){
            g_android_java_service_class = g_android_java_env->FindClass("com/trojan_plus/android/TrojanPlusVPNService");
            if(g_android_java_service_class != NULL){

                g_android_java_protect_socket = g_android_java_env->GetStaticMethodID( g_android_java_service_class, "protectSocket","(I)V");

                if (NULL == g_android_java_protect_socket) {
                    _log_with_date_time("[jni] can't find method protectSocket from TrojanPlusVPNService", Log::ERROR);
                    return;
                }
            }
        }

        if(g_android_java_protect_socket != NULL){
             g_android_java_env->CallStaticVoidMethod(g_android_java_service_class, g_android_java_protect_socket, fd);
        }
    }
}
#else

void android_protect_socket(int){}
#endif