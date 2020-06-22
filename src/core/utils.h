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

#ifndef _TROJAN_UTILS_H_
#define _TROJAN_UTILS_H_

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>
#include <functional>
#include <list>
#include <vector>
#include <string>
#include <exception>

#include "log.h"

// These 2 definitions are respectively from linux/netfilter_ipv4.h and
// linux/netfilter_ipv6/ip6_tables.h. Including them will 1) cause linux-headers
// to be one of trojan's dependencies, which is not good, and 2) prevent trojan
// from even compiling.
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif // SO_ORIGINAL_DST
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif // IP6T_SO_ORIGINAL_DST

#ifdef ENABLE_REUSE_PORT
typedef boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> reuse_port;
#endif  // ENABLE_REUSE_PORT

#ifndef IP_RECVTTL
#define IP_RECVTTL 12
#endif

#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT 51
#endif

#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT 21
#endif

#ifndef IP_TTL
#define IP_TTL 4
#endif

// copied from shadowsocks-libe udprelay.h
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#ifndef IP_RECVORIGDSTADDR
#ifdef IP_ORIGDSTADDR
#define IP_RECVORIGDSTADDR IP_ORIGDSTADDR
#else
#define IP_RECVORIGDSTADDR 20
#endif
#endif

#ifndef IPV6_RECVORIGDSTADDR
#ifdef IPV6_ORIGDSTADDR
#define IPV6_RECVORIGDSTADDR IPV6_ORIGDSTADDR
#else
#define IPV6_RECVORIGDSTADDR 74
#endif
#endif

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#define PACKET_HEADER_SIZE (1 + 28 + 2 + 64)
#define DEFAULT_PACKET_SIZE 1397  // 1492 - PACKET_HEADER_SIZE = 1397, the default MTU for UDP relay

#define _define_simple_getter_setter(type, name) \
    [[nodiscard]] inline type get_##name() const { return name; } \
    inline void set_##name(type val) { name = val; }

#define _define_getter(type, name) \
    [[nodiscard]] inline type get_##name() {return name;}

#define _define_getter_const(type, name) \
    [[nodiscard]] inline type get_##name() const {return name;}

const static int half_byte_shift_4_bits = 4;
const static int one_byte_shift_8_bits = 8;
const static int two_bytes_shift_16_bits = 16;
const static int three_bytes_shift_24_bits = 24;

const static int half_byte_mask_0xF = 0xF;
const static int one_byte_mask_0xFF = 0xFF;
const static int two_bytes_mask_0xFFFF = 0xFFFF;

size_t streambuf_append(boost::asio::streambuf& target, const boost::asio::streambuf& append_buf);
size_t streambuf_append(boost::asio::streambuf& target, const boost::asio::streambuf& append_buf, size_t start, size_t n);
size_t streambuf_append(boost::asio::streambuf& target, const char* append_str);
size_t streambuf_append(boost::asio::streambuf& target, const uint8_t* append_data, size_t append_length);
size_t streambuf_append(boost::asio::streambuf& target, char append_char);
size_t streambuf_append(boost::asio::streambuf& target, const std::string_view& append_data);
size_t streambuf_append(boost::asio::streambuf& target, const std::string& append_data);
std::string_view streambuf_to_string_view(const boost::asio::streambuf& target);

unsigned short get_checksum(const boost::asio::streambuf& buf);
unsigned short get_checksum(const std::string_view& str);
unsigned short get_checksum(const std::string& str);

int get_hashCode(const std::string& str);

void write_data_to_file(int id, const std::string& tag, const std::string_view& data);

using SentHandler = std::function<void(const boost::system::error_code ec)>;
using AsyncWriter = std::function<void(const boost::asio::streambuf& data, SentHandler&& handler)>;
using ConnectionFunc = std::function<bool()> ;
using ReadHandler = std::function<void(const std::string_view& data)> ;
using PushDataHandler = std::function<void(boost::asio::streambuf& buf)> ;

class SendDataCache{
    std::vector<SentHandler> handler_queue;
    boost::asio::streambuf data_queue;
    
    std::vector<SentHandler> handler_queue_other;
    boost::asio::streambuf data_queue_other;
    
    std::vector<SentHandler>* current_recv_handler;
    boost::asio::streambuf* current_recv_queue;

    bool is_async_sending;
    AsyncWriter async_writer;
    ConnectionFunc is_connected;

    bool destroyed;

    void swap_recv();

public: 
    SendDataCache();
    ~SendDataCache();

    void set_async_writer(AsyncWriter&& writer);
    void set_is_connected_func(ConnectionFunc&& func);
    void insert_data(const std::string_view& data);
    void push_data(PushDataHandler&& push, SentHandler&& handler);
    void async_send();
};

class ReadDataCache{
    boost::asio::streambuf data_queue;
    ReadHandler read_handler;
    bool is_waiting = { false};
public :
    inline void push_data(const std::string_view& data) {
        if (is_waiting) {
            is_waiting = false;
            read_handler(data);
        }else{
            streambuf_append(data_queue, data);
        }
    }

    inline void async_read(ReadHandler&& handler) {
        if (data_queue.size() == 0) {
            is_waiting = true;
            read_handler = std::move(handler);
        }else{
            handler(streambuf_to_string_view(data_queue));
            data_queue.consume(data_queue.size());
        }
    }

    [[nodiscard]] inline bool has_queued_data()const{
        return data_queue.size() > 0;
    }
};


class SendingDataAllocator{
    std::vector<std::shared_ptr<boost::asio::streambuf>> allocated;
    std::list<std::shared_ptr<boost::asio::streambuf>> free_bufs;

public:
    std::shared_ptr<boost::asio::streambuf> allocate(const std::string_view& data){
        auto buf = std::shared_ptr<boost::asio::streambuf>(nullptr);
        if(free_bufs.empty()){
            buf = std::make_shared<boost::asio::streambuf>();
            allocated.push_back(buf);
        }else{
            buf = free_bufs.front();
            free_bufs.pop_front();
        }
        
        streambuf_append(*buf, data);
        return buf;
    }

    void free(const std::shared_ptr<boost::asio::streambuf>& buf){ 
        bool found = false;
        for(const auto& it : allocated){
            if(it.get() == buf.get()){
                found = true;
                break;
            }
        }

        if(!found){
            throw std::logic_error("cannot find the buf in SendingDataAllocator!");
        }

        buf->consume(buf->size());
        free_bufs.push_back(buf);
    }
};

class ReadBufWithGuard{
    boost::asio::streambuf read_buf;
    bool read_buf_guard = false;
public:
    inline void consume_all(){
        read_buf.consume(read_buf.size());
    }

    inline void consume(size_t length){
        read_buf.consume(length);
    }

    [[nodiscard]]
    inline size_t size()const noexcept{
        return read_buf.size();
    }

    inline void commit(size_t length){
        read_buf.commit(length);
    }

    [[nodiscard]]
    inline boost::asio::streambuf::const_buffers_type data()const{
        return read_buf.data();
    }

    [[nodiscard]]
    inline boost::asio::streambuf::mutable_buffers_type prepare(size_t length){
        return read_buf.prepare(length);
    }
    
    inline operator std::string_view() const{ 
        return streambuf_to_string_view(read_buf);
    }

    inline operator boost::asio::streambuf&(){ 
        return read_buf;
    }

    inline void begin_read(const char* __file__, int __line__){
        if(read_buf_guard){
            throw std::logic_error("!! guard_read_buf failed! Cannot enter this function before _guard_read_buf_end  !! " + 
                std::string(__file__) + std::to_string(__line__));
        } 
        read_buf_guard = true;
    }

    inline void end_read(){
        read_buf_guard = false;
    }
};

void android_protect_socket(int fd);

template <typename ThisT, typename EndPoint>
void connect_out_socket(ThisT this_ptr, std::string addr, std::string port, boost::asio::ip::tcp::resolver& resolver,
                        boost::asio::ip::tcp::socket& out_socket, EndPoint in_endpoint, std::function<void()>&& connected_handler) {
    resolver.async_resolve(addr, port, [=, &out_socket](const boost::system::error_code error, const boost::asio::ip::tcp::resolver::results_type& results) {
        if (error || results.empty()) {
            _log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + addr + ":" + port + " reason: " + error.message(), Log::ERROR);
            this_ptr->destroy();
            return;
        }
        auto iterator = results.begin();
        _log_with_endpoint(in_endpoint, addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
        boost::system::error_code ec;
        out_socket.open(iterator->endpoint().protocol(), ec);
        if (ec) {
            output_debug_info_ec(ec);
            this_ptr->destroy();
            return;
        }
        android_protect_socket((int)out_socket.native_handle());
        if (this_ptr->get_config().get_tcp().no_delay) {
            out_socket.set_option(boost::asio::ip::tcp::no_delay(true));
        }
        if (this_ptr->get_config().get_tcp().keep_alive) {
            out_socket.set_option(boost::asio::socket_base::keep_alive(true));
        }
#ifdef TCP_FASTOPEN_CONNECT
        if (this_ptr->get_config().get_tcp().fast_open) {
            using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
            boost::system::error_code ec;
            out_socket.set_option(fastopen_connect(true), ec);
        }
#endif  // TCP_FASTOPEN_CONNECT
        auto timeout_timer = std::shared_ptr<boost::asio::steady_timer>(nullptr);
        if (this_ptr->get_config().get_tcp().connect_time_out > 0) {
            // out_socket.async_connect will be stuck forever when the host is not reachable
            // we must set a timeout timer
            timeout_timer = std::make_shared<boost::asio::steady_timer>(this_ptr->get_service()->get_io_context());
            timeout_timer->expires_after(std::chrono::seconds(this_ptr->get_config().get_tcp().connect_time_out));
            timeout_timer->async_wait([=](const boost::system::error_code error) {
                if (!error) {
                    _log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + addr + ':' + port + " reason: timeout", Log::ERROR);
                    this_ptr->destroy();
                }
            });
        }

        out_socket.async_connect(*iterator, [=](const boost::system::error_code error) {
            if (timeout_timer) {
                timeout_timer->cancel();
            }

            if (error) {
                _log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + addr + ':' + port + " reason: " + error.message(), Log::ERROR);
                this_ptr->destroy();
                return;
            }

            connected_handler();
        });
    });
}

template <typename ThisT, typename EndPoint>
void connect_remote_server_ssl(ThisT this_ptr, std::string addr, std::string port, boost::asio::ip::tcp::resolver& resolver,
                               boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& out_socket, EndPoint in_endpoint, std::function<void()>&& connected_handler) {

    connect_out_socket(this_ptr, addr, port, resolver, out_socket.next_layer(), in_endpoint, [=, &out_socket]() {
        out_socket.async_handshake(boost::asio::ssl::stream_base::client, [=, &out_socket](const boost::system::error_code error) {
            if (error) {
                _log_with_endpoint(in_endpoint, "SSL handshake failed with " + addr + ':' + port + " reason: " + error.message(), Log::ERROR);
                this_ptr->destroy();
                return;
            }
            _log_with_endpoint(in_endpoint, "tunnel established");
            if (this_ptr->get_config().get_ssl().reuse_session) {
                auto* ssl = out_socket.native_handle();
                if (!SSL_session_reused(ssl)) {
                    _log_with_endpoint(in_endpoint, "SSL session not reused");
                } else {
                    _log_with_endpoint(in_endpoint, "SSL session reused");
                }
            }
            connected_handler();
        });
    });
}

template <typename ThisPtr>
void shutdown_ssl_socket(ThisPtr this_ptr, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket) {
    if (socket.next_layer().is_open()) {
        auto self = this_ptr->shared_from_this();
        auto ssl_shutdown_timer = std::make_shared<boost::asio::steady_timer>(this_ptr->get_service()->get_io_context());
        auto ssl_shutdown_cb = [self, ssl_shutdown_timer, &socket](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            ssl_shutdown_timer.get()->cancel();
            socket.next_layer().cancel(ec);
            socket.next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            socket.next_layer().close(ec);
        };
        boost::system::error_code ec;
        socket.next_layer().cancel(ec);
        socket.async_shutdown(ssl_shutdown_cb);
        ssl_shutdown_timer.get()->expires_after(std::chrono::seconds(this_ptr->get_config().get_ssl().ssl_shutdown_wait_time));
        ssl_shutdown_timer.get()->async_wait(ssl_shutdown_cb);
    }
}

std::pair<std::string, uint16_t> recv_target_endpoint(int _native_fd);
std::pair<std::string, uint16_t> recv_tproxy_udp_msg(int fd, boost::asio::ip::udp::endpoint& target_endpoint, char* buf, int& buf_len, int& ttl);
bool set_udp_send_recv_buf(int fd, int buf_size);
boost::asio::ip::udp::endpoint make_udp_endpoint_safe(const std::string& address, uint16_t port, boost::system::error_code& ec);

bool prepare_nat_udp_bind(int fd, bool is_ipv4, bool recv_ttl);
bool prepare_nat_udp_target_bind(int fd, bool is_ipv4, const boost::asio::ip::udp::endpoint& udp_target_endpoint, int buf_size);

#endif  //_TROJAN_UTILS_H_