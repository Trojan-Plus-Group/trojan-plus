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

#include "udpforwardsession.h"

#include <stdexcept>
#include <utility>

#include "core/service.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include "ssl/sslsession.h"
#include "core/utils.h"

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

UDPForwardSession::UDPForwardSession(Service* _service, const Config& config, context &ssl_context, 
    const udp::endpoint &endpoint,const std::pair<std::string, uint16_t>& targetdst, UDPWrite in_write) :
    SocketSession(_service, config),
    status(CONNECT),
    in_write(move(in_write)),
    out_socket(_service->get_io_context(), ssl_context),
    udp_target_socket(_service->get_io_context()){

    udp_recv_endpoint = endpoint;
    out_udp_endpoint = udp::endpoint(boost::asio::ip::make_address(targetdst.first), targetdst.second);    
    in_endpoint = tcp::endpoint(endpoint.address(), endpoint.port());
    is_udp_forward_session = true;
    pipeline_com.allocate_session_id();
}

UDPForwardSession::~UDPForwardSession(){
    pipeline_com.free_session_id();
}

tcp::socket& UDPForwardSession::accept_socket() {
    throw logic_error("accept_socket does not exist in UDPForwardSession");
}
void UDPForwardSession::start(){
    throw logic_error("start does not exist in UDPForwardSession");
}

void UDPForwardSession::start_udp(const std::string_view& data) {
    udp_timer_async_wait();
    start_time = time(nullptr);

    auto self = shared_from_this();
    auto cb = [this, self](){
        if(config.run_type == Config::NAT){
            udp_target_socket.open(out_udp_endpoint.protocol());
            bool is_ipv4 = out_udp_endpoint.protocol().family() == boost::asio::ip::tcp::v6().family();
            if (prepare_nat_udp_target_bind((int)udp_target_socket.native_handle(), is_ipv4, out_udp_endpoint, config.udp_socket_buf)) {
                udp_target_socket.bind(out_udp_endpoint);
            } else {
                destroy();
                return;
            }
        }
        
        status = FORWARDING;
        out_async_read();

        out_async_write(streambuf_to_string_view(out_write_buf));
        out_write_buf.consume(out_write_buf.size());
    };

    out_write_buf.consume(out_write_buf.size());
    streambuf_append(out_write_buf, TrojanRequest::generate(config.password.cbegin()->first, out_udp_endpoint.address().to_string(), out_udp_endpoint.port(), false));
    process(udp_recv_endpoint, data);

    _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(get_session_id()) + " forwarding UDP packets to " + out_udp_endpoint.address().to_string() + ':' + to_string(out_udp_endpoint.port()) + " via " + config.remote_addr + ':' + to_string(config.remote_port), Log::INFO);

    if(pipeline_com.is_using_pipeline()){
        cb();
    }else{
        config.prepare_ssl_reuse(out_socket);
        connect_remote_server_ssl(this, config.remote_addr, to_string(config.remote_port), resolver, out_socket, udp_recv_endpoint, cb);
    }    
}

bool UDPForwardSession::process(const udp::endpoint &endpoint, const string_view &data) {
    if (endpoint != udp_recv_endpoint) {
        return false;
    }
    in_recv(data);
    return true;
}

void UDPForwardSession::out_async_read() {
    if (pipeline_com.is_using_pipeline()) {
        pipeline_com.pipeline_data_cache.async_read([this](const string_view &data) {
            out_recv(data);
        });
    } else {
        _guard_read_buf_begin(out_read_buf);
        out_read_buf.consume(out_read_buf.size());
        auto self = shared_from_this();
        out_socket.async_read_some(out_read_buf.prepare(MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
            _guard_read_buf_end(out_read_buf);
            if (error) {
                destroy();
                return;
            }
            out_read_buf.commit(length);
            out_recv(streambuf_to_string_view(out_read_buf));
        });
    }
}

void UDPForwardSession::out_async_write(const string_view &data) {
    auto self = shared_from_this();
    if(pipeline_com.is_using_pipeline()){
        service->session_async_send_to_pipeline(*this, PipelineRequest::DATA, data, [this, self](const boost::system::error_code error) {
            if (error) {
                destroy();
                return;
            }
            out_sent();
        });
    }else{
        auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
        boost::asio::async_write(out_socket, data_copy->data(), [this, self, data_copy](const boost::system::error_code error, size_t) {
            get_service()->get_sending_data_allocator().free(data_copy);
            if (error) {
                destroy();
                return;
            }
            out_sent();
        });
    }
}

void UDPForwardSession::in_recv(const string_view &data) {
    if (status == DESTROY) {
        return;
    }

    udp_timer_async_wait();
    
    size_t length = data.length();
    sent_len += length;

    _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(get_session_id()) + " sent a UDP packet of length " + to_string(length) + 
        " bytes to " + out_udp_endpoint.address().to_string() + ':' + to_string(out_udp_endpoint.port()) + " sent_len: " + to_string(sent_len));

    UDPPacket::generate(out_write_buf, out_udp_endpoint.address().to_string(), out_udp_endpoint.port(), data);
    if (status == FORWARD) {
        status = FORWARDING;   
        out_async_write(streambuf_to_string_view(out_write_buf));
        out_write_buf.consume(out_write_buf.size());
    }
}

void UDPForwardSession::out_recv(const string_view &data) {
    if (status == FORWARD || status == FORWARDING) {
        udp_timer_async_wait();
        streambuf_append(udp_data_buf, data);
        for (;;) {
            UDPPacket packet;
            size_t packet_len;
            bool is_packet_valid = packet.parse(streambuf_to_string_view(udp_data_buf), packet_len);
            if (!is_packet_valid) {
                if (udp_data_buf.size() > MAX_BUF_LENGTH) {
                    _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(get_session_id()) + " UDP packet too long", Log::ERROR);
                    destroy();
                    return;
                }
                break;
            }
            _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(get_session_id()) + " received a UDP packet of length " + to_string(packet.length) + " bytes from " + packet.address.address + ':' + to_string(packet.address.port));
            
            if(config.run_type == Config::NAT){
                boost::system::error_code ec;
                udp_target_socket.send_to(boost::asio::buffer(packet.payload.data(), packet.payload.length()), udp_recv_endpoint, 0 , ec);
                if (ec == boost::asio::error::no_permission) {
                    _log_with_endpoint(udp_recv_endpoint, "[udp] dropped a packet due to firewall policy or rate limit");
                } else if (ec) {
                    output_debug_info_ec(ec);
                    destroy();
                    return;
                } 
            }else{
                in_write(udp_recv_endpoint, packet.payload);
            }

            udp_data_buf.consume(packet_len);
            recv_len += packet.length;          
        }
        out_async_read();
    }
}

void UDPForwardSession::out_sent() {
    if (status == FORWARDING) {
        if (out_write_buf.size() == 0) {
            status = FORWARD;
        } else {
            out_async_write(streambuf_to_string_view(out_write_buf));
            out_write_buf.consume(out_write_buf.size());
        }
    }
}

void UDPForwardSession::destroy(bool pipeline_call /*= false*/) {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    _log_with_endpoint(udp_recv_endpoint, "session_id: " + to_string(get_session_id()) + " disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    resolver.cancel();
    
    if(udp_target_socket.is_open()){
        boost::system::error_code ec;
        udp_gc_timer.cancel(ec);
        udp_target_socket.cancel(ec);
        udp_target_socket.close();
    }

    shutdown_ssl_socket(this, out_socket);
    
    if(!pipeline_call && pipeline_com.is_using_pipeline()){
        service->session_destroy_in_pipeline(*this);
    }
}
