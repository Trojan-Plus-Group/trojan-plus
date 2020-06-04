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

#include "serversession.h"

#include "core/service.h"
#include "core/utils.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ServerSession::ServerSession(Service* _service, const Config& config, boost::asio::ssl::context &ssl_context, Authenticator *auth, const std::string &plain_http_response) :
    SocketSession(_service, config),
    status(HANDSHAKE),
    in_socket(_service->get_io_context(), ssl_context),
    out_socket(_service->get_io_context()),
    udp_resolver(_service->get_io_context()),
    auth(auth),
    plain_http_response(plain_http_response),
    has_queried_out(false) {}

tcp::socket& ServerSession::accept_socket() {
    return (tcp::socket&)in_socket.next_layer();
}

void ServerSession::start() {
    
    start_time = time(nullptr);

    if(!pipeline_com.is_using_pipeline()){
        boost::system::error_code ec;
        in_endpoint = in_socket.next_layer().remote_endpoint(ec);
        if (ec) {
            output_debug_info_ec(ec);
            destroy();
            return;
        }
        auto self = shared_from_this();
        in_socket.async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
            if (error) {
                _log_with_endpoint(in_endpoint, "SSL handshake failed: " + error.message(), Log::ERROR);
                if (error.message() == "http request" && plain_http_response.empty()) {
                    recv_len += plain_http_response.length();
                    boost::asio::async_write(accept_socket(), boost::asio::buffer(plain_http_response), [this, self](const boost::system::error_code, size_t) {
                        output_debug_info();
                        destroy();
                    });
                    return;
                }
                output_debug_info();
                destroy();
                return;
            }
            in_async_read();
        });
    }else{
        in_async_read();
    }
}

void ServerSession::in_async_read() {
    if(pipeline_com.is_using_pipeline()){
        pipeline_com.pipeline_data_cache.async_read([this](const string_view &data) {
            in_recv(data);
        });
    }else{
        _guard_read_buf_begin(in_read_buf);
        in_read_buf.consume(in_read_buf.size());
        auto self = shared_from_this();
        in_socket.async_read_some(in_read_buf.prepare(MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
            _guard_read_buf_end(in_read_buf);
            if (error) {
                output_debug_info_ec(error);
                destroy();
                return;
            }
            in_read_buf.commit(length);
            in_recv(streambuf_to_string_view(in_read_buf));
        });
    }
}

void ServerSession::in_async_write(const string_view& data) {
    _log_with_date_time_DEBUG("ServerSession::in_async_write session_id: " + to_string(get_session_id()) + " length: " + to_string(data.length()) + " checksum: " + to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ServerSession_in_async_write", data);
    auto self = shared_from_this();
    if(pipeline_com.is_using_pipeline()){
        if(!pipeline_session.expired()){
            (static_cast<PipelineSession*>(pipeline_session.lock().get()))->session_write_data(*this, data, [this, self](const boost::system::error_code){
                in_sent();
            });            
        }else{
            output_debug_info();
            destroy();
        }
    }else{
        auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
        boost::asio::async_write(in_socket, data_copy->data(), [this, self, data_copy](const boost::system::error_code error, size_t) {
            get_service()->get_sending_data_allocator().free(data_copy);
            if (error) {
                output_debug_info_ec(error);
                destroy();
                return;
            }
            in_sent();
        });
    }
}

void ServerSession::out_async_read() {
    if(pipeline_com.is_using_pipeline()){
        if(!pipeline_com.pre_call_ack_func()){
            _log_with_endpoint_DEBUG(in_endpoint, "session_id: " + to_string(get_session_id()) + " cannot ServerSession::out_async_read ! Is waiting for ack");
            return;
        }
        _log_with_endpoint_DEBUG(in_endpoint, "session_id: " + to_string(get_session_id()) + 
            " permit to ServerSession::out_async_read aysnc! ack:" + to_string(pipeline_com.pipeline_ack_counter));
    }

    _guard_read_buf_begin(out_read_buf);
    out_read_buf.consume(out_read_buf.size());
    auto self = shared_from_this();
    out_socket.async_read_some(out_read_buf.prepare(MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        _guard_read_buf_end(out_read_buf);
        if (error) {
            output_debug_info_ec(error);
            destroy();
            return;
        }
        out_read_buf.commit(length);
        out_recv(streambuf_to_string_view(out_read_buf));
    });
}

void ServerSession::out_async_write(const string_view &data) {
    _log_with_date_time_DEBUG("ServerSession::out_async_write session_id: " + to_string(get_session_id()) + " length: " + to_string(data.length()) + " checksum: " + to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ServerSession_out_async_write", data);
    auto self = shared_from_this();
    auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
    boost::asio::async_write(out_socket, data_copy->data(), [this, self, data_copy](const boost::system::error_code error, size_t) {
        get_service()->get_sending_data_allocator().free(data_copy);
        if (error) {
            output_debug_info_ec(error);
            destroy();
            return;
        }
        
        if(pipeline_com.is_using_pipeline() && !pipeline_session.expired()){
            (static_cast<PipelineSession*>(pipeline_session.lock().get()))->session_write_ack(*this, [this, self](const boost::system::error_code){
                out_sent();
            });
        }else{
            out_sent();
        }        
    });
}

void ServerSession::out_udp_async_read() {
    _guard_read_buf_begin(udp_read_buf);
    udp_read_buf.consume(udp_read_buf.size());
    auto self = shared_from_this();
    udp_socket.async_receive_from(udp_read_buf.prepare(MAX_BUF_LENGTH), udp_recv_endpoint, [this, self](const boost::system::error_code error, size_t length) {
        _guard_read_buf_end(udp_read_buf);
        if (error) {
            output_debug_info_ec(error);
            destroy();
            return;
        }
        udp_read_buf.commit(length);
        out_udp_recv(streambuf_to_string_view(udp_read_buf), udp_recv_endpoint);
    });
}

void ServerSession::out_udp_async_write(const string_view &data, const udp::endpoint &endpoint) {
    auto self = shared_from_this();
    auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
    udp_socket.async_send_to(data_copy->data(), endpoint, [this, self, data_copy](const boost::system::error_code error, size_t) {
        get_service()->get_sending_data_allocator().free(data_copy);
        if (error) {
            output_debug_info_ec(error);
            destroy();
            return;
        }
        out_udp_sent();
    });
}

void ServerSession::in_recv(const string_view &data) {
    _log_with_date_time_DEBUG("ServerSession::in_recv session_id: " + to_string(get_session_id()) + " length: " + to_string(data.length()) + " checksum: " + to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ServerSession_in_recv", data);
    if (status == HANDSHAKE) {
        
        if(has_queried_out){
            // pipeline session will call this in_recv directly so that the HANDSHAKE status will remain for a while
            streambuf_append(out_write_buf, data);
            sent_len += data.length();
            return;
        }

        TrojanRequest req;
        bool use_alpn = req.parse(data) == -1;
        if(!use_alpn){
            auto password_iterator = config.password.find(req.password);
            if (password_iterator == config.password.end()) {
                if (auth && auth->auth(req.password)) {
                    auth_password = req.password;
                    _log_with_endpoint(in_endpoint, "session_id: " + to_string(get_session_id()) + " authenticated by authenticator (" + req.password.substr(0, 7) + ')', Log::INFO);
                }else{
                    use_alpn = true;
                }
            } else {
                _log_with_endpoint(in_endpoint, "session_id: " + to_string(get_session_id()) + " authenticated as " + password_iterator->second, Log::INFO);
            }
        }      
                
        string query_addr = use_alpn ? config.remote_addr : req.address.address;
        string query_port = to_string([&]() {
            if (!use_alpn) {
                return req.address.port;
            }
            const unsigned char *alpn_out;
            unsigned int alpn_len;
            SSL_get0_alpn_selected(in_socket.native_handle(), &alpn_out, &alpn_len);
            if (alpn_out == nullptr) {
                return config.remote_port;
            }
            auto it = config.ssl.alpn_port_override.find(string(alpn_out, alpn_out + alpn_len));
            return it == config.ssl.alpn_port_override.end() ? config.remote_port : it->second;
        }());
        
        if (!use_alpn) {
            if (req.command == TrojanRequest::UDP_ASSOCIATE) {
                out_udp_endpoint = udp::endpoint(make_address(req.address.address), req.address.port);
                _log_with_endpoint(out_udp_endpoint, "session_id: " + to_string(get_session_id()) + " requested UDP associate to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
                status = UDP_FORWARD;
                udp_data_buf.consume(udp_data_buf.size());
                streambuf_append(udp_data_buf, req.payload);
                out_udp_sent();
                return;
            } else {
                _log_with_endpoint(in_endpoint, "session_id: " + to_string(get_session_id()) + " requested connection to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
                streambuf_append(out_write_buf, req.payload);
            }
        } else {            
            streambuf_append(out_write_buf, data);
        }
        
        sent_len += out_write_buf.size();
        has_queried_out = true;

        auto self = shared_from_this();
        connect_out_socket(this, query_addr, query_port, resolver, out_socket, in_endpoint, [this, self](){
            status = FORWARD;
            out_async_read();
            if (out_write_buf.size() != 0) {
                out_async_write(streambuf_to_string_view(out_write_buf));
            } else {
                in_async_read();
            }
        });

    } else if (status == FORWARD) {
        sent_len += data.length();
        out_async_write(data);
    } else if (status == UDP_FORWARD) {
        streambuf_append(udp_data_buf, data);
        out_udp_sent();
    }
}

void ServerSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    } else if (status == UDP_FORWARD) {
        out_udp_async_read();
    }
}

void ServerSession::out_recv(const string_view &data) {
    _log_with_date_time_DEBUG("ServerSession::out_recv session_id: " + to_string(get_session_id()) + " length: " + to_string(data.length()) + " checksum: " + to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ServerSession_out_recv", data);
    if (status == FORWARD) {
        recv_len += data.length();
        in_async_write(data);
    }
}

void ServerSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();        
    }
}

void ServerSession::out_udp_recv(const string_view &data, const udp::endpoint &endpoint) {
    if (status == UDP_FORWARD) {
        size_t length = data.length();
        _log_with_endpoint(out_udp_endpoint, "session_id: " + to_string(get_session_id()) + " received a UDP packet of length " + to_string(length) + " bytes from " + endpoint.address().to_string() + ':' + to_string(endpoint.port()));
        recv_len += length;
        out_write_buf.consume(out_write_buf.size());
        in_async_write(streambuf_to_string_view(UDPPacket::generate(out_write_buf, endpoint, data)));
    }
}

void ServerSession::out_udp_sent() {
    if (status == UDP_FORWARD) {
        UDPPacket packet;
        size_t packet_len;
        bool is_packet_valid = packet.parse(streambuf_to_string_view(udp_data_buf), packet_len);
        if (!is_packet_valid) {
            if (udp_data_buf.size() > MAX_BUF_LENGTH) {
                _log_with_endpoint(out_udp_endpoint, "session_id: " + to_string(get_session_id()) + " UDP packet too long", Log::ERROR);
                destroy();
                return;
            }
            in_async_read();
            return;
        }
        _log_with_endpoint(out_udp_endpoint, "session_id: " + to_string(get_session_id()) + " sent a UDP packet of length " + to_string(packet.length) + " bytes to " + packet.address.address + ':' + to_string(packet.address.port));
        
        auto self = shared_from_this();
        udp_resolver.async_resolve(packet.address.address, to_string(packet.address.port), [this, self, packet, packet_len](const boost::system::error_code error, udp::resolver::results_type results) {
            if (error || results.empty()) {
                _log_with_endpoint(out_udp_endpoint, "session_id: " + to_string(get_session_id()) + " cannot resolve remote server hostname " + packet.address.address + ": " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            auto iterator = results.begin();
            if (config.tcp.prefer_ipv4) {
                for (auto it = results.begin(); it != results.end(); ++it) {
                    const auto &addr = it->endpoint().address();
                    if (addr.is_v4()) {
                        iterator = it;
                        break;
                    }
                }
            }
            _log_with_endpoint(out_udp_endpoint, "session_id: " + to_string(get_session_id()) + " " + packet.address.address + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
            if (!udp_socket.is_open()) {
                auto protocol = iterator->endpoint().protocol();
                boost::system::error_code ec;
                udp_socket.open(protocol, ec);
                if (ec) {
                    output_debug_info_ec(ec);
                    destroy();
                    return;
                }
                udp_socket.bind(udp::endpoint(protocol, 0));
                out_udp_async_read();
            }
            sent_len += packet.length;
            out_udp_async_write(packet.payload, *iterator);

            // we must consume here after packet.payload has been writen
            udp_data_buf.consume(packet_len);
        });
    }
}

void ServerSession::destroy(bool pipeline_call /*= false*/) {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    _log_with_endpoint(in_endpoint, "session_id: " + to_string(get_session_id()) + " disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    if (auth && !auth_password.empty()) {
        auth->record(auth_password, recv_len, sent_len);
    }
    boost::system::error_code ec;
    resolver.cancel();
    udp_resolver.cancel();
    if (out_socket.is_open()) {
        out_socket.cancel(ec);
        out_socket.shutdown(tcp::socket::shutdown_both, ec);
        out_socket.close(ec);
    }
    if (udp_socket.is_open()) {
        udp_socket.cancel(ec);
        udp_socket.close(ec);
    }

    shutdown_ssl_socket(this, in_socket);    

    if(!pipeline_call && pipeline_com.is_using_pipeline() && !pipeline_session.expired()){
        (static_cast<PipelineSession*>(pipeline_session.lock().get()))->remove_session_after_destroy(*this);
    }
}
