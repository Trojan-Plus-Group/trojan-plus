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

#include "clientsession.h"

#include "core/service.h"
#include "core/utils.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include "ssl/sslsession.h"
#include "mem/memallocator.h"

using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ClientSession::ClientSession(Service* _service, const Config& config, context& ssl_context)
    : SocketSession(_service, config),
      status(HANDSHAKE),
      first_packet_recv(false),
      in_socket(_service->get_io_context()),
      out_socket(_service->get_io_context(), ssl_context),
      udp_socket(_service->get_io_context()) {
    set_session_name("ClientSession");
    get_pipeline_component().allocate_session_id();
}

ClientSession::~ClientSession() { get_pipeline_component().free_session_id(); }

tcp::socket& ClientSession::accept_socket() { return in_socket; }

bool ClientSession::prepare_session() {
    boost::system::error_code ec;

    set_in_endpoint(in_socket.remote_endpoint(ec));
    if (ec) {
        _log_with_date_time("cannot get get_in_endpoint() in prepare_session", Log::FATAL);
        destroy();
        return false;
    }
    get_config().prepare_ssl_reuse(out_socket);
    return true;
}

void ClientSession::start() {
    if (prepare_session()) {
        in_async_read();
    }
}
void ClientSession::recv_ack_cmd(size_t ack_count) {
    SocketSession::recv_ack_cmd(ack_count);
    if (get_pipeline_component().is_wait_for_pipeline_ack()) {
        in_async_read();
    }
}

void ClientSession::in_async_read() {
    if (get_pipeline_component().is_using_pipeline() && status == FORWARD) {
        if (!get_pipeline_component().pre_call_ack_func()) {
            _log_with_endpoint_DEBUG(get_in_endpoint(), "session_id: " + tp::to_string(get_session_id()) +
                                                          " Cannot ClientSession::in_async_read ! Is waiting for ack");
            return;
        }
        _log_with_endpoint_DEBUG(get_in_endpoint(),
          "session_id: " + tp::to_string(get_session_id()) +
            " Permit to ClientSession::in_async_read! ack:" + tp::to_string(get_pipeline_component().pipeline_ack_counter));
    }

    in_read_buf.begin_read(__FILE__, __LINE__);
    in_read_buf.consume_all();
    auto self = shared_from_this();
    in_socket.async_read_some(
      in_read_buf.prepare(MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
          in_read_buf.end_read();
          if (error == boost::asio::error::operation_aborted) {
              return;
          }
          if (error) {
              output_debug_info_ec(error);
              destroy();
              return;
          }
          in_read_buf.commit(length);
          in_recv(in_read_buf);
      });
}

void ClientSession::in_async_write(const std::string_view& data, size_t ack_count) {

    _log_with_date_time_DEBUG("ClientSession::in_async_write status: " + tp::to_string((int)status) +
                              " session_id: " + tp::to_string(get_session_id()) + " length: " + tp::to_string(data.length()) +
                              " checksum: " + tp::to_string(get_checksum(data)));

    _write_data_to_file_DEBUG(get_session_id(), "ClientSession_in_async_write", data);

    if (get_pipeline_component().is_using_pipeline() && status == FORWARD) {
        get_pipeline_component().set_async_writing_data(true);
    }

    auto self      = shared_from_this();
    auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
    boost::asio::async_write(
      in_socket, data_copy->data(), [this, self, data_copy, ack_count](const boost::system::error_code error, size_t) {
          get_service()->get_sending_data_allocator().free(data_copy);
          if (error) {
              output_debug_info_ec(error);
              destroy();
              return;
          }

          if (get_pipeline_component().is_using_pipeline() && status == FORWARD) {

              if (get_pipeline_component().is_write_close_future() &&
                  !get_pipeline_component().get_pipeline_data_cache().has_queued_data()) {
                  output_debug_info_ec(error);
                  destroy();
                  return;
              }

              get_pipeline_component().set_async_writing_data(false);

              get_service()->session_async_send_to_pipeline(
                *this, PipelineRequest::ACK, "",
                [this, self](const boost::system::error_code error) {
                    if (error) {
                        output_debug_info_ec(error);
                        destroy();
                        return;
                    }

                    in_sent();
                },
                ack_count);
          } else {
              in_sent();
          }
      });
}

void ClientSession::out_async_read() {
    if (get_pipeline_component().is_using_pipeline()) {
        get_pipeline_component().get_pipeline_data_cache().async_read(
          [this](const std::string_view& data, size_t ack_count) { out_recv(data, ack_count); });
    } else {
        out_read_buf.begin_read(__FILE__, __LINE__);
        out_read_buf.consume_all();
        auto self = shared_from_this();
        out_socket.async_read_some(
          out_read_buf.prepare(MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
              out_read_buf.end_read();
              if (error) {
                  output_debug_info_ec(error);
                  destroy();
                  return;
              }
              out_read_buf.commit(length);
              out_recv(out_read_buf);
          });
    }
}

void ClientSession::out_async_write(const std::string_view& data) {

    _write_data_to_file_DEBUG("ClientSession::out_async_write status: " + tp::to_string((int)status) +
                              " session_id: " + tp::to_string(get_session_id()) + " length: " + tp::to_string(data.length()) +
                              " checksum: " + tp::to_string(get_checksum(data)));

    _write_data_to_file_DEBUG(get_session_id(), "ClientSession_out_async_write", data);

    auto self = shared_from_this();
    if (get_pipeline_component().is_using_pipeline()) {
        get_service()->session_async_send_to_pipeline(
          *this, PipelineRequest::DATA, data, [this, self](const boost::system::error_code error) {
              if (error) {
                  output_debug_info_ec(error);
                  destroy();
                  return;
              }
              out_sent();
          });
    } else {
        auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
        boost::asio::async_write(
          out_socket, data_copy->data(), [this, self, data_copy](const boost::system::error_code error, size_t) {
              get_service()->get_sending_data_allocator().free(data_copy);
              if (error) {
                  output_debug_info_ec(error);
                  destroy();
                  return;
              }
              out_sent();
          });
    }
}

void ClientSession::udp_async_read() {
    udp_read_buf.begin_read(__FILE__, __LINE__);
    udp_read_buf.consume_all();
    auto self = shared_from_this();
    udp_socket.async_receive_from(udp_read_buf.prepare(get_config().get_udp_recv_buf()), udp_recv_endpoint,
      [this, self](const boost::system::error_code error, size_t length) {
          udp_read_buf.end_read();
          if (error == boost::asio::error::operation_aborted) {
              return;
          }
          if (error) {
              output_debug_info_ec(error);
              destroy();
              return;
          }
          udp_read_buf.commit(length);
          udp_recv(udp_read_buf, udp_recv_endpoint);
      });
}

void ClientSession::udp_async_write(const std::string_view& data, const udp::endpoint& endpoint) {
    auto self      = shared_from_this();
    auto data_copy = get_service()->get_sending_data_allocator().allocate(data);
    udp_socket.async_send_to(
      data_copy->data(), endpoint, [this, self, data_copy](const boost::system::error_code error, size_t) {
          get_service()->get_sending_data_allocator().free(data_copy);
          if (error) {
              output_debug_info_ec(error);
              destroy();
              return;
          }
          udp_sent();
      });
}

static const int socks_version = 5;

static inline bool socks5_is_invalid_handshake_data(const std::string_view& data) {
    const size_t min_length = 2;
    return data.length() < min_length || data[0] != socks_version ||
           data.length() != (unsigned int)(unsigned char)data[1] + min_length;
}

static inline bool socks5_is_invalid_quest_data(const std::string_view& data) {
    const size_t min_length = 7;
    return data.length() < min_length || data[0] != socks_version || data[2] != 0;
}

static const tp::string socks5_handshake_reply_failed("\x05\xff", 2);
static const tp::string socks5_handshake_reply_succ("\x05\x00", 2);
static const tp::string socks5_request_reply_failed("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10);
static const tp::string socks5_request_reply_succ_tcp("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10);
static const tp::string socks5_request_reply_succ_udp_header("\x05\x00\x00", 3);

void ClientSession::in_recv(const std::string_view& data) {
    _write_data_to_file_DEBUG("ClientSession::in_recv status: " + tp::to_string((int)status) +
                              " session_id: " + tp::to_string(get_session_id()) + " length: " + tp::to_string(data.length()) +
                              " checksum: " + tp::to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ClientSession_in_recv", data);

    switch (status) {
        case HANDSHAKE: {
            if (socks5_is_invalid_handshake_data(data)) {
                _log_with_endpoint(
                  get_in_endpoint(), "session_id: " + tp::to_string(get_session_id()) + " unknown protocol", Log::ERROR);
                destroy();
                return;
            }
            bool has_method = false;
            for (int i = 2; i < data[1] + 2; ++i) {
                if (data[i] == 0) {
                    has_method = true;
                    break;
                }
            }
            if (!has_method) {
                _log_with_endpoint(get_in_endpoint(),
                  "session_id: " + tp::to_string(get_session_id()) + " unsupported auth method", Log::ERROR);
                in_async_write(socks5_handshake_reply_failed);
                status = INVALID;
                return;
            }
            in_async_write(socks5_handshake_reply_succ);
            break;
        }
        case REQUEST: {
            if (socks5_is_invalid_quest_data(data)) {
                _log_with_endpoint(
                  get_in_endpoint(), "session_id: " + tp::to_string(get_session_id()) + " bad request", Log::ERROR);
                destroy();
                return;
            }
            out_write_buf.consume(out_write_buf.size());

            streambuf_append(out_write_buf, get_config().get_password().cbegin()->first);
            streambuf_append(out_write_buf, "\r\n");
            streambuf_append(out_write_buf, data[1]);
            streambuf_append(out_write_buf, data.substr(3));
            streambuf_append(out_write_buf, "\r\n");

            TrojanRequest req;
            if (req.parse(streambuf_to_string_view(out_write_buf)) == -1) {
                _log_with_endpoint(
                  get_in_endpoint(), "session_id: " + tp::to_string(get_session_id()) + " unsupported command", Log::ERROR);
                in_async_write(socks5_request_reply_failed);
                status = INVALID;
                return;
            }

            if (req.address.address_type != SOCKS5Address::DOMAINNAME) {
                boost::system::error_code ec;
                auto endpoint = make_udp_endpoint_safe(req.address.address, req.address.port, ec);
                if (ec) {
                    _log_with_endpoint(endpoint,
                      "session_id: " + tp::to_string(get_session_id()) + " cannot make address " + req.address.address +
                        ':' + tp::to_string(req.address.port) + ec.message(),
                      Log::ERROR);
                    in_async_write(socks5_request_reply_failed);
                    status = INVALID;
                    return;
                }
            }

            set_udp_forward_session(req.command == TrojanRequest::UDP_ASSOCIATE);
            if (is_udp_forward_session()) {
                udp_timer_async_wait();
                auto endpoint = udp::endpoint(in_socket.local_endpoint().address(), 0);
                boost::system::error_code ec;
                udp_socket.open(endpoint.protocol(), ec);
                if (ec) {
                    output_debug_info();
                    destroy();
                    return;
                }
                set_udp_send_recv_buf((int)udp_socket.native_handle(), get_config().get_udp_socket_buf());
                udp_socket.bind(endpoint);

                _log_with_endpoint(get_in_endpoint(),
                  "session_id: " + tp::to_string(get_session_id()) + " requested UDP associate to " + req.address.address +
                    ':' + tp::to_string(req.address.port) + ", open UDP socket " +
                    udp_socket.local_endpoint().address().to_string() + ':' +
                    tp::to_string(udp_socket.local_endpoint().port()) + " for relay",
                  Log::INFO);

                udp_send_buf.consume(udp_send_buf.size());
                streambuf_append(udp_send_buf, socks5_request_reply_succ_udp_header);
                SOCKS5Address::generate(udp_send_buf, udp_socket.local_endpoint());

                in_async_write(streambuf_to_string_view(udp_send_buf));
            } else {
                _log_with_endpoint(get_in_endpoint(),
                  "session_id: " + tp::to_string(get_session_id()) + " requested connection to " + req.address.address +
                    ':' + tp::to_string(req.address.port),
                  Log::INFO);
                in_async_write(socks5_request_reply_succ_tcp);
            }

            break;
        }
        case CONNECT: {
            get_stat().inc_sent_len(data.length());
            first_packet_recv = true;
            streambuf_append(out_write_buf, data);
            break;
        }
        case FORWARD: {
            get_stat().inc_sent_len(data.length());
            out_async_write(data);
            break;
        }
        case UDP_FORWARD: {
            _log_with_endpoint(get_in_endpoint(),
              "session_id: " + tp::to_string(get_session_id()) + " unexpected data from TCP port", Log::ERROR);
            destroy();
            break;
        }
        default:
            break;
    }
}

void ClientSession::in_sent() {
    switch (status) {
        case HANDSHAKE: {
            status = REQUEST;
            in_async_read();
            break;
        }
        case REQUEST: {
            status = CONNECT;
            request_remote();
            break;
        }
        case FORWARD: {
            out_async_read();
            break;
        }
        case INVALID: {
            output_debug_info();
            destroy();
            break;
        }
        default:
            break;
    }
}

void ClientSession::request_remote() {
    auto self = shared_from_this();
    auto cb   = [this, self]() {
        boost::system::error_code ec;
        if (is_udp_forward_session()) {
            if (!first_packet_recv) {
                udp_socket.cancel(ec);
            }
            status = UDP_FORWARD;
        } else {
            if (!first_packet_recv) {
                in_socket.cancel(ec);
            }
            status = FORWARD;
        }

        out_async_read();
        out_async_write(streambuf_to_string_view(out_write_buf));
    };

    if (get_pipeline_component().is_using_pipeline()) {
        cb();
    } else {
        connect_remote_server_ssl(this, get_config().get_remote_addr(), tp::to_string(get_config().get_remote_port()),
          get_resolver(), out_socket, get_in_endpoint(), cb);
    }
}

void ClientSession::out_recv(const std::string_view& data, size_t ack_count) {
    _write_data_to_file_DEBUG("ClientSession::out_recv session_id: " + tp::to_string(get_session_id()) +
                              " length: " + tp::to_string(data.length()) + " checksum: " + tp::to_string(get_checksum(data)));
    _write_data_to_file_DEBUG(get_session_id(), "ClientSession_out_recv", data);
    if (status == FORWARD) {
        get_stat().inc_recv_len(data.length());
        in_async_write(data, ack_count);
    } else if (status == UDP_FORWARD) {
        streambuf_append(udp_data_buf, data);
        udp_sent();
    }
}

void ClientSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    } else if (status == UDP_FORWARD) {
        udp_async_read();
    }
}

void ClientSession::udp_recv(const std::string_view& data, const udp::endpoint&) {
    if (data.length() == 0) {
        return;
    }
    if (data.length() < 3 || data[0] != 0 || data[1] != 0 || data[2] != 0) {
        _log_with_endpoint(
          udp_recv_endpoint, "session_id: " + tp::to_string(get_session_id()) + " bad UDP packet", Log::ERROR);
        destroy();
        return;
    }
    SOCKS5Address address;
    size_t address_len = 0;
    bool is_addr_valid = address.parse(data.substr(3), address_len);
    if (!is_addr_valid) {
        _log_with_endpoint(
          udp_recv_endpoint, "session_id: " + tp::to_string(get_session_id()) + " bad UDP packet", Log::ERROR);
        destroy();
        return;
    }
    udp_timer_async_wait();

    size_t length = data.length() - 3 - address_len;
    get_stat().inc_sent_len(length);

    _log_with_endpoint(udp_recv_endpoint, "session_id: " + tp::to_string(get_session_id()) +
                                            " sent a UDP packet of length " + tp::to_string(length) + " bytes to " +
                                            address.address + ':' + tp::to_string(address.port));

    if (status == CONNECT) {
        first_packet_recv = true;

        // same as UDPacket::generate:
        streambuf_append(out_write_buf, data.substr(3, address_len));
        streambuf_append(out_write_buf, char(uint8_t(length >> one_byte_shift_8_bits)));
        streambuf_append(out_write_buf, char(uint8_t(length & one_byte_mask_0xFF)));
        streambuf_append(out_write_buf, "\r\n");
        streambuf_append(out_write_buf, data.substr(address_len + 3));

    } else if (status == UDP_FORWARD) {
        udp_recv_buf.consume(udp_recv_buf.size());

        // same as UDPacket::generate:
        streambuf_append(udp_recv_buf, data.substr(3, address_len));
        streambuf_append(udp_recv_buf, char(uint8_t(length >> one_byte_shift_8_bits)));
        streambuf_append(udp_recv_buf, char(uint8_t(length & one_byte_mask_0xFF)));
        streambuf_append(udp_recv_buf, "\r\n");
        streambuf_append(udp_recv_buf, data.substr(address_len + 3));

        out_async_write(streambuf_to_string_view(udp_recv_buf));
    }
}

void ClientSession::udp_sent() {
    if (status == UDP_FORWARD) {
        udp_timer_async_wait();
        auto parse_data = streambuf_to_string_view(udp_data_buf);
        UDPPacket packet;
        size_t packet_len    = 0;
        bool is_packet_valid = packet.parse(parse_data, packet_len);
        if (!is_packet_valid) {
            if (udp_data_buf.size() > MAX_BUF_LENGTH) {
                _log_with_endpoint(
                  udp_recv_endpoint, "session_id: " + tp::to_string(get_session_id()) + " UDP packet too long", Log::ERROR);
                destroy();
                return;
            }
            out_async_read();
            return;
        }

        _log_with_endpoint(udp_recv_endpoint,
          "session_id: " + tp::to_string(get_session_id()) + " received a UDP packet of length " +
            tp::to_string(packet.length) + " bytes from " + packet.address.address + ':' + tp::to_string(packet.address.port));

        SOCKS5Address address;
        size_t address_len = 0;
        bool is_addr_valid = address.parse(parse_data, address_len);
        if (!is_addr_valid) {
            _log_with_endpoint(udp_recv_endpoint,
              "session_id: " + tp::to_string(get_session_id()) + " udp_sent: invalid UDP packet address", Log::ERROR);
            destroy();
            return;
        }

        udp_send_buf.consume(udp_send_buf.size());
        streambuf_append(udp_send_buf, (const uint8_t*)"\x00\x00\x00", 3);
        streambuf_append(udp_send_buf, udp_data_buf, 0, address_len);
        streambuf_append(udp_send_buf, packet.payload);

        get_stat().inc_recv_len(packet.length);
        udp_async_write(streambuf_to_string_view(udp_send_buf), udp_recv_endpoint);

        udp_data_buf.consume(packet_len);
    }
}

void ClientSession::destroy(bool pipeline_call /*= false*/) {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;

    _log_with_endpoint(get_in_endpoint(),
      "session_id: " + tp::to_string(get_session_id()) + " disconnected, " + get_stat().to_string(), Log::INFO);

    boost::system::error_code ec;
    get_resolver().cancel();

    if (in_socket.is_open()) {
        in_socket.cancel(ec);
        in_socket.shutdown(tcp::socket::shutdown_both, ec);
        in_socket.close(ec);
    }

    udp_timer_cancel();
    if (udp_socket.is_open()) {
        udp_socket.cancel(ec);
        udp_socket.close(ec);
    }

    shutdown_ssl_socket(this, out_socket);

    if (!pipeline_call && get_pipeline_component().is_using_pipeline()) {
        get_service()->session_destroy_in_pipeline(*this);
    }
}
