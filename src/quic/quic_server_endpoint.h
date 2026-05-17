/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_SERVER_ENDPOINT_H_
#define _QUIC_SERVER_ENDPOINT_H_

#include "quic_connection.h"
#include "quic_endpoint.h"

// Server-side QUIC endpoint. Binds to local_addr:local_port and dispatches
// incoming datagrams to QuicConnection instances keyed by DCID.
class QuicServerEndpoint : public QuicEndpoint {
  public:
    QuicServerEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                       std::shared_ptr<QuicTlsCtx> tls_ctx);

    void start() override;

  protected:
    void on_packet(const uint8_t* data, std::size_t len,
                   const boost::asio::ip::udp::endpoint& src) override;
    void on_pump_write() override;

  private:
    // Connection table: hex-encoded DCID → QuicConnection.
    tp::unordered_map<tp::string, std::shared_ptr<QuicConnection>> m_conns;

    static tp::string dcid_key(const uint8_t* dcid, std::size_t dcidlen);

    // Send a Stateless Reset packet to |dest| for the given DCID.
    // Used when a Short Header packet arrives for an unknown connection.
    void send_stateless_reset(const uint8_t* dcid, std::size_t dcidlen,
                              const boost::asio::ip::udp::endpoint& dest);

    tp::vector<tp::string> m_pumping_conn;
};

#endif // _QUIC_SERVER_ENDPOINT_H_
