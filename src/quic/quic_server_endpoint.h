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

#include "quic_endpoint.h"

class QuicServerEndpoint : public QuicEndpoint {
  public:
    QuicServerEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                       std::shared_ptr<QuicTlsCtx> tls_ctx);

    void start() override;

  protected:
    void on_packet(const uint8_t* data, std::size_t len,
                   const boost::asio::ip::udp::endpoint& src) override;
};

#endif // _QUIC_SERVER_ENDPOINT_H_
