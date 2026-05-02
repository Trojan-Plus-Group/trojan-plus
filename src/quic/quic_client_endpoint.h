/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_CLIENT_ENDPOINT_H_
#define _QUIC_CLIENT_ENDPOINT_H_

#include "quic_endpoint.h"

class QuicClientEndpoint : public QuicEndpoint {
  public:
    QuicClientEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                       std::shared_ptr<QuicTlsCtx> tls_ctx);

    void start() override;

    [[nodiscard]] bool is_known_unreachable() const { return m_known_unreachable; }
    void mark_unreachable() { m_known_unreachable = true; }

  protected:
    void on_packet(const uint8_t* data, std::size_t len,
                   const boost::asio::ip::udp::endpoint& src) override;

  private:
    bool m_known_unreachable;
};

#endif // _QUIC_CLIENT_ENDPOINT_H_
