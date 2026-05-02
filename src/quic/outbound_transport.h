/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _OUTBOUND_TRANSPORT_H_
#define _OUTBOUND_TRANSPORT_H_

#include <memory>

class Service;

// Phase 1 placeholder. Real abstraction will let ClientSession switch between
// SSLSocket and a QUIC bidi stream as its outbound transport, with automatic
// QUIC->TCP+TLS fallback when the QUIC handshake fails or the server is
// unreachable. See plan file Phase 1 for the full interface.
class OutboundTransport {
  public:
    virtual ~OutboundTransport() = default;

    [[nodiscard]] virtual bool is_via_quic() const { return false; }
};

// Factory hook to be implemented in a follow-up commit.
std::shared_ptr<OutboundTransport> create_outbound_transport(Service& service);

#endif // _OUTBOUND_TRANSPORT_H_
