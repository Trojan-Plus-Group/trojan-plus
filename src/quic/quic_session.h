/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_SESSION_H_
#define _QUIC_SESSION_H_

#include <cstdint>
#include <memory>

#include "mem/memallocator.h"

class QuicConnection;

// Per-stream session on a QUIC connection. Mirrors ServerSession (parses a
// TrojanRequest, dials the upstream target, and splices bytes between the
// QUIC stream and a TCP socket). Phase 1 skeleton only.
class QuicProxySession : public std::enable_shared_from_this<QuicProxySession> {
  public:
    QuicProxySession(std::weak_ptr<QuicConnection> conn, int64_t stream_id);
    ~QuicProxySession();

    [[nodiscard]] int64_t stream_id() const { return m_stream_id; }

  private:
    std::weak_ptr<QuicConnection> m_conn;
    int64_t m_stream_id;
};

#endif // _QUIC_SESSION_H_
