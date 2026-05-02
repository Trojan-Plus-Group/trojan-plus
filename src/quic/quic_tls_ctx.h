/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_TLS_CTX_H_
#define _QUIC_TLS_CTX_H_

#include "core/config.h"
#include "mem/memallocator.h"

struct WOLFSSL_CTX;

class QuicTlsCtx {
  public:
    enum class Role { Server, Client };

    QuicTlsCtx(const Config& config, Role role);
    ~QuicTlsCtx();

    QuicTlsCtx(const QuicTlsCtx&)            = delete;
    QuicTlsCtx& operator=(const QuicTlsCtx&) = delete;

    [[nodiscard]] WOLFSSL_CTX* native_handle() const { return m_ctx; }
    [[nodiscard]] Role role() const { return m_role; }
    [[nodiscard]] const tp::string& alpn_token() const { return m_alpn_token; }

  private:
    WOLFSSL_CTX* m_ctx;
    Role m_role;
    tp::string m_alpn_token;
};

#endif // _QUIC_TLS_CTX_H_
