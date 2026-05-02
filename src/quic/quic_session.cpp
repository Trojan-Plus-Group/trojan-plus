/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_session.h"

QuicProxySession::QuicProxySession(std::weak_ptr<QuicConnection> conn, int64_t stream_id)
    : m_conn(std::move(conn)), m_stream_id(stream_id) {}

QuicProxySession::~QuicProxySession() = default;
