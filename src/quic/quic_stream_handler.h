/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef QUIC_STREAM_HANDLER_H
#define QUIC_STREAM_HANDLER_H

#include <cstdint>
#include <cstddef>

class QuicStreamHandler {
public:
    virtual ~QuicStreamHandler() = default;
    virtual void on_stream_data(const uint8_t* data, std::size_t len, bool fin) = 0;
    virtual void on_stream_close() = 0;
    virtual void on_connection_pump() {}
};

#endif // QUIC_STREAM_HANDLER_H
