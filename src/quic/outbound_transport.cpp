/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "outbound_transport.h"

std::shared_ptr<OutboundTransport> create_outbound_transport(Service& /*service*/) {
    // Phase 1: not yet wired into ClientSession; returns nullptr by design so
    // callers continue to use the existing SSLSocket path.
    return nullptr;
}
