/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_CLOCK_H_
#define _QUIC_CLOCK_H_

#include <chrono>
#include <boost/asio/wait_traits.hpp>

#if defined(__linux__) || defined(__ANDROID__)
#include <cerrno>
#include <ctime>
#include <system_error>
#endif

// QUIC deadlines must include time spent suspended, without wall-clock jumps.
struct QuicClock {
    using duration = std::chrono::nanoseconds;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::time_point<QuicClock>;
    static constexpr bool is_steady = true;

    static time_point now() {
#if defined(__linux__) || defined(__ANDROID__)
        timespec ts{};
        if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
            // Never switch epochs after a clock failure.
            throw std::system_error(errno, std::generic_category(), "clock_gettime(CLOCK_BOOTTIME)");
        }
        return time_point(std::chrono::seconds(ts.tv_sec) + duration(ts.tv_nsec));
#else
        return time_point(std::chrono::duration_cast<duration>(
            std::chrono::steady_clock::now().time_since_epoch()));
#endif
    }
};

struct QuicWaitTraits : boost::asio::wait_traits<QuicClock> {
    static QuicClock::duration to_wait_duration(const QuicClock::duration& duration) {
#if defined(__linux__) || defined(__ANDROID__)
        // Asio's reactor waits use CLOCK_MONOTONIC, which excludes suspend.
        // Bound each wait so overdue BOOTTIME deadlines run within one second of resume.
        const auto limit = std::chrono::duration_cast<QuicClock::duration>(std::chrono::seconds(1));
        return duration > limit ? limit : duration;
#else
        return duration;
#endif
    }

    static QuicClock::duration to_wait_duration(const QuicClock::time_point& time) {
        return to_wait_duration(time - QuicClock::now());
    }
};

#endif // _QUIC_CLOCK_H_
