#ifndef TP_QUIC_UDP_GSO_H
#define TP_QUIC_UDP_GSO_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#ifdef __linux__
#include <linux/udp.h>
#endif
#if defined(__linux__) && defined(UDP_SEGMENT)
#define TP_QUIC_UDP_GSO 1
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <utility>
#else
#define TP_QUIC_UDP_GSO 0
#endif

namespace quic_udp_gso {
constexpr std::size_t buffer_size = 65536;
constexpr std::size_t queue_limit = 4;
constexpr uint64_t timer_tolerance_ns = 1'000'000;
// Later deadlines within 1 ms are equivalent; farther later deadlines also keep
// the already armed earlier wakeup. Earlier requests always rearm, even within 1 ms.
constexpr bool keep_timer(uint64_t armed, uint64_t requested) {
    return armed != 0 && armed != UINT64_MAX && requested >= armed;
}
#if TP_QUIC_UDP_GSO
// Container uses tp allocations in production; tests use std containers.
// All entries own ciphertext, including after EAGAIN and permanent GSO fallback.
template <class Container> class Queue {
  public:
    Container pending;
    bool disabled{false};
    int fallback_errno{0};
#if TROJAN_QUIC_STATS
    uint64_t gso_attempts{0};
    uint64_t gso_successes{0};
    uint64_t gso_datagrams{0};
    uint64_t gso_bytes{0};
    uint64_t fallback_activations{0};
    uint64_t eagain_retries{0};
    uint64_t fallback_datagrams{0};
#endif
#ifdef TP_QUIC_GSO_TEST
    int (*send_fault)(bool gso){nullptr};
#endif
    bool full() const { return pending.size() >= queue_limit; }
    template <class Packet> bool push(Packet&& packet) {
        if (full() || packet.bytes.empty() || packet.bytes.size() > buffer_size ||
            !packet.segment || packet.segment > UINT16_MAX) return false;
        pending.push_back(std::move(packet));
        return true;
    }
    // 0: drained, EAGAIN: keep bytes and wait for writability, other errno: stop endpoint.
    int drain(int fd) {
        while (!pending.empty()) {
            auto& p = pending.front();
            const auto remaining = p.bytes.size() - p.offset;
            const bool gso = !disabled && remaining > p.segment;
            const auto length = gso ? remaining : std::min(p.segment, remaining);
            iovec iov{p.bytes.data() + p.offset, length};
            alignas(cmsghdr) char control[CMSG_SPACE(sizeof(uint16_t))]{};
            msghdr msg{};
            msg.msg_name = p.dest.data();
            msg.msg_namelen = p.dest.size();
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            if (gso) {
                msg.msg_control = control;
                msg.msg_controllen = sizeof(control);
                auto* c = CMSG_FIRSTHDR(&msg);
                c->cmsg_level = IPPROTO_UDP;
                c->cmsg_type = UDP_SEGMENT;
                c->cmsg_len = CMSG_LEN(sizeof(uint16_t));
                const auto segment = static_cast<uint16_t>(p.segment);
                std::memcpy(CMSG_DATA(c), &segment, sizeof(segment));
            }
#if TROJAN_QUIC_STATS
            if (gso) ++gso_attempts;
#endif
            ssize_t n;
#ifdef TP_QUIC_GSO_TEST
            const int fault = send_fault ? send_fault(gso) : 0;
            if (fault) { errno = fault; n = -1; }
            else
#endif
            n = gso ? sendmsg(fd, &msg, MSG_DONTWAIT)
                    : sendto(fd, p.bytes.data() + p.offset, length, MSG_DONTWAIT,
                             reinterpret_cast<const sockaddr*>(p.dest.data()), p.dest.size());
            if (n < 0) {
                const int error = errno;
                if (error == EINTR) continue;
                if (error == EAGAIN || error == EWOULDBLOCK) {
#if TROJAN_QUIC_STATS
                    ++eagain_retries;
#endif
                    return EAGAIN;
                }
                if (gso) {
                    disabled = true;
                    fallback_errno = error;
#if TROJAN_QUIC_STATS
                    ++fallback_activations;
#endif
                    continue; // Same bytes, same boundaries, same queue position.
                }
                return error;
            }
            // Datagram sends are atomic. Never replay a successful prefix.
            if (static_cast<std::size_t>(n) != length) return EIO;
#if TROJAN_QUIC_STATS
            if (gso) {
                ++gso_successes;
                gso_datagrams += (length + p.segment - 1) / p.segment;
                gso_bytes += length;
            } else if (disabled) {
                ++fallback_datagrams;
            }
#endif
            p.offset += static_cast<std::size_t>(n);
            if (p.offset == p.bytes.size()) pending.pop_front();
        }
        return 0;
    }
};
#endif
} // namespace quic_udp_gso
#endif
