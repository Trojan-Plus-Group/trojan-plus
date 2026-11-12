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
#include <array>
#else
#define TP_QUIC_UDP_GSO 0
#endif

namespace quic_udp_gso {
constexpr std::size_t buffer_size = 65536;
constexpr std::size_t queue_limit = 4;
constexpr uint64_t timer_tolerance_ns = 1'000'000;
// Shared ngtcp2 expiry covers loss/PTO, delayed ACK, pacing and idle.
// Tolerance delays loss/PTO detection, delayed-ACK sending and pacing wakeup by at most 1 ms.
// Expired wakeups must rearm, even if their handler has not run yet.
constexpr bool keep_timer(uint64_t armed, uint64_t requested, uint64_t now = 0) {
    return armed != 0 && armed != UINT64_MAX && requested != 0 && requested != UINT64_MAX && armed > now &&
           (requested >= armed || armed - requested <= timer_tolerance_ns);
}
#if TP_QUIC_UDP_GSO
constexpr std::size_t aggregate_limit(std::size_t segment) {
    return segment > 65507 / 64 ? 65507 : 64 * segment;
}
// Endpoint owns four queued buffers plus one in-flight writer. Storage is lazy,
// uninitialized, and retained until endpoint destruction; leases never copy bytes.
template <class Storage> class BufferPool {
    struct Slot {
        Storage storage;
        bool used{false};
    };
    std::array<Slot, queue_limit + 1> slots;

  public:
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
    uint64_t buffer_allocations{0};
#endif
    class Buffer {
        Slot* slot{nullptr};
        std::size_t length{0};
        friend class BufferPool;
        explicit Buffer(Slot& value) : slot(&value), length(buffer_size) { slot->used = true; }
        void release() { if (slot) slot->used = false; }

      public:
        Buffer() = default;
        ~Buffer() { release(); }
        Buffer(const Buffer&) = delete;
        Buffer& operator=(const Buffer&) = delete;
        Buffer(Buffer&& other) noexcept : slot(std::exchange(other.slot, nullptr)), length(other.length) {}
        Buffer& operator=(Buffer&& other) noexcept {
            if (this != &other) {
                release();
                slot = std::exchange(other.slot, nullptr);
                length = other.length;
            }
            return *this;
        }
        explicit operator bool() const { return slot != nullptr; }
        uint8_t* data() { return slot ? slot->storage.get() : nullptr; }
        std::size_t size() const { return slot ? length : 0; }
        bool empty() const { return size() == 0; }
        void resize(std::size_t size) { assert(slot && size <= buffer_size); length = size; }
    };
    template <class Allocate> Buffer acquire(Allocate allocate) {
        for (auto& slot : slots) {
            if (slot.used) continue;
            if (!slot.storage) {
                slot.storage = allocate();
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
                ++buffer_allocations;
#endif
            }
            return Buffer(slot);
        }
        return {};
    }
};

// Container uses tp allocations in production; tests use std containers.
// All entries own ciphertext, including after EAGAIN and permanent GSO fallback.
template <class Container> class Queue {
    bool split{false}; // EMSGSIZE applies only to the current aggregate, across retries.

  public:
    Container pending;
    bool disabled{false};
    int fallback_errno{0};
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
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
    bool (*short_send)(bool gso){nullptr};
#endif
    void clear() { pending.clear(); split = false; }
    bool full() const { return pending.size() >= queue_limit; }
    template <class Packet> bool push(Packet&& packet) {
        if (full() || packet.bytes.empty() || packet.bytes.size() > buffer_size ||
            !packet.segment || packet.segment > UINT16_MAX) return false;
        pending.push_back(std::move(packet));
        return true;
    }
    // Errors are reported on every occurrence; endpoint may suppress duplicate warnings.
    // 0: drained; EAGAIN/ENOBUFS: keep bytes and retry later.
    int drain(int fd) { return drain(fd, [](int) {}); }
    template <class OnError> int drain(int fd, OnError on_error) {
        while (!pending.empty()) {
            auto& p = pending.front();
            const auto remaining = p.bytes.size() - p.offset;
            const bool gso = !disabled && !split && remaining > p.segment;
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
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
            if (gso) ++gso_attempts;
#endif
            ssize_t n;
#ifdef TP_QUIC_GSO_TEST
            const int fault = send_fault ? send_fault(gso) : 0;
            if (fault) { errno = fault; n = -1; }
            else if (short_send && short_send(gso)) n = length - 1;
            else
#endif
            n = gso ? sendmsg(fd, &msg, MSG_DONTWAIT)
                    : sendto(fd, p.bytes.data() + p.offset, length, MSG_DONTWAIT,
                             reinterpret_cast<const sockaddr*>(p.dest.data()), p.dest.size());
            if (n < 0) {
                const int error = errno;
                if (error == EINTR) continue;
                if (error == EAGAIN || error == EWOULDBLOCK) {
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
                    ++eagain_retries;
#endif
                    return EAGAIN;
                }
                if (error == ENOBUFS) return ENOBUFS;
                on_error(error);
                if (gso && (error == EIO || error == EINVAL || error == EOPNOTSUPP ||
                            error == ENOPROTOOPT || error == ENOTSUP)) {
                    disabled = true;
                    fallback_errno = error;
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
                    ++fallback_activations;
#endif
                    continue; // Same bytes, same boundaries, same queue position.
                }
                if (gso && error == EMSGSIZE) {
                    split = true;
                    continue;
                }
            } else if (static_cast<std::size_t>(n) != length) {
                // Datagram sends are atomic. Never replay a successful prefix.
                on_error(EIO);
            } else {
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
                if (gso) {
                    ++gso_successes;
                    gso_datagrams += (length + p.segment - 1) / p.segment;
                    gso_bytes += length;
                } else if (disabled || split) {
                    ++fallback_datagrams;
                }
#endif
            }
            // Success or permanent error: consume this aggregate/datagram and continue.
            p.offset += length;
            if (p.offset == p.bytes.size()) {
                pending.pop_front();
                split = false;
            }
        }
        return 0;
    }
};
#endif
} // namespace quic_udp_gso
#endif
