#ifndef QUIC_UDP_GSO_H
#define QUIC_UDP_GSO_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <utility>
#ifdef __linux__
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
// Older Android NDK headers omit this Linux UAPI socket option.
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#endif

namespace quic_udp_gso {
#ifdef __linux__
constexpr bool platform_supported() { return true; }
inline bool probe(std::intptr_t fd) {
    int segment = 0;
    socklen_t length = sizeof(segment);
    return getsockopt(static_cast<int>(fd), IPPROTO_UDP, UDP_SEGMENT, &segment, &length) == 0;
}
inline std::ptrdiff_t send_datagram(std::intptr_t fd, const void* dest, std::size_t destlen,
                                    const uint8_t* bytes, std::size_t length, std::size_t segment) {
    if (!segment)
        return sendto(static_cast<int>(fd), bytes, length, MSG_DONTWAIT,
                      static_cast<const sockaddr*>(dest), static_cast<socklen_t>(destlen));
    iovec iov{const_cast<uint8_t*>(bytes), length};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(uint16_t))]{};
    msghdr msg{};
    msg.msg_name = const_cast<void*>(dest);
    msg.msg_namelen = static_cast<socklen_t>(destlen);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    auto* c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = IPPROTO_UDP;
    c->cmsg_type = UDP_SEGMENT;
    c->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    const auto size = static_cast<uint16_t>(segment);
    std::memcpy(CMSG_DATA(c), &size, sizeof(size));
    return sendmsg(static_cast<int>(fd), &msg, MSG_DONTWAIT);
}
inline bool would_block(int error) { return error == EAGAIN || error == EWOULDBLOCK; }
inline bool no_buffers(int error) { return error == ENOBUFS; }
inline bool message_too_large(int error) { return error == EMSGSIZE; }
inline bool capability_error(int error) {
    return error == EIO || error == EINVAL || error == EOPNOTSUPP ||
           error == ENOPROTOOPT || error == ENOTSUP;
}
#else
constexpr bool platform_supported() { return false; }
inline bool probe(std::intptr_t) { return false; }
// Unused off Linux: endpoint uses its native asynchronous send path.
inline std::ptrdiff_t send_datagram(std::intptr_t, const void*, std::size_t,
                                    const uint8_t*, std::size_t, std::size_t) {
    errno = EINVAL;
    return -1;
}
inline bool would_block(int error) { return error == EAGAIN; }
inline bool no_buffers(int) { return false; }
inline bool message_too_large(int) { return false; }
inline bool capability_error(int) { return false; }
#endif
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
    int drain(std::intptr_t fd) { return drain(fd, [](int) {}); }
    template <class OnError> int drain(std::intptr_t fd, OnError on_error) {
        while (!pending.empty()) {
            auto& p = pending.front();
            const auto remaining = p.bytes.size() - p.offset;
            const bool gso = !disabled && !split && remaining > p.segment;
            const auto length = gso ? remaining : std::min(p.segment, remaining);
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
            if (gso) ++gso_attempts;
#endif
            std::ptrdiff_t n;
#ifdef TP_QUIC_GSO_TEST
            const int fault = send_fault ? send_fault(gso) : 0;
            if (fault) { errno = fault; n = -1; }
            else if (short_send && short_send(gso)) n = length - 1;
            else
#endif
            n = send_datagram(fd, p.dest.data(), p.dest.size(), p.bytes.data() + p.offset,
                              length, gso ? p.segment : 0);
            if (n < 0) {
                const int error = errno;
                if (error == EINTR) continue;
                if (would_block(error)) {
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
                    ++eagain_retries;
#endif
                    return EAGAIN;
                }
                if (no_buffers(error)) return error;
                on_error(error);
                if (gso && capability_error(error)) {
                    disabled = true;
                    fallback_errno = error;
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
                    ++fallback_activations;
#endif
                    continue; // Same bytes, same boundaries, same queue position.
                }
                if (gso && message_too_large(error)) {
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
} // namespace quic_udp_gso
#endif
