// Run: python3 tests/test_quic_udp_gso_queue.py
#include <cstdio>
#define TP_QUIC_GSO_TEST
#include "quic/quic_udp_gso.h"
#include <deque>
#include <vector>
#include <utility>
#if TP_QUIC_UDP_GSO
#include <netinet/in.h>
#include <unistd.h>

struct Address {
    sockaddr_in value{};
    sockaddr* data() { return reinterpret_cast<sockaddr*>(&value); }
    std::size_t size() const { return sizeof(value); }
};
struct Packet {
    Address dest;
    std::vector<uint8_t> bytes;
    std::size_t segment;
    std::size_t offset{0};
};
static int calls;
static int fault(bool gso) {
    if (!gso) return 0;
    ++calls;
    return calls == 1 ? EAGAIN : EIO;
}
#endif
int main() {
    using namespace quic_udp_gso;
    static_assert(timer_tolerance_ns == 1'000'000);
    assert(!keep_timer(0, 1));
    assert(!keep_timer(UINT64_MAX, 1));
    assert(!keep_timer(2'000'000, 1'999'999));
    assert(!keep_timer(2'000'000, 1'000'000));
    assert(keep_timer(2'000'000, 2'000'000));
    assert(keep_timer(2'000'000, 2'000'001));
    assert(keep_timer(2'000'000, 20'000'000));
    // Compare actual arm decisions, including earlier deadlines and fired reset.
    uint64_t armed = 0, baseline = 0;
    unsigned arms = 0, baseline_arms = 0;
    for (uint64_t deadline : {10'000'000ULL, 10'500'000ULL, 30'000'000ULL,
                              9'999'999ULL, 9'000'000ULL}) {
        if (baseline != deadline) { baseline = deadline; ++baseline_arms; }
        if (!keep_timer(armed, deadline)) { armed = deadline; ++arms; }
        assert(armed <= deadline);
    }
    assert(arms == 3 && baseline_arms == 5);
    armed = 0; // Successful handler fired: next identical expiry must arm again.
    assert(!keep_timer(armed, 9'000'000));
#if TP_QUIC_UDP_GSO
    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    assert(rx >= 0 && tx >= 0);
    Address dest;
    dest.value.sin_family = AF_INET;
    dest.value.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(rx, dest.data(), dest.size()) == 0);
    socklen_t addrlen = dest.size();
    assert(getsockname(rx, dest.data(), &addrlen) == 0);
    timeval timeout{1, 0};
    assert(setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    Queue<std::deque<Packet>> queue;
    queue.send_fault = fault;
    std::vector<std::vector<uint8_t>> expected;
    for (std::size_t i = 0; i < queue_limit; ++i) {
        const std::size_t segment = 100 + i * 37;
        std::vector<uint8_t> bytes(segment * 2 + 17);
        for (std::size_t j = 0; j < bytes.size(); ++j) bytes[j] = (i * 71 + j) % 256;
        for (std::size_t offset = 0; offset < bytes.size(); offset += segment)
            expected.emplace_back(bytes.begin() + offset, bytes.begin() + std::min(offset + segment, bytes.size()));
        assert(queue.push(Packet{dest, std::move(bytes), segment}));
        if (i == 0) {
            assert(queue.drain(tx) == EAGAIN);
            assert(queue.pending.size() == 1 && queue.pending.front().offset == 0);
            assert(!queue.disabled);
        }
    }
    assert(queue.full());
    assert(!queue.push(Packet{dest, {99}, 1}));
    assert(queue.pending.size() == queue_limit);
    assert(queue.drain(tx) == 0);
    assert(queue.disabled && queue.fallback_errno == EIO && calls == 2);
    assert(queue.pending.empty());
#if TROJAN_QUIC_STATS
    assert(queue.eagain_retries == 1 && queue.fallback_activations == 1);
    assert(queue.fallback_datagrams == expected.size());
#endif
    for (const auto& bytes : expected) {
        uint8_t buffer[1024];
        auto n = recvfrom(rx, buffer, sizeof(buffer), 0, nullptr, nullptr);
        assert(n == static_cast<ssize_t>(bytes.size()));
        assert(std::equal(bytes.begin(), bytes.end(), buffer));
    }
    uint8_t extra;
    assert(recvfrom(rx, &extra, 1, MSG_DONTWAIT, nullptr, nullptr) == -1 && errno == EAGAIN);
    // Once disabled, later aggregates must not attempt GSO again.
    assert(queue.push(Packet{dest, {1, 2, 3}, 2}));
    assert(queue.drain(tx) == 0 && calls == 2);
    uint8_t buffer[3];
    assert(recvfrom(rx, buffer, sizeof(buffer), 0, nullptr, nullptr) == 2);
    assert(buffer[0] == 1 && buffer[1] == 2);
    assert(recvfrom(rx, buffer, sizeof(buffer), 0, nullptr, nullptr) == 1 && buffer[0] == 3);
    assert(!queue.push(Packet{dest, std::vector<uint8_t>(buffer_size + 1), 1200}));
    // Genuine no-fault production queue path. Kernel may reject UDP_SEGMENT;
    // identical ciphertext must still arrive through permanent fallback.
    Queue<std::deque<Packet>> real_queue;
    std::vector<uint8_t> real_bytes(2 * 1200 + 73);
    for (std::size_t i = 0; i < real_bytes.size(); ++i) real_bytes[i] = i % 251;
    assert(real_queue.push(Packet{dest, real_bytes, 1200}));
    assert(real_queue.drain(tx) == 0 && real_queue.pending.empty());
    for (std::size_t offset = 0; offset < real_bytes.size(); offset += 1200) {
        uint8_t received[1500];
        const auto length = std::min<std::size_t>(1200, real_bytes.size() - offset);
        assert(recvfrom(rx, received, sizeof(received), 0, nullptr, nullptr) == static_cast<ssize_t>(length));
        assert(std::equal(real_bytes.begin() + offset, real_bytes.begin() + offset + length, received));
    }
#if TROJAN_QUIC_STATS
    assert(real_queue.gso_attempts == 1);
    if (real_queue.disabled) {
        std::puts("SKIP native UDP_SEGMENT: kernel rejected it; ordered fallback passed");
    } else {
        assert(real_queue.gso_successes == 1 && real_queue.gso_datagrams == 3);
        assert(real_queue.gso_bytes == real_bytes.size());
    }
#endif
    close(tx);
    close(rx);
#endif
}
