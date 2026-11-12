// Run: python3 tests/test_quic_udp_gso_queue.py
#include <cstdio>
#define TP_QUIC_GSO_TEST
#include "quic/quic_udp_gso.h"
#include <deque>
#include <vector>
#include <utility>
#include <memory>
#ifdef __linux__
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
static std::size_t allocations;
template <class T> struct CountingAllocator : std::allocator<T> {
    template <class U> struct rebind { using other = CountingAllocator<U>; };
    T* allocate(std::size_t n) { ++allocations; return std::allocator<T>::allocate(n); }
};
using Pool = quic_udp_gso::BufferPool<std::unique_ptr<uint8_t[]>>;
struct PooledPacket {
    Address dest;
    Pool::Buffer bytes;
    std::size_t segment;
    std::size_t offset{0};
};
static void test_pool(int tx, int rx, Address dest) {
    constexpr unsigned iterations = 10000;
    for (unsigned i = 0; i < iterations; ++i) {
        std::vector<uint8_t, CountingAllocator<uint8_t>> old(quic_udp_gso::buffer_size);
        old[0] = i;
    }
    const auto before = allocations;
    assert(before == iterations);
    Pool pool;
    auto allocate = [] { ++allocations; return std::unique_ptr<uint8_t[]>(new uint8_t[quic_udp_gso::buffer_size]); };
    const auto start = allocations;
    quic_udp_gso::Queue<std::deque<PooledPacket>> queue;
    for (unsigned i = 0; i < iterations; ++i) {
        auto buffer = pool.acquire(allocate);
        assert(buffer && buffer.size() == quic_udp_gso::buffer_size);
        buffer.data()[0] = i;
        buffer.resize(1);
        assert(queue.push(PooledPacket{dest, std::move(buffer), 1}));
        assert(queue.drain(tx) == 0);
        uint8_t received;
        assert(recvfrom(rx, &received, 1, 0, nullptr, nullptr) == 1);
        assert(received == static_cast<uint8_t>(i));
    }
    assert(allocations - start == 1);
    const auto warm = allocations;
    for (unsigned i = 0; i < iterations; ++i) {
        auto buffer = pool.acquire(allocate);
        assert(buffer);
    }
    assert(allocations == warm);
#if TROJAN_QUIC_STATS
    assert(pool.buffer_allocations == 1);
#endif
    std::printf("allocation-before-after calls=%u old=%zu new=%zu steady=%zu\n",
                iterations, before, warm - start, allocations - warm);
    queue.send_fault = [](bool) { return EAGAIN; };
    for (std::size_t i = 0; i < quic_udp_gso::queue_limit; ++i) {
        auto buffer = pool.acquire(allocate);
        buffer.data()[0] = i;
        buffer.data()[1] = i + 10;
        buffer.data()[2] = i + 20;
        buffer.resize(3);
        assert(queue.push(PooledPacket{dest, std::move(buffer), 2}));
        assert(!buffer); // Queue alone owns ciphertext.
    }
    assert(queue.full() && queue.drain(tx) == EAGAIN);
    {
        auto in_flight = pool.acquire(allocate);
        assert(in_flight);
        assert(!pool.acquire(allocate)); // Four pending plus one writer; no sixth allocation.
        auto moved = std::move(in_flight);
        assert(!in_flight && moved);
    }
    assert(allocations - start == quic_udp_gso::queue_limit + 1);
#if TROJAN_QUIC_STATS
    assert(pool.buffer_allocations == quic_udp_gso::queue_limit + 1);
#endif
    queue.send_fault = [](bool gso) { return gso ? EIO : 0; };
    assert(queue.drain(tx) == 0 && queue.disabled);
    for (std::size_t i = 0; i < quic_udp_gso::queue_limit; ++i) {
        uint8_t bytes[3];
        assert(recvfrom(rx, bytes, sizeof(bytes), 0, nullptr, nullptr) == 2);
        assert(bytes[0] == i && bytes[1] == i + 10);
        assert(recvfrom(rx, bytes, sizeof(bytes), 0, nullptr, nullptr) == 1);
        assert(bytes[0] == i + 20);
    }
    const auto peak = allocations;
    { auto empty_write = pool.acquire(allocate); } // ngtcp2 zero/error path.
    auto buffer = pool.acquire(allocate);
    buffer.resize(1);
    assert(queue.push(PooledPacket{dest, std::move(buffer), 1}));
    queue.pending.clear(); // Endpoint stop returns leases.
    std::array<Pool::Buffer, quic_udp_gso::queue_limit + 1> leases;
    for (auto& lease : leases) { lease = pool.acquire(allocate); assert(lease); }
    assert(!pool.acquire(allocate) && allocations == peak);
}
struct SendStep { bool gso; int error; };
static std::vector<SendStep> send_steps;
static std::size_t send_step;
static int scripted_fault(bool gso) {
    assert(send_step < send_steps.size());
    const auto step = send_steps[send_step++];
    assert(step.gso == gso);
    return step.error;
}
static void test_errors(int tx, int rx, Address dest) {
    using TestQueue = quic_udp_gso::Queue<std::deque<Packet>>;
    auto script = [](std::initializer_list<SendStep> steps) {
        send_steps = steps;
        send_step = 0;
    };
    auto receive = [&](std::initializer_list<uint8_t> expected) {
        uint8_t bytes[8];
        assert(recvfrom(rx, bytes, sizeof(bytes), MSG_DONTWAIT, nullptr, nullptr) ==
               static_cast<ssize_t>(expected.size()));
        assert(std::equal(expected.begin(), expected.end(), bytes));
    };
    auto empty = [&] {
        uint8_t byte;
        assert(recvfrom(rx, &byte, 1, MSG_DONTWAIT, nullptr, nullptr) == -1 && errno == EAGAIN);
    };
    for (int error : {EIO, EINVAL, EOPNOTSUPP, ENOPROTOOPT, ENOTSUP}) {
        TestQueue q;
        q.send_fault = scripted_fault;
        assert(q.push(Packet{dest, {1, 2, 3}, 2}));
        script({{true, error}, {false, 0}, {false, 0}});
        std::vector<int> errors;
        assert(q.drain(tx, [&](int e) { errors.push_back(e); }) == 0);
        assert(q.disabled && q.fallback_errno == error && q.pending.empty());
        assert(errors == std::vector<int>{error} && send_step == 3);
        receive({1, 2});
        receive({3});
        empty();
    }
    for (int error : {EAGAIN, EWOULDBLOCK, ENOBUFS}) {
        for (bool fallback : {false, true}) {
            TestQueue q;
            q.disabled = fallback;
            q.send_fault = scripted_fault;
            assert(q.push(Packet{dest, {1, 2, 3}, 2}));
            script({{!fallback, error}});
            unsigned warnings = 0;
            assert(q.drain(tx, [&](int) { ++warnings; }) == (error == ENOBUFS ? ENOBUFS : EAGAIN));
            assert(q.pending.size() == 1 && q.pending.front().offset == 0);
            assert(q.disabled == fallback && warnings == 0);
            q.disabled = true;
            script({{false, 0}, {false, 0}});
            assert(q.drain(tx) == 0);
            receive({1, 2});
            receive({3});
            empty();
        }
    }
    // EMSGSIZE splits only this entry, including across a transient retry.
    {
        TestQueue q;
        q.send_fault = scripted_fault;
        assert(q.push(Packet{dest, {1, 2, 3}, 2}));
        assert(q.push(Packet{dest, {4, 5, 6}, 2}));
        script({{true, EMSGSIZE}, {false, 0}, {false, ENOBUFS}});
        std::vector<int> errors;
        auto warn = [&](int e) { errors.push_back(e); };
        assert(q.drain(tx, warn) == ENOBUFS);
        assert(!q.disabled && q.pending.front().offset == 2);
        receive({1, 2});
        script({{false, 0}, {true, EAGAIN}});
        assert(q.drain(tx, warn) == EAGAIN);
        assert(!q.disabled && q.pending.size() == 1 && q.pending.front().offset == 0);
        assert(errors == std::vector<int>{EMSGSIZE});
        receive({3});
        q.disabled = true;
        script({{false, 0}, {false, 0}});
        assert(q.drain(tx) == 0);
        receive({4, 5});
        receive({6});
        empty();
    }
    // Endpoint restart must discard an EMSGSIZE split retained across EAGAIN.
    {
        TestQueue q;
        q.send_fault = scripted_fault;
        assert(q.push(Packet{dest, {1, 2, 3}, 2}));
        script({{true, EMSGSIZE}, {false, EAGAIN}});
        assert(q.drain(tx) == EAGAIN && send_step == 2);
        assert(!q.disabled && q.pending.front().offset == 0);
        q.clear();
        assert(q.pending.empty());
        assert(q.push(Packet{dest, {4, 5, 6}, 2}));
        script({{true, EAGAIN}});
        assert(q.drain(tx) == EAGAIN && send_step == 1);
        assert(!q.disabled && q.pending.front().offset == 0);
        empty();
    }
    // Non-capability errors drop only the failing aggregate or fallback datagram.
    for (int error : {ENETUNREACH, EHOSTUNREACH, EPERM, EACCES, ECONNREFUSED, EADDRNOTAVAIL, EAFNOSUPPORT, EMSGSIZE}) {
        for (bool fallback : {false, true}) {
            if (!fallback && error == EMSGSIZE) continue;
            TestQueue q;
            q.disabled = fallback;
            q.send_fault = scripted_fault;
            assert(q.push(Packet{dest, {1, 2, 3}, 2}));
            assert(q.push(Packet{dest, {4}, 2}));
            if (fallback) script({{false, error}, {false, 0}, {false, 0}});
            else script({{true, error}, {false, 0}});
            std::vector<int> errors;
            assert(q.drain(tx, [&](int e) { errors.push_back(e); }) == 0);
            assert(q.pending.empty() && q.disabled == fallback);
            assert(errors == std::vector<int>{error});
            if (fallback) receive({3});
            receive({4});
            empty();
        }
    }
    // Short sends never replay bytes; report EIO without disabling GSO.
    for (bool fallback : {false, true}) {
        TestQueue q;
        q.disabled = fallback;
        q.short_send = [](bool) { return true; };
        assert(q.push(Packet{dest, {1, 2, 3}, 2}));
        assert(q.push(Packet{dest, {4}, 2}));
        std::vector<int> errors;
        assert(q.drain(tx, [&](int e) { errors.push_back(e); }) == 0);
        assert(q.pending.empty() && q.disabled == fallback);
        assert(errors == std::vector<int>(fallback ? 3 : 2, EIO));
        empty();
    }
    {
        TestQueue q;
        q.send_fault = scripted_fault;
        assert(q.push(Packet{dest, {9}, 2}));
        script({{false, EINTR}, {false, 0}});
        assert(q.drain(tx, [](int) { assert(false); }) == 0);
        receive({9});
        empty();
    }
}
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
    assert(!keep_timer(1, 0));
    assert(!keep_timer(1, UINT64_MAX));
    assert(keep_timer(2'000'000, 1'999'999));
    assert(keep_timer(2'000'000, 1'000'000));
    assert(!keep_timer(2'000'000, 999'999));
    assert(!keep_timer(2'000'000, 2'000'000, 2'000'000));
    assert(!keep_timer(2'000'000, 3'000'000, 2'000'001));
    assert(!keep_timer(2'000'000, 1'999'999, 2'000'001));
    assert(keep_timer(2'000'000, 2'000'000));
    assert(keep_timer(2'000'000, 2'000'001));
    assert(keep_timer(2'000'000, 20'000'000));
    // Compare actual arm decisions, including earlier deadlines and fired reset.
    uint64_t armed = 0, baseline = 0;
    unsigned arms = 0, baseline_arms = 0;
    for (uint64_t deadline : {10'000'000ULL, 10'500'000ULL, 30'000'000ULL,
                              9'999'999ULL, 9'000'000ULL, 8'999'999ULL}) {
        if (baseline != deadline) { baseline = deadline; ++baseline_arms; }
        if (!keep_timer(armed, deadline)) { armed = deadline; ++arms; }
        assert(armed <= deadline || armed - deadline <= timer_tolerance_ns);
    }
    assert(arms == 2 && baseline_arms == 6);
    armed = 0; // Successful handler fired: next identical expiry must arm again.
    assert(!keep_timer(armed, 9'000'000));
#ifdef __linux__
    static_assert(aggregate_limit(0) == 0);
    static_assert(aggregate_limit(1) == 64);
    static_assert(aggregate_limit(1023) == 65472);
    static_assert(aggregate_limit(1024) == 65507);
    static_assert(aggregate_limit(1200) == 65507);
    static_assert(aggregate_limit(SIZE_MAX) == 65507);
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
    test_pool(tx, rx, dest);
    test_errors(tx, rx, dest);
    close(tx);
    close(rx);
#endif
}
