#!/usr/bin/env python3
"""Compile production S2 codec/allocator; deterministic RAND_bytes tests, no network.

Uses BoringSSL's real declaration and an injectable link-time RNG stub to cover
rejection sampling and RNG failure. Does not build or modify any submodule.
All generated files and compiler/runtime output stay in /home/hermes/work/logs/s2.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOGS = Path("/home/hermes/work/logs/s2")
PROGRAM = r'''
#include "proto/padding.h"
#include <cassert>
#include <cstring>
#include <deque>
#include <limits>

static std::deque<uint32_t> draws;
static uint32_t seed = 0x12345678;
static bool fail_rng = false;
static int fail_after = -1;
static unsigned calls = 0;

extern "C" int RAND_bytes(uint8_t* out, size_t size) {
    ++calls;
    if (fail_rng || fail_after == 0) return 0;
    if (fail_after > 0) --fail_after;
    if (size == 4 && !draws.empty()) {
        const auto value = draws.front();
        draws.pop_front();
        std::memcpy(out, &value, 4);
        return 1;
    }
    for (size_t i = 0; i < size; ++i) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        out[i] = static_cast<uint8_t>(seed);
    }
    return 1;
}

static std::string_view view(const tp::string& value) {
    return {value.data(), value.size()};
}
static tp::string frame(unsigned type, size_t length, char byte = 'x') {
    tp::string wire;
    wire.push_back(static_cast<char>(type));
    wire.push_back(static_cast<char>(length >> 8));
    wire.push_back(static_cast<char>(length & 255));
    wire.append(length, byte);
    return wire;
}
static size_t length_at(const tp::string& wire, size_t pos) {
    return (static_cast<unsigned char>(wire[pos + 1]) << 8) |
           static_cast<unsigned char>(wire[pos + 2]);
}
static tp::string join(const s2::EncodeResult& result) {
    assert(result.success);
    tp::string wire;
    for (const auto& flush : result.flushes) wire += flush;
    return wire;
}
static void roundtrip(size_t budget, size_t size, size_t step) {
    tp::string source;
    for (size_t i = 0; i < size; ++i) source.push_back(static_cast<char>(i));
    s2::Encoder encoder(budget);
    tp::string wire;
    for (size_t i = 0; i < size;) {
        const auto n = std::min(step, size - i);
        bool raw = encoder.ended();
        auto encoded = encoder.encode({source.data() + i, n});
        assert(encoded.success);
        for (const auto& flush : encoded.flushes) {
            if (raw) continue;
            if (flush == frame(s2::END, 0)) {
                raw = true;
                continue;
            }
            assert(flush.size() >= 900 && flush.size() <= 1450);
            size_t pos = 0, real = 0, data_frames = 0;
            while (pos < flush.size() && flush[pos] == s2::DATA) {
                const auto length = length_at(flush, pos);
                assert(length > 0 && length <= s2::max_frame_length);
                real += length;
                ++data_frames;
                pos += 3 + length;
            }
            assert(data_frames >= 1 && data_frames <= 2);
            assert(real > 0 && real <= flush.size() - 12);
            assert(flush[pos] == s2::PAD);
            pos += 3 + length_at(flush, pos);
            if (pos < flush.size()) {
                assert(flush.substr(pos) == frame(s2::END, 0));
                raw = true;
                pos += 3;
            }
            assert(pos == flush.size());
        }
        wire += join(encoded);
        i += n;
    }
    wire += join(encoder.encode({}));
    assert(encoder.ended());
    s2::Decoder decoder;
    tp::string decoded;
    for (size_t i = 0; i < wire.size();) {
        const auto n = std::min(step, wire.size() - i);
        const auto result = decoder.decode({wire.data() + i, n});
        assert(result.success);
        decoded += result.data;
        i += n;
    }
    assert(decoded == source);
    assert(decoder.complete() && !decoder.failed());
    assert(decoder.saw_data() == (budget != 0 && size != 0));
    const auto raw = encoder.encode("raw\0tail"sv);
    const auto result = decoder.decode(view(join(raw)));
    assert(result.success && result.data == tp::string("raw\0tail", 8));
}

int main() {
    using namespace std::literals;
    // Exact endpoint sizes and explicit rejection of biased low draws.
    for (uint32_t total : {900u, 1450u}) {
        s2::Encoder encoder(1);
        draws = {0, 551 + total - 900, 1};
        const auto before = calls;
        const auto encoded = encoder.encode("ab");
        assert(encoded.success && draws.empty() && calls == before + 4);
        assert(encoded.flushes.size() == 2);
        const auto& padded = encoded.flushes[0];
        assert(padded.size() == total && padded[0] == s2::DATA);
        assert(length_at(padded, 0) == 1 && padded[3] == 'a');
        assert(padded[4] == s2::PAD && length_at(padded, 4) == total - 10);
        assert(padded.substr(total - 3) == frame(s2::END, 0));
        assert(encoded.flushes[1] == "b" && encoder.remaining() == 0);
    }
    for (size_t budget : {0u, 1u, 899u, 8192u, 65536u}) {
        for (size_t size : {0u, 1u, 100u, 20000u}) {
            for (size_t step : {1u, 2u, 3u, 997u, 65536u}) roundtrip(budget, size, step);
        }
    }
    // Packing guarantees progress regardless of random split: at least 888
    // real bytes per full flush, without a geometric tail near budget exhaustion.
    s2::Encoder packed(16384);
    const auto packed_result = packed.encode(tp::string(20000, 'p'));
    assert(packed_result.success && packed.ended());
    assert(packed_result.flushes.size() <= (16384 + 887) / 888 + 1);
    s2::Decoder packed_decoder;
    const auto packed_decoded = packed_decoder.decode(view(join(packed_result)));
    assert(packed_decoded.success && packed_decoder.complete());
    assert(packed_decoded.data == tp::string(20000, 'p'));
    s2::Encoder empty;
    assert(join(empty.encode({})) == frame(s2::END, 0));
    assert(join(empty.encode("raw")) == "raw");
    s2::Encoder zero(0);
    assert(join(zero.encode("raw")) == frame(s2::END, 0) + "raw");

    // Multiple frames in one input, full 1447-byte DATA and PAD, raw after END.
    const auto valid = frame(s2::PAD, 1447) + frame(s2::DATA, 1447, 'd') +
                       frame(s2::DATA, 0) + frame(s2::END, 0) + "raw";
    for (size_t split = 0; split <= valid.size(); ++split) {
        s2::Decoder decoder;
        auto a = decoder.decode({valid.data(), split});
        auto b = decoder.decode({valid.data() + split, valid.size() - split});
        assert(a.success && b.success && decoder.complete() && decoder.saw_data());
        assert(a.data + b.data == tp::string(1447, 'd') + "raw");
    }
    for (const auto& bad : {frame(3, 0), frame(255, 0), frame(s2::END, 1),
                            frame(s2::DATA, 1448), frame(s2::PAD, 65535)}) {
        for (size_t step : {1u, 65536u}) {
            s2::Decoder decoder;
            for (size_t i = 0; i < bad.size() && !decoder.failed();) {
                const auto n = std::min(step, bad.size() - i);
                auto result = decoder.decode({bad.data() + i, n});
                assert(result.success == !decoder.failed());
                assert(result.data.empty());
                i += n;
            }
            assert(decoder.failed() && !decoder.complete() && !decoder.saw_data());
            assert(!decoder.decode(view(frame(s2::END, 0))).success);
        }
    }
    s2::Decoder transactional;
    assert(!transactional.decode(view(frame(s2::DATA, 1) + frame(7, 0))).success);
    assert(transactional.saw_data()); // Never allow fallback after accepted DATA.
    s2::Decoder truncated;
    assert(truncated.decode(view(frame(s2::DATA, 3))).success);
    assert(truncated.saw_data() && !truncated.complete());
    s2::Decoder partial;
    assert(partial.decode("\0\0\3x"sv).success);
    assert(!partial.saw_data() && !partial.complete());
    assert(partial.decode("yz"sv).data == "xyz");
    assert(partial.saw_data());

    // Failure on size selection, split selection, PAD fill, or a later flush.
    for (int after : {0, 1, 2, 3}) {
        s2::Encoder encoder(10000);
        fail_after = after;
        const auto result = encoder.encode(tp::string(20000, 'x'));
        assert(!result.success && result.flushes.empty() && encoder.failed());
        fail_after = -1;
        assert(!encoder.encode("retry").success);
    }
    fail_rng = true;
    s2::Encoder no_rng(0);
    assert(join(no_rng.encode("raw")) == frame(s2::END, 0) + "raw");
    s2::Encoder empty_no_rng;
    assert(join(empty_no_rng.encode({})) == frame(s2::END, 0));
}
'''.replace('static void roundtrip(', 'using namespace std::literals;\nstatic void roundtrip(')


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="codec-", dir=LOGS))
    source = run / "codec.cpp"
    binary = run / "codec"
    source.write_text(PROGRAM)
    command = shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-pthread",
        "-I", str(ROOT / "src"), "-I", str(ROOT / "boringssl/include"),
        str(source), str(ROOT / "src/mem/memallocator.cpp"), "-o", str(binary),
    ]
    with (run / "output.log").open("w") as log:
        log.write(shlex.join(command) + "\n")
        log.flush()
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        subprocess.run([str(binary)], check=True, stdout=log, stderr=subprocess.STDOUT)
        log.write("S2 codec checks passed\n")


if __name__ == "__main__":
    main()
