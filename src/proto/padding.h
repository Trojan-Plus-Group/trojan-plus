#pragma once

#include "mem/memallocator.h"
#include <openssl/rand.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace s2 {

// Wire format: type:u8, payload_length:u16 (big endian), payload.
// END has no payload; everything after END is unframed application data.
inline constexpr unsigned char DATA = 0;
inline constexpr unsigned char PAD = 1;
inline constexpr unsigned char END = 2;
inline constexpr std::size_t max_frame_length = 1447; // 1450-byte flush minus 3-byte header.
inline constexpr std::size_t default_budget = 16384; // Real DATA bytes, not padding or headers.

struct EncodeResult {
    bool success = false;
    tp::vector<tp::string> flushes;
};

struct DecodeResult {
    bool success = false;
    tp::string data;
};

class Encoder {
    std::size_t remaining_;
    bool ended_ = false;
    bool failed_ = false;
    bool started_ = false;

    // Rejection sampling avoids modulo bias, including non-power-of-two ranges.
    static bool uniform(std::uint32_t count, std::uint32_t& result) {
        const std::uint32_t threshold = (std::uint32_t{0} - count) % count;
        std::uint32_t value;
        do {
            if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
                return false;
            }
        } while (value < threshold);
        result = value % count;
        return true;
    }

    static void header(tp::string& out, unsigned char type, std::size_t length) {
        out.push_back(static_cast<char>(type));
        out.push_back(static_cast<char>(length >> 8));
        out.push_back(static_cast<char>(length & 255));
    }

public:
    explicit Encoder(std::size_t budget = default_budget) : remaining_(budget) {}
    bool ended() const { return ended_; }
    bool failed() const { return failed_; }
    std::size_t remaining() const { return remaining_; }

    // Each padded flush is uniformly 900..1450 bytes: packed DATA split at a
    // random boundary, then one random PAD, then END if budget is exhausted.
    // Empty-input END and subsequent raw flushes are exempt from size bounds.
    // Empty input without a prefix explicitly ends padding, including on the first call.
    // RNG failure is terminal: no partial flushes returned; caller must close.
    // Prefix is allowed only on the first call, at most 887 bytes so even a
    // 900-byte flush can hold split DATA, PAD and END. It is not framed DATA.
    // A prefix-only call pads the header without ending a nonzero budget.
    EncodeResult encode(std::string_view data, std::string_view first_flush_prefix = {}) {
        EncodeResult result;
        if (failed_) {
            return result;
        }
        if (!first_flush_prefix.empty() && (started_ || first_flush_prefix.size() > 887)) {
            failed_ = true;
            return result;
        }
        started_ = true;
        while (!ended_ && ((!data.empty() && remaining_) || !first_flush_prefix.empty())) {
            std::uint32_t choice;
            if (!uniform(551, choice)) {
                failed_ = true;
                return {};
            }
            const std::size_t total = 900 + choice;
            // Reserve two DATA headers, one PAD header and END. Pack a fixed
            // amount of real data so random splits cannot create a long tail.
            const auto real = std::min({data.size(), remaining_, total - first_flush_prefix.size() - 12});
            if (real && !uniform(static_cast<std::uint32_t>(real), choice)) {
                failed_ = true;
                return {};
            }
            const std::size_t first = real ? 1 + choice : 0;
            const bool finish = real == remaining_;
            tp::string flush;
            flush.reserve(total);
            if (!first_flush_prefix.empty()) {
                flush.append(first_flush_prefix.data(), first_flush_prefix.size());
            }
            first_flush_prefix = {};
            if (real) {
                header(flush, DATA, first);
                flush.append(data.data(), first);
                if (first < real) {
                    header(flush, DATA, real - first);
                    flush.append(data.data() + first, real - first);
                }
            }
            const std::size_t padding = total - flush.size() - 3 - (finish ? 3 : 0);
            header(flush, PAD, padding);
            const auto offset = flush.size();
            flush.resize(offset + padding);
            if (padding && RAND_bytes(reinterpret_cast<unsigned char*>(flush.data() + offset), padding) != 1) {
                failed_ = true;
                return {};
            }
            if (finish) {
                header(flush, END, 0);
                ended_ = true;
            }
            result.flushes.push_back(std::move(flush));
            data.remove_prefix(real);
            remaining_ -= real;
        }
        // A nonempty call that did not exhaust budget leaves framing active.
        // An empty call is also an explicit finish operation.
        if (!ended_ && (!remaining_ || result.flushes.empty())) {
            tp::string end;
            header(end, END, 0);
            result.flushes.push_back(std::move(end));
            ended_ = true;
        }
        if (!data.empty()) {
            result.flushes.emplace_back(data.data(), data.size());
        }
        result.success = true;
        return result;
    }
};

class Decoder {
    tp::string pending_; // At most one frame: 3 + 1447 bytes, independent of input size.
    bool ended_ = false;
    bool failed_ = false;
    bool saw_data_ = false;

public:
    bool ended() const { return ended_; }
    bool failed() const { return failed_; }
    // True once real bytes were accepted, from nonempty DATA or raw after END.
    // Caller retains original wire bytes if pre-data protocol fallback is needed.
    bool saw_data() const { return saw_data_; }
    // EOF before END is truncation, even at a frame boundary.
    bool complete() const { return !failed_ && ended_; }

    // Partial headers/payloads succeed with no output until their frame completes.
    // Malformed input permanently fails and discards this call's decoded output.
    DecodeResult decode(std::string_view input) {
        DecodeResult result;
        if (failed_) {
            return result;
        }
        while (!input.empty()) {
            if (ended_) {
                result.data.append(input.data(), input.size());
                saw_data_ = true;
                break;
            }
            if (pending_.size() < 3) {
                const auto n = std::min(3 - pending_.size(), input.size());
                pending_.append(input.data(), n);
                input.remove_prefix(n);
                if (pending_.size() < 3) {
                    break;
                }
            }
            const auto type = static_cast<unsigned char>(pending_[0]);
            const std::size_t length = (static_cast<unsigned char>(pending_[1]) << 8) |
                                      static_cast<unsigned char>(pending_[2]);
            if (type > END || length > max_frame_length || (type == END && length != 0)) {
                failed_ = true;
                pending_.clear();
                return {};
            }
            const auto n = std::min(3 + length - pending_.size(), input.size());
            pending_.append(input.data(), n);
            input.remove_prefix(n);
            if (pending_.size() < 3 + length) {
                break;
            }
            if (type == DATA) {
                saw_data_ = saw_data_ || length != 0;
                result.data.append(pending_.data() + 3, length);
            } else if (type == END) {
                ended_ = true;
            }
            pending_.clear();
        }
        result.success = true;
        return result;
    }
};

} // namespace s2
