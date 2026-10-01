#include "test_util.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <span>
#include <stdexcept>
#include <vector>

#include "common/Utils.hpp"
#include "common/BitReader.hpp"
#include "pos/ProofCore.hpp"
#include "pos/sha/sha256.hpp"
#include "fse.h"

// Load dependencies first so the assert replacement applies only to ChunkCompression.hpp.
#pragma push_macro("assert")
#undef assert
#define assert(condition) TEST_ASSERT(condition)
#include "plot/ChunkCompression.hpp"
#pragma pop_macro("assert")

namespace {

// Find the largest integer whose square is at most n, using binary search.
// Calling gsz_isqrt_u64 here would make the tests compare that function with itself.
uint64_t reference_sqrt(uint64_t n)
{
    uint64_t low = 0;
    uint64_t high = uint64_t(1) << 32;
    while (low + 1 < high) {
        uint64_t const middle = low + (high - low) / 2;
        if (middle <= n / middle) {
            low = middle;
        }
        else {
            high = middle;
        }
    }
    return low;
}

// Calculate the expected remainder width k without calling any gsz_* functions.
// If there's a bug in those functions, it must not also change the value the tests expect.
uint32_t reference_k(uint64_t group_size)
{
    uint64_t const median = std::max(uint64_t(1), reference_sqrt(357 * group_size));
    uint32_t k = 0;
    while (median * median >= (uint64_t(1) << (2 * k + 1))) {
        ++k;
    }
    return k;
}

// Build expected bits without BitWriter so that if there's a bug in it,
// the same bug won't affect the expected result.
struct ReferenceBits {
    std::vector<uint64_t> fields;
    size_t bit_count = 0;

    // Append the lowest width bits, starting with the least significant bit.
    // Tests use this to build prefixes, suffixes, and deliberately incomplete input.
    void append(uint64_t value, uint32_t width)
    {
        for (uint32_t bit = 0; bit < width; ++bit) {
            if (bit_count % 64 == 0) {
                fields.push_back(0);
            }
            fields.back() |= ((value >> bit) & 1) << (bit_count % 64);
            ++bit_count;
        }
    }

    // Write the sign, k remainder bits, and a run of quotient ones ending in zero.
    // This lets tests check the encoder and decoder without using either to produce the expected bits.
    void delta(int64_t value, uint32_t k)
    {
        uint64_t const magnitude = value < 0 ? uint64_t(-(value + 1)) + 1 : uint64_t(value);
        uint64_t const divisor = uint64_t(1) << k;
        append(value < 0, 1);
        append(magnitude % divisor, k);
        for (uint64_t i = 0; i < magnitude / divisor; ++i) {
            append(1, 1);
        }
        append(0, 1);
    }
};

// Compare the writer's bit count and bytes, including padding, with the expected sequence.
// A round trip alone could miss a mistake shared by the encoder and decoder.
void check_encoding(BitWriter const& writer, ReferenceBits const& expected)
{
    REQUIRE(writer.bitCount() == expected.bit_count);
    auto const bytes = writer.asBytes();
    REQUIRE(bytes.size() == (expected.bit_count + 7) / 8);
    for (size_t i = 0; i < bytes.size(); ++i) {
        CAPTURE(i);
        CHECK(bytes[i] == uint8_t(expected.fields[i / 8] >> (8 * (i % 8))));
    }
}

// Choose the encoder variant that omits the remainder when k is zero.
// This lets each test loop cover both variants with the same checks.
void encode_delta(int64_t delta, uint32_t k, BitWriter& writer)
{
    if (k == 0) {
        gsz_encode_delta<false>(delta, 0, 0, writer);
    }
    else {
        gsz_encode_delta<true>(delta, k, (uint64_t(1) << k) - 1, writer);
    }
}

// Choose the decoder variant that omits the remainder when k is zero.
// This lets each test loop cover both variants with the same checks.
int64_t decode_delta(uint32_t k, BitReader& reader)
{
    return k == 0 ? gsz_decode_delta<false>(0, reader) : gsz_decode_delta<true>(k, reader);
}

// Find the largest absolute delta that fits so tests can check the limit and the next value.
// The sign, k remainder bits, and terminating zero leave room for 62 - k unary ones.
uint64_t max_magnitude(uint32_t k)
{
    return ((uint64_t(63) - k) << k) - 1;
}

} // namespace

TEST_SUITE_BEGIN("gsz");

TEST_CASE("gsz-isqrt-small-values")
{
    // Check every small input, including zero and values between consecutive squares.
    for (uint64_t n = 0; n <= 4096; ++n) {
        CAPTURE(n);
        CHECK(gsz_isqrt_u64(n) == reference_sqrt(n));
    }
}

TEST_CASE("gsz-isqrt-square-boundaries")
{
    // Check exact squares and their neighbors up to the largest 64-bit square.
    std::vector<uint64_t> roots { 1, 2, 3, std::numeric_limits<uint32_t>::max() };
    for (unsigned bit = 1; bit < 32; ++bit) {
        uint64_t const root = uint64_t(1) << bit;
        roots.insert(roots.end(), { root - 1, root, root + 1 });
    }
    for (uint64_t root: roots) {
        CAPTURE(root);
        uint64_t const square = root * root;
        CHECK(gsz_isqrt_u64(square - 1) == root - 1);
        CHECK(gsz_isqrt_u64(square) == root);
        CHECK(gsz_isqrt_u64(square + 1) == root);
    }
    CHECK(gsz_isqrt_u64(std::numeric_limits<uint64_t>::max())
        == std::numeric_limits<uint32_t>::max());
}

TEST_CASE("gsz-isqrt-full-range")
{
    // Compare deterministic samples across the full 64-bit range with a binary search.
    std::mt19937_64 random(0x5a17);
    for (int i = 0; i < 4096; ++i) {
        uint64_t const n = random();
        CAPTURE(n);
        CHECK(gsz_isqrt_u64(n) == reference_sqrt(n));
    }
}

TEST_CASE("gsz-floor-log2-boundaries")
{
    // Check every power of two and both ends of each interval with the same logarithm.
    for (int bit = 0; bit < 64; ++bit) {
        CAPTURE(bit);
        uint64_t const power = uint64_t(1) << bit;
        CHECK(gsz_floor_log2_u64(power) == bit);
        CHECK(gsz_floor_log2_u64(power | (power - 1)) == bit);
        if (bit > 0) {
            CHECK(gsz_floor_log2_u64(power - 1) == bit - 1);
        }
    }
}

TEST_CASE("gsz-round-log2-boundaries")
{
    // Check both sides of every rounding threshold without using floating-point arithmetic.
    CHECK(gsz_round_log2_u64(0) == 0);
    CHECK(gsz_round_log2_u64(1) == 0);
    for (int bit = 0; bit < 32; ++bit) {
        CAPTURE(bit);
        uint64_t const threshold = reference_sqrt(uint64_t(1) << (2 * bit + 1)) + 1;
        CHECK(gsz_round_log2_u64(uint64_t(1) << bit) == bit);
        CHECK(gsz_round_log2_u64(threshold - 1) == bit);
        CHECK(gsz_round_log2_u64(threshold) == bit + 1);
    }
    CHECK(gsz_round_log2_u64(std::numeric_limits<uint32_t>::max()) == 32);
    CHECK_THROWS_AS(gsz_round_log2_u64(uint64_t(1) << 32), std::runtime_error);
    CHECK_THROWS_AS(gsz_round_log2_u64((uint64_t(1) << 32) + 1), std::runtime_error);
    CHECK_THROWS_AS(gsz_round_log2_u64(std::numeric_limits<uint64_t>::max()), std::runtime_error);
}

TEST_CASE("gsz-group-parameters")
{
    // Check every on-disk group size, plus zero and the documented 32-bit arithmetic limit.
    for (uint64_t group = 0; group <= std::numeric_limits<uint16_t>::max(); ++group) {
        CAPTURE(group);
        CHECK(gsz_rice_k_for_g(group) == int(reference_k(group)));
        CHECK(gsz_expected_for_g(group) == (group * 60301) / 256);
    }
    uint64_t const largest = std::numeric_limits<uint32_t>::max();
    CHECK(gsz_rice_k_for_g(largest) == int(reference_k(largest)));
    CHECK(gsz_expected_for_g(largest) == (largest * 60301) / 256);
    CHECK(gsz_rice_k_for_g(1) == 4);
    CHECK(gsz_expected_for_g(1) == 235);
    CHECK(gsz_rice_k_for_g(65535) == 12);
}

TEST_CASE("gsz-delta-known-bits")
{
    // Check literal encodings for zero, both signs, and a zero-width remainder.
    struct Example { uint32_t k; int64_t delta; uint64_t field; size_t width; };
    std::array<Example, 7> const examples {{
        { 0, 0, 0x00, 2 }, { 0, 3, 0x0e, 5 }, { 0, -3, 0x0f, 5 },
        { 2, 5, 0x0a, 5 }, { 2, -5, 0x0b, 5 },
        { 4, 17, 0x22, 7 }, { 4, -17, 0x23, 7 },
    }};
    for (auto const& example: examples) {
        CAPTURE(example.k);
        CAPTURE(example.delta);
        BitWriter writer;
        encode_delta(example.delta, example.k, writer);
        CHECK(writer.bitCount() == example.width);
        REQUIRE(writer.asBytes().size() == 1);
        CHECK(writer.asBytes()[0] == example.field);
        std::array<uint64_t, 1> fields { example.field };
        BitReader reader(fields, example.width);
        CHECK(decode_delta(example.k, reader) == example.delta);
        CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
    }
}

TEST_CASE("gsz-delta-width-and-offset")
{
    // Check signs and remainder boundaries at every bit offset, including 64-bit encodings.
    for (uint32_t k = 0; k <= 62; ++k) {
        uint64_t const mask = (uint64_t(1) << k) - 1;
        std::vector<int64_t> magnitudes { 0, 1, int64_t(mask), int64_t(max_magnitude(k)) };
        if (k < 62) {
            magnitudes.push_back(int64_t(uint64_t(1) << k));
        }
        std::sort(magnitudes.begin(), magnitudes.end());
        magnitudes.erase(std::unique(magnitudes.begin(), magnitudes.end()), magnitudes.end());
        for (uint32_t offset = 0; offset < 64; ++offset) {
            for (int64_t magnitude: magnitudes) {
                for (int sign: { 1, -1 }) {
                    int64_t const delta = sign * magnitude;
                    CAPTURE(k);
                    CAPTURE(offset);
                    CAPTURE(delta);
                    uint64_t const prefix = (uint64_t(1) << offset) - 1;
                    ReferenceBits expected;
                    expected.append(prefix, offset);
                    expected.delta(delta, k);
                    expected.append(0x2d, 6);

                    BitWriter writer;
                    writer.append(prefix, offset);
                    encode_delta(delta, k, writer);
                    writer.append(0x2d, 6);
                    check_encoding(writer, expected);

                    BitReader reader(expected.fields, expected.bit_count);
                    if (offset != 0) {
                        CHECK(reader.read_u64(offset) == prefix);
                    }
                    CHECK(decode_delta(k, reader) == delta);
                    CHECK(reader.read_u64(6) == 0x2d);
                    CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
                }
            }
        }
    }
}

TEST_CASE("gsz-delta-encoding-assertions")
{
    // Reject oversized deltas, including signed integer limits, without writing any bits.
    for (uint32_t k = 0; k <= 63; ++k) {
        int64_t const too_large = k == 63 ? 0 : int64_t(max_magnitude(k) + 1);
        for (int64_t delta: { too_large, -too_large,
                 std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max() }) {
            CAPTURE(k);
            CAPTURE(delta);
            BitWriter writer;
            writer.append(5, 3);
            CHECK_THROWS_AS(encode_delta(delta, k, writer), AssertFailure);
            CHECK(writer.bitCount() == 3);
            REQUIRE(writer.asBytes().size() == 1);
            CHECK(writer.asBytes()[0] == 5);
        }
    }
}

TEST_CASE("gsz-delta-truncated")
{
    // Cut a valid delta at every bit, including within its sign, remainder, and unary field.
    for (uint32_t k: { 0u, 1u, 4u, 12u, 31u, 62u }) {
        for (uint32_t offset: { 0u, 1u, 63u, 64u }) {
            ReferenceBits encoded;
            encoded.append(0, offset);
            encoded.delta(-int64_t(max_magnitude(k)), k);
            for (size_t length = offset; length < encoded.bit_count; ++length) {
                CAPTURE(k);
                CAPTURE(offset);
                CAPTURE(length);
                auto fields = encoded.fields;
                fields.resize((length + 63) / 64);
                BitReader reader(fields, length);
                if (offset != 0) {
                    CHECK(reader.read_u64(offset) == 0);
                }
                CHECK_THROWS_AS(decode_delta(k, reader), std::runtime_error);
            }
        }
    }
}

TEST_CASE("gsz-delta-unary-too-long")
{
    // Reject 64 unary ones even when a terminating zero follows them in the buffer.
    for (uint32_t k: { 0u, 4u, 12u }) {
        ReferenceBits encoded;
        encoded.append(0, 1 + k);
        encoded.append(std::numeric_limits<uint64_t>::max(), 64);
        encoded.append(0, 1);
        BitReader reader(encoded.fields, encoded.bit_count);
        CHECK_THROWS_AS(decode_delta(k, reader), std::runtime_error);
    }
}

TEST_CASE("gsz-sizes-round-trip")
{
    // Check mixed size sequences, repeated calls, and preserved bits before and after the index.
    std::mt19937_64 random(0x67537a);
    for (uint64_t group: { 0u, 1u, 2u, 16u, 255u, 256u, 257u, 4096u, 32768u, 65535u }) {
        uint32_t const k = reference_k(group);
        uint64_t const expected_size = group * 60301 / 256;
        uint64_t const magnitude = max_magnitude(k);
        uint64_t const smallest = expected_size > magnitude ? expected_size - magnitude : 1;
        uint64_t const largest = expected_size + magnitude;
        std::vector<uint64_t> sizes { smallest, largest, std::max(uint64_t(1), expected_size),
            expected_size + 1, expected_size + 1 };
        for (int i = 0; i < 128; ++i) {
            sizes.push_back(smallest + random() % (largest - smallest + 1));
        }
        for (uint32_t offset: { 0u, 1u, 7u, 31u, 63u }) {
            CAPTURE(group);
            CAPTURE(offset);
            uint64_t const prefix = (uint64_t(1) << offset) - 1;
            ReferenceBits expected;
            expected.append(prefix, offset);
            for (uint64_t size: sizes) {
                expected.delta(int64_t(size) - int64_t(expected_size), k);
            }
            expected.append(0x2d, 6);

            BitWriter writer;
            writer.append(prefix, offset);
            auto const input = std::span<uint64_t const>(sizes);
            size_t const split = sizes.size() / 2;
            gsz_encode(input.first(split), group, writer);
            gsz_encode(input.subspan(split), group, writer);
            writer.append(0x2d, 6);
            check_encoding(writer, expected);

            std::vector<uint64_t> fields((writer.bitCount() + 63) / 64, 0);
            auto const bytes = writer.asBytes();
            std::memcpy(fields.data(), bytes.data(), bytes.size());
            BitReader reader(fields, writer.bitCount());
            if (offset != 0) {
                CHECK(reader.read_u64(offset) == prefix);
            }
            std::vector<uint64_t> decoded(sizes.size());
            auto output = std::span<uint64_t>(decoded);
            gsz_decode(output.first(split), group, reader);
            gsz_decode(output.subspan(split), group, reader);
            CHECK(decoded == sizes);
            CHECK(reader.read_u64(6) == 0x2d);
            CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
        }
    }
}

TEST_CASE("gsz-sizes-empty")
{
    // Empty spans must not append output or consume input, including when the reader is empty.
    for (uint64_t group: { 0u, 1u, 65535u }) {
        BitWriter writer;
        gsz_encode({}, group, writer);
        CHECK(writer.bitCount() == 0);
        CHECK(writer.asBytes().empty());
        writer.append(0x55, 7);
        gsz_encode({}, group, writer);
        CHECK(writer.bitCount() == 7);
        REQUIRE(writer.asBytes().size() == 1);
        CHECK(writer.asBytes()[0] == 0x55);

        BitReader empty({}, 0);
        CHECK_NOTHROW(gsz_decode({}, group, empty));
        std::array<uint64_t, 1> fields { 0x55 };
        BitReader reader(fields, 7);
        gsz_decode({}, group, reader);
        CHECK(reader.read_u64(7) == 0x55);
    }
}

TEST_CASE("gsz-sizes-truncated")
{
    // Reject an index cut at any bit, even when earlier sizes were decoded successfully.
    for (uint64_t group: { 0u, 1u, 65535u }) {
        uint32_t const k = reference_k(group);
        ReferenceBits encoded;
        encoded.delta(1, k);
        encoded.delta(2, k);
        encoded.delta(int64_t(max_magnitude(k)), k);
        for (size_t length = 0; length < encoded.bit_count; ++length) {
            CAPTURE(group);
            CAPTURE(length);
            auto fields = encoded.fields;
            fields.resize((length + 63) / 64);
            BitReader reader(fields, length);
            std::array<uint64_t, 3> sizes {};
            CHECK_THROWS_AS(gsz_decode(sizes, group, reader), std::runtime_error);
        }
    }
}

TEST_CASE("gsz-sizes-nonpositive")
{
    // Reject decoded sizes of zero or less after a valid first entry.
    for (uint64_t group: { 0u, 1u, 2u }) {
        for (int64_t invalid_size: { 0, -1 }) {
            CAPTURE(group);
            CAPTURE(invalid_size);
            uint32_t const k = reference_k(group);
            ReferenceBits encoded;
            encoded.delta(1, k);
            encoded.delta(invalid_size - int64_t(group * 60301 / 256), k);
            BitReader reader(encoded.fields, encoded.bit_count);
            std::array<uint64_t, 2> sizes {};
            CHECK_THROWS_WITH_AS(gsz_decode(sizes, group, reader),
                "Invalid delta " + std::to_string(invalid_size) + " at index 1", std::runtime_error);
        }
    }
}

TEST_CASE("gsz-sizes-encoding-assertion")
{
    // Reject a positive size whose delta is too large for one encoded field.
    for (uint64_t group: { 0u, 1u, 65535u }) {
        uint64_t const size = group * 60301 / 256 + max_magnitude(reference_k(group)) + 1;
        std::array<uint64_t, 1> sizes { size };
        BitWriter writer;
        CHECK_THROWS_AS(gsz_encode(sizes, group, writer), AssertFailure);
        CHECK(writer.bitCount() == 0);
        CHECK(writer.asBytes().empty());
    }
}

TEST_SUITE_END();
