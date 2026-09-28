#include "test_util.h"

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <limits>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// Load standard headers first so the assert replacement applies only to the code being tested.
#pragma push_macro("POS2_TEST_ASSERT_OVERRIDE")
#undef POS2_TEST_ASSERT_OVERRIDE
#define POS2_TEST_ASSERT_OVERRIDE 1
#pragma push_macro("assert")
#undef assert
#define assert(condition) TEST_ASSERT(condition)
#include "common/BitReader.hpp"
#include "common/Utils.hpp"
#pragma pop_macro("assert")
#pragma pop_macro("POS2_TEST_ASSERT_OVERRIDE")

namespace {

uint64_t low_mask(uint32_t const bit_count)
{
    return bit_count == 64 ? std::numeric_limits<uint64_t>::max() : (uint64_t(1) << bit_count) - 1;
}

uint64_t read_reference(
    std::span<uint64_t const> const fields, size_t const offset, uint32_t const bit_count)
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < bit_count; ++i) {
        size_t const bit = offset + i;
        value |= ((fields[bit / 64] >> (bit % 64)) & 1) << i;
    }
    return value;
}

void set_bit(std::span<uint64_t> const fields, size_t const bit)
{
    fields[bit / 64] |= uint64_t(1) << (bit % 64);
}

std::vector<uint64_t> writer_fields(BitWriter const& writer)
{
    std::vector<uint64_t> fields((writer.bitCount() + 63) / 64, 0);
    std::span<uint8_t const> const bytes = writer.asBytes();
    if (!bytes.empty()) {
        std::memcpy(fields.data(), bytes.data(), bytes.size());
    }
    return fields;
}

} // namespace

TEST_SUITE_BEGIN("bits");

TEST_CASE("reader-assertions")
{
    // Check invalid widths and lengths. Failed assertions must leave the reader in place.
    std::array<uint64_t, 1> fields { 0x0123456789abcdefULL };
    size_t const max_length = std::numeric_limits<size_t>::max();
    CHECK_THROWS_AS(BitReader(fields, max_length), AssertFailure);
    CHECK_THROWS_AS(BitReader(fields, max_length - 62), AssertFailure);
    CHECK_THROWS_AS(BitReader(fields, max_length - 63), std::runtime_error);

    BitReader reader(fields, 64);
    CHECK(reader.read_u64(7) == read_reference(fields, 0, 7));
    for (uint32_t width: { 0u, 65u, std::numeric_limits<uint32_t>::max() }) {
        CAPTURE(width);
        CHECK_THROWS_AS(reader.read_u64(width), AssertFailure);
    }
    CHECK(reader.read_u64(57) == read_reference(fields, 7, 57));
    CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
}

TEST_CASE("writer-assertions")
{
    // Reject invalid widths and values without changing bits that were already written.
    BitWriter writer;
    writer.append(0x55, 7);
    CHECK_THROWS_AS(writer.append(0, 65), AssertFailure);
    CHECK_THROWS_AS(writer.append(0, std::numeric_limits<uint32_t>::max()), AssertFailure);

    for (uint32_t width = 0; width < 64; ++width) {
        CAPTURE(width);
        CHECK_THROWS_AS(writer.append(uint64_t(1) << width, width), AssertFailure);
        CHECK_THROWS_AS(writer.append(low_mask(64), width), AssertFailure);
    }
    CHECK(writer.bitCount() == 7);
    REQUIRE(writer.asBytes().size() == 1);
    CHECK(writer.asBytes()[0] == 0x55);

    writer.append(0, 0);
    writer.append(low_mask(64), 64);
    CHECK(writer.bitCount() == 71);
    auto fields = writer_fields(writer);
    CHECK(read_reference(fields, 0, 7) == 0x55);
    CHECK(read_reference(fields, 7, 64) == low_mask(64));
}

TEST_CASE("reader-buffer-capacity")
{
    // Verify that BitReader accepts sufficient storage and rejects undersized buffers.
    std::array<uint64_t, 1> fields {};
    std::span<uint64_t> empty;

    CHECK_NOTHROW(BitReader(empty, 0));
    CHECK_NOTHROW(BitReader(fields, 0));
    CHECK_NOTHROW(BitReader(fields, 1));
    CHECK_NOTHROW(BitReader(fields, 64));

    CHECK_THROWS_AS(BitReader(empty, 1), std::runtime_error);
    CHECK_THROWS_AS(BitReader(fields, 65), std::runtime_error);
}

TEST_CASE("reader-width-and-offset")
{
    // Read every width from 1 to 64 bits at every possible offset within a field.
    std::array<uint64_t, 2> fields {
        0x0123456789abcdefULL,
        0xfedcba9876543210ULL,
    };

    for (size_t offset = 0; offset < 64; ++offset) {
        for (uint32_t bit_count = 1; bit_count <= 64; ++bit_count) {
            CAPTURE(offset);
            CAPTURE(bit_count);

            BitReader reader(fields, 128);
            if (offset != 0) {
                CHECK(reader.read_u64(static_cast<uint32_t>(offset))
                    == read_reference(fields, 0, static_cast<uint32_t>(offset)));
            }
            CHECK(reader.read_u64(bit_count) == read_reference(fields, offset, bit_count));
        }
    }
}

TEST_CASE("reader-one-bit-boundary")
{
    // Verify LSB-first single-bit reads before, at, and across a 64-bit boundary.
    std::array<uint64_t, 2> fields {
        uint64_t(1) << 63,
        1,
    };
    BitReader reader(fields, 65);

    for (int i = 0; i < 63; ++i) {
        CHECK(reader.read_one() == 0);
    }
    CHECK(reader.read_one() == 1);
    CHECK(reader.read_one() == 1);
    CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
}

TEST_CASE("reader-exact-buffer")
{
    // Read up to the end using only the one or two words needed to hold the input.
    auto check_read = [](auto& fields, uint32_t offset, uint32_t bit_count) {
        BitReader reader(fields, offset + bit_count);
        if (offset != 0) {
            CHECK(reader.read_u64(offset) == read_reference(fields, 0, offset));
        }
        CHECK(reader.read_u64(bit_count) == read_reference(fields, offset, bit_count));
        CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
        CHECK_THROWS_AS(reader.read_u64(1), std::runtime_error);
        CHECK_THROWS_AS(reader.read_unary_64(), std::runtime_error);

        BitReader single_bits(fields, offset + bit_count);
        for (uint32_t bit = 0; bit < offset + bit_count; ++bit) {
            CHECK(single_bits.read_one() == read_reference(fields, bit, 1));
        }
        CHECK_THROWS_AS(single_bits.read_one(), std::runtime_error);
    };

    for (uint32_t offset = 0; offset < 64; ++offset) {
        for (uint32_t bit_count = 1; bit_count <= 64; ++bit_count) {
            CAPTURE(offset);
            CAPTURE(bit_count);
            if (offset + bit_count <= 64) {
                std::array<uint64_t, 1> fields { 0x0123456789abcdefULL };
                check_read(fields, offset, bit_count);
            }
            else {
                std::array<uint64_t, 2> fields {
                    0x0123456789abcdefULL, 0xfedcba9876543210ULL
                };
                check_read(fields, offset, bit_count);
            }
        }
    }
}

TEST_CASE("reader-unary-exact-buffer")
{
    // Read a unary value from an exact-size buffer, then check that removing its zero makes it fail.
    auto check_read = [](auto& fields, uint32_t offset, uint32_t ones) {
        fields.fill(low_mask(64));
        size_t const terminator = offset + ones;
        fields[terminator / 64] &= ~(uint64_t(1) << (terminator % 64));
        BitReader valid(fields, terminator + 1);
        if (offset != 0) {
            CHECK(valid.read_u64(offset) == low_mask(offset));
        }
        CHECK(valid.read_unary_64() == ones);
        CHECK_THROWS_AS(valid.read_one(), std::runtime_error);
        CHECK_THROWS_AS(valid.read_unary_64(), std::runtime_error);

        set_bit(fields, terminator);
        BitReader invalid(fields, terminator + 1);
        if (offset != 0) {
            invalid.read_u64(offset);
        }
        CHECK_THROWS_AS(invalid.read_unary_64(), std::runtime_error);
        CHECK(invalid.read_u64(ones + 1) == low_mask(ones + 1));
        CHECK_THROWS_AS(invalid.read_one(), std::runtime_error);
    };

    for (uint32_t offset = 0; offset < 64; ++offset) {
        for (uint32_t ones = 0; ones < 64; ++ones) {
            CAPTURE(offset);
            CAPTURE(ones);
            if (offset + ones + 1 <= 64) {
                std::array<uint64_t, 1> fields {};
                check_read(fields, offset, ones);
            }
            else {
                std::array<uint64_t, 2> fields {};
                check_read(fields, offset, ones);
            }
        }
    }
}

TEST_CASE("reader-out-of-range")
{
    // Verify that out-of-range reads fail without consuming any input.
    std::array<uint64_t, 1> fields { 0b10101 };
    BitReader reader(fields, 5);

    CHECK_THROWS_AS(reader.read_u64(6), std::runtime_error);

    // A failed range check must not consume input.
    CHECK(reader.read_u64(5) == 0b10101);
    CHECK_THROWS_AS(reader.read_u64(1), std::runtime_error);
}

TEST_CASE("reader-unary-width-and-offset")
{
    // Read every valid unary length at every offset and verify the terminator is consumed.
    for (size_t offset = 0; offset < 64; ++offset) {
        for (uint64_t ones = 0; ones < 64; ++ones) {
            CAPTURE(offset);
            CAPTURE(ones);

            std::array<uint64_t, 2> fields {};
            for (size_t bit = offset; bit < offset + ones; ++bit) {
                set_bit(fields, bit);
            }
            // Leave the unary terminator clear and put a one immediately after it.
            set_bit(fields, offset + ones + 1);

            BitReader reader(fields, offset + ones + 2);
            if (offset != 0) {
                CHECK(reader.read_u64(static_cast<uint32_t>(offset)) == 0);
            }
            CHECK(reader.read_unary_64() == ones);
            CHECK(reader.read_one() == 1);
        }
    }
}

TEST_CASE("reader-empty")
{
    // Reject every read from an empty logical stream, even when backing storage exists.
    std::array<uint64_t, 1> fields { 0 };
    for (size_t capacity: { size_t(0), size_t(1) }) {
        CAPTURE(capacity);
        BitReader reader(std::span<uint64_t>(fields).first(capacity), 0);
        CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
        CHECK_THROWS_AS(reader.read_u64(1), std::runtime_error);
        CHECK_THROWS_AS(reader.read_u64(64), std::runtime_error);
        CHECK_THROWS_AS(reader.read_unary_64(), std::runtime_error);
    }
}

TEST_CASE("reader-partial-failure")
{
    // Preserve the cursor after failed reads at every offset, including across word boundaries.
    std::array<uint64_t, 2> fields { 0x0123456789abcdefULL, 0xfedcba9876543210ULL };
    for (uint32_t offset = 1; offset <= 64; ++offset) {
        CAPTURE(offset);
        BitReader reader(fields, offset + 7);
        CHECK(reader.read_u64(offset) == read_reference(fields, 0, offset));
        CHECK_THROWS_AS(reader.read_u64(8), std::runtime_error);
        CHECK_THROWS_AS(reader.read_u64(64), std::runtime_error);
        CHECK(reader.read_u64(7) == read_reference(fields, offset, 7));
        CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
    }
}

TEST_CASE("reader-unary-logical-end")
{
    // Accept a terminator at the last logical bit, but reject one just beyond the end.
    for (uint32_t offset = 0; offset < 64; ++offset) {
        for (uint32_t ones = 0; ones < 64; ++ones) {
            for (uint64_t padding: { uint64_t(0), low_mask(64) }) {
                CAPTURE(offset);
                CAPTURE(ones);
                CAPTURE(padding);
                std::array<uint64_t, 2> fields { padding, padding };
                for (size_t bit = offset; bit < offset + ones; ++bit) {
                    set_bit(fields, bit);
                }
                size_t const terminator = offset + ones;
                fields[terminator / 64] &= ~(uint64_t(1) << (terminator % 64));

                BitReader valid(fields, terminator + 1);
                BitReader truncated(fields, terminator);
                if (offset != 0) {
                    valid.read_u64(offset);
                    truncated.read_u64(offset);
                }
                CHECK(valid.read_unary_64() == ones);
                CHECK_THROWS_AS(valid.read_one(), std::runtime_error);
                CHECK_THROWS_AS(truncated.read_unary_64(), std::runtime_error);

                // A failed unary read must leave all the original input available.
                if (ones != 0) {
                    CHECK(truncated.read_u64(ones) == low_mask(ones));
                }
                CHECK_THROWS_AS(truncated.read_one(), std::runtime_error);
            }
        }
    }
}

TEST_CASE("reader-unary-padding")
{
    // Reject a missing terminator regardless of the bits outside the logical stream.
    for (uint32_t offset = 0; offset < 64; ++offset) {
        for (uint64_t padding: { uint64_t(0), low_mask(64) }) {
            CAPTURE(offset);
            CAPTURE(padding);
            std::array<uint64_t, 2> fields { padding, padding };
            for (size_t bit = offset; bit < offset + 63; ++bit) {
                set_bit(fields, bit);
            }
            BitReader reader(fields, offset + 63);
            if (offset != 0) {
                reader.read_u64(offset);
            }
            CHECK_THROWS_AS(reader.read_unary_64(), std::runtime_error);
            CHECK(reader.read_u64(63) == low_mask(63));
            CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
        }
    }
}

TEST_CASE("reader-overlong-unary-offset")
{
    // Reject 64 or more unary ones at every offset without advancing the cursor.
    for (uint32_t offset = 0; offset < 64; ++offset) {
        for (uint32_t ones: { 64u, 65u }) {
            CAPTURE(offset);
            CAPTURE(ones);
            std::array<uint64_t, 3> fields {};
            for (size_t bit = offset; bit < offset + ones; ++bit) {
                set_bit(fields, bit);
            }
            BitReader reader(fields, offset + ones + 1);
            if (offset != 0) {
                reader.read_u64(offset);
            }
            CHECK_THROWS_AS(reader.read_unary_64(), std::runtime_error);
            CHECK(reader.read_u64(64) == low_mask(64));
            if (ones == 65) {
                CHECK(reader.read_one() == 1);
            }
            CHECK(reader.read_one() == 0);
            CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
        }
    }
}

TEST_CASE("reader-invalid-unary")
{
    // Verify that empty, unterminated, and overlong unary values are rejected.
    std::array<uint64_t, 1> partial { 0b11111 };
    BitReader partial_reader(partial, 5);
    CHECK_THROWS_AS(partial_reader.read_unary_64(), std::runtime_error);

    std::array<uint64_t, 2> overlong {
        std::numeric_limits<uint64_t>::max(),
        0,
    };
    BitReader overlong_reader(overlong, 65);
    CHECK_THROWS_AS(overlong_reader.read_unary_64(), std::runtime_error);

    std::span<uint64_t> empty;
    BitReader empty_reader(empty, 0);
    CHECK_THROWS_AS(empty_reader.read_unary_64(), std::runtime_error);
}

TEST_CASE("writer-empty-and-clear")
{
    // Verify the initial state, zero-width writes, clearing, and reuse of BitWriter.
    BitWriter writer;
    CHECK(writer.bitCount() == 0);
    CHECK(writer.asBytes().empty());

    writer.append(0, 0);
    CHECK(writer.bitCount() == 0);
    CHECK(writer.asBytes().empty());

    writer.append(0xabc, 12);
    CHECK(writer.bitCount() == 12);
    CHECK(writer.asBytes().size() == 2);

    writer.clear();
    CHECK(writer.bitCount() == 0);
    CHECK(writer.asBytes().empty());

    writer.append(1, 1);
    CHECK(writer.bitCount() == 1);
    CHECK(writer.asBytes().size() == 1);
}

TEST_CASE("writer-width-and-offset")
{
    // Write every width at every offset and verify data, byte size, padding, and round trips.
    constexpr uint64_t pattern = 0xd6a59c3e781bf042ULL;

    for (uint32_t offset = 0; offset < 64; ++offset) {
        for (uint32_t bit_count = 1; bit_count <= 64; ++bit_count) {
            CAPTURE(offset);
            CAPTURE(bit_count);

            uint64_t const value = pattern & low_mask(bit_count);
            BitWriter writer;
            writer.append(0, offset);
            writer.append(value, bit_count);

            CHECK(writer.bitCount() == offset + bit_count);
            CHECK(writer.asBytes().size() == (offset + bit_count + 7) / 8);

            std::vector<uint64_t> fields = writer_fields(writer);
            if (offset != 0) {
                CHECK(read_reference(fields, 0, offset) == 0);
            }
            CHECK(read_reference(fields, offset, bit_count) == value);

            uint32_t const padding = (8 - ((offset + bit_count) % 8)) % 8;
            if (padding != 0) {
                CHECK(read_reference(fields, offset + bit_count, padding) == 0);
            }

            BitReader reader(fields, writer.bitCount());
            if (offset != 0) {
                CHECK(reader.read_u64(offset) == 0);
            }
            CHECK(reader.read_u64(bit_count) == value);
        }
    }
}

TEST_CASE("writer-sequential-values")
{
    // Verify that sequential values survive writes and reads across field boundaries.
    std::array<std::pair<uint64_t, uint32_t>, 8> const values { {
        { 1, 1 },
        { 0x2a, 6 },
        { 0x12345678, 32 },
        { 0x1ffffff, 25 },
        { std::numeric_limits<uint64_t>::max(), 64 },
        { 0, 1 },
        { 0x1ff, 9 },
        { 0x55, 7 },
    } };

    BitWriter writer;
    uint64_t expected_bits = 0;
    for (auto const& [value, bit_count]: values) {
        writer.append(value, bit_count);
        expected_bits += bit_count;
    }
    CHECK(writer.bitCount() == expected_bits);

    std::vector<uint64_t> fields = writer_fields(writer);
    BitReader reader(fields, writer.bitCount());
    for (auto const& [value, bit_count]: values) {
        CHECK(reader.read_u64(bit_count) == value);
    }
    CHECK_THROWS_AS(reader.read_one(), std::runtime_error);
}

TEST_CASE("writer-zero-width-offset")
{
    // Verify zero-width zero writes preserve existing bytes and subsequent writes at every offset.
    for (uint32_t offset = 0; offset <= 64; ++offset) {
        CAPTURE(offset);
        BitWriter writer;
        writer.append(low_mask(offset), offset);
        auto bytes = writer.asBytes();
        std::vector<uint8_t> const before(bytes.begin(), bytes.end());

        writer.append(0, 0);
        writer.append(0, 0);
        CHECK(writer.bitCount() == offset);
        bytes = writer.asBytes();
        CHECK(std::vector<uint8_t>(bytes.begin(), bytes.end()) == before);

        writer.append(0, 64);
        CHECK(writer.bitCount() == offset + 64);
        auto fields = writer_fields(writer);
        if (offset != 0) {
            CHECK(read_reference(fields, 0, offset) == low_mask(offset));
        }
        CHECK(read_reference(fields, offset, 64) == 0);
    }
}

TEST_CASE("writer-clear-multiple-fields")
{
    // Clear several all-one fields, then reuse storage without retaining any old bits.
    BitWriter writer;
    for (int i = 0; i < 4; ++i) {
        writer.append(low_mask(64), 64);
    }
    writer.clear();
    writer.clear();
    CHECK(writer.bitCount() == 0);
    CHECK(writer.asBytes().empty());

    writer.append(0, 3);
    CHECK(writer.bitCount() == 3);
    REQUIRE(writer.asBytes().size() == 1);
    CHECK(writer.asBytes()[0] == 0);

    writer.append(0, 64);
    CHECK(writer.bitCount() == 67);
    REQUIRE(writer.asBytes().size() == 9);
    for (uint8_t byte: writer.asBytes()) {
        CHECK(byte == 0);
    }
}

TEST_CASE("writer-little-endian-bytes")
{
    // Check the bytes written for a partial word and for values that cross into the next word.
    BitWriter writer;
    writer.append(7, 4);
    REQUIRE(writer.asBytes().size() == 1);
    CHECK(writer.asBytes()[0] == 0x07);

    writer.clear();
    writer.append(0xcdef, 16);
    writer.append(0x32100123456789abULL, 64);
    std::array<uint8_t, 10> const expected {
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32
    };
    CHECK(writer.bitCount() == 80);
    REQUIRE(writer.asBytes().size() == expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        CAPTURE(i);
        CHECK(writer.asBytes()[i] == expected[i]);
    }

    writer.append(0xabc, 12);
    CHECK(writer.bitCount() == 92);
    REQUIRE(writer.asBytes().size() == 12);
    for (size_t i = 0; i < expected.size(); ++i) {
        CHECK(writer.asBytes()[i] == expected[i]);
    }
    CHECK(writer.asBytes()[10] == 0xbc);
    CHECK(writer.asBytes()[11] == 0x0a);
}

TEST_SUITE_END();
