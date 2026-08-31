#pragma once
#include <stdint.h>
#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>
#if _WIN32
    #include <intrin.h>
#endif

struct Bits {
    inline static uint64_t count_trailing_ones(uint64_t const value, uint64_t const limit = 64) {
        uint64_t ones = 0;
        #if defined(_MSC_VER)
                unsigned long zero_bit_index = 0;
                ones = _BitScanForward64(&zero_bit_index, ~value)
                    ? static_cast<uint64_t>(zero_bit_index)
                    : 64;
        #elif defined(__GNUC__) || defined(__clang__)
                ones = ~value == 0 ? 64 : static_cast<uint64_t>(__builtin_ctzll(~value));
        #else
                while (ones < limit && ((value >> ones) & uint64_t(1)) != 0) {
                    ones += 1;
                }
        #endif
        return std::min(ones, limit);
    }

    inline static uint64_t count_leading_zeros(uint64_t const value) {
        #if defined(_MSC_VER)
                unsigned long one_bit_index = 0;
                return _BitScanReverse64(&one_bit_index, value)
                    ? 63 - static_cast<uint64_t>(one_bit_index)
                    : 64;
        #elif defined(__GNUC__) || defined(__clang__)
                return value == 0 ? 64 : static_cast<uint64_t>(__builtin_clzll(value));
        #else
                uint64_t zeroes = 0;
                while (zeroes < 64 && ((value >> (63 - zeroes)) & uint64_t(1)) == 0) {
                    zeroes += 1;
                }
                return zeroes;
        #endif
    }
};

class BitReader {
    // Returns:
    //  field_index:     Index of u64 field
    //  field_bit_index: Bit index inside the field (next bit to be read/written in that field)
    inline static std::pair<size_t, uint32_t> bit_field_index( size_t const bit_offset ) {
        size_t   field_index     = bit_offset >> 6;                  // Divide by 64
        uint32_t field_bit_index = uint32_t(bit_offset & 0b111111);  // Mask-off the upper 58 bits (mod 64)

        return { field_index, field_bit_index };
    }
    static constexpr uint64_t MASK_64 = 0xffffffffffffffff;

public:
    BitReader(std::span<uint64_t> fields, size_t bit_length)
        : fields_(fields)
        , bit_length_(bit_length)
    {
        assert(bit_length+63 >= bit_length);

        if( (bit_length+63) / 64 > fields.size() ) {
            throw std::runtime_error("Bit length is greater than the field capacity");
        }
    }

    inline uint64_t read_one() {
        if (pos_ >= bit_length_) {
            throw std::runtime_error("Bit read out of range");
        }

        auto [field_index, field_bit_index] = bit_field_index(pos_);
        pos_ ++;

        uint64_t const field = fields_[field_index];
        return (field >> field_bit_index) & 1;
    }

    inline uint64_t read_u64(uint32_t const bit_count) {
        assert(bit_count > 0);
        assert(bit_count <= 64);
        assert(pos_ + bit_count >= pos_);

        if (pos_ + bit_count > bit_length_) {
            throw std::runtime_error("Bit read out of range");
        }

        auto [field_index, field_bit_index] = bit_field_index(pos_);
        pos_ += bit_count;

        size_t bits_avail = 64 - field_bit_index;

        uint64_t value = fields_[field_index];
        value = value >> field_bit_index;

        if (bits_avail < bit_count) {
            value |= fields_[field_index + 1] << bits_avail;
        }

        value &= (MASK_64 >> (64 - bit_count));

        return value;
    }

    inline uint64_t read_unary_64() {
        // Read (max 64 bits) a unary-encoded field.
        // Meaning we read up to 64 bits until we find bit set to 0
        uint64_t value = 0;

        size_t read_pos = pos_;
        for (;;) {
            if (read_pos >= bit_length_) {
                throw std::runtime_error("Unary bit read out of bounds");
            }

            auto [field_index, field_bit_index] = bit_field_index(read_pos);

            uint64_t field = fields_[field_index] >> field_bit_index;

            uint64_t const n_ones = Bits::count_trailing_ones(field);
            value += n_ones;

            if (value >= 64) {
                throw std::runtime_error("No unary terminating zero found after reading 64 bits");
            }
            uint64_t const bits_remaining = bit_length_ - read_pos;
            uint64_t const max_ones_in_field = std::min(64 - (uint64_t)field_bit_index, bits_remaining);

            read_pos += int(n_ones);

            if (n_ones >= max_ones_in_field) {
                // Have not found a zero yet, all were ones
                continue;
            }

            pos_ = read_pos + 1;
            return value;
        }
    }

private:
    std::span<uint64_t> fields_ = {};
    size_t bit_length_ = 0;
    size_t pos_ = 0;            // Read position
};
