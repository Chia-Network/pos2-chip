#pragma once

#include <cstdint>
#include <limits>
#include <utility>
#include <bit>

namespace SafeFractionMath
{
    // Helper: bit length of uint64_t
    inline uint32_t bitlen_u64(uint64_t x)
    {
        // number of significant bits; 0 → 0
        if (x == 0)
            return 0;
        constexpr int W = std::numeric_limits<uint64_t>::digits; // 64
        return static_cast<uint32_t>(W - std::countl_zero(x));
    }

    // Helper: right shift with round-to-nearest
    inline uint64_t shr_round_u64(uint64_t x, uint32_t s)
    {
        if (s == 0)
            return x;
        if (s >= 64)
            return x ? 1u : 0u; // extreme shrink
        return (x + (1ull << (s - 1))) >> s;
    }

    // Safe multiply for rational pairs: (num/den) * (mul_num/mul_den)
    inline std::pair<uint64_t, uint64_t>
    mul_fraction_u64(std::pair<uint64_t, uint64_t> frac,
                     uint64_t mul_num, uint64_t mul_den)
    {
        uint64_t num = frac.first;
        uint64_t den = frac.second;

        // Handle edge cases
        if (den == 0)
            den = 1;
        if (mul_num == 0)
            return {0, 1};
        if (mul_den == 0)
            return {std::numeric_limits<uint64_t>::max(), 1};

        // Compute how many bits would overflow for numerator/denominator
        auto overflow_bits = [](uint64_t a, uint64_t b)
        {
            uint32_t na = bitlen_u64(a);
            uint32_t nb = bitlen_u64(b);
            return (na && nb && na + nb > 64) ? (na + nb - 64) : 0u;
        };

        uint32_t need_num = overflow_bits(num, mul_num);
        uint32_t need_den = overflow_bits(den, mul_den);
        uint32_t shift = (need_num > need_den) ? need_num : need_den;

        // Shrink both num and den equally
        if (shift)
        {
            num = shr_round_u64(num, shift);
            den = shr_round_u64(den, shift);
            if (den == 0)
                den = 1; // avoid zero denominator
        }

        num *= mul_num;
        den *= mul_den;

        return {num, den};
    }

    inline std::pair<uint64_t, uint64_t>
    invert_fraction_u64(std::pair<uint64_t, uint64_t> frac)
    {
        // avoid 0 denominator; treat 0/den as 0 → return 0/1 to keep it valid
        if (frac.first == 0)
            return {0, 1};
        if (frac.second == 0)
            return {std::numeric_limits<uint64_t>::max(), 1};
        return {frac.second, frac.first};
    }

    // Map fraction (num/den) in [0,1] → 32-bit integer with rounding
    inline uint32_t map_fraction_to_u32(std::pair<uint64_t, uint64_t> frac)
    {
        uint64_t num = frac.first;
        uint64_t den = frac.second;

        if (den == 0)
            return std::numeric_limits<uint32_t>::max(); // treat invalid as 1.0
        if (num >= den)
            return std::numeric_limits<uint32_t>::max(); // saturate at 1.0
        if (num == 0)
            return 0;

        // downscale to fit 64-bit safely
        // note we could use int128 here if available for more precision
        uint32_t nbits = 64u - static_cast<uint32_t>(std::countl_zero(den));
        uint32_t shift = (nbits > 32) ? (nbits - 32) : 0;
        num >>= shift;
        den >>= shift;
        if (den == 0)
            return 0xFFFFFFFFu;
        uint64_t scaled = ((num << 32) + (den >> 1)) / den;
        return static_cast<uint32_t>(scaled);
    }

} // namespace SafeFractionMath