#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <bit>

#if defined(_MSC_VER)
    #include <stdlib.h>
#endif

#include "sha/sha256.hpp"

class FeistelCipher {
public:
    static constexpr uint32_t K_BASE = 28;
    static constexpr uint32_t ROUNDS = 4;
    static constexpr const char ROUND_KEY_SALT[] = "ChiaPos2Fesitel";
    static_assert(sizeof(ROUND_KEY_SALT) == 16);

    struct RoundKey {
        uint32_t b, c, d;
    };

    struct FullRoundKey {
        RoundKey round[ROUNDS];
    };

    uint32_t k_;                // Half the block size (block is 2*k bits)
    FullRoundKey round_key_;    // Pre-extracted key for each round

    // Constructor.
    //   plot_id: Pointer to a 32-byte key.
    //   k: Half of the total bit length. Must be at most 28.
    FeistelCipher(uint8_t const* plot_id, uint32_t k)
        : k_(k)
    {
        static_assert(ROUNDS == 4);
        static_assert(K_BASE == 28);
        static_assert(K_BASE*3 <= 256);

        // Because we've settled on max k == 28, we've adapted this to be based
        // on that value. Key extraction assumes a fixed k or 28.
        // Lower k's simply get truncated after extraction.
        if (k_ > K_BASE)
            throw std::invalid_argument("k cannot be greater than " + std::to_string(K_BASE));

        if (k_ < 18)
            throw std::invalid_argument("k cannot be lesser than 18");


        /// Pre-extract key to per-round, per-mixing word key

        // Expand plot id to round keys
        union alignas(8) AlignedRoundKey {
            uint64_t q   [4];  // 32/8
            uint8_t  byte[32];
        };


        // Expand plot id to round keys
        #pragma pack(push, 1)
        struct Key_Input {
            uint8_t key [32];
            uint8_t salt[15];
            uint8_t round;
        };
        #pragma pack(pop)
        static_assert(sizeof(Key_Input) == 48);

        constexpr uint64_t MASK_K_BASE = (1ull << K_BASE) - 1;
        const uint32_t mask_k = (1u << k_) - 1;

        AlignedRoundKey round_key, prev_round_key;
        memcpy(prev_round_key.byte, plot_id, 32);

        sha256 sha_ctx = {};

        Key_Input input;
        memcpy(input.salt, ROUND_KEY_SALT, sizeof(ROUND_KEY_SALT)-1);

        for (uint32_t round = 0; round < ROUNDS; round++) {
            input.round = uint8_t(round+1);
            memcpy(input.key, prev_round_key.byte, 32);

            sha256_init(&sha_ctx);
            sha256_update(&sha_ctx, &input, sizeof(input));
            sha256_sum(&sha_ctx, round_key.byte);

            // Retain prev round key unswapped for next round
            if (round+1 < ROUNDS) {
                memcpy(prev_round_key.byte, round_key.byte, 32);
            }

            for (int i = 0; i < 4; i++) {
                round_key.q[i] = swap64(round_key.q[i]);
            }

            // The first 28*3 bits are used for the per-round mixing words
            uint32_t subkey[3];

            for (uint32_t i = 0; i < 3; ++i) {
                uint32_t const bit    = i * K_BASE;
                uint32_t const word   = bit / 64;
                uint32_t const offset = bit % 64;

                uint64_t value = round_key.q[word] << offset;

                if (offset + K_BASE > 64) {
                    value |= round_key.q[word + 1] >> (64 - offset);
                }

                subkey[i] = uint32_t((value >> (64 - K_BASE)) & MASK_K_BASE);
            }

            round_key_.round[round].b = subkey[0] & mask_k;
            round_key_.round[round].c = subkey[1] & mask_k;
            round_key_.round[round].d = subkey[2] & mask_k;
        }
    }

    // Destructor: Nothing to free since we use a fixed-size array.
    ~FeistelCipher() {}

    struct FeistelResult {
        uint64_t left;
        uint64_t right;
    };

    // Encrypts an integer block (of 2*k bits) and returns the ciphertext as a uint64_t.
    inline uint64_t encrypt(uint64_t input_value) const
    {
        uint64_t const half_length = k_;
        uint64_t const bitmask     = (1ull << k_) - 1;

        uint64_t left = (input_value >> half_length) & bitmask;
        uint64_t right = input_value & bitmask;

        for (uint32_t round = 0; round < ROUNDS; round++) {
            FeistelResult res = feistel_round(left, right, bitmask, get_round_key(round));
            left = res.left;
            right = res.right;
        }

        return (left << half_length) | right;
    }

    // Decrypts an integer block (of 2*k bits) and returns the plaintext.
    inline uint64_t decrypt(uint64_t cipher_value) const
    {
        uint64_t const half_length = k_;
        uint64_t const bitmask     = (1ull << k_) - 1;

        uint64_t left = (cipher_value >> half_length) & bitmask;
        uint64_t right = cipher_value & bitmask;

        // Reverse order of rounds.
        for (uint32_t round = ROUNDS; round-- > 0;) {
            // Invert the round by swapping left/right.
            FeistelResult res = feistel_round(right, left, bitmask, get_round_key(round));
            right = res.left;
            left = res.right;
        }

        return (left << half_length) | right;
    }

private:
    inline RoundKey get_round_key(uint32_t round_num) const
    {
        return round_key_.round[round_num];
    }

    // Performs one Feistel round using a quarter-round function inspired by ChaCha20.
    inline FeistelResult feistel_round(uint64_t left, uint64_t right, uint64_t bitmask, RoundKey round_key) const
    {
        uint64_t a = right;
        uint64_t b = round_key.b;
        uint64_t c = round_key.c;
        uint64_t d = round_key.d;

        // First quarter-round.
        a = (a + b) & bitmask;
        d = rotate_left(d ^ a, 16, k_, bitmask);
        c = (c + d) & bitmask;
        b = rotate_left(b ^ c, 12, k_, bitmask);

        // Second quarter-round.
        a = (a + b) & bitmask;
        d = rotate_left(d ^ a, 8, k_, bitmask);
        c = (c + d) & bitmask;
        b = rotate_left(b ^ c, 7, k_, bitmask);

        FeistelResult result;
        result.left = right;
        result.right = (left ^ b) & bitmask;
        return result;
    }

    // Rotate-left operation confined to a field of bit_length bits.
    static inline uint64_t rotate_left(uint64_t value, uint64_t shift, uint64_t bit_length, uint64_t mask)
    {
        return ((value << shift) & mask) | (value >> (bit_length - shift));
    }

    static inline uint64_t swap64(uint64_t v)
    {
        // Based on fse's mem.h
        if constexpr (std::endian::native == std::endian::little) {
            #if defined(_MSC_VER)
                return _byteswap_uint64(v);
            #elif (defined (__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__ >= 403)) \
                    || (defined(__clang__) && __has_builtin(__builtin_bswap64))
                return __builtin_bswap64(v);
            #else
                return  ((v << 56) & 0xff00000000000000ULL) |
                        ((v << 40) & 0x00ff000000000000ULL) |
                        ((v << 24) & 0x0000ff0000000000ULL) |
                        ((v << 8 ) & 0x000000ff00000000ULL) |
                        ((v >> 8 ) & 0x00000000ff000000ULL) |
                        ((v >> 24) & 0x0000000000ff0000ULL) |
                        ((v >> 40) & 0x000000000000ff00ULL) |
                        ((v >> 56) & 0x00000000000000ffULL);
            #endif
        }
        else {
            return v;
        }
    }
};
