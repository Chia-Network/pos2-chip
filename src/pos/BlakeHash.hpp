#pragma once

#include <sstream>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>

//----------------------------------------------------------------------
// BlakeHash.hpp
//----------------------------------------------------------------------

// local definitions, they are undef'd at the end
#define rotr32(w, c) ((w) >> (c)) | ((w) << (32 - (c)))

#define g(state, a, b, c, d, x, y)              \
    state[a] = state[a] + state[b] + (x);       \
    state[d] = rotr32(state[d] ^ state[a], 16); \
    state[c] = state[c] + state[d];             \
    state[b] = rotr32(state[b] ^ state[c], 12); \
    state[a] = state[a] + state[b] + (y);       \
    state[d] = rotr32(state[d] ^ state[a], 8);  \
    state[c] = state[c] + state[d];             \
    state[b] = rotr32(state[b] ^ state[c], 7);

#define _b3_inline_rounds(input_byte_size)                    \
    uint32_t state[16] = {                                    \
        0x6A09E667, /*IV full*/                               \
        0xBB67AE85,                                           \
        0x3C6EF372,                                           \
        0xA54FF53A,                                           \
        0x510E527F,                                           \
        0x9B05688C,                                           \
        0x1F83D9AB,                                           \
        0x5BE0CD19,                                           \
        0x6A09E667, /*IV 0-4*/                                \
        0xBB67AE85,                                           \
        0x3C6EF372,                                           \
        0xA54FF53A,                                           \
        0,                           /*count lo*/             \
        0,                           /*count hi*/             \
        (uint32_t)(input_byte_size), /*buffer length*/        \
        11                           /*flags. Always 11*/     \
    };                                                        \
                                                              \
    /* Round 0 */                                             \
    g(state, 0, 4, 8, 12, block_words[0], block_words[1]);    \
    g(state, 1, 5, 9, 13, block_words[2], block_words[3]);    \
    g(state, 2, 6, 10, 14, block_words[4], block_words[5]);   \
    g(state, 3, 7, 11, 15, block_words[6], block_words[7]);   \
                                                              \
    g(state, 0, 5, 10, 15, block_words[8], block_words[9]);   \
    g(state, 1, 6, 11, 12, block_words[10], block_words[11]); \
    g(state, 2, 7, 8, 13, block_words[12], block_words[13]);  \
    g(state, 3, 4, 9, 14, block_words[14], block_words[15]);  \
                                                              \
    /* Round 1 */                                             \
    g(state, 0, 4, 8, 12, block_words[2], block_words[6]);    \
    g(state, 1, 5, 9, 13, block_words[3], block_words[10]);   \
    g(state, 2, 6, 10, 14, block_words[7], block_words[0]);   \
    g(state, 3, 7, 11, 15, block_words[4], block_words[13]);  \
                                                              \
    g(state, 0, 5, 10, 15, block_words[1], block_words[11]);  \
    g(state, 1, 6, 11, 12, block_words[12], block_words[5]);  \
    g(state, 2, 7, 8, 13, block_words[9], block_words[14]);   \
    g(state, 3, 4, 9, 14, block_words[15], block_words[8]);   \
                                                              \
    /* Round 2 */                                             \
    g(state, 0, 4, 8, 12, block_words[3], block_words[4]);    \
    g(state, 1, 5, 9, 13, block_words[10], block_words[12]);  \
    g(state, 2, 6, 10, 14, block_words[13], block_words[2]);  \
    g(state, 3, 7, 11, 15, block_words[7], block_words[14]);  \
                                                              \
    g(state, 0, 5, 10, 15, block_words[6], block_words[5]);   \
    g(state, 1, 6, 11, 12, block_words[9], block_words[0]);   \
    g(state, 2, 7, 8, 13, block_words[11], block_words[15]);  \
    g(state, 3, 4, 9, 14, block_words[8], block_words[1]);    \
                                                              \
    /* Round 3 */                                             \
    g(state, 0, 4, 8, 12, block_words[10], block_words[7]);   \
    g(state, 1, 5, 9, 13, block_words[12], block_words[9]);   \
    g(state, 2, 6, 10, 14, block_words[14], block_words[3]);  \
    g(state, 3, 7, 11, 15, block_words[13], block_words[15]); \
                                                              \
    g(state, 0, 5, 10, 15, block_words[4], block_words[0]);   \
    g(state, 1, 6, 11, 12, block_words[11], block_words[2]);  \
    g(state, 2, 7, 8, 13, block_words[5], block_words[8]);    \
    g(state, 3, 4, 9, 14, block_words[1], block_words[6]);    \
                                                              \
    /* Round 4 */                                             \
    g(state, 0, 4, 8, 12, block_words[12], block_words[13]);  \
    g(state, 1, 5, 9, 13, block_words[9], block_words[11]);   \
    g(state, 2, 6, 10, 14, block_words[15], block_words[10]); \
    g(state, 3, 7, 11, 15, block_words[14], block_words[8]);  \
                                                              \
    g(state, 0, 5, 10, 15, block_words[7], block_words[2]);   \
    g(state, 1, 6, 11, 12, block_words[5], block_words[3]);   \
    g(state, 2, 7, 8, 13, block_words[0], block_words[1]);    \
    g(state, 3, 4, 9, 14, block_words[6], block_words[4]);    \
                                                              \
    /* Round 5 */                                             \
    g(state, 0, 4, 8, 12, block_words[9], block_words[14]);   \
    g(state, 1, 5, 9, 13, block_words[11], block_words[5]);   \
    g(state, 2, 6, 10, 14, block_words[8], block_words[12]);  \
    g(state, 3, 7, 11, 15, block_words[15], block_words[1]);  \
                                                              \
    g(state, 0, 5, 10, 15, block_words[13], block_words[3]);  \
    g(state, 1, 6, 11, 12, block_words[0], block_words[10]);  \
    g(state, 2, 7, 8, 13, block_words[2], block_words[6]);    \
    g(state, 3, 4, 9, 14, block_words[4], block_words[7]);    \
/* Round 6 */                                                 \
    g(state, 0, 4, 8,  12, block_words[11], block_words[15]); \
    g(state, 1, 5, 9,  13, block_words[5],  block_words[0]);  \
    g(state, 2, 6, 10, 14, block_words[1],  block_words[9]);  \
    g(state, 3, 7, 11, 15, block_words[8],  block_words[6]);  \
                                                              \
    g(state, 0, 5, 10, 15, block_words[14], block_words[10]); \
    g(state, 1, 6, 11, 12, block_words[2],  block_words[12]); \
    g(state, 2, 7, 8,  13, block_words[3],  block_words[4]);  \
    g(state, 3, 4, 9,  14, block_words[7],  block_words[13]); \

class BlakeHash
{
public:
    struct Result64
    {
        uint32_t r[2];
    };

    struct Result128
    {
        uint32_t r[4];
    };

    struct Result256
    {
        uint32_t r[8];

        std::string toString() const
        {
            std::ostringstream oss;
            oss << std::hex << std::uppercase << std::setfill('0');
            for (int i = 0; i < 8; ++i)
            {
                if (i > 0)
                    oss << ' ';
                oss << std::setw(8) << r[i];
            }
            return oss.str();
        }
    };

    // Constructor.
    //   plotIdBytes: pointer to an array of exactly 32 bytes.
    //   k_value: desired output bit-size, default is 32.
    // Throws std::invalid_argument if plotIdBytes is null.
    BlakeHash(const uint8_t *plot_id_bytes, int k_value = 32)
        : k(k_value)
    {
        if (!plot_id_bytes)
            throw std::invalid_argument("plotIdBytes pointer is null.");
        // Fill first 8 words from the 32-byte plot ID (little-endian conversion).
        for (int i = 0; i < 8; i++)
        {
            // Each word is 4 bytes.
            block_words[i] =
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 0])) |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 3]) << 24);
        }
        // Zero the remaining 8 words.
        for (int i = 8; i < 16; i++)
        {
            block_words[i] = 0;
        }
    }

    static Result256 hash_block_256(const uint32_t block_words[16])
    {
        _b3_inline_rounds(21);

        // Finally, compute the result.
        // For each of r0..r3, compute: big_endian( state[i] XOR state[i+8] )
        Result256 result;
        result.r[0] = (state[0] ^ state[8]);
        result.r[1] = (state[1] ^ state[9]);
        result.r[2] = (state[2] ^ state[10]);
        result.r[3] = (state[3] ^ state[11]);
        result.r[4] = (state[4] ^ state[12]);
        result.r[5] = (state[5] ^ state[13]);
        result.r[6] = (state[6] ^ state[14]);
        result.r[7] = (state[7] ^ state[15]);
        return result;
    }

    static Result64 hash_block_64(const uint32_t block_words[16])
    {
        _b3_inline_rounds(21);

        // Finally, compute the result.
        // For each of r0..r3, compute: big_endian( state[i] XOR state[i+8] )
        Result64 result;
        result.r[0] = (state[0] ^ state[8]);
        result.r[1] = (state[1] ^ state[9]);
        return result;
    }

    BlakeHash(const uint8_t *plot_id_bytes, const uint8_t *challenge_bytes)
        : k(32) // Default output bit-size is 32.
    {
        if (!plot_id_bytes || !challenge_bytes)
            throw std::invalid_argument("plotIdBytes or challengeBytes pointer is null.");

        // Fill first 8 words from the 32-byte plot ID (little-endian conversion).
        for (int i = 0; i < 8; i++)
        {
            block_words[i] =
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 0])) |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 3]) << 24);
        }

        // Fill next 8 words from the challenge bytes.
        for (int i = 0; i < 8; i++)
        {
            block_words[i + 8] =
                (static_cast<uint32_t>(challenge_bytes[i * 4 + 0])) |
                (static_cast<uint32_t>(challenge_bytes[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(challenge_bytes[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(challenge_bytes[i * 4 + 3]) << 24);
        }

        // Do 256 bit hash, set the first 8 words to the result and the last to zero.
        Result256 result = generate_hash_256();
        for (int i = 0; i < 8; i++)
        {
            block_words[i] = result.r[i];
        }
        for (int i = 8; i < 16; i++)
        {
            block_words[i] = 0;
        }
    }

    // set_data sets a value in the "data" portion of block_words (indices 8..15).
    // index must be between 0 and 7; the value is stored at block_words[index + 8].
    void set_data(int index, uint32_t value)
    {
        if (index < 0 || index >= 8)
            throw std::out_of_range("Index out of range for data block.");
        block_words[index + 8] = value;
    }

    uint32_t generate_hash_32() const
    {

        _b3_inline_rounds(21);

        // Finally, compute the result.
        // For each of r0..r3, compute: big_endian( state[i] XOR state[i+8] )
        return (state[0] ^ state[8]);
    }

    Result64 generate_hash_64() const
    {

        _b3_inline_rounds(21);

        // Finally, compute the result.
        // For each of r0..r3, compute: big_endian( state[i] XOR state[i+8] )
        Result64 result;
        result.r[0] = (state[0] ^ state[8]);
        result.r[1] = (state[1] ^ state[9]);
        return result;
    }

    // generate_hash() computes the hash and returns a Result128 containing 4 words.
    Result128 generate_hash() const
    {

        _b3_inline_rounds(21);

        // Finally, compute the result.
        // For each of r0..r3, compute: big_endian( state[i] XOR state[i+8] )
        Result128 result;
        result.r[0] = (state[0] ^ state[8]);
        result.r[1] = (state[1] ^ state[9]);
        result.r[2] = (state[2] ^ state[10]);
        result.r[3] = (state[3] ^ state[11]);
        return result;
    }

    Result256 generate_hash_256() const
    {

        _b3_inline_rounds(21);

        // Finally, compute the result.
        // For each of r0..r3, compute: big_endian( state[i] XOR state[i+8] )
        Result256 result;
        result.r[0] = (state[0] ^ state[8]);
        result.r[1] = (state[1] ^ state[9]);
        result.r[2] = (state[2] ^ state[10]);
        result.r[3] = (state[3] ^ state[11]);
        result.r[4] = (state[4] ^ state[12]);
        result.r[5] = (state[5] ^ state[13]);
        result.r[6] = (state[6] ^ state[14]);
        result.r[7] = (state[7] ^ state[15]);
        return result;
    }

    // Returns the 32-bit big-endian representation of value.
    /*static inline uint32_t big_endian(uint32_t value)
    {
        return ((value & 0xFFU) << 24) |
               ((value & 0xFF00U) << 8) |
               ((value & 0xFF0000U) >> 8) |
               ((value & 0xFF000000U) >> 24);
    }*/

private:
    int k;                    // Output bit-size parameter (e.g., 32)
    uint32_t block_words[16]; // 16 32-bit words; first 8 come from plotIdBytes, rest are zero.
};

#undef g
#undef rotr32
#undef _b3_inline_rounds
