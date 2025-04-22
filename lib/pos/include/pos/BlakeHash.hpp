#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>

//----------------------------------------------------------------------
// BlakeHash.hpp
//----------------------------------------------------------------------

/*
    BlakeHash implements a simplified Blake3-like (or Blake-inspired) hash function.
    It takes a 32‐byte plot ID and an optional output bit‐size (default 32). The 32‐byte
    plot ID is split into eight 32‑bit words (using little‑endian conversion), and stored
    in a fixed array along with eight zeroed words.
    
    The generate_hash() method then builds a 16‑word state using Blake3 constants,
    mixes in the stored block using a series of "g" functions and bit rotations,
    and finally returns four 32‑bit words (r0, r1, r2, r3) after XORing portions
    of the state and converting the result to big‑endian format.

    This header‐only implementation does not use dynamic memory or STL containers,
    so it is written in a style that is friendly to later CUDA integration.
*/
class BlakeHash {
public:
    // Structure for returning the final 4×32-bit hash words.
    struct BlakeHashResult {
        uint32_t r0;
        uint32_t r1;
        uint32_t r2;
        uint32_t r3;
    };

    // Constructor.
    //   plotIdBytes: pointer to an array of exactly 32 bytes.
    //   k_value: desired output bit-size, default is 32.
    // Throws std::invalid_argument if plotIdBytes is null.
    BlakeHash(const uint8_t* plot_id_bytes, int k_value = 32)
        : k(k_value)
    {
        if (!plot_id_bytes)
            throw std::invalid_argument("plotIdBytes pointer is null.");
        // Fill first 8 words from the 32-byte plot ID (little-endian conversion).
        for (int i = 0; i < 8; i++) {
            // Each word is 4 bytes.
            block_words[i] = 
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 0]))        |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 1]) << 8)   |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 2]) << 16)  |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 3]) << 24);
        }
        // Zero the remaining 8 words.
        for (int i = 8; i < 16; i++) {
            block_words[i] = 0;
        }
    }

    // set_data sets a value in the "data" portion of block_words (indices 8..15).
    // index must be between 0 and 7; the value is stored at block_words[index + 8].
    void set_data(int index, uint32_t value) {
        if (index < 0 || index >= 8)
            throw std::out_of_range("Index out of range for data block.");
        block_words[index + 8] = value;
    }

    // generate_hash() computes the hash and returns a BlakeHashResult containing 4 words.
    BlakeHashResult generate_hash() const {
        // Create a local state initialized with Blake-inspired constants:
        // (these constants mimic the ones used in the Python code)
        uint32_t state[16] = {
            0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
            0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U,
            0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
            0, 0, 21, 11  // Note: 1|2|8 == 11.
        };

        // Local helper: rotate right 32 bits.
        auto rotr32 = [](uint32_t value, int count) -> uint32_t {
            return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFFU;
        };

        // Local helper lambda for the "g" mixing function.
        auto g = [&](int a, int b, int c, int d, uint32_t x, uint32_t y) {
            state[a] = (state[a] + state[b] + x) & 0xFFFFFFFFU;
            state[d] = rotr32(state[d] ^ state[a], 16);
            state[c] = (state[c] + state[d]) & 0xFFFFFFFFU;
            state[b] = rotr32(state[b] ^ state[c], 12);
            state[a] = (state[a] + state[b] + y) & 0xFFFFFFFFU;
            state[d] = rotr32(state[d] ^ state[a], 8);
            state[c] = (state[c] + state[d]) & 0xFFFFFFFFU;
            state[b] = rotr32(state[b] ^ state[c], 7);
        };

        // Run a series of mixing operations; the parameters follow the Python code.
        g(0, 4, 8, 12, block_words[0], block_words[1]);
        g(1, 5, 9, 13, block_words[2], block_words[3]);
        g(2, 6, 10, 14, block_words[4], block_words[5]);
        g(3, 7, 11, 15, block_words[6], block_words[7]);

        g(0, 5, 10, 15, block_words[8], block_words[9]);
        g(1, 6, 11, 12, block_words[10], block_words[11]);
        g(2, 7, 8, 13, block_words[12], block_words[13]);
        g(3, 4, 9, 14, block_words[14], block_words[15]);

        g(0, 4, 8, 12, block_words[2], block_words[6]);
        g(1, 5, 9, 13, block_words[3], block_words[10]);
        g(2, 6, 10, 14, block_words[7], block_words[0]);
        g(3, 7, 11, 15, block_words[4], block_words[13]);

        g(0, 5, 10, 15, block_words[1], block_words[11]);
        g(1, 6, 11, 12, block_words[12], block_words[5]);
        g(2, 7, 8, 13, block_words[9], block_words[14]);
        g(3, 4, 9, 14, block_words[15], block_words[8]);

        g(0, 4, 8, 12, block_words[3], block_words[4]);
        g(1, 5, 9, 13, block_words[10], block_words[12]);
        g(2, 6, 10, 14, block_words[13], block_words[2]);
        g(3, 7, 11, 15, block_words[7], block_words[14]);

        g(0, 5, 10, 15, block_words[6], block_words[5]);
        g(1, 6, 11, 12, block_words[9], block_words[0]);
        g(2, 7, 8, 13, block_words[11], block_words[15]);
        g(3, 4, 9, 14, block_words[8], block_words[1]);

        g(0, 4, 8, 12, block_words[10], block_words[7]);
        g(1, 5, 9, 13, block_words[12], block_words[9]);
        g(2, 6, 10, 14, block_words[14], block_words[3]);
        g(3, 7, 11, 15, block_words[13], block_words[15]);

        g(0, 5, 10, 15, block_words[4], block_words[0]);
        g(1, 6, 11, 12, block_words[11], block_words[2]);
        g(2, 7, 8, 13, block_words[5], block_words[8]);
        g(3, 4, 9, 14, block_words[1], block_words[6]);

        g(0, 4, 8, 12, block_words[12], block_words[13]);
        g(1, 5, 9, 13, block_words[9], block_words[11]);
        g(2, 6, 10, 14, block_words[15], block_words[10]);
        g(3, 7, 11, 15, block_words[14], block_words[8]);

        g(0, 5, 10, 15, block_words[7], block_words[2]);
        g(1, 6, 11, 12, block_words[5], block_words[3]);
        g(2, 7, 8, 13, block_words[0], block_words[1]);
        g(3, 4, 9, 14, block_words[6], block_words[4]);

        g(0, 4, 8, 12, block_words[9], block_words[14]);
        g(1, 5, 9, 13, block_words[11], block_words[5]);
        g(2, 6, 10, 14, block_words[8], block_words[12]);
        g(3, 7, 11, 15, block_words[15], block_words[1]);

        g(0, 5, 10, 15, block_words[13], block_words[3]);
        g(1, 6, 11, 12, block_words[0], block_words[10]);
        g(2, 7, 8, 13, block_words[2], block_words[6]);
        g(3, 4, 9, 14, block_words[4], block_words[7]);

        // Finally, compute the result.
        // For each of r0..r3, compute: big_endian( state[i] XOR state[i+8] )
        BlakeHashResult result;
        result.r0 = big_endian(state[0] ^ state[8]);
        result.r1 = big_endian(state[1] ^ state[9]);
        result.r2 = big_endian(state[2] ^ state[10]);
        result.r3 = big_endian(state[3] ^ state[11]);
        return result;
    }

    // Returns the 32-bit big-endian representation of value.
    static inline uint32_t big_endian(uint32_t value) {
        return ((value & 0xFFU) << 24) |
               ((value & 0xFF00U) << 8) |
               ((value & 0xFF0000U) >> 8) |
               ((value & 0xFF000000U) >> 24);
    }

private:
    int k;                      // Output bit-size parameter (e.g., 32)
    uint32_t block_words[16];   // 16 32-bit words; first 8 come from plotIdBytes, rest are zero.
};