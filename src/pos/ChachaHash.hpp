#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>

//----------------------------------------------------------------------
// Utility functions
//----------------------------------------------------------------------

// Converts 4 bytes at the given pointer (in little‑endian order) into a uint32_t.
inline uint32_t bytes_to_u32_le(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0])) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

// Rotates a 32‑bit value to the left by a given count.
inline uint32_t rotl32(uint32_t value, int count) {
    return ((value << count) & 0xFFFFFFFFU) | (value >> (32 - count));
}

// Rotates a 32‑bit value left by 8 bits.
inline uint32_t rotl8(uint32_t value) {
    return ((value << 8) & 0xFFFFFFFFU) | (value >> 24);
}

// Rotates a 32‑bit value left by 16 bits.
inline uint32_t rotl16(uint32_t value) {
    return ((value << 16) & 0xFFFFFFFFU) | (value >> 16);
}

// Swaps byte order of a 32‑bit unsigned integer.
/*inline uint32_t cpubyteswap32(uint32_t value) {
    return ((value & 0xFF000000U) >> 24) |
           ((value & 0x00FF0000U) >> 8)  |
           ((value & 0x0000FF00U) << 8)  |
           ((value & 0x000000FFU) << 24);
}*/

//----------------------------------------------------------------------
// ChachaHash class
//----------------------------------------------------------------------

/*
   The ChachaHash class encapsulates the ChaCha8 (with 8 rounds) key setup and hash generation.
   It is written as a header-only class using fixed-size arrays and basic C++ features.
   It is designed to be CUDA-friendly (no dynamic memory, inline functions) although it contains
   no CUDA-specific keywords.
*/
class ChachaHash {
public:
    // Constructor.
    //   plot_id_bytes: pointer to 32 bytes (the plot ID).
    //   k_size: desired bit-size (default 32). When k_size is 32 the full 32-bit values are used.
    //           Otherwise the output hash values are masked to k_size bits.
    ChachaHash(const uint8_t* plot_id_bytes, int k_size = 28)
        : k_size_(k_size)
    {
        if (!plot_id_bytes)
            throw std::invalid_argument("plot_id_bytes pointer is null.");
        // Create an "enc_key" of 32 bytes:
        //   Set the first byte to 1 and copy the next 31 bytes from plot_id_bytes.
        uint8_t enc_key[32];
        enc_key[0] = 1;
        std::memcpy(enc_key + 1, plot_id_bytes, 31);
        // Setup the internal chacha_input using the key.
        // Here kbits is hard-coded to 256 and no IV is provided.
        chacha8_keysetup_data(enc_key);
    }

    // Generates match info for a given x.
    // The function divides x into a group (x_group = x >> 4) and then computes a 16-word hash,
    // finally returning the hash word corresponding to the lower 4 bits of x.
    uint32_t generate_match_info(uint32_t x) {
        uint32_t x_group = x >> 4;
        uint32_t out_hashes[16];
        do_chacha16_range(x_group * 16, out_hashes);
        return out_hashes[x & 15];
    }

    //----------------------------------------------------------------------

    // Performs 16-word ChaCha hash rounds starting from a given x value.
    // The computed 16 uint32_t values are stored in the out_hashes array.
    void do_chacha16_range(uint32_t x, uint32_t* out_hashes) {
        // Form a local working copy "datax" of 16 words:
        //   datax[0..11] are from the internal chacha_input[0..11]
        //   datax[12] = x / 16, datax[13] = 0,
        //   datax[14..15] are from chacha_input[14..15].
        uint32_t datax[16];
        for (int i = 0; i < 12; i++) {
            datax[i] = chacha_input[i];
        }
        datax[12] = x / 16;
        datax[13] = 0;
        datax[14] = chacha_input[14];
        datax[15] = chacha_input[15];

        // Run 4 rounds (each round consists of 8 quarter-round operations):
        for (int i = 0; i < 4; i++) {
            cpu_quarter_round(datax, 0, 4, 8, 12);
            cpu_quarter_round(datax, 1, 5, 9, 13);
            cpu_quarter_round(datax, 2, 6, 10, 14);
            cpu_quarter_round(datax, 3, 7, 11, 15);
            cpu_quarter_round(datax, 0, 5, 10, 15);
            cpu_quarter_round(datax, 1, 6, 11, 12);
            cpu_quarter_round(datax, 2, 7, 8, 13);
            cpu_quarter_round(datax, 3, 4, 9, 14);
        }

        // Finalize: add the original chacha_input word–by–word,
        // then perform a byte swap on each word.
        for (int i = 0; i < 16; i++) {
            datax[i] = (datax[i] + chacha_input[i]) & 0xFFFFFFFFU;
            //datax[i] = cpubyteswap32(datax[i]);
        }

        // Copy result to out_hashes.
        if (k_size_ == 32) {
            for (int i = 0; i < 16; i++) {
                out_hashes[i] = datax[i];
            }
        } else {
            uint32_t mask = (1U << k_size_) - 1U;
            for (int i = 0; i < 16; i++) {
                out_hashes[i] = datax[i] & mask;
            }
        }
    }

    //----------------------------------------------------------------------

    // The CPU quarter-round operation.
    // It mixes four 32-bit values in the datax array at indices a, b, c, d.
    static void cpu_quarter_round(uint32_t* datax, int a, int b, int c, int d) {
        datax[a] = (datax[a] + datax[b]) & 0xFFFFFFFFU;
        datax[d] = rotl16(datax[d] ^ datax[a]);
        datax[c] = (datax[c] + datax[d]) & 0xFFFFFFFFU;
        datax[b] = rotl32(datax[b] ^ datax[c], 12);
        datax[a] = (datax[a] + datax[b]) & 0xFFFFFFFFU;
        datax[d] = rotl8(datax[d] ^ datax[a]);
        datax[c] = (datax[c] + datax[d]) & 0xFFFFFFFFU;
        datax[b] = rotl32(datax[b] ^ datax[c], 7);
    }

    //----------------------------------------------------------------------

    // Performs the ChaCha8 key setup.
    //   k: pointer to a 32-byte key (which may be modified by key slicing).
    //   kbits: key size in bits (expected to be 256).
    //   iv: pointer to an 8-byte IV, or nullptr if none is provided.
    void chacha8_keysetup_data(uint8_t* plot_id) {
        // Constants string: 16 bytes "expand 32-byte k"
        const char* constants = "expand 32-byte k";

        chacha_input[0] = bytes_to_u32_le(reinterpret_cast<const uint8_t*>(constants));
        chacha_input[1] = bytes_to_u32_le(reinterpret_cast<const uint8_t*>(constants + 4));
        chacha_input[2] = bytes_to_u32_le(reinterpret_cast<const uint8_t*>(constants + 8));
        chacha_input[3] = bytes_to_u32_le(reinterpret_cast<const uint8_t*>(constants + 12));

        chacha_input[4] = bytes_to_u32_le(plot_id + 0);
        chacha_input[5] = bytes_to_u32_le(plot_id + 4);
        chacha_input[6] = bytes_to_u32_le(plot_id + 8);
        chacha_input[7] = bytes_to_u32_le(plot_id + 12);
        
        chacha_input[8]  = bytes_to_u32_le(plot_id + 16);
        chacha_input[9]  = bytes_to_u32_le(plot_id + 20);
        chacha_input[10] = bytes_to_u32_le(plot_id + 24);
        chacha_input[11] = bytes_to_u32_le(plot_id + 28);

        chacha_input[12] = 0;
        chacha_input[13] = 0;
        chacha_input[14] = 0;
        chacha_input[15] = 0;        
    }

private:
    int k_size_;               // Desired bit size for output hashing.
    uint32_t chacha_input[16]; // Internal ChaCha state (16 words).
};
