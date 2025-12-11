#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>

class FeistelCipher {
public:
    // The key is stored as a fixed-size array of 32 bytes.
    uint8_t plot_id_[32];
    size_t k_; // Half the block size (block is 2*k bits)
    size_t rounds_; // Number of Feistel rounds
    size_t bit_length_; // Total block size in bits (2*k)

    // Constructor.
    //   plot_id: Pointer to a 32-byte key.
    //   k: Half of the total bit length. Must be at most 32.
    //   rounds: Number of rounds (default is 4).
    //
    // __host__ __device__ makes it callable on both host and device.
    //__host__ __device__
    FeistelCipher(uint8_t const* plot_id, size_t k, size_t rounds = 4)
        : k_(k)
        , rounds_(rounds)
        , bit_length_(2 * k)
    {
        // On host, we throw exceptions if the parameters are invalid.
#ifndef __CUDA_ARCH__
        if (k_ > 32)
            throw std::invalid_argument("k cannot be greater than 32.");
        if (bit_length_ > 256)
            throw std::invalid_argument("bit_length (2*k) must not exceed 256.");
        if (3 * k_ > 256)
            throw std::invalid_argument("3*k cannot exceed 256 bits.");
#endif
        // Copy the provided 32-byte key.
        for (int i = 0; i < 32; ++i)
            plot_id_[i] = plot_id[i];
    }

    // Destructor: Nothing to free since we use a fixed-size array.
    //__host__ __device__
    ~FeistelCipher() {}

    // Rotate-left operation confined to a field of bit_length bits.
    //__host__ __device__
    static inline uint64_t rotate_left(uint64_t value, uint64_t shift, uint64_t bit_length)
    {
        if (shift > bit_length)
            shift = bit_length;
        uint64_t mask = (bit_length == 64 ? ~0ULL : ((1ULL << bit_length) - 1));
        return ((value << shift) & mask) | (value >> (bit_length - shift));
    }

    // Extracts a slice from the 256-bit key.
    // Returns a uint64_t containing num_bits starting at start_bit.
    //__host__ __device__
    inline uint64_t slice_key(size_t start_bit, size_t num_bits) const
    {
        size_t start_byte = start_bit / 8;
        size_t bit_offset = start_bit % 8;
        size_t needed_bytes = (bit_offset + num_bits + 7) / 8;
        // In device code exceptions are not supported; on host we throw.
#ifndef __CUDA_ARCH__
        if (start_byte + needed_bytes > 32)
            throw std::runtime_error("Key slice out of range.");
#else
        if (start_byte + needed_bytes > 32)
            return 0;
#endif
        uint64_t key_segment = 0;
        for (size_t i = 0; i < needed_bytes; ++i)
            key_segment = (key_segment << 8) | plot_id_[start_byte + i];
        size_t total_bits = needed_bytes * 8;
        size_t shift_amount = total_bits - bit_offset - num_bits;
        uint64_t mask = (num_bits >= 64 ? ~0ULL : ((1ULL << num_bits) - 1));
        return (key_segment >> shift_amount) & mask;
    }

    // Computes the round key for a given round.
    // For rounds > 1, the starting bit for round i is:
    //      start_bit = i * (256 - 3*k) / (rounds - 1)
    // Otherwise, start_bit is 0.
    //__host__ __device__
    inline uint64_t get_round_key(size_t round_num) const
    {
        size_t half_length = k_;
        size_t bits_for_round = 3 * half_length;
        size_t start_bit = 0;
        if (rounds_ > 1)
            start_bit = (round_num * (256 - 3 * half_length)) / (rounds_ - 1);
        return slice_key(start_bit, bits_for_round);
    }

    // Custom struct to hold the result of a Feistel round.
    struct FeistelResult {
        uint64_t left;
        uint64_t right;
    };

    // Performs one Feistel round using a quarter-round function inspired by ChaCha20.
    // Returns a FeistelResult structure (instead of std::pair) for host/device compatibility.
    // __host__ __device__
    inline FeistelResult feistel_round(uint64_t left, uint64_t right, uint64_t round_key) const
    {
        uint64_t bitmask = (k_ == 64 ? ~0ULL : ((1ULL << k_) - 1));
        uint64_t a = right;
        uint64_t b = round_key & bitmask;
        uint64_t c = (round_key >> k_) & bitmask;
        uint64_t d = (round_key >> (2 * k_)) & bitmask;

        // First quarter-round.
        a = (a + b) & bitmask;
        d = rotate_left(d ^ a, 16, k_);
        c = (c + d) & bitmask;
        b = rotate_left(b ^ c, 12, k_);

        // Second quarter-round.
        a = (a + b) & bitmask;
        d = rotate_left(d ^ a, 8, k_);
        c = (c + d) & bitmask;
        b = rotate_left(b ^ c, 7, k_);

        FeistelResult result;
        result.left = right;
        result.right = (left ^ b) & bitmask;
        return result;
    }

    // Encrypts an integer block (of 2*k bits) and returns the ciphertext as a uint64_t.
    //__host__ __device__
    inline uint64_t encrypt(uint64_t input_value) const
    {
        size_t half_length = k_;
        uint64_t bitmask = (half_length == 64 ? ~0ULL : ((1ULL << half_length) - 1));
        uint64_t left = (input_value >> half_length) & bitmask;
        uint64_t right = input_value & bitmask;
        for (size_t round_num = 0; round_num < rounds_; ++round_num) {
            uint64_t round_key = get_round_key(round_num);
            FeistelResult res = feistel_round(left, right, round_key);
            left = res.left;
            right = res.right;
        }
        return (left << half_length) | right;
    }

    // Decrypts an integer block (of 2*k bits) and returns the plaintext.
    //__host__ __device__
    inline uint64_t decrypt(uint64_t cipher_value) const
    {
        size_t half_length = k_;
        uint64_t bitmask = (half_length == 64 ? ~0ULL : ((1ULL << half_length) - 1));
        uint64_t left = (cipher_value >> half_length) & bitmask;
        uint64_t right = cipher_value & bitmask;
        // Reverse order of rounds.
        for (size_t round = rounds_; round-- > 0;) {
            uint64_t round_key = get_round_key(round);
            // Invert the round by swapping left/right.
            FeistelResult res = feistel_round(right, left, round_key);
            right = res.left;
            left = res.right;
        }
        return (left << half_length) | right;
    }
};
