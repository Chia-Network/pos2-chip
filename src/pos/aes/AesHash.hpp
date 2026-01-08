#pragma once

#include "intrin_portable.h"
#include "soft_aes.hpp"
#include <vector>

constexpr int AES_G_ROUNDS = 16;
constexpr int AES_PAIRING_ROUNDS = 16;
constexpr int AES_MATCHING_TARGET_ROUNDS = 16;

#define AES_COUNT_HASHES 0
#if AES_COUNT_HASHES
#include <atomic>
std::atomic<uint64_t> aes_g_hash_count;
std::atomic<uint64_t> aes_pairing_hash_count;
std::atomic<uint64_t> aes_t1_matching_target_hash_count;
std::atomic<uint64_t> aes_t2_matching_target_hash_count;
std::atomic<uint64_t> aes_t3_matching_target_hash_count;
void showHashCounts()
{
    std::cout << "AES G Hash Count: " << aes_g_hash_count.load() << std::endl;
    std::cout << "AES Pairing Hash Count: " << aes_pairing_hash_count.load() << std::endl;
    std::cout << "AES T1 Matching Target Hash Count: " << aes_t1_matching_target_hash_count.load()
              << std::endl;
    std::cout << "AES T2 Matching Target Hash Count: " << aes_t2_matching_target_hash_count.load()
              << std::endl;
    std::cout << "AES T3 Matching Target Hash Count: " << aes_t3_matching_target_hash_count.load()
              << std::endl;
}
#endif

// Class that preloads AES key vectors from a 32-byte plot id.
// Usage:
//   AesHash hasher(plot_id_bytes);
//   auto h = hasher.g_x<false>(x, Rounds);
class AesHash {
public:
    // Construct from a pointer to at least 32 bytes of plot id material.
    AesHash(uint8_t const* plot_id_bytes, int k) : k_(k)
    {
        round_key_1 = load_plot_id_as_aes_key(plot_id_bytes);
        round_key_2 = load_plot_id_as_aes_key(plot_id_bytes + 16);
    }

    struct Result64 {
        uint32_t r[2];

        constexpr bool operator==(Result64 const& o) const noexcept
        {
            return r[0] == o.r[0] && r[1] == o.r[1];
        }
    };

    struct Result128 {
        std::array<uint32_t, 4> r;
        constexpr bool operator==(Result128 const& o) const noexcept = default;
    };

    // Templated hash function that uses the preloaded AES keys.
    // Rounds of 16 are optimal for the Pi5 Solver performance yet still pressure a GPU into compute
    // bound.
    template <bool Soft>
    uint32_t g_x(uint32_t x, int const Rounds = AES_G_ROUNDS) const
    {
        // place uint32_t x into lowest 32 bits of the vector
        int32_t i0 = static_cast<int32_t>(x);
        rx_vec_i128 state = rx_set_int_vec_i128(/*i3*/ 0, /*i2*/ 0, /*i1*/ 0, /*i0*/ i0);
        for (int r = 0; r < Rounds; ++r) {
            state = aesenc<Soft>(state, round_key_1);
            state = aesenc<Soft>(state, round_key_2);
        }
        // only get bottom k bits.
        return static_cast<uint32_t>(rx_vec_i128_x(state)) & ((1u << k_) - 1u);
    }

    template <bool Soft>
    uint32_t matching_target(
        uint32_t table_id, uint32_t match_key, uint64_t meta, int extra_rounds_bits = 0) const
    {
#if AES_COUNT_HASHES
        if (table_id == 1) {
            // atomic add to t1 counter
            aes_t1_matching_target_hash_count.fetch_add(
                1 << extra_rounds_bits, std::memory_order_relaxed);
        }
        else if (table_id == 2) {
            aes_t2_matching_target_hash_count.fetch_add(
                1 << extra_rounds_bits, std::memory_order_relaxed);
        }
        else if (table_id == 3) {
            aes_t3_matching_target_hash_count.fetch_add(
                1 << extra_rounds_bits, std::memory_order_relaxed);
        }
#endif
        // load table id, match_key, and meta into AES state
        int32_t i0 = static_cast<int32_t>(table_id);
        int32_t i1 = static_cast<int32_t>(match_key);
        int32_t i2 = static_cast<int32_t>(meta & 0xFFFFFFFFULL);
        int32_t i3 = static_cast<int32_t>((meta >> 32) & 0xFFFFFFFFULL);
        rx_vec_i128 state = rx_set_int_vec_i128(i3, i2, i1, i0);
        int const Rounds = AES_MATCHING_TARGET_ROUNDS << extra_rounds_bits;
        for (int r = 0; r < Rounds; ++r) {
            state = aesenc<Soft>(state, round_key_1);
            state = aesenc<Soft>(state, round_key_2);
        }
        return static_cast<uint32_t>(rx_vec_i128_x(state));
    }

    template <bool Soft>
    Result128 pairing(uint64_t meta_l, uint64_t meta_r, int extra_rounds_bits = 0) const
    {
#if AES_COUNT_HASHES
        aes_pairing_hash_count.fetch_add(1 << extra_rounds_bits, std::memory_order_relaxed);
#endif
        // load table id, meta_l, meta_r into AES state
        int32_t i0 = static_cast<int32_t>(meta_l & 0xFFFFFFFFULL);
        int32_t i1 = static_cast<int32_t>((meta_l >> 32) & 0xFFFFFFFFULL);
        int32_t i2 = static_cast<int32_t>(meta_r & 0xFFFFFFFFULL);
        int32_t i3 = static_cast<int32_t>((meta_r >> 32) & 0xFFFFFFFFULL);
        rx_vec_i128 state = rx_set_int_vec_i128(i3, i2, i1, i0);
        int const Rounds = AES_PAIRING_ROUNDS << extra_rounds_bits;
        for (int r = 0; r < Rounds; ++r) {
            state = aesenc<Soft>(state, round_key_1);
            state = aesenc<Soft>(state, round_key_2);
        }
        Result128 result;
        result.r[0] = static_cast<uint32_t>(rx_vec_i128_x(state));
        result.r[1] = static_cast<uint32_t>(rx_vec_i128_y(state));
        result.r[2] = static_cast<uint32_t>(rx_vec_i128_z(state));
        result.r[3] = static_cast<uint32_t>(rx_vec_i128_w(state));
        return result;
    }

private:
    int k_;
    rx_vec_i128 round_key_1;
    rx_vec_i128 round_key_2;

    // Load 16 bytes into rx_vec_i128 (little-endian 32-bit words)
    static FORCE_INLINE rx_vec_i128 load_plot_id_as_aes_key(uint8_t const* plot_id_bytes)
    {
        int i0 = static_cast<int32_t>(load32(plot_id_bytes + 0));
        int i1 = static_cast<int32_t>(load32(plot_id_bytes + 4));
        int i2 = static_cast<int32_t>(load32(plot_id_bytes + 8));
        int i3 = static_cast<int32_t>(load32(plot_id_bytes + 12));
        return rx_set_int_vec_i128(i3, i2, i1, i0);
    }
};
