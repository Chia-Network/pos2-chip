#pragma once

#include "soft_aes.hpp"
#include "intrin_portable.h"

// Class that preloads AES key vectors from a 32-byte plot id.
// Usage:
//   AesHash hasher(plot_id_bytes);
//   auto h = hasher.hash_x<false>(x, Rounds);
class AesHash {
  public:
    // Construct from a pointer to at least 32 bytes of plot id material.
    AesHash(const uint8_t* plot_id_bytes, int k) : k_(k) {
        round_key_1 = load_plot_id_as_aes_key(plot_id_bytes);
        round_key_2 = load_plot_id_as_aes_key(plot_id_bytes + 16);
    }

    // Templated hash function that uses the preloaded AES keys.
    // Rounds of 16 are optimal for the Pi5 Solver performance yet still pressure a GPU into compute bound.
    template<bool Soft>
    uint32_t hash_x(uint32_t x, const int Rounds = 16) const {
        // place uint32_t x into lowest 32 bits of the vector
        int32_t i0 = static_cast<int32_t>(x);
        rx_vec_i128 state = rx_set_int_vec_i128(/*i3*/0, /*i2*/0, /*i1*/0, /*i0*/i0);
        for (int r = 0; r < Rounds; ++r) {
            state = aesenc<Soft>(state, round_key_1);
            state = aesenc<Soft>(state, round_key_2);
        }
        // only get bottom k bits.
        return static_cast<uint32_t>(rx_vec_i128_x(state)) & ((1u << k_) - 1u);
    }

  private:
    int k_;
    rx_vec_i128 round_key_1;
    rx_vec_i128 round_key_2;

    // Load 16 bytes into rx_vec_i128 (little-endian 32-bit words)
    static FORCE_INLINE rx_vec_i128 load_plot_id_as_aes_key(const uint8_t* plot_id_bytes) {
        int i0 = static_cast<int32_t>(load32(plot_id_bytes + 0));
        int i1 = static_cast<int32_t>(load32(plot_id_bytes + 4));
        int i2 = static_cast<int32_t>(load32(plot_id_bytes + 8));
        int i3 = static_cast<int32_t>(load32(plot_id_bytes + 12));
        return rx_set_int_vec_i128(i3, i2, i1, i0);
    }
};
