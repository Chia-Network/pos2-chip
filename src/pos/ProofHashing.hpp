#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>

#include "BlakeHash.hpp"
#include "ProofConstants.hpp"
#include "ProofCore.hpp"
#include "ProofParams.hpp"
#include "aes/AesHash.hpp"

// A simple structure to hold the result of a pairing computation.
struct PairingResult {
    uint32_t match_info_result; // Always present.
    uint64_t meta_result; // Valid if out_num_meta_bits != 0.
    uint32_t test_result; // Valid if num_test_bits != 0.
};

class ProofHashing {
public:
    // Constructor.
    // proof_params: a ProofParams instance.
    ProofHashing(ProofParams const& proof_params)
        : params_(proof_params)
        , aes_(proof_params.get_plot_id_bytes(), static_cast<int>(proof_params.get_k()))
    {
    }

    // Returns a single hash value computed from x.
    uint32_t g(uint32_t x);

    // Computes and returns the matching target using the Blake hash.
    // table_id: used as salt, match_key, meta: additional parameters.
    // num_target_bits: the number of bits to return from the hash.
    uint32_t matching_target(
        uint32_t table_id, uint32_t match_key, uint64_t meta, int num_target_bits);

    PairingResult pairing_t1(uint64_t meta_l,
        uint64_t meta_r,
        int num_match_info_bits,
        int out_num_meta_bits,
        int num_test_bits);
    PairingResult pairing_t2(uint64_t meta_l,
        uint64_t meta_r,
        int num_match_info_bits,
        int out_num_meta_bits,
        int num_test_bits);
    PairingResult pairing_t3(uint64_t meta_l, uint64_t meta_r, int num_test_bits);

    std::array<uint64_t, NUM_CHAIN_LINKS> chainingChallengeWithPlotIdHash(
        std::span<uint8_t const, 32> const challenge) const
    {
        std::array<uint64_t, NUM_CHAIN_LINKS> result;

        uint32_t block_words[16];
        uint8_t const* plot_id_bytes = params_.get_plot_id_bytes();
        // Fill the first 8 words with the plot ID.

        // set data from plot id
        for (int i = 0; i < 8; i++) {
            block_words[i] = (static_cast<uint32_t>(plot_id_bytes[i * 4 + 0]))
                | (static_cast<uint32_t>(plot_id_bytes[i * 4 + 1]) << 8)
                | (static_cast<uint32_t>(plot_id_bytes[i * 4 + 2]) << 16)
                | (static_cast<uint32_t>(plot_id_bytes[i * 4 + 3]) << 24);
        }
        // set data from challenge
        for (int i = 0; i < 8; i++) {
            block_words[i + 8] = (static_cast<uint32_t>(challenge[i * 4 + 0]))
                | (static_cast<uint32_t>(challenge[i * 4 + 1]) << 8)
                | (static_cast<uint32_t>(challenge[i * 4 + 2]) << 16)
                | (static_cast<uint32_t>(challenge[i * 4 + 3]) << 24);
        }

        auto blake = BlakeHash::hash_block_256(block_words);
        result[0] = blake.r[0] + ((uint64_t)blake.r[1] << 32);
        result[1] = blake.r[2] + ((uint64_t)blake.r[3] << 32);
        result[2] = blake.r[4] + ((uint64_t)blake.r[5] << 32);
        result[3] = blake.r[6] + ((uint64_t)blake.r[7] << 32);

        // do hashes for rest of chain links
        assert(NUM_CHAIN_LINKS % 4 == 0);
        for (int c = 1; c < NUM_CHAIN_LINKS / 4; c++) {
            // set up block words (note: first 8 words are still from plot id)
            for (int i = 0; i < 8; i++) {
                block_words[i + 8] = blake.r[i];
            }
            blake = BlakeHash::hash_block_256(block_words);
            result[c * 4 + 0] = blake.r[0] + ((uint64_t)blake.r[1] << 32);
            result[c * 4 + 1] = blake.r[2] + ((uint64_t)blake.r[3] << 32);
            result[c * 4 + 2] = blake.r[4] + ((uint64_t)blake.r[5] << 32);
            result[c * 4 + 3] = blake.r[6] + ((uint64_t)blake.r[7] << 32);
        }

        return result;
    }

    BlakeHash::Result256 challengeWithGroupedPlotIdHash(
        std::span<uint8_t const, 32> const challenge) const
    {
        uint32_t block_words[16];
        std::array<uint8_t, 32> grouped_plot_id = params_.get_grouped_plot_id();
        // Fill the first 8 words with the plot ID.

        // set data from plot id
        for (int i = 0; i < 8; i++) {
            block_words[i] = (static_cast<uint32_t>(grouped_plot_id[i * 4 + 0]))
                | (static_cast<uint32_t>(grouped_plot_id[i * 4 + 1]) << 8)
                | (static_cast<uint32_t>(grouped_plot_id[i * 4 + 2]) << 16)
                | (static_cast<uint32_t>(grouped_plot_id[i * 4 + 3]) << 24);
        }
        // set data from challenge
        for (int i = 0; i < 8; i++) {
            block_words[i + 8] = (static_cast<uint32_t>(challenge[i * 4 + 0]))
                | (static_cast<uint32_t>(challenge[i * 4 + 1]) << 8)
                | (static_cast<uint32_t>(challenge[i * 4 + 2]) << 16)
                | (static_cast<uint32_t>(challenge[i * 4 + 3]) << 24);
        }

        return BlakeHash::hash_block_256(block_words);
    }

private:
    ProofParams params_;
    AesHash aes_;
};

inline uint32_t mask32(int const bits) { return numeric_cast<uint32_t>((uint64_t(1) << bits) - 1); }

//
// -------------------------
// Member function definitions
// -------------------------
//

inline uint32_t ProofHashing::g(uint32_t x)
{
#if HAVE_AES
    return aes_.g_x<false>(x);
#else
    return aes_.g_x<true>(x);
#endif
}

inline uint32_t ProofHashing::matching_target(
    uint32_t table_id, uint32_t match_key, uint64_t meta, int num_target_bits)
{
    // T1 get's extra hashing rounds based on strength.
    int const extra_rounds_bits = (table_id == 1) ? (params_.get_strength() - 2) : 0;
#if HAVE_AES
    return aes_.matching_target<false>(table_id, match_key, meta, extra_rounds_bits)
        & mask32(num_target_bits);
#else
    return aes_.matching_target<true>(
               static_cast<uint32_t>(table_id), match_key, meta, extra_rounds_bits)
        & mask32(num_target_bits);
#endif
}

inline PairingResult ProofHashing::pairing_t1(uint64_t meta_l,
    uint64_t meta_r,
    int num_match_info_bits,
    int out_num_meta_bits,
    int num_test_bits)
{
    assert(num_match_info_bits > 0 && num_match_info_bits <= 32);
    assert(out_num_meta_bits > 0 && out_num_meta_bits <= 64);
    assert(num_test_bits > 0 && num_test_bits <= 32);

    // T1 get's extra hashing rounds based on strength.
    int const extra_rounds_bits = params_.get_strength() - 2;
#if HAVE_AES
    AesHash::Result128 res = aes_.pairing<false>(meta_l, meta_r, extra_rounds_bits);
#else
    AesHash::Result128 res = aes_.pairing<true>(meta_l, meta_r, extra_rounds_bits);
#endif

    PairingResult pr = { 0, 0, 0 };

    if (num_match_info_bits == 32)
        pr.match_info_result = res.r[0];
    else if (num_match_info_bits < 32)
        pr.match_info_result = res.r[0] & mask32(num_match_info_bits);
    else {
        throw std::invalid_argument("num_match_info_bits > 32 not supported");
    }

    if (out_num_meta_bits == 64)
        pr.meta_result = res.r[1] + (static_cast<uint64_t>(res.r[2]) << 32);
    else if (out_num_meta_bits < 64)
        pr.meta_result = (res.r[1] + (static_cast<uint64_t>(res.r[2]) << 32))
            & ((1ULL << out_num_meta_bits) - 1);
    else {
        throw std::invalid_argument("num_bits_meta > 64 not supported");
    }

    uint32_t test_result = res.r[3] & mask32(num_test_bits);
    pr.test_result = test_result;
    return pr;
}

inline PairingResult ProofHashing::pairing_t2(uint64_t meta_l,
    uint64_t meta_r,
    int num_match_info_bits,
    int out_num_meta_bits,
    int num_test_bits)
{
    assert(num_match_info_bits > 0 && num_match_info_bits <= 32);
    assert(out_num_meta_bits > 0 && out_num_meta_bits <= 64);
    assert(num_test_bits >= 0 && num_test_bits <= 32);
#if HAVE_AES
    AesHash::Result128 res = aes_.pairing<false>(meta_l, meta_r);
#else
    AesHash::Result128 res = aes_.pairing<true>(meta_l, meta_r);
#endif

    PairingResult pr = { 0, 0, 0 };

    if (num_match_info_bits == 32)
        pr.match_info_result = res.r[0];
    else if (num_match_info_bits < 32)
        pr.match_info_result = res.r[0] & mask32(num_match_info_bits);
    else {
        throw std::invalid_argument("num_match_info_bits > 32 not supported");
    }

    if (out_num_meta_bits == 64)
        pr.meta_result = res.r[1] + (static_cast<uint64_t>(res.r[2]) << 32);
    else if (out_num_meta_bits < 64)
        pr.meta_result = (res.r[1] + (static_cast<uint64_t>(res.r[2]) << 32))
            & ((1ULL << out_num_meta_bits) - 1);
    else {
        throw std::invalid_argument("num_bits_meta > 64 not supported");
    }

    uint32_t test_result = res.r[3] & mask32(num_test_bits);
    pr.test_result = test_result;
    return pr;
}

inline PairingResult ProofHashing::pairing_t3(uint64_t meta_l, uint64_t meta_r, int num_test_bits)
{
    assert(num_test_bits >= 0 && num_test_bits <= 32);
#if HAVE_AES
    AesHash::Result128 res = aes_.pairing<false>(meta_l, meta_r);
#else
    AesHash::Result128 res = aes_.pairing<true>(meta_l, meta_r);
#endif

    PairingResult pr = { 0, 0, 0 };

    uint32_t test_result = res.r[3] & mask32(num_test_bits);
    pr.test_result = test_result;
    return pr;
}
