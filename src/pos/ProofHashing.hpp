#pragma once

#include <cstdint>
#include <stdexcept>
#include <span>

#include "ProofParams.hpp"
#include "ChachaHash.hpp"
#include "BlakeHash.hpp"


// A simple structure to hold the result of a pairing computation.
struct PairingResult {
    uint32_t match_info_result; // Always present.
    uint64_t meta_result;       // Valid if out_num_meta_bits != 0.
    uint32_t test_result;       // Valid if num_test_bits != 0.
};

class ProofHashing {
public:
    // Constructor.
    // proof_params: a ProofParams instance.
    ProofHashing(const ProofParams& proof_params)
        : params_(proof_params),
          chacha_(proof_params.get_plot_id_bytes(), static_cast<int>(proof_params.get_k())),
          blake_(proof_params.get_plot_id_bytes())
    {
    }

    // Returns a single hash value computed from x.
    uint32_t g(uint32_t x);

    // Populates out_hashes (an array of 16 uint32_t) with hash words starting from x.
    void g_range_16(uint32_t x, uint32_t* out_hashes);

    // Computes and returns the matching target using the Blake hash.
    // table_id: used as salt, match_key, meta: additional parameters.
    // num_meta_bits: number of bits used for meta data.
    // num_target_bits: the number of bits to return from the hash.
    uint32_t matching_target(size_t table_id, uint32_t match_key, uint64_t meta,
                             int num_meta_bits, int num_target_bits);

    // Prepares Blake hash data for pairing and computes the pairing result.
    // in_meta_bits: the number of bits for the input meta data.
    // num_match_info_bits: number of bits for the match info.
    // out_num_meta_bits: number of meta bits desired in the output.
    // num_test_bits: if >0, indicates additional test bits.
    PairingResult pairing(int table_id, uint64_t meta_l, uint64_t meta_r,
                          int in_meta_bits, int num_match_info_bits,
                          int out_num_meta_bits = 0, int num_test_bits = 0);

    // A specialized filter for T3 pairings to rule out non-matching pairs, used when plot strength > 2. Under consideration (not currently used).
    // bool t3_pairing_filter(uint64_t meta_l, uint64_t meta_r, int in_meta_bits, int num_test_bits);

    // Prepares Blake hash data for pairing.
    void set_data_for_pairing(uint32_t salt, uint64_t meta_l, uint64_t meta_r, int num_meta_bits);

    BlakeHash::Result256 challengeWithPlotIdHash(const uint8_t *challenge_32_bytes)
    {   
        uint32_t block_words[16];
        const uint8_t *plot_id_bytes = params_.get_plot_id_bytes();
        // Fill the first 8 words with the plot ID.

        // set data from plot id
        for (int i = 0; i < 8; i++) {
            block_words[i] = 
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 0]))        |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 1]) << 8)   |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 2]) << 16)  |
                (static_cast<uint32_t>(plot_id_bytes[i * 4 + 3]) << 24);
        }
        // set data from challenge
        for (int i = 0; i < 8; i++) {
            block_words[i + 8] = 
                (static_cast<uint32_t>(challenge_32_bytes[i * 4 + 0]))        |
                (static_cast<uint32_t>(challenge_32_bytes[i * 4 + 1]) << 8)   |
                (static_cast<uint32_t>(challenge_32_bytes[i * 4 + 2]) << 16)  |
                (static_cast<uint32_t>(challenge_32_bytes[i * 4 + 3]) << 24);
        }
        
        return BlakeHash::hash_block_256(block_words);
    }

    BlakeHash::Result256 chainHash(BlakeHash::Result256 prev_chain_hash, std::span<uint64_t const, 3> const link_fragments)
    {
        uint32_t block_words[16];
        for (int i = 0; i < 8; i++) {
            block_words[i] = prev_chain_hash.r[i];
        }
        block_words[8] = static_cast<uint32_t>(link_fragments[0] & 0xFFFFFFFF);
        block_words[9] = static_cast<uint32_t>(link_fragments[0] >> 32);
        block_words[10] = static_cast<uint32_t>(link_fragments[1] & 0xFFFFFFFF);
        block_words[11] = static_cast<uint32_t>(link_fragments[1] >> 32);
        block_words[12] = static_cast<uint32_t>(link_fragments[2] & 0xFFFFFFFF);
        block_words[13] = static_cast<uint32_t>(link_fragments[2] >> 32);
        block_words[14] = 0; // Zero out the last two words.
        block_words[15] = 0;

        return BlakeHash::hash_block_256(block_words);
    }

private:
    // Prepares Blake hash data for computing the matching target.
    void _set_data_for_matching_target(uint32_t salt, uint32_t match_key, uint64_t meta, int num_meta_bits);

    ProofParams params_;
    ChachaHash chacha_;
    BlakeHash blake_;
};

inline uint32_t mask32(const int bits) {
    return static_cast<uint32_t>((uint64_t(1) << bits) - 1);
}

//
// -------------------------
// Member function definitions
// -------------------------
//

inline uint32_t ProofHashing::g(uint32_t x) {
    uint32_t x_group = x >> 4;
    uint32_t out_hashes[16];
    chacha_.do_chacha16_range(x_group * 16, out_hashes);
    return out_hashes[x & 15];
}

inline void ProofHashing::g_range_16(uint32_t x, uint32_t* out_hashes) {
    chacha_.do_chacha16_range(x, out_hashes);
}

inline uint32_t ProofHashing::matching_target(size_t table_id, uint32_t match_key,
                                              uint64_t meta, int num_meta_bits, int num_target_bits) {
    // Use table_id as the salt.
    _set_data_for_matching_target(static_cast<uint32_t>(table_id), match_key, meta, num_meta_bits);
    return blake_.generate_hash_32() & mask32(num_target_bits);
}

inline void ProofHashing::_set_data_for_matching_target(uint32_t salt, uint32_t match_key,
                                                         uint64_t meta, int num_meta_bits) {
    blake_.set_data(0, salt);
    blake_.set_data(1, match_key);
    int zero_data_from = 0;
    if (num_meta_bits <= 32) {
        blake_.set_data(2, static_cast<uint32_t>(meta));
        zero_data_from = 3;
    } else if (num_meta_bits <= 64) {
        blake_.set_data(2, static_cast<uint32_t>(meta & 0xFFFFFFFFULL));
        blake_.set_data(3, static_cast<uint32_t>((meta >> 32) & 0xFFFFFFFFULL));
        zero_data_from = 4;
    } else {
        throw std::invalid_argument("Unsupported num_meta_bits");
    }
    for (int i = zero_data_from; i < 8; i++) {
        blake_.set_data(i, 0);
    }
}

inline void ProofHashing::set_data_for_pairing(uint32_t salt, uint64_t meta_l, uint64_t meta_r, int num_meta_bits) {
    blake_.set_data(0, salt);
    int zero_data_from = 0;
    if (num_meta_bits <= 32) {
        blake_.set_data(1, static_cast<uint32_t>(meta_l));
        blake_.set_data(2, static_cast<uint32_t>(meta_r));
        zero_data_from = 3;
    } else if (num_meta_bits <= 64) {
        blake_.set_data(1, static_cast<uint32_t>(meta_l & 0xFFFFFFFFULL));
        blake_.set_data(2, static_cast<uint32_t>((meta_l >> 32) & 0xFFFFFFFFULL));
        blake_.set_data(3, static_cast<uint32_t>(meta_r & 0xFFFFFFFFULL));
        blake_.set_data(4, static_cast<uint32_t>((meta_r >> 32) & 0xFFFFFFFFULL));
        zero_data_from = 5;
    } else {
        throw std::invalid_argument("Unsupported num_meta_bits");
    }
    for (int i = zero_data_from; i < 8; i++) {
        blake_.set_data(i, 0);
    }
}

/*inline bool ProofHashing::t3_pairing_filter(uint64_t meta_l, uint64_t meta_r, int in_meta_bits, int num_test_bits) {

    set_data_for_pairing(3, meta_l, meta_r, in_meta_bits);
    BlakeHash::Result128 res = blake_.generate_hash();
    uint32_t test_result = res.r[3] & mask32(num_test_bits);
    return test_result == 0;
}*/

inline PairingResult ProofHashing::pairing(int table_id, uint64_t meta_l, uint64_t meta_r,
                                           int in_meta_bits, int num_match_info_bits,
                                           int out_num_meta_bits, int num_test_bits) {
    set_data_for_pairing(static_cast<uint32_t>(table_id), meta_l, meta_r, in_meta_bits);
    BlakeHash::Result128 res = blake_.generate_hash();

    PairingResult pr = {0, 0, 0};

    // Special case: table 5 returns only test bits for match filter.
    if (num_match_info_bits == 0 && out_num_meta_bits == 0 && num_test_bits > 0) {
        pr.test_result = res.r[0] & mask32(num_test_bits);
        return pr;
    }

    if (num_match_info_bits == 32)
        pr.match_info_result = res.r[0];
    else if (num_match_info_bits < 32)
        pr.match_info_result = res.r[0] & mask32(num_match_info_bits);
    else {
        // num_match_info_bits > 32
        //match_info_result = (res.r0 | (static_cast<uint64_t>(res.r1) << 32))
        //                    & ((1ULL << num_match_info_bits) - 1);
        throw std::invalid_argument("num_match_info_bits > 32 not supported");
    }

    if (out_num_meta_bits == 0) {
        return pr;
    }

    if (out_num_meta_bits == 64)
        pr.meta_result = res.r[1] + (static_cast<uint64_t>(res.r[2]) << 32);
    else if (out_num_meta_bits < 64)
        pr.meta_result = (res.r[1] + (static_cast<uint64_t>(res.r[2]) << 32))
                      & ((1ULL << out_num_meta_bits) - 1);
    else {
        throw std::invalid_argument("num_bits_meta > 64 not supported");
    }

    if (num_test_bits == 0) {
        return pr;
    }

    uint32_t test_result = res.r[3] & mask32(num_test_bits);
    pr.test_result = test_result;
    return pr;
}
