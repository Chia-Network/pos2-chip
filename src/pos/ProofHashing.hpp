#pragma once

#include <cstdint>
#include <stdexcept>

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
    uint32_t matching_target(int table_id, uint32_t match_key, uint64_t meta,
                             int num_meta_bits, int num_target_bits);

    // Prepares Blake hash data for pairing and computes the pairing result.
    // in_meta_bits: the number of bits for the input meta data.
    // num_match_info_bits: number of bits for the match info.
    // out_num_meta_bits: number of meta bits desired in the output.
    // num_test_bits: if >0, indicates additional test bits.
    PairingResult pairing(int table_id, uint64_t meta_l, uint64_t meta_r,
                          int in_meta_bits, int num_match_info_bits,
                          int out_num_meta_bits = 0, int num_test_bits = 0);

    // Prepares Blake hash data for pairing.
    void set_data_for_pairing(uint32_t salt, uint64_t meta_l, uint64_t meta_r, int num_meta_bits);

private:
    // Prepares Blake hash data for computing the matching target.
    void _set_data_for_matching_target(uint32_t salt, uint32_t match_key, uint64_t meta, int num_meta_bits);

    ProofParams params_;
    ChachaHash chacha_;
    BlakeHash blake_;
};

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

inline uint32_t ProofHashing::matching_target(int table_id, uint32_t match_key,
                                              uint64_t meta, int num_meta_bits, int num_target_bits) {
    // Use table_id as the salt.
    _set_data_for_matching_target(static_cast<uint32_t>(table_id), match_key, meta, num_meta_bits);
    BlakeHash::BlakeHashResult res = blake_.generate_hash();

    uint32_t match_target_bits = 0;
    if (num_target_bits == 32) {
        match_target_bits = res.r0;
    } else if (num_target_bits < 32) {
        match_target_bits = res.r0 & ((1ULL << num_target_bits) - 1);
    } else {
        throw std::invalid_argument("num_target_bits > 32 not supported");
    }
    return match_target_bits;
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

inline PairingResult ProofHashing::pairing(int table_id, uint64_t meta_l, uint64_t meta_r,
                                           int in_meta_bits, int num_match_info_bits,
                                           int out_num_meta_bits, int num_test_bits) {
    set_data_for_pairing(static_cast<uint32_t>(table_id), meta_l, meta_r, in_meta_bits);
    BlakeHash::BlakeHashResult res = blake_.generate_hash();

    PairingResult pr = {0, 0, 0};

    // Special case: table 5 returns only test bits for match filter.
    if (num_match_info_bits == 0 && out_num_meta_bits == 0 && num_test_bits > 0) {
        pr.test_result = res.r0 & ((1ULL << num_test_bits) - 1);
        return pr;
    }

    if (num_match_info_bits == 32)
        pr.match_info_result = res.r0;
    else if (num_match_info_bits < 32)
        pr.match_info_result = res.r0 & ((1ULL << num_match_info_bits) - 1);
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
        pr.meta_result = res.r1 + (static_cast<uint64_t>(res.r2) << 32);
    else if (out_num_meta_bits < 64)
        pr.meta_result = (res.r1 + (static_cast<uint64_t>(res.r2) << 32))
                      & ((1ULL << out_num_meta_bits) - 1);
    else {
        throw std::invalid_argument("num_bits_meta > 64 not supported");
    }

    if (num_test_bits == 0) {
        return pr;
    }

    uint32_t test_result = res.r3 & ((1ULL << num_test_bits) - 1);
    pr.test_result = test_result;
    return pr;
}
