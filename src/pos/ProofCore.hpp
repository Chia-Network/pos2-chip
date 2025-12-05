#pragma once

#include <cstdint>
#include <stdexcept>
#include <tuple>
#include <iostream>
#include <optional>
#include <limits>
#include <vector>

#include "ProofParams.hpp"
#include "ProofHashing.hpp"
#include "ProofFragment.hpp"

constexpr int TOTAL_XS_IN_PROOF = 128;
constexpr int TOTAL_T1_PAIRS_IN_PROOF = 64;
constexpr int TOTAL_T2_PAIRS_IN_PROOF = 32;
constexpr int TOTAL_T3_PAIRS_IN_PROOF = 16;
constexpr int TOTAL_PROOF_FRAGMENTS_IN_PROOF = 16;
//------------------------------------------------------------------------------
// Structs for pairing results
//------------------------------------------------------------------------------

// use retain x values to make a plot and save x values to disk for analysis
// use BOTH includes to for deeper validation of results
// #define RETAIN_X_VALUES_TO_T3 true
// #define RETAIN_X_VALUES true

constexpr int NUM_CHAIN_LINKS = 16;
constexpr int AVERAGE_PROOFS_PER_CHALLENGE_BITS = 5; // expected proofs per challenge is 1/2^5 = 1/32.

using QualityChainLinks = std::array<ProofFragment, NUM_CHAIN_LINKS>;

struct QualityChain
{
    QualityChainLinks chain_links;
    uint8_t strength;
};

// chaining
// A chain: list of challenges and the corresponding chosen proof fragments.
struct Chain
{
    std::array<ProofFragment, NUM_CHAIN_LINKS> fragments;      // the proof fragments used in the chain
};

// chaining end 

struct T1Pairing
{
    uint64_t meta;       // 2k-bit meta value.
    uint32_t match_info; // k-bit match info.
};

struct T2Pairing
{
    uint64_t meta;       // 2k-bit meta value.
    uint32_t match_info; // k-bit match info.
    uint32_t x_bits;     // k-bit x bits.
#ifdef RETAIN_X_VALUES_TO_T3
    uint32_t xs[4];
#endif
};

struct T3Pairing
{
    ProofFragment proof_fragment;  // 2k-bit encrypted x-values.
#ifdef RETAIN_X_VALUES_TO_T3
    uint32_t xs[8];
#endif
};

//------------------------------------------------------------------------------
// ProofCore Class
//------------------------------------------------------------------------------

class ProofCore
{
public:
    ProofHashing hashing;
    ProofFragmentCodec fragment_codec;

    // Constructor: Initializes internal ProofHashing and ProofFragmentCodec objects.
    ProofCore(const ProofParams &proof_params)
        : hashing(proof_params),
          fragment_codec(proof_params),
          params_(proof_params)
    {
    }

    // matching_target:
    // Returns a hash value (as uint64_t) computed from meta and match_key.
    uint32_t matching_target(size_t table_id, uint64_t meta, uint32_t match_key)
    {
        size_t num_match_target_bits = params_.get_num_match_target_bits(table_id);
        size_t num_meta_bits = params_.get_num_meta_bits(table_id);
        return hashing.matching_target(table_id, match_key, meta,
                                       static_cast<int>(num_meta_bits),
                                       static_cast<int>(num_match_target_bits));
    }

    // pairing_t1:
    // Input: x_l and x_r (each k bits).
    // Returns: a T1Pairing with match_info (k bits) and meta (2k bits).
    std::optional<T1Pairing> pairing_t1(uint32_t x_l, uint32_t x_r)
    {
        // fast test for matching to speed up solver.
        /*if (params_.get_num_match_key_bits(1) == 4)
        {
            if (!match_filter_16(x_l & 0xFFFFU, x_r & 0xFFFFU))
                return std::nullopt;
        }
        else */
        if (params_.get_num_match_key_bits(1) == 2)
        {
            if (!match_filter_4(x_l & 0xFFFFU, x_r & 0xFFFFU))
                return std::nullopt;
        }
        else
        {
            std::cerr << "pairing_t1: match_filter not supported for this table." << std::endl;
            abort();
        }

        PairingResult pair = hashing.pairing(1, x_l, x_r,
                                             static_cast<int>(params_.get_k()),
                                             static_cast<int>(params_.get_k()));

        T1Pairing result =
            {
                .meta = static_cast<uint64_t>(x_l) << params_.get_k() | x_r,
                .match_info = pair.match_info_result};

        return result;
    }

    // pairing_t2:
    // Input: meta_l and meta_r (each 2k bits).
    // Returns: a T2Pairing with match_info (k bits), meta (2k bits), and x_bits (k bits).
    std::optional<T2Pairing> pairing_t2(const uint64_t meta_l, uint64_t meta_r)
    {
        assert(params_.get_num_match_key_bits(2) == 2);
        if (!match_filter_4(static_cast<uint32_t>(meta_l & 0xFFFFU),
                            static_cast<uint32_t>(meta_r & 0xFFFFU)))
            return std::nullopt;
        uint64_t in_meta_bits = params_.get_num_pairing_meta_bits();
        PairingResult pair = hashing.pairing(2, meta_l, meta_r,
                                             static_cast<int>(in_meta_bits),
                                             static_cast<int>(params_.get_k()),
                                             static_cast<int>(in_meta_bits));
        T2Pairing result;
        result.match_info = pair.match_info_result;
        result.meta = pair.meta_result;
        uint32_t half_k = params_.get_k() / 2;
        uint32_t x_bits_l = numeric_cast<uint32_t>((meta_l >> params_.get_k()) >> half_k);
        uint32_t x_bits_r = numeric_cast<uint32_t>((meta_r >> params_.get_k()) >> half_k);
        result.x_bits = (x_bits_l << half_k) | x_bits_r;
        return result;
    }

    // pairing_t3:
    // Input: meta_l, meta_r (each 2k bits), x_bits_l, x_bits_r (each k bits).
    // Returns: a T3Pairing struct with lower/upper partition, partition-specific match_info,
    // meta, order bits, and the full proof fragments.
    std::optional<T3Pairing> pairing_t3(uint64_t meta_l, uint64_t meta_r, uint32_t x_bits_l, uint32_t x_bits_r)
    {
        int num_test_bits = params_.get_num_match_key_bits(3); // synonymous with get_strength()
        /*
        // commented out is an alternative explicit filter that would slow down plotting but not necessarily improve attack resistance significantly.
        if (!hashing.t3_pairing_filter(meta_l, meta_r,
                                    static_cast<int>(params_.get_num_pairing_meta_bits()),
                                    params_.get_num_match_key_bits(3)))
            return std::nullopt;
        */

        PairingResult pair = hashing.pairing(3, meta_l, meta_r,
                                                             static_cast<int>(params_.get_num_pairing_meta_bits()),
                                                             0,
                                                             0,
                                                             num_test_bits);

        // pairing filter test
        if (pair.test_result != 0)
            return std::nullopt;

        uint64_t all_x_bits = (static_cast<uint64_t>(x_bits_l) << params_.get_k()) | x_bits_r;
        ProofFragment proof_fragment = fragment_codec.encode(all_x_bits);
        
        T3Pairing result;
        result.proof_fragment = proof_fragment;
        return result;
    }

    // validate_match_info_pairing:
    // Validates that match_info pairing is correct by comparing extracted sections and targets.
    bool validate_match_info_pairing(int table_id, uint64_t meta_l, uint32_t match_info_l, uint32_t match_info_r)
    {
        uint32_t section_l = params_.extract_section_from_match_info(table_id, match_info_l);
        uint32_t section_r = params_.extract_section_from_match_info(table_id, match_info_r);
        
        uint32_t match_section = matching_section(section_l);
        if (section_r != match_section)
        {
                // std::cout << "section_l " << section_l << " != match_section " << match_section << std::endl
                //           << "    meta_l: " << meta_l << " match_info_l: " << match_info_l << " match_info_r: " << match_info_r << std::endl;
            return false;
        }

        uint32_t match_key_r = params_.extract_match_key_from_match_info(table_id, match_info_r);
        uint32_t match_target_r = params_.extract_match_target_from_match_info(table_id, match_info_r);
        if (match_target_r != matching_target(table_id, meta_l, match_key_r))
        {
            // std::cout << "match_target_r " << match_target_r
            //           << " != matching_target(" << table_id << ", " << meta_l << ", " << match_key_r << ")" << std::endl;
            return false;
        }
        return true;
    }

    // matching_section: Given a section, returns its matching section.
    uint32_t matching_section(uint32_t section)
    {
        uint32_t num_section_bits = params_.get_num_section_bits();
        uint32_t num_sections = params_.get_num_sections();
        uint32_t rotated_left = (section << 1) | (section >> (num_section_bits - 1));
        uint32_t rotated_left_plus_1 = (rotated_left + 1) & (num_sections - 1);
        uint32_t section_new = (rotated_left_plus_1 >> 1) | (rotated_left_plus_1 << (num_section_bits - 1));
        return section_new & (num_sections - 1);
    }

    // inverse_matching_section: Returns the inverse matching section.
    uint32_t inverse_matching_section(uint32_t section)
    {
        uint32_t num_section_bits = params_.get_num_section_bits();
        uint32_t num_sections = params_.get_num_sections();
        uint32_t rotated_left = ((section << 1) | (section >> (num_section_bits - 1))) & (num_sections - 1);
        uint32_t rotated_left_minus_1 = (rotated_left - 1) & (num_sections - 1);
        uint32_t section_l = ((rotated_left_minus_1 >> 1) | (rotated_left_minus_1 << (num_section_bits - 1))) & (num_sections - 1);
        return section_l;
    }

    // get_matching_sections: Returns two matching sections via output parameters.
    void get_matching_sections(uint32_t section, uint32_t &section1, uint32_t &section2)
    {
        section1 = matching_section(section);
        section2 = inverse_matching_section(section);
    }

    // Static match filters:
    static bool match_filter_16(uint32_t x, uint32_t y)
    {
        uint32_t v = (x + y) & 0xFFFFU;
        v = v * v;
        uint32_t r = 0;
        r ^= v >> 24;
        r ^= v >> 17;
        r ^= v >> 11;
        r ^= v >> 4;
        return (r & 15U) == 1;
    }

    static bool match_filter_4(uint32_t x, uint32_t y)
    {
        uint32_t v = (x + y) & 0xFFFFU;
        v = v * v;
        uint32_t r = 0;
        r ^= v >> 25;
        r ^= v >> 16;
        r ^= v >> 10;
        r ^= v >> 2;
        return (((r >> 2) + r) & 3U) == 2;
    }

    struct SelectedChallengeSets 
    {
        uint32_t fragment_set_A_index;
        uint32_t fragment_set_B_index;
        Range fragment_set_A_range;
        Range fragment_set_B_range;
    };
    SelectedChallengeSets selectChallengeSets(std::span<uint8_t const, 32> const challenge)
    {
        // challenge sets will be the same withing a grouped plot id
        BlakeHash::Result256 grouped_challenge_hash = hashing.challengeWithGroupedPlotIdHash(challenge);
        
        // use bits from challenge to select two distinct chaining sets
        uint32_t num_chaining_sets_bits = params_.get_num_chaining_sets_bits();

        // fragments are guaranteed to be different by forcing one even and one odd index
        // get first set index from lower bits, but always even (0 on lsb)
        uint32_t fragment_set_A_index = (grouped_challenge_hash.r[0] & ((1U << num_chaining_sets_bits) - 1)) & ~1U;
        // get second set index from lower of next 32 bits, and always odd (1 on lsb)
        uint32_t fragment_set_B_index = (grouped_challenge_hash.r[1] & ((1U << num_chaining_sets_bits) - 1)) | 1U;
        
        Range fragment_set_A_range = params_.get_chaining_set_range(fragment_set_A_index);
        Range fragment_set_B_range = params_.get_chaining_set_range(fragment_set_B_index);
        
        return {fragment_set_A_index, fragment_set_B_index, fragment_set_A_range, fragment_set_B_range};
    }

    ProofParams getProofParams() const
    {
        return params_;
    }

    uint32_t quality_chain_pass_threshold_ = 0;

private:
    ProofParams params_;
};
