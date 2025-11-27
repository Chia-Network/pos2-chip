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

#define TOTAL_XS_IN_PROOF 128
#define TOTAL_T3_PAIRS_IN_PROOF 16
#define TOTAL_T2_PAIRS_IN_PROOF 32
#define TOTAL_T1_PAIRS_IN_PROOF 64
#define PROOF_FRAGMENTS_IN_CHAIN 16

//------------------------------------------------------------------------------
// Structs for pairing results
//------------------------------------------------------------------------------

// use retain x values to t3 to make a plot and save x values to disk for analysis
// use BOTH includes to for deeper validation of results
// #define RETAIN_X_VALUES_TO_T3 true
// #define RETAIN_X_VALUES true

// T4 and T5 are bipartite for optimal compression, T3 links back to T2 and T2 to T1 are omitted
// so bipartite is optional. Some notes as to which mode is best:
// - The solver's performance seems slightly better without bipartite
// - plotting could be optimized to be faster using bipartite
// - bipartite may mix less well, and needs more analysis for T4 Partition Attack
// NOTE: when chip goes into review should remove this macro and use the final chosen branched code.
#define NON_BIPARTITE_BEFORE_T3 true

constexpr int NUM_CHAIN_LINKS = 16;
constexpr int AVERAGE_PROOFS_PER_CHALLENGE_BITS = 5; // expected proofs per challenge is 1/2^5 = 1/32.

// first chain link is always passed in from passing fragment scan filter
// while not used in ProofCore due to pre-computed constants, this is the chaining factors used in quality chain math
// and referenced in testing.
constexpr uint64_t CHAINING_FACTORS[NUM_CHAIN_LINKS - 1] = {
    4, 1, 1, 1, 1, 1, 1};//, 1, 1, 1, 1, 1, 1, 1, 1};

// for k sizes 18 to 32 even.
constexpr uint32_t QUALITY_LINK_FIRST_CHAIN_PASS_THRESHOLD[8] = {
    5263856, // k=18, sub_k=15
    5263856, // k=20, sub_k=16
    5263856, // k=22, sub_k=17
    5263856, // k=24, sub_k=18
    5263856, // k=26, sub_k=19
    5263856, // k=28, sub_k=20
    1315964, // k=30, sub_k=22
    1315964  // k=32, sub_k=23
};

constexpr uint32_t QUALITY_LINK_REST_CHAIN_PASS_THRESHOLD[8] = {
    1315964, // k=18, sub_k=15
    1315964, // k=20, sub_k=16
    1315964, // k=22, sub_k=17
    1315964, // k=24, sub_k=18
    1315964, // k=26, sub_k=19
    1315964, // k=28, sub_k=20
    328991,  // k=30, sub_k=22
    328991   // k=32, sub_k=23
};

// constexpr double PROOF_FRAGMENT_SCAN_FILTER = 2.0; // 1 / expected number of fragments to pass scan filter.

enum class FragmentsPattern : uint8_t
{
    OUTSIDE_FRAGMENT_IS_LR = 0, // outside t3 index is RL
    OUTSIDE_FRAGMENT_IS_RR = 1  // outside t3 index is RR
};

// Utility function to convert FragmentsPattern to string
inline std::string FragmentsPatternToString(FragmentsPattern pattern)
{
    switch (pattern)
    {
    case FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR:
        return "OUTSIDE_FRAGMENT_IS_LR";
    case FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR:
        return "OUTSIDE_FRAGMENT_IS_RR";
    default:
        return "UNKNOWN_PATTERN";
    }
}

enum class FragmentsParent : uint8_t
{
    PARENT_NODE_IN_CHALLENGE_PARTITION = 0, // challenge partition is the partition in t3 for proof fragment scan filter
    PARENT_NODE_IN_OTHER_PARTITION = 1      // other partition, is the r-side partition of the proof fragment passing the scan filter
};

enum QualityLinkProofFragmentPositions : size_t
{
    LL = 0, // left left
    LR = 1, // left right
    RL = 2, // right left
    RR = 3  // right right
};

struct QualityLink
{
    // there are 2 patterns: either LR or RR is included in the fragment, but never both.
    std::array<ProofFragment, 3> fragments; // our 3 proof fragments that form a chain, always in order: LL, LR, RL, RR
    FragmentsPattern pattern;
    uint64_t outside_t3_index;
};

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
        // For this version, we ignore bipartite logic.
#ifdef NON_BIPARTITE_BEFORE_T3
        if (table_id <= 3)
        {
            uint32_t match_section = matching_section(section_l);
            if (section_r != match_section)
            {
                // std::cout << "section_l " << section_l << " != match_section " << match_section << std::endl
                //           << "    meta_l: " << meta_l << " match_info_l: " << match_info_l << " match_info_r: " << match_info_r << std::endl;
                return false;
            }
        }
        else
        {
            // use bipartite logic for T4 and T5
            uint32_t section_1;
            uint32_t section_2;
            get_matching_sections(section_l, section_1, section_2);

            if (section_r != section_1 && section_r != section_2)
            {
                // std::cout << "section_r " << section_r << " != section_1 " << section_1 << " and section_2 " << section_2 << std::endl
                //           << "    meta_l: " << meta_l << " match_info_l: " << match_info_l << " match_info_r: " << match_info_r << std::endl;
                return false;
            }
        }
#else
        uint32_t section_1;
        uint32_t section_2;
        get_matching_sections(section_l, section_1, section_2);

        if (section_r != section_1 && section_r != section_2)
        {
            // std::cout << "bipartite section_r " << section_r << " != section_1 " << section_1 << " and section_2 " << section_2 << std::endl
            //           << "    meta_l: " << meta_l << " match_info_l: " << match_info_l << " match_info_r: " << match_info_r << std::endl;
            return false;
        }
#endif

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

    uint32_t quality_chain_pass_threshold(size_t link_index)
    {
        // referencing the constants. The root math works out to:
        // chance = 2 * CHAINING_FACTORS[link_index - 1] / expected_quality_links_set_size();
        // mapped to 32 bits range.
        if (link_index == 1) {
            return QUALITY_LINK_FIRST_CHAIN_PASS_THRESHOLD[(params_.get_k() - 18) / 2];
        }
        return QUALITY_LINK_REST_CHAIN_PASS_THRESHOLD[(params_.get_k() - 18) / 2];
        
    }

    struct SelectedChallengeSets 
    {
        uint32_t fragment_set_A_index;
        uint32_t fragment_set_B_index;
        Range fragment_set_A_range;
        Range fragment_set_B_range;
    };
    SelectedChallengeSets selectChallengeSets(std::array<uint8_t, 32> challenge)
    {
        // challenge sets will be the same withing a grouped plot id
        BlakeHash::Result256 grouped_challenge_hash = hashing.challengeWithGroupedPlotIdHash(challenge.data());
        
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

    // Determines the required fragments pattern based on the challenge.
    FragmentsPattern requiredPatternFromChallenge(BlakeHash::Result256 challenge)
    {
        // if the highest order bit is 0, return RL else return RR
        uint32_t highest_order_bits = challenge.r[3];
        uint32_t highest_order_bit = highest_order_bits >> 31; // get the highest order bit
        if (highest_order_bit == 0)
        {
            return FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;
        }
        return FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;
    }

    // Quality Chaining functions
    BlakeHash::Result256 firstLinkHash(const QualityLink &link, const BlakeHash::Result256 &next_challenge) // const std::array<uint8_t, 32> &challenge)
    {
        // BlakeHash::Result256 challenge_plotid_hash = hashing.challengeWithPlotIdHash(challenge.data());
        return hashing.chainHash(next_challenge, link.fragments);
    }

    struct NewLinksResult
    {
        QualityLink link;
        BlakeHash::Result256 new_hash;
    };

    std::vector<QualityLink> filterLinkSetToPartitions(const std::vector<QualityLink> &link_set, uint32_t lower_partition, uint32_t upper_partition)
    {
        std::vector<QualityLink> filtered_links;
        for (const auto &link : link_set)
        {
            if (link.pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR)
            {
                // bogus for now
                uint32_t lateral_partition = 0;
                uint32_t cross_partition = 1;
                if ((lateral_partition == lower_partition) && (cross_partition == upper_partition))
                {
                    filtered_links.push_back(link);
                }
                else if ((lateral_partition == upper_partition) && (cross_partition == lower_partition))
                {
                    filtered_links.push_back(link);
                }
            }
            else if (link.pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR)
            {
                // bogus for now
                uint32_t lateral_partition = 0;
                uint32_t cross_partition = 1;
                if ((lateral_partition == lower_partition) && (cross_partition == upper_partition))
                {
                    filtered_links.push_back(link);
                }
                else if ((lateral_partition == upper_partition) && (cross_partition == lower_partition))
                {
                    filtered_links.push_back(link);
                }
            }
            else
            {
                throw std::runtime_error("Unknown fragments pattern in filterLinkSetToPartitions");
            }
        }
        return filtered_links;
    }

    std::vector<NewLinksResult> getNewLinksForChain(BlakeHash::Result256 current_challenge, const std::vector<QualityLink> &link_set, size_t link_index) // , uint32_t lower_partition, uint32_t upper_partition)
    {
        uint32_t qc_pass_threshold = quality_chain_pass_threshold(link_index);

        FragmentsPattern pattern = requiredPatternFromChallenge(current_challenge);

        std::vector<NewLinksResult> new_links;
        for (QualityLink const &link : link_set)
        {
            if (link.pattern != pattern)
            {
                // skip links that do not match the required pattern
                continue;
            }

            // test the hash
            BlakeHash::Result256 next_challenge = hashing.chainHash(current_challenge, link.fragments);
            if (next_challenge.r[0] < qc_pass_threshold)
            {
                new_links.push_back({link, next_challenge});
            }
        }
        return new_links;
    }

    ProofParams getProofParams() const
    {
        return params_;
    }

    uint32_t quality_chain_pass_threshold_ = 0;

private:
    ProofParams params_;
};
