#pragma once

#include <cstdint>
#include <stdexcept>
#include <tuple>
#include <iostream>
#include <optional>
#include <limits>

#include "ProofParams.hpp"
#include "ProofHashing.hpp"
#include "ProofFragment.hpp"

//------------------------------------------------------------------------------
// Structs for pairing results
//------------------------------------------------------------------------------

// use retain x values to t3 to make a plot and save x values to disk for analysis
// use BOTH includes to for deeper validation of results
//#define RETAIN_X_VALUES_TO_T3 true
//#define RETAIN_X_VALUES true

// T4 and T5 are bipartite for optimal compression, T3 links back to T2 and T2 to T1 are omitted
// so bipartite is optional. Some notes as to which mode is best:
// - The solver's performance seems slightly better without bipartite
// - plotting could be optimized to be faster using bipartite
// - bipartite may mix less well, and needs more analysis for T4 Partition Attack
#define NON_BIPARTITE_BEFORE_T3 true

// use to reduce T4/T5 relative to T3, T4 and T5 will be approx same size.
// #define T3_FACTOR_T4_T5_EVEN 1

const uint32_t FINAL_TABLE_FILTER = 855570511; // out of 2^32
const double FINAL_TABLE_FILTER_D = 0.19920303275; 

// define this if want quality chain to pass more up front, then less in subsequent passes
// this helps distribution of number of quality chains to be more compact.0.
#define USE_UPFRONT_CHAINING_FACTOR true

constexpr int NUM_CHAIN_LINKS = 16;

#ifdef USE_UPFRONT_CHAINING_FACTOR
// first chain link is always passed in from passing fragment scan filter
constexpr double CHAINING_FACTORS[NUM_CHAIN_LINKS-1] = {
    4.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.25,
    //1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1
};
#else
constexpr double CHAINING_FACTOR = 1.1;
#endif

constexpr double PROOF_FRAGMENT_SCAN_FILTER = 2.0; // 1 / expected number of fragments to pass scan filter.


enum class FragmentsPattern : uint8_t
{
    OUTSIDE_FRAGMENT_IS_LR = 0, // outside t3 index is RL
    OUTSIDE_FRAGMENT_IS_RR = 1  // outside t3 index is RR
};

enum class FragmentsParent : uint8_t
{
    PARENT_NODE_IN_CHALLENGE_PARTITION = 0, // challenge partition is the partition in t3 for proof fragment scan filter
    PARENT_NODE_IN_OTHER_PARTITION = 1      // other partition, is the r-side partition of the proof fragment passing the scan filter
};

enum class QualityLinkProofFragmentPositions : int
{
    LL = 0, // left left
    LR = 1, // left right
    RL = 2, // right left
    RR = 3  // right right
};

struct QualityLink
{
    // there are 2 patterns: either LR or RR is included in the fragment, but never both.
    ProofFragment fragments[3]; // our 3 proof fragments that form a chain, always in order: LL, LR, RL, RR
    FragmentsPattern pattern;
    uint64_t outside_t3_index;
};

struct QualityChain
{
    std::array<QualityLink, NUM_CHAIN_LINKS> chain_links;
    BlakeHash::Result256 chain_hash;
};

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
    ProofFragment proof_fragment;               // 2k-bit encrypted x-values.
    uint64_t meta_lower_partition;                       // 2k-bit meta.
    uint64_t meta_upper_partition;
    uint32_t match_info_lower_partition; // sub_k bits (from lower partition).
    uint32_t match_info_upper_partition; // sub_k bits (from upper partition).
    uint32_t lower_partition;            // (k - sub_k) bits.
    uint32_t upper_partition;            // (k - sub_k) bits.
    uint32_t order_bits;                 // 2-bit order field.
#ifdef RETAIN_X_VALUES_TO_T3
    uint32_t xs[8];
#endif
};

// Split from T3Pairing, 2 for 1
struct T3PartitionedPairing
{
    uint64_t meta;
    uint64_t fragment_index;
    uint32_t match_info; // sub_k bits
    uint32_t order_bits;
#ifdef RETAIN_X_VALUES
    uint32_t xs[8];
#endif
};

struct T4Pairing
{
    uint64_t meta; // 2k-bit meta value.
    uint64_t fragment_index_l;
    uint64_t fragment_index_r;
    uint32_t match_info; // sub_k-bit match info.
#ifdef RETAIN_X_VALUES
    uint32_t xs[16];
#endif
};

struct T4BackPointers
{
    uint64_t fragment_index_l;
    uint64_t fragment_index_r;
#ifdef RETAIN_X_VALUES
    uint32_t xs[16];
#endif

    bool operator==(T4BackPointers const &o) const = default;
};

struct T4PairingPropagation
{
    uint64_t meta;       // 2k-bit meta value.
    uint32_t match_info; // sub_k-bit match info.
    uint32_t t4_back_pointer_index;
#ifdef RETAIN_X_VALUES
    uint32_t xs[16];
#endif
};

struct T5Pairing
{
    uint32_t t4_index_l;
    uint32_t t4_index_r;
#ifdef RETAIN_X_VALUES
    uint32_t xs[32];
#endif

    bool operator==(T5Pairing const &o) const = default;
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
        : params_(proof_params),
          hashing(proof_params),
          fragment_codec(proof_params)
    {
    }

    // matching_target:
    // Returns a hash value (as uint64_t) computed from meta and match_key.
    uint32_t matching_target(int table_id, uint64_t meta, uint32_t match_key)
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
        if (params_.get_num_match_key_bits(1) == 4) {
            if (!match_filter_16(x_l & 0xFFFFU, x_r & 0xFFFFU)) 
                return std::nullopt;
        }
        else if (params_.get_num_match_key_bits(1) == 2) {
            if (!match_filter_4(x_l & 0xFFFFU, x_r & 0xFFFFU)) 
                return std::nullopt;
        }
        else {
            std::cerr << "pairing_t1: match_filter_4 not supported for this table." << std::endl;
            exit(1);
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
    std::optional<T2Pairing> pairing_t2(uint64_t meta_l, uint64_t meta_r)
    {
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
        uint32_t x_bits_l = ((meta_l >> params_.get_k()) >> half_k);
        uint32_t x_bits_r = ((meta_r >> params_.get_k()) >> half_k);
        result.x_bits = (x_bits_l << half_k) | x_bits_r;
        return result;
    }

    // pairing_t3:
    // Input: meta_l, meta_r (each 2k bits), x_bits_l, x_bits_r (each k bits).
    // Returns: a T3Pairing struct with lower/upper partition, partition-specific match_info,
    // meta, order bits, and the full proof fragments.
    std::optional<T3Pairing> pairing_t3(uint64_t meta_l, uint64_t meta_r, uint32_t x_bits_l, uint32_t x_bits_r)
    {
        if (!match_filter_4(static_cast<uint32_t>(meta_l & 0xFFFFU),
                            static_cast<uint32_t>(meta_r & 0xFFFFU)))
            return std::nullopt;

        uint64_t all_x_bits = (static_cast<uint64_t>(x_bits_l) << params_.get_k()) | x_bits_r;
        ProofFragment proof_fragment = fragment_codec.encode(all_x_bits);
        uint32_t order_bits = fragment_codec.extract_t3_order_bits(proof_fragment);
        uint32_t top_order_bit = order_bits >> 1;
        uint32_t lower_partition, upper_partition;

        if (top_order_bit == 0)
        {
            lower_partition = fragment_codec.extract_t3_l_partition_bits(proof_fragment);
            upper_partition = fragment_codec.extract_t3_r_partition_bits(proof_fragment) + params_.get_num_partitions();
        }
        else
        {
            lower_partition = fragment_codec.extract_t3_r_partition_bits(proof_fragment);
            upper_partition = fragment_codec.extract_t3_l_partition_bits(proof_fragment) + params_.get_num_partitions();
        }


        PairingResult lower_partition_pair = hashing.pairing(3, meta_l, meta_r,
                                             static_cast<int>(params_.get_num_pairing_meta_bits()),
                                             static_cast<int>(params_.get_sub_k()) - 1,
                                             static_cast<int>(params_.get_num_pairing_meta_bits()));

        PairingResult upper_partition_pair = hashing.pairing(~3, meta_l, meta_r,
                                            static_cast<int>(params_.get_num_pairing_meta_bits()),
                                            static_cast<int>(params_.get_sub_k()) - 1,
                                            static_cast<int>(params_.get_num_pairing_meta_bits()));

        // TODO: this can be bitpacked much better
        T3Pairing result;

        result.proof_fragment = proof_fragment;
        result.order_bits = order_bits;

        result.lower_partition = lower_partition;
        result.meta_lower_partition = lower_partition_pair.meta_result;
        result.match_info_lower_partition = (top_order_bit << (params_.get_sub_k() - 1)) | lower_partition_pair.match_info_result;
        
        result.upper_partition = upper_partition;
        result.meta_upper_partition = upper_partition_pair.meta_result;
        result.match_info_upper_partition = ((1 - top_order_bit) << (params_.get_sub_k() - 1)) | upper_partition_pair.match_info_result;
        return result;
    }

    // pairing_t4:
    // Input: meta_l, meta_r (each 2k bits), order_bits_l, order_bits_r (each 2 bits).
    // Returns: a T4Pairing with match_info (sub_k bits) and meta (2k bits).
    std::optional<T4Pairing> pairing_t4(uint64_t meta_l, uint64_t meta_r, uint32_t order_bits_l, uint32_t order_bits_r)
    {
#if defined(T3_FACTOR_T4_T5_EVEN)
        int num_test_bits = 32;
#else
        // shrink output by 50% by using 1 bit larger than num match bits.
        int num_test_bits = params_.get_num_match_key_bits(4) + 1;
#endif
        PairingResult pair = hashing.pairing(4, meta_l, meta_r,
                                             static_cast<int>(params_.get_num_pairing_meta_bits()),
                                             static_cast<int>(params_.get_k()) - 1,
                                             static_cast<int>(params_.get_num_pairing_meta_bits()),
                                             num_test_bits);

#if defined(T3_FACTOR_T4_T5_EVEN)
        double threshold_double = (4294967296 / 8) * T3_FACTOR_T4_T5_EVEN;
        unsigned long threshold = static_cast<unsigned long>(threshold_double);
        if (pair.test_result > threshold)
            return std::nullopt;
#else
        if (pair.test_result > 0)
            return std::nullopt;
#endif
        T4Pairing result;
        result.match_info = pair.match_info_result;
        result.meta = pair.meta_result;
        uint32_t top_bit = order_bits_l & 1;
        result.match_info = (top_bit << (params_.get_k() - 1)) | result.match_info;
        return result;
    }

    // pairing_t5:
    // Input: meta_l and meta_r (each 2k bits).
    // Returns true if the pairing filter passes (i.e. test bits are zero), false otherwise.
    bool pairing_t5(uint64_t meta_l, uint64_t meta_r)
    {
        // filter_test_bits is 32 bits of hash, the chance of passing is 0.1992030328 or 855570511 out of 2^32
        // this will result in T3 onwards being at same sizes after pruning.
        int num_test_bits = 32;
        PairingResult pair = hashing.pairing(5, meta_l, meta_r,
                                             static_cast<int>(params_.get_num_pairing_meta_bits()),
                                             0, 0, num_test_bits);

        // adjust the final table so that T3/4/5 will prune to the same # of entries each.
        if (pair.test_result >= (FINAL_TABLE_FILTER << 1))
            return false;
        return true;

        /*
        // below does parity matching, T5 will have more entries than T4/3.
        int num_test_bits = params_.get_num_match_key_bits(5) - 1;
        PairingResult pair = hashing.pairing(5, meta_l, meta_r,
                                             static_cast<int>(params_.get_num_pairing_meta_bits()),
                                             0, 0, num_test_bits);

        return (pair.test_result == 0);*/
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
            int match_section = matching_section(section_l);
            if (section_r != match_section)
            {
                //std::cout << "section_l " << section_l << " != match_section " << match_section << std::endl
                //          << "    meta_l: " << meta_l << " match_info_l: " << match_info_l << " match_info_r: " << match_info_r << std::endl;
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
                //std::cout << "section_r " << section_r << " != section_1 " << section_1 << " and section_2 " << section_2 << std::endl
                //          << "    meta_l: " << meta_l << " match_info_l: " << match_info_l << " match_info_r: " << match_info_r << std::endl;
                return false;
            }
        }
#else
        uint32_t section_1;
        uint32_t section_2;
        get_matching_sections(section_l, section_1, section_2);

        if (section_r != section_1 && section_r != section_2)
        {
            //std::cout << "bipartite section_r " << section_r << " != section_1 " << section_1 << " and section_2 " << section_2 << std::endl
            //          << "    meta_l: " << meta_l << " match_info_l: " << match_info_l << " match_info_r: " << match_info_r << std::endl;
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

    double num_expected_pruned_entries_for_t3() {
        double k_entries = (double) (1UL << params_.get_k());
        double t3_entries = (FINAL_TABLE_FILTER_D / 0.25)*k_entries;
        return t3_entries;
    }

    double expected_quality_links_set_size() {
        double entries_per_partition = num_expected_pruned_entries_for_t3() / (double) params_.get_num_partitions();
        return 2.0 * entries_per_partition / (double) params_.get_num_partitions();
    }

    static double expected_number_of_quality_chains_per_passing_fragment() {
        // chaining_factor ^ (num_chain_links-1)
        #ifdef USE_UPFRONT_CHAINING_FACTOR
            double expected = CHAINING_FACTORS[0];
            for (int i = 1; i < NUM_CHAIN_LINKS-1; ++i) {
                expected *= CHAINING_FACTORS[i];
            }
            return expected;
        #else
            return pow(CHAINING_FACTOR, NUM_CHAIN_LINKS - 1);
        #endif
    }

    // depth 0 is first quality link added by passsing fragment scan filter
    // depth 1 starts using CHAINING_FACTORS[0] and so on.
    uint32_t quality_chain_pass_threshold(int depth) {
        // 1) compute pass probability
        #ifdef USE_UPFRONT_CHAINING_FACTOR
        double chance = CHAINING_FACTORS[depth-1] / expected_quality_links_set_size();
        #else
        double chance = CHAINING_FACTOR / expected_quality_links_set_size();
        #endif

        // 2) use long double for extra precision
        long double max_uint32 = static_cast<long double>(std::numeric_limits<uint32_t>::max());

        // 3) compute raw threshold
        long double raw = chance * max_uint32;

        // 4) clamp to avoid overflow
        if (raw >= max_uint32) {
            raw = max_uint32;
        }

        if (false) {
            // debug output
            std::cout << "Num expected links for t3: " << (int) num_expected_pruned_entries_for_t3() << std::endl;
            std::cout << "num_partitions: " << params_.get_num_partitions() << std::endl;
            std::cout << "expected_quality_links_set_size: " << (int) expected_quality_links_set_size() << std::endl;
            std::cout << "chance: " << chance << std::endl;
            std::cout << "raw threshold: " << raw << std::endl;
            std::cout << "clamped threshold: " << raw << std::endl;
        }

        // 5) round to nearest integer and return
        return static_cast<uint32_t>(raw + 0.5L);
    }

    // Quality Chaining functions
    BlakeHash::Result256 firstLinkHash(const QualityLink &link, const std::array<uint8_t, 32> &challenge)
    {
        BlakeHash::Result256 challenge_plotid_hash = hashing.challengeWithPlotIdHash(challenge.data());
        return hashing.chainHash(challenge_plotid_hash, link.fragments);
    }

    struct NewLinksResult {
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
                uint32_t lateral_partition = fragment_codec.get_lateral_to_t4_partition(link.fragments[2]); // the RR fragment
                uint32_t cross_partition = fragment_codec.get_r_t4_partition(link.fragments[2]); // the RR fragment
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
                uint32_t lateral_partition = fragment_codec.get_lateral_to_t4_partition(link.fragments[1]); // the LR fragment
                uint32_t cross_partition = fragment_codec.get_r_t4_partition(link.fragments[1]); // the LR fragment
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

    std::vector<NewLinksResult> getNewLinksForChain(BlakeHash::Result256 current_hash, const std::vector<QualityLink> &link_set, int depth) // , uint32_t lower_partition, uint32_t upper_partition)
    {
        uint32_t qc_pass_threshold = quality_chain_pass_threshold(depth);
        // initialize threshold on first use
        //if (quality_chain_pass_threshold_ == 0) {
        //    quality_chain_pass_threshold_ = quality_chain_pass_threshold();
        //}

        std::vector<NewLinksResult> new_links;
        for (int i = 0; i < link_set.size(); ++i)
        {
            const QualityLink &link = link_set[i];

            // test the hash
            BlakeHash::Result256 new_hash = hashing.chainHash(current_hash, link.fragments);
            if (new_hash.r[0] < qc_pass_threshold)
            {
                new_links.push_back({link, new_hash});
            }
        }
        return new_links;
    }

    ProofParams getProofParams() const {
        return params_;
    }

    uint32_t quality_chain_pass_threshold_ = 0;
private:
    
    ProofParams params_;
};
