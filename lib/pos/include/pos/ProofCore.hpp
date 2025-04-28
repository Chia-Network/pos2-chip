#pragma once

#include <pos/ProofParams.hpp>
#include <pos/ProofHashing.hpp>
#include <pos/XsEncryptor.hpp>

#include <cstdint>
#include <stdexcept>
#include <tuple>
#include <iostream>
#include <optional>

//------------------------------------------------------------------------------
// Structs for pairing results
//------------------------------------------------------------------------------

// use retain x values to t3 to make a plot and save x values to disk for analysis
// use BOTH includes to for deeper validation of results
//#define RETAIN_X_VALUES_TO_T3 true
//#define RETAIN_X_VALUES true

// use to reduce T4/T5 relative to T3, T4 and T5 will be approx same size.
//#define T3_FACTOR_T4_T5_EVEN 1

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
    uint64_t encrypted_xs;          // 2k-bit encrypted x-values.
    uint64_t meta;                  // 2k-bit meta.
    uint32_t match_info_lower_partition; // sub_k bits (from lower partition).
    uint32_t match_info_upper_partition; // sub_k bits (from upper partition).
    uint32_t lower_partition;       // (k - sub_k) bits.
    uint32_t upper_partition;       // (k - sub_k) bits.
    uint32_t order_bits;            // 2-bit order field.
#ifdef RETAIN_X_VALUES_TO_T3
    uint32_t xs[8];
#endif
};

// Split from T3Pairing, 2 for 1
struct T3PartitionedPairing
{
    uint64_t meta;
    uint64_t encx_index;
    uint32_t match_info; // sub_k bits
    uint32_t order_bits;
    #ifdef RETAIN_X_VALUES
    uint32_t xs[8];
    #endif   
};

struct T4Pairing
{
    uint64_t meta;       // 2k-bit meta value.
    uint64_t encx_index_l;
    uint64_t encx_index_r;
    uint32_t match_info; // sub_k-bit match info.
#ifdef RETAIN_X_VALUES
    uint32_t xs[16];
#endif
};

struct T4BackPointers
{
    uint64_t encx_index_l;
    uint64_t encx_index_r;
    #ifdef RETAIN_X_VALUES
    uint32_t xs[16];
    #endif

    bool operator==(T4BackPointers const& o) const = default;
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

    bool operator==(T5Pairing const& o) const = default;
};

//------------------------------------------------------------------------------
// ProofCore Class
//------------------------------------------------------------------------------

class ProofCore
{
public:
    ProofHashing hashing;
    XsEncryptor xs_encryptor;

    // Constructor: Initializes internal ProofHashing and XsEncryptor objects.
    ProofCore(const ProofParams &proof_params)
        : params_(proof_params),
          hashing(proof_params),
          xs_encryptor(proof_params)
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
        if (!match_filter_16(x_l & 0xFFFFU, x_r & 0xFFFFU))
            return std::nullopt;
        
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
    // meta, order bits, and the full encrypted_xs.
    std::optional<T3Pairing> pairing_t3(uint64_t meta_l, uint64_t meta_r, uint32_t x_bits_l, uint32_t x_bits_r)
    {
        if (!match_filter_4(static_cast<uint32_t>(meta_l & 0xFFFFU),
                            static_cast<uint32_t>(meta_r & 0xFFFFU)))
            return std::nullopt;
        
        uint64_t all_x_bits = (static_cast<uint64_t>(x_bits_l) << params_.get_k()) | x_bits_r;
        uint64_t encrypted_xs = xs_encryptor.encrypt(all_x_bits);
        uint32_t order_bits = xs_encryptor.get_t3_order_bits(encrypted_xs);
        uint32_t top_order_bit = order_bits >> 1;
        uint32_t lower_partition, upper_partition;

        if (top_order_bit == 0)
        {
            lower_partition = xs_encryptor.get_t3_l_partition(encrypted_xs);
            upper_partition = xs_encryptor.get_t3_r_partition(encrypted_xs) + params_.get_num_partitions();
        }
        else
        {
            lower_partition = xs_encryptor.get_t3_r_partition(encrypted_xs);
            upper_partition = xs_encryptor.get_t3_l_partition(encrypted_xs) + params_.get_num_partitions();
        }
        
        PairingResult pair = hashing.pairing(3, meta_l, meta_r,
                                             static_cast<int>(params_.get_num_pairing_meta_bits()),
                                             static_cast<int>(params_.get_sub_k()) - 1,
                                             static_cast<int>(params_.get_num_pairing_meta_bits()));

        // TODO: this can be bitpacked much better
        T3Pairing result;
        result.meta = pair.meta_result;
        result.lower_partition = lower_partition;
        result.upper_partition = upper_partition;
        result.order_bits = order_bits;
        result.encrypted_xs = encrypted_xs;
        // Build match_info by combining top_order_bit with lower_match_info.
        result.match_info_lower_partition = (top_order_bit << (params_.get_sub_k() - 1)) | pair.match_info_result;
        result.match_info_upper_partition = ((1 - top_order_bit) << (params_.get_sub_k() - 1)) | pair.match_info_result;
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
        if (pair.test_result >= (855570511 << 1))
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

        uint32_t section_1;
        uint32_t section_2;
        get_matching_sections(section_l, section_1, section_2);

        if (section_r != section_1 && section_r != section_2)
        {
            std::cout << "section_r " << section_r << " != section_1 " << section_1 << " and section_2 " << section_2 << std::endl
                     << "    meta_l: " << meta_l << " match_info_l: " << match_info_l << " match_info_r: " << match_info_r << std::endl;
            return false;
        }

        uint32_t match_key_r = params_.extract_match_key_from_match_info(table_id, match_info_r);
        uint32_t match_target_r = params_.extract_match_target_from_match_info(table_id, match_info_r);
        if (match_target_r != matching_target(table_id, meta_l, match_key_r))
        {
            //std::cout << "match_target_r " << match_target_r
            //          << " != matching_target(" << table_id << ", " << meta_l << ", " << match_key_r << ")" << std::endl;
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

private:
    ProofParams params_;
};
