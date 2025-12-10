#pragma once

#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"
#include "pos/aes/AesHash.hpp"

#include "pos/ProofValidator.hpp"
#include "ProofSolverTimings.hpp"
#include "ParallelRadixSort.hpp"

#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <bitset>
#include <numeric> // for iota
#include "common/ParallelForRange.hpp"


#ifdef __cpp_lib_execution
#include <execution>
#endif

// Prefetch Macro
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
#include <xmmintrin.h>
#define PREFETCH(addr) \
    _mm_prefetch(reinterpret_cast<const char *>(addr), _MM_HINT_T0)
#elif defined(__arm__) || defined(__aarch64__)
#define PREFETCH(addr) \
    __builtin_prefetch((addr), 0 /* read */, 0 /* no locality hint */)
#else
// Fallback: no-op
#define PREFETCH(addr) ((void)0)
#endif

// #define DEBUG_VERIFY true

// Needed for macOS
typedef unsigned int uint;

struct T1_Match
{
    uint32_t x1;
    uint32_t x2;
    uint32_t pair_hash; // hash of x1 and x2 when paired.
};

// Structures used in later match stages
struct T2_match
{
    std::array<uint32_t, 4> x_values;
    // variables below could be passed along for optimization
    // uint32_t match_info;
    // uint64_t meta;
};

struct T3_match
{
    std::array<uint32_t, 8> x_values;
};

//
// ProofSolver
//
// This class implements a CPU‐based proof solver. Given a 32‐byte plot ID and a “k” parameter,
// it goes through a sequence of phases:
//
//  1. Allocate storage for x1 candidates.
//  2. Hash all x1 candidates (using ProofCore’s chacha range functions).
//  3. Sort the resulting x1 candidate hashes.
//  4. Build a bitmask from the sorted x1 hashes.
//  5. Filter x2 candidates using the bitmask.
//  6. Sort the filtered x2 candidates.
//  7. Compute “section boundaries” on x1 and x2 arrays.
//  8. Match x1 and x2 entries (T1 matching).
//  9. Group T1 matches by x1 range.
// 10. Process adjacent groups to produce T2 matches.
// 11. Pair and merge T2 matches (T3, T4, T5 matching).
// 12. Finally, construct one or more complete proofs from T5 matches.

class Solver
{
public:
    // Constructor: supply the 32‐byte plot ID and the “k” parameter.
    Solver(const ProofParams &proof_params)
        : params_(proof_params)
    {
        // Use a ProofCore instance to initialize parameters.
        ProofCore proof_core(proof_params);
        // num_section_bits_ = proof_params.get_num_section_bits();
        // num_match_key_bits_ = 4;
        // num_match_target_bits_ = num_k_bits_ - num_section_bits_ - num_match_key_bits_;
        // num_T2_match_key_bits_ = 2;
        // num_T2_match_target_bits_ = num_k_bits_ - num_section_bits_ - num_T2_match_key_bits_;
    }

    void setUsePrefetching(bool use_prefetching)
    {
        use_prefetching_ = use_prefetching;
    }

    ~Solver() = default;

    struct XBitGroupMappings
    {
        std::vector<int> lookup; // our lookup vector for x_bits -> group
        std::vector<uint32_t> unique_x_bits_list;
        std::vector<int> mapping; // our group mappings
    };

    XBitGroupMappings compress_with_lookup(std::span<uint32_t const> const x_bits_list,
                                           size_t const x1_bits)
    {
        int total_ranges = 1 << x1_bits;
        // lookup[v] == -1  → we haven't seen v yet
        //         >= 0  → index into unique_values
        std::vector<int> lookup(total_ranges, -1);

        XBitGroupMappings out;

        int mapping_idx = 0;
        for (uint32_t x_bits : x_bits_list)
        {
            int const idx = lookup[x_bits];
            if (idx < 0)
            {
                // first time we see `x_bits`
                // idx = (int)out.unique_values.size();   // next slot
                lookup[x_bits] = mapping_idx;
                out.unique_x_bits_list.push_back(x_bits);
                out.mapping.push_back(mapping_idx);
                mapping_idx++;
            }
            else
            {
                // already seen 'x_bits'
                out.mapping.push_back(idx);
            }
        }

        out.lookup = lookup;

        return out;
    }

    // Main solver function.
    // Input: an array of 256 x1 candidates.
    //        x_solution is an dev-mode test array that the solver should solve to and test against (debug and verify).
    // Returns: a vector of complete proofs (each proof is an array of TOTAL_XS_IN_PROOF uint32_t x-values).
    std::vector<std::array<uint32_t, TOTAL_XS_IN_PROOF>> solve(std::span<uint32_t const, TOTAL_XS_IN_PROOF / 2> const x_bits_list, std::span<uint32_t const> const x_solution = {})
    {
        XBitGroupMappings x_bits_group = compress_with_lookup(x_bits_list, params_.get_k() / 2);
#ifdef DEBUG_VERIFY
        if (true)
        {
            std::cout << "original x bits list: ";
            for (auto v : x_bits_list)
            {
                std::cout << v << ", ";
            }
            std::cout << std::endl;
            // output x1 list
            std::cout << "unique x bits list (" << x_bits_group.unique_x_bits_list.size() << "):" << std::endl;
            for (auto v : x_bits_group.unique_x_bits_list)
            {
                std::cout << v << ", ";
            }
            std::cout << std::endl;

            // output mappings
            std::cout << "x bits mapping (" << x_bits_group.mapping.size() << "):" << std::endl;
            for (auto v : x_bits_group.mapping)
            {
                std::cout << v << ", ";
            }
            std::cout << std::endl;

            std::cout << "x_solution (" << x_solution.size() << "):" << std::endl;
            for (auto v : x_solution)
            {
                std::cout << v << ", ";
            }
            std::cout << std::endl;
        }
#else
        (void)x_solution;
#endif
        const int num_k_bits_ = params_.get_k();

        // Derived parameters for phase 1:
        const int x1_bits = num_k_bits_ / 2;
        const int x1_range_size = 1 << (num_k_bits_ - x1_bits);

        const size_t num_unique_x_pairs = x_bits_group.unique_x_bits_list.size();
        const size_t num_match_keys = params_.get_num_match_keys(1);
        const size_t num_match_target_hashes = num_unique_x_pairs * x1_range_size * num_match_keys;

#ifdef DEBUG_VERIFY
        std::cout << "x1 bits: " << x1_bits << std::endl;
        std::cout << "x1 range size: " << x1_range_size << std::endl;
        std::cout << "num_match_keys: " << num_match_keys << std::endl;

        std::cout << "num_match_target_hashes: " << num_match_target_hashes << " (num_unique_x_pairs: " << num_unique_x_pairs << " x " << x1_range_size << " x " << num_match_keys << ")" << std::endl;
        std::cout << "unique_x1_list size: " << x_bits_group.unique_x_bits_list.size() << std::endl;

        std::cout << "bitmask shift: " << this->bitmask_shift_ << std::endl;
#endif

        // Phase 1: Allocate storage for x1 candidates.
        Timer timer;
        timer.start("Allocating Hash List (" + std::to_string(num_match_target_hashes) + ")");
        std::vector<uint32_t> x1s(num_match_target_hashes);
        std::vector<uint32_t> x1_hashes(num_match_target_hashes);
        timings_.allocating += timer.stop();

        // Phase 2: Hash x1 candidates for comparing match info's
        hashX1Candidates(x_bits_group.unique_x_bits_list, x1_bits, x1_range_size, x1s, x1_hashes);

        timer.start("Allocating buffer for sort");
        std::vector<uint32_t> x1s_sort_buffer(x1_hashes.size());
        std::vector<uint32_t> x1_hashes_sort_buffer(x1_hashes.size());
        timings_.allocating += timer.stop();

        // Phase 3: Sort x1 candidates using parallel radix sort.
        timer.start("Sorting " + std::to_string(x1_hashes.size()) + " x1's");
        ParallelRadixSort radixSort;
        radixSort.sortByKey(x1_hashes, x1s, x1_hashes_sort_buffer, x1s_sort_buffer, num_k_bits_);
        timings_.sorting_x1s += timer.stop();

        // Phase 4: Build a bitmask from the sorted x1 hashes.
        std::vector<uint32_t> x1_bitmask;
        buildX1Bitmask(x1_hashes, x1_bitmask);

        // Phase 5: Filter x2 candidates using the x1 bitmask.
        std::vector<uint32_t> x2_potential_match_xs;
        std::vector<uint32_t> x2_potential_match_hashes;

        filterX2Candidates(x1_bitmask, num_unique_x_pairs, x2_potential_match_xs, x2_potential_match_hashes);

        // Phase 6: Sort the filtered x2 candidates.
        timer.start("Sorting matches (" + std::to_string(x2_potential_match_xs.size()) + ")");
        // resize sort buffer to match size so it can be used as switchable buffer
        x1s_sort_buffer.resize(x2_potential_match_xs.size());
        x1_hashes_sort_buffer.resize(x2_potential_match_xs.size());
        radixSort.sortByKey(x2_potential_match_hashes, x2_potential_match_xs, x1s_sort_buffer, x1_hashes_sort_buffer, num_k_bits_);
        timings_.sorting_filtered_x2s += timer.stop();

        // Phase 7: Match x1 and x2 entries within corresponding sections.
        std::vector<T1_Match> t1_matches = matchT1Candidates(x1_hashes, x1s, x2_potential_match_hashes, x2_potential_match_xs, numeric_cast<int>(num_match_target_hashes));

#ifdef DEBUG_VERIFY
        std::cout << "T1 matches: " << t1_matches.size() << std::endl;
        // exit(23);
        if (true)
        {
            // check if each of our x pairs from our solution is in the t1_matches
            std::cout << "Checking x pairs from solution:" << std::endl;
            for (size_t i = 0; i < x_solution.size(); i += 2)
            {
                uint32_t x1 = x_solution[i];
                uint32_t x2 = x_solution[i + 1];
                bool found = false;
                for (auto const &t1 : t1_matches)
                {
                    if (t1.x1 == x1 && t1.x2 == x2)
                    {
                        found = true;
                        std::cout << "Found match for x pair: " << x1 << ", " << x2 << ", hash: " << t1.pair_hash << std::endl;
                        break;
                    }
                }
                if (!found)
                {
                    std::cout << "Did not find match for x pair: " << x1 << ", " << x2 << std::endl;
                    exit(23);
                }
            }
        }
#endif
        // Phase 9: Group T1 matches by x1 “range” (using the high‐order half of x1).
        std::vector<std::vector<T1_Match>> t1_match_groups = groupT1Matches(num_k_bits_, x1_bits, x_bits_group, t1_matches);

        // T1 groupings now hold all possible x1,x2 pairs that could be used to form T2 matches, often duplicates.

        // output count of all sublists
#ifdef DEBUG_VERIFY
        if (true)
        {
            // output count of all sublists
            for (size_t i = 0; i < t1_match_groups.size(); i++)
            {
                std::cout << "Group " << i << " count: " << t1_match_groups[i].size() << std::endl;
                /*std::cout << "xs: ";
                for (size_t j = 0; j < t1_match_groups[i].size(); j++)
                {
                    std::cout << "[" << t1_match_groups[i][j].x1 << ", " << t1_match_groups[i][j].x2 << "] ";
                }
                std::cout << std::endl;*/
            }
            std::cout << "Checking T2 pairs present in x groups:" << std::endl;
            for (size_t i = 0; i < x_solution.size(); i += 4)
            {
                uint32_t x1 = x_solution[i];
                uint32_t x2 = x_solution[i + 1];
                uint32_t x3 = x_solution[i + 2];
                uint32_t x4 = x_solution[i + 3];

                size_t const x1_group = x_bits_group.mapping[i / 2];
                size_t const x2_group = x_bits_group.mapping[i / 2 + 1];
                std::cout << "x1 group: " << x1_group << ", x2 group: " << x2_group << std::endl;

                bool found_l = false;
                for (auto const &group : t1_match_groups[x1_group])
                {
                    if (group.x1 == x1 && group.x2 == x2)
                    {
                        std::cout << "Found match for x pair: " << x1 << ", " << x2 << " hash: " << group.pair_hash << std::endl;
                        found_l = true;
                    }
                }

                bool found_r = false;
                for (auto const &group : t1_match_groups[x2_group])
                {
                    if (group.x1 == x3 && group.x2 == x4)
                    {
                        std::cout << "Found match for x pair: " << x3 << ", " << x4 << " hash: " << group.pair_hash << std::endl;
                        found_r = true;
                    }
                }

                if (found_l && found_r)
                {
                    std::cout << "Found match for x pair: " << x1 << ", " << x2 << " and " << x3 << ", " << x4 << std::endl;
                }
                else
                {
                    std::cout << "Did not find match for x pair: " << x1 << ", " << x2 << " and " << x3 << ", " << x4 << std::endl;
                    exit(23);
                }
            }
        }
#endif
        // Phase 10: T2 Matching – Process adjacent T1 groups to produce T2 matches.
        std::array<std::vector<T2_match>, TOTAL_T2_PAIRS_IN_PROOF> t2_matches = matchT2Candidates(t1_match_groups, x_bits_group);
#ifdef DEBUG_VERIFY
        if (true)
        {
            std::cout << "T2 matches (" << t2_matches.size() << "):" << std::endl;
#ifdef RETAIN_X_VALUES_TO_T3
            for (size_t i = 0; i < t2_matches.size(); i++)
            {
                std::cout << "Group " << i << ":";
                bool found = false;
                uint32_t check_xs[4] = {x_solution[i * 4 + 0], x_solution[i * 4 + 1], x_solution[i * 4 + 2], x_solution[i * 4 + 3]};
                for (size_t j = 0; j < t2_matches[i].size(); j++)
                {
                    if (t2_matches[i][j].x_values[0] == check_xs[0] &&
                        t2_matches[i][j].x_values[1] == check_xs[1] &&
                        t2_matches[i][j].x_values[2] == check_xs[2] &&
                        t2_matches[i][j].x_values[3] == check_xs[3])
                    {
                        found = true;
                    }
                    std::cout << "[" << t2_matches[i][j].x_values[0] << ", " << t2_matches[i][j].x_values[1] << ", "
                              << t2_matches[i][j].x_values[2] << ", " << t2_matches[i][j].x_values[3] << "]";
                }
                std::cout << std::endl;
                if (found)
                {
                    std::cout << "Found match for T2 xs group " << i << ": " << check_xs[0] << ", " << check_xs[1] << ", " << check_xs[2] << ", " << check_xs[3] << std::endl;
                }
                else
                {
                    std::cout << "Did not find match for T2 xs group " << i << ":" << check_xs[0] << ", " << check_xs[1] << ", " << check_xs[2] << ", " << check_xs[3] << std::endl;
                    exit(23);
                }
            }
#endif
        }
        std::cout << "T2 match groups: " << t2_matches.size() << std::endl;
#endif

        // Phase 11: T3 Matching – Further pair T2 matches.
        std::array<std::vector<T3_match>, TOTAL_T3_PAIRS_IN_PROOF> t3_matches;
        matchT3Candidates(num_k_bits_, t2_matches, t3_matches);

#ifdef DEBUG_VERIFY
        std::cout << "T3 matches: " << t3_matches.size() << std::endl;
        for (size_t i = 0; i < t3_matches.size(); i++)
        {
            std::cout << "Group " << i << ":";
            for (size_t j = 0; j < t3_matches[i].size(); j++)
            {
                for (int x = 0; x < 32; x++)
                {
                    std::cout << t3_matches[i][j].x_values[x] << ", ";
                }
            }
            std::cout << std::endl;
        }
#endif

        // TODO: handle rare chance we get a false positive full proof
        auto all_proofs = constructProofs(t3_matches);

        return all_proofs;
    }

    // Phase 11 helper: T3, T4, T5 matching – further pair and validate matches.
    void matchT3Candidates(int /*num_k_bits*/,
                           std::span<std::vector<T2_match>, TOTAL_T2_PAIRS_IN_PROOF> const t2_matches,
                           std::span<std::vector<T3_match>, TOTAL_T3_PAIRS_IN_PROOF> const t3_matches)
    {

        Timer timer;
        timer.start("T3, T4, T5 Matching");

        // T3 matching.
        {
            ProofValidator validator(params_);
            for (size_t i = 0; i < t2_matches.size(); i += 2)
            {
                size_t t3_group = i / 2;
                const std::vector<T2_match> &groupA = t2_matches[i];
                const std::vector<T2_match> &groupB = t2_matches[i + 1];
                for (size_t j = 0; j < groupA.size(); j++)
                {
                    for (size_t k = 0; k < groupB.size(); k++)
                    {
                        uint32_t x_values[8] = {groupA[j].x_values[0], groupA[j].x_values[1],
                                                groupA[j].x_values[2], groupA[j].x_values[3],
                                                groupB[k].x_values[0], groupB[k].x_values[1],
                                                groupB[k].x_values[2], groupB[k].x_values[3]};
                        std::optional<T3Pairing> result = validator.validate_table_3_pairs(x_values);
                        if (result.has_value())
                        {
                            // could match faster in T4 by adding both T3 matches and then doing more checks
                            // but probably negligible speedup than this simpler way.
                            T3_match t3;
                            t3.x_values = {groupA[j].x_values[0], groupA[j].x_values[1],
                                           groupA[j].x_values[2], groupA[j].x_values[3],
                                           groupB[k].x_values[0], groupB[k].x_values[1],
                                           groupB[k].x_values[2], groupB[k].x_values[3]};
                            // t3.match_info = result.value().match_info_lower_partition;
                            // t3.meta = result.value().meta_lower_partition;
                            // t3.partition = result.value().lower_partition;
                            t3_matches[t3_group].push_back(t3);
                        }
                    }
                }
            }
        }

        timings_.misc += timer.stop();
    }

    // Phase 12 helper: Construct final proofs from T3 matches.
    // A full proof is all t3 x-value collections, in the same sequence order as the quality chain.
    std::vector<std::array<uint32_t, TOTAL_XS_IN_PROOF>>
    constructProofs(std::span<std::vector<T3_match>, TOTAL_T3_PAIRS_IN_PROOF> const t3_matches)
    {
        std::vector<std::array<uint32_t, TOTAL_XS_IN_PROOF>> all_proofs;

        // One working buffer we fill as we choose matches for each group
        std::array<uint32_t, TOTAL_XS_IN_PROOF> full_proof{};

        // How many x-values belong to each T3 pair in the final proof
        constexpr size_t XS_PER_GROUP = TOTAL_XS_IN_PROOF / TOTAL_T3_PAIRS_IN_PROOF;
        static_assert(TOTAL_XS_IN_PROOF % TOTAL_T3_PAIRS_IN_PROOF == 0,
                      "TOTAL_XS_IN_PROOF must be divisible by TOTAL_T3_PAIRS_IN_PROOF");

        // Recursive helper: choose a match for group g, then recurse to g+1.
        std::function<void(size_t)> buildProofs =
            [&](size_t g)
        {
            // Base case: we have chosen a match for every group -> store one full proof
            if (g == TOTAL_T3_PAIRS_IN_PROOF)
            {
                all_proofs.push_back(full_proof);
                return;
            }

            // For this group g, try every possible match
            auto const &matches_for_group = t3_matches[g];
            for (auto const &match : matches_for_group)
            {
                // Copy this match's x-values into the correct slice of the full proof
                auto dest_begin = full_proof.begin() + g * XS_PER_GROUP;
                std::copy(match.x_values.begin(), match.x_values.end(), dest_begin);

                // Recurse to pick matches for the next group
                buildProofs(g + 1);
            }
        };

        // Start recursion at group 0; this will generate the cartesian product:
        // for each match in t3_matches[0]
        //   for each match in t3_matches[1]
        //     ...
        //       for each match in t3_matches[TOTAL_T3_PAIRS_IN_PROOF-1]
        //         emit full_proof
        buildProofs(0);

        return all_proofs;
    }


    std::array<std::vector<T2_match>, TOTAL_T2_PAIRS_IN_PROOF> matchT2Candidates(
        std::span<std::vector<T1_Match>> const t1_match_groups,
        const XBitGroupMappings &x_bits_group)
    {
        Timer timer, sub_timer;
        timer.start("Matching T2 candidates");

        int num_k_bits = params_.get_k();
        int num_section_bits = params_.get_num_section_bits();
        int num_T2_match_key_bits = params_.get_num_match_key_bits(2);
        size_t num_T2_match_target_bits = params_.get_num_match_target_bits(2);

#ifdef DEBUG_VERIFY
        std::cout << "num_k_bits: " << num_k_bits << std::endl;
        std::cout << "num_section_bits: " << num_section_bits << std::endl;
        std::cout << "num_T2_match_key_bits: " << num_T2_match_key_bits << std::endl;
        std::cout << "num_T2_match_target_bits: " << num_T2_match_target_bits << std::endl;
        int num_R_collisions = 0;
#endif

        // Tuning of reduced-hash size
        const int HASHES_BITMASK_SIZE_BITS = num_k_bits - 8;

        const size_t num_buckets = size_t(1) << HASHES_BITMASK_SIZE_BITS;
        const uint16_t INVALID_INDEX = std::numeric_limits<uint16_t>::max();
        const int REDUCE_SHIFT = num_k_bits - HASHES_BITMASK_SIZE_BITS;

        // For each reduced hash value, store the *lowest* index in R_sorted that has it.
        std::vector<uint16_t> hash_to_index(num_buckets);

        std::array<std::vector<T2_match>, TOTAL_T2_PAIRS_IN_PROOF> t2_matches;

        // Process adjacent groups: group 0 with 1, 2 with 3, etc.
        for (size_t t2_group = 0; t2_group < t2_matches.size(); ++t2_group)
        {
            #ifdef DEBUG_VERIFY
            num_R_collisions = 0;
            #endif
            size_t group_mapping_index_l = t2_group * 2;
            size_t group_mapping_index_r = group_mapping_index_l + 1;
            int t1_group_l = x_bits_group.mapping[group_mapping_index_l];
            int t1_group_r = x_bits_group.mapping[group_mapping_index_r];

            const auto &R_list = t1_match_groups[t1_group_r];

            // --- sort R_list by pair_hash ---
            sub_timer.start();
            auto R_sorted = R_list;
            std::sort(
#ifdef __cpp_lib_execution
                std::execution::par_unseq,
#endif
                R_sorted.begin(), R_sorted.end(),
                [](const T1_Match &a, const T1_Match &b)
                {
                    return a.pair_hash < b.pair_hash;
                });
            timings_.t2_sort_short_list += sub_timer.stop();

            // --- build hash_to_index: reduced hash -> first index in R_sorted with that reduced value ---
            sub_timer.start();

            std::fill(hash_to_index.begin(), hash_to_index.end(), INVALID_INDEX);
            assert(R_sorted.size() < INVALID_INDEX); // ensure we don't overflow uint16_t
            for (uint16_t j = 0; j < static_cast<uint16_t>(R_sorted.size()); ++j)
            {
                uint32_t reduced = R_sorted[j].pair_hash >> REDUCE_SHIFT;
                if (hash_to_index[reduced] == INVALID_INDEX)
                {
                    // Because R_sorted is sorted, this will be the lowest index for this reduced value.
                    hash_to_index[reduced] = j;
                }
                #ifdef DEBUG_VERIFY
                else {
                    num_R_collisions++;
                }
                #endif
            }
            #ifdef DEBUG_VERIFY
            std::cout << "Num R collisions: " << num_R_collisions << std::endl;
            #endif

            timings_.t2_sort_short_list += sub_timer.stop(); // reuse this bucket for index build time

            const auto &L_list = t1_match_groups[t1_group_l];
            uint32_t num_match_keys = 1u << num_T2_match_key_bits;

            auto &out = t2_matches[t2_group];
            std::mutex out_mutex;

            // --- parallel processing of unsorted L_list ---
            sub_timer.start();

            parallel_for_range(L_list.begin(), L_list.end(),
                               [&](const T1_Match &lm)
                               {
                                   ProofCore thread_core(params_);
                                   std::vector<T2_match> local_out;
                                   local_out.reserve(4);

                                   for (uint32_t match_key = 0; match_key < num_match_keys; ++match_key)
                                   {
                                       // Build target hash exactly as in original code.
                                       uint64_t meta = (uint64_t(lm.x1) << num_k_bits) | lm.x2;
                                       uint32_t L_hash = thread_core.matching_target(2, meta, match_key);

                                       uint32_t sec_bits = lm.pair_hash >> (num_k_bits - num_section_bits);
                                       uint32_t R_sec = thread_core.matching_section(sec_bits);

                                       uint32_t final_hash =
                                           (R_sec << (num_k_bits - num_section_bits)) |
                                           (match_key << num_T2_match_target_bits) |
                                           L_hash;

                                       uint32_t reduced = final_hash >> REDUCE_SHIFT;
                                       uint32_t idx = hash_to_index[reduced];

                                       if (idx == INVALID_INDEX)
                                       {
                                           // No R entries share this reduced hash.
                                           continue;
                                       }

                                       // Walk down R_sorted from that index while R is in-range (same reduced).
                                       // For each, check exact pair_hash match and then validate.
                                       for (uint32_t j = idx; j < static_cast<uint32_t>(R_sorted.size()); ++j)
                                       {
                                           uint32_t r_hash = R_sorted[j].pair_hash;
                                           uint32_t r_reduced = r_hash >> REDUCE_SHIFT;

                                           if (r_reduced != reduced)
                                           {
                                               // We've left the bucket / range for this reduced value.
                                               break;
                                           }

                                           if (r_hash != final_hash)
                                           {
                                               continue;
                                           }

                                           // Exact hash match: run filter / pairing.
                                           uint32_t x_values[4] = {
                                               lm.x1,
                                               lm.x2,
                                               R_sorted[j].x1,
                                               R_sorted[j].x2};

#ifdef USE_T2_FAST_FILTER
                                           {
                                               ProofCore pc(params_);
                                               uint16_t lowL = uint16_t(x_values[1] & 0xFFFF);
                                               uint16_t lowR = uint16_t(x_values[3] & 0xFFFF);
                                               if (params_.get_k() < 16)
                                               {
                                                   uint64_t ml = (uint64_t(x_values[0]) << num_k_bits) | x_values[1];
                                                   uint64_t mr = (uint64_t(x_values[2]) << num_k_bits) | x_values[3];
                                                   lowL = uint16_t(ml & 0xFFFF);
                                                   lowR = uint16_t(mr & 0xFFFF);
                                               }
                                               if (pc.match_filter_4(lowL, lowR))
                                               {
                                                   ProofValidator validator(params_);
                                                   if (auto pairing = validator.validate_table_2_pairs(x_values))
                                                   {
                                                       T2_match t2;
                                                       t2.x_values = {x_values[0], x_values[1], x_values[2], x_values[3]};
                                                       // t2.match_info = pairing->match_info;
                                                       // t2.meta = pairing->meta;
                                                       local_out.push_back(t2);
                                                   }
                                               }
                                           }
#else
                                       {
                                           int num_test_bits = num_T2_match_key_bits;
                                           const uint64_t out_meta_bits = num_k_bits * 2;
                                           uint64_t meta_l =
                                               ((uint64_t(lm.x1) << num_k_bits) | lm.x2);
                                           uint64_t meta_r =
                                               ((uint64_t(R_sorted[j].x1) << num_k_bits) | R_sorted[j].x2);

                                           PairingResult pair = thread_core.hashing.pairing(
                                               meta_l,
                                               meta_r,
                                               num_k_bits,
                                               static_cast<int>(out_meta_bits),
                                               num_test_bits);

                                           if (pair.test_result == 0)
                                           {
                                               T2_match t2;
                                               t2.x_values = {x_values[0], x_values[1], x_values[2], x_values[3]};
                                               local_out.push_back(t2);
                                           }
                                       }
#endif
                                       }
                                   }

                                   if (!local_out.empty())
                                   {
                                       std::lock_guard<std::mutex> lock(out_mutex);
                                       out.insert(out.end(), local_out.begin(), local_out.end());
                                   }
                               });

            timings_.t2_gen_L_list += sub_timer.stop();

            // We folded the old two-pointer scan work into the L loop above,
            // so we don't add to t2_scan_for_matches here.
        }

        timings_.t2_matches += timer.stop();
        return t2_matches;
    }

    // Phase 9 helper: Group T1 matches by x1 “range.”
    std::vector<std::vector<T1_Match>> groupT1Matches(int num_k_bits, int x1_bits,
                                                      const XBitGroupMappings &x_bit_group_mappings,
                                                      // const std::vector<uint32_t> &x_bits_list,
                                                      const std::vector<T1_Match> &t1_matches)
    {
        // split matches into seperate lists for each x1 group
        // make lookup table for x1 ranges
        
        Timer timer;

        timer.start("Splitting matches into x1 groups");
        // Split concurrent_matches into separate match lists
        // We iterate over all matches to find the x1 part of the match, then we map that x1 by it's lower k/2 bits
        //  to find which of the TOTAL_T2_PAIRS_IN_PROOF groups it belongs to.
        //  Then we push all matches into their own groups defined by x1.
        // A "group" is basically the nth x-pair in the proof.
        const size_t NUM_X1S = x_bit_group_mappings.unique_x_bits_list.size();
        size_t t1_num_matches = t1_matches.size();
        size_t max_matches_per_x_range = t1_num_matches * 2 / NUM_X1S;
        std::vector<std::vector<T1_Match>> match_lists(NUM_X1S, std::vector<T1_Match>());
        for (auto &list : match_lists)
        {
            list.reserve(max_matches_per_x_range);
        }

        for (T1_Match const &match : t1_matches)
        {
            uint32_t const x1_bit_dropped = match.x1 >> (num_k_bits - x1_bits);
            int const lookup_index = x_bit_group_mappings.lookup[x1_bit_dropped];
#ifdef DEBUG_VERIFY
            if ((lookup_index == -1) || (size_t(lookup_index) >= NUM_X1S))
            {
                // error
                std::cout << "x1_bit_dropped: " << x1_bit_dropped << " OUT OF BOUNDS to total_ranges: " << NUM_X1S << std::endl;
                continue;
            }
#endif

            match_lists[lookup_index].push_back(match);
        }
        timings_.misc += timer.stop();

        return match_lists;
    }

    std::vector<T1_Match> matchT1Candidates(
        const std::span<uint32_t const> x1_hashes,
        const std::span<uint32_t const> x1s,
        const std::span<uint32_t const> x2_match_hashes,
        const std::span<uint32_t const> x2_match_xs,
        const int num_match_target_hashes)
    {
        // 1) compute section boundaries
        Timer timer;
        timer.start("Computing section boundaries");

        const auto section_boundaries_x1 = computeSectionBoundaries(x1_hashes);
        const auto section_boundaries_x2 = computeSectionBoundaries(x2_match_hashes);

        timings_.misc += timer.stop();

        if (false)
        {
            // show section boundaries
            std::cout << "Section boundaries x1: ";
            for (auto b : section_boundaries_x1)
            {
                std::cout << b << ", ";
            }
            std::cout << std::endl;
            std::cout << "Section boundaries x2: ";
            for (auto b : section_boundaries_x2)
            {
                std::cout << b << ", ";
            }
            std::cout << std::endl;
            std::cout << "x1_hashes size: " << x1_hashes.size() << std::endl;
            std::cout << "x2_match_hashes size: " << x2_match_hashes.size() << std::endl;

            const int k = params_.get_k();
            const int num_section_bits = params_.get_num_section_bits();
            // verify section boundaries have section bits as part of hash range for section
            for (size_t i = 0; i < section_boundaries_x1.size(); i++)
            {
                const int start_section = section_boundaries_x1[i];
                const int end_section = (i + 1 == section_boundaries_x1.size())
                                            ? num_match_target_hashes
                                            : section_boundaries_x1[i + 1];
                std::cout << "section_boundaries_x1 section:" << i << " start_section: " << start_section << " end_section: " << end_section << std::endl;
                for (int j = start_section; j < end_section; j++)
                {
                    // std::cout << "x1 hash[" << j << "]: " << std::bitset<20>(x1_hashes[j]) << std::endl;
                    const uint32_t hash = x1_hashes[j];
                    const uint32_t section_bits = hash >> (k - num_section_bits);
                    if (section_bits != i)
                    {
                        std::cout << "Section bits: " << section_bits << " != " << i << std::endl;
                        std::cout << "x1     : " << x1s[j] << std::endl;
                        std::cout << "x1 hash: " << std::bitset<20>(hash) << std::endl;
                        std::cout << "i      : " << i << std::endl;
                        std::cout << "start  : " << start_section << std::endl;
                        std::cout << "end    : " << end_section << std::endl;
                        abort();
                    }
                }
                std::cout << "Section " << i << ": [" << start_section << ", " << end_section << ")" << std::endl;
            }
            for (size_t i = 0; i < section_boundaries_x2.size(); i++)
            {
                const int start_section = section_boundaries_x2[i];
                const int end_section = (i + 1 == section_boundaries_x2.size())
                                            ? static_cast<int>(x2_match_hashes.size())
                                            : section_boundaries_x2[i + 1];
                for (int j = start_section; j < end_section; j++)
                {
                    const uint32_t hash = x2_match_hashes[j];
                    const uint32_t section_bits = hash >> (k - num_section_bits);
                    if (section_bits != i)
                    {
                        std::cout << "Section bits: " << section_bits << " != " << i << std::endl;
                        abort();
                    }
                }
                std::cout << "Section " << i << ": [" << start_section << ", " << end_section << ")" << std::endl;
            }
        }

        const int NUM_SECTIONS = params_.get_num_sections();

        // 2) determine max matches & allocate
        int max_matches = 2100000;
        switch (params_.get_k())
        {
        case 28:
            max_matches = 2100000 * 2;
            break;
        case 30:
            max_matches = 4200000 * 2;
            break;
        case 32:
            max_matches = 8400000 * 2;
            break;
        }

        std::vector<T1_Match> t1_matches(max_matches);
        std::atomic<int> t1_num_matches{0};

        // 4) parallel match over each section
        timer.start("Matching x1 and x2 sorted lists");
        if (true)
        {
            // this section splits execution into NUM_SECTIONS tasks
            // performs better when small number of cpu's.
            parallel_for_range(0, NUM_SECTIONS, [&](int section)
                               {
                    ProofCore proof_core(params_);

                    int x1_start = section_boundaries_x1[section];
                    int x1_end = (section + 1 == NUM_SECTIONS)
                                     ? num_match_target_hashes
                                     : section_boundaries_x1[section + 1];
                    int x2_start = section_boundaries_x2[section];
                    int x2_end = (section + 1 == NUM_SECTIONS)
                                     ? static_cast<int>(x2_match_hashes.size())
                                     : section_boundaries_x2[section + 1];

                    int i = x1_start, j = x2_start;
                    while (i < x1_end && j < x2_end)
                    {
                        uint32_t h1 = x1_hashes[i];
                        uint32_t h2 = x2_match_hashes[j];

                        if (h1 == h2)
                        {
                            // scan all equal h1 entries
                            int ti = i;
                            while (ti < x1_end && x1_hashes[ti] == h2)
                            {
                                uint32_t xx1 = x1s[ti];
                                uint32_t xx2 = x2_match_xs[j];

                                auto pairing = proof_core.pairing_t1(xx1, xx2);
                                if (pairing.has_value())
                                {
                                    int pos = t1_num_matches.fetch_add(1, std::memory_order_relaxed);
                                    if (pos >= max_matches)
                                    {
                                        std::cerr << "ERROR: Too many matches\n";
                                        std::exit(1);
                                    }
                                    T1_Match m;
                                    m.x1 = xx1;
                                    m.x2 = xx2;
                                    m.pair_hash = pairing->match_info;
                                    t1_matches[pos] = m;
                                }
                                ++ti;
                            }
                            ++j;
                        }
                        else if (h1 < h2)
                        {
                            ++i;
                        }
                        else
                        {
                            ++j;
                        }
                    } });
        }
        else
        {
            // this section splits execution into NUM_SECTIONS * num_task_bit_splits tasks
            int num_task_bit_splits = 4; // 16 splits

            for (int section = 0; section < NUM_SECTIONS; ++section)
            {
                const int x1_start = section_boundaries_x1[section];
                const int x1_end = (section + 1 == NUM_SECTIONS)
                                       ? num_match_target_hashes
                                       : section_boundaries_x1[section + 1];
                const int x2_start = section_boundaries_x2[section];
                const int x2_end = (section + 1 == NUM_SECTIONS)
                                       ? static_cast<int>(x2_match_hashes.size())
                                       : section_boundaries_x2[section + 1];
                const auto task_boundaries_x1 = makeTaskBoundariesSimple(
                    x1_start, x1_end,
                    x1_hashes,
                    num_task_bit_splits);
                
                auto task_boundaries_x2 = makeTaskBoundariesSimple(
                    x2_start, x2_end,
                    x2_match_hashes,
                    num_task_bit_splits);
                
                int total_tasks = 1 << num_task_bit_splits;

                std::vector<int> task_ids(total_tasks);
                std::iota(task_ids.begin(), task_ids.end(), 0);

                parallel_for_range(task_ids.begin(), task_ids.end(), [&](int task_id)
                                   {
                        ProofCore proof_core(params_);

                        const int x1_start = task_boundaries_x1[task_id];
                        const int x1_end = task_boundaries_x1[task_id + 1];
                        const int x2_start = task_boundaries_x2[task_id];
                        const int x2_end = task_boundaries_x2[task_id + 1];

                        // std::cout << "Task " << task_id << ": x1 [" << x1_start << ", " << x1_end << "), x2 [" << x2_start << ", " << x2_end << ") length: " << (x1_end - x1_start) << ", " << (x2_end - x2_start) << std::endl;

                        int i = x1_start, j = x2_start;
                        while (i < x1_end && j < x2_end)
                        {
                            const uint32_t h1 = x1_hashes[i];
                            const uint32_t h2 = x2_match_hashes[j];

                            if (h1 == h2)
                            {
                                // scan all equal h1 entries
                                int ti = i;
                                while (ti < x1_end && x1_hashes[ti] == h2)
                                {
                                    const uint32_t xx1 = x1s[ti];
                                    const uint32_t xx2 = x2_match_xs[j];

                                    auto pairing = proof_core.pairing_t1(xx1, xx2);
                                    if (pairing.has_value())
                                    {
                                        const int pos = t1_num_matches.fetch_add(1, std::memory_order_relaxed);
                                        if (pos >= max_matches)
                                        {
                                            std::cerr << "ERROR: Too many matches\n";
                                            std::exit(1);
                                        }
                                        T1_Match m;
                                        m.x1 = xx1;
                                        m.x2 = xx2;
                                        m.pair_hash = pairing->match_info;
                                        t1_matches[pos] = m;
                                    }
                                    ++ti;
                                }
                                ++j;
                            }
                            else if (h1 < h2)
                            {
                                ++i;
                            }
                            else
                            {
                                ++j;
                            }
                        } });
            }
        }
        timings_.match_x1_x2_sorted_lists += timer.stop();

        // 5) trim to actual match count and return
        const int total = t1_num_matches.load(std::memory_order_relaxed);
        t1_matches.resize(total);

        return t1_matches;
    }

    /*
    // kept for debugging.
    std::vector<int> computeSectionBoundariesSimple(const std::vector<uint32_t> &hashes)
    {
        int NUM_SECTIONS = params_.get_num_sections();
        int num_k_bits = params_.get_k();
        int num_section_bits = params_.get_num_section_bits();
        std::vector<int> section_boundaries(NUM_SECTIONS);

        // set all to zero
        std::fill(section_boundaries.begin(), section_boundaries.end(), -1);

        // scan x1 hashes, get section and set boundary for it's index
        for (size_t i = 0; i < hashes.size(); i++)
        {
            uint32_t hash = hashes[i];
            uint32_t section = hash >> (num_k_bits - num_section_bits);
            if (section_boundaries[section] == -1)
            {
                // set boundary for this section
                section_boundaries[section] = i;
            }
        }
        return section_boundaries;
    }*/

    /*
    TODO: This code has a bug and does not always match makeTaskBoundariesSimple.
    std::vector<int> makeTaskBoundariesFast(
        int x1_start,
        int x1_end,
        const std::vector<uint32_t> &hashes,
        int num_split_bits)
    {
        const int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int num_splits = 1 << num_split_bits;
        const int shift_sub = num_k_bits - num_section_bits - num_split_bits;
        const int mask_sub = (1 << num_split_bits) - 1;

        int M = x1_end - x1_start;
        int chunk = M / num_splits; // ideal size per split

        std::vector<int> bounds(num_splits + 1);
        bounds[0] = x1_start; // first split always starts here

        for (int s = 1; s < num_splits; ++s)
        {
            // 1) guess
            int idx = x1_start + std::min(s * chunk, M - 1);
            uint32_t sub = (hashes[idx] >> shift_sub) & mask_sub;

            // 2) if we’re too early, scan forward until `sub == s`
            if (sub < (uint32_t)s)
            {
                while (idx < x1_end &&
                       (((hashes[idx] >> shift_sub) & mask_sub) < (uint32_t)s))
                {
                    ++idx;
                }
            }
            // 3) if we’re too late, scan backward until `< s`, then +1
            else if (sub > (uint32_t)s)
            {
                while (idx > x1_start &&
                       (((hashes[idx] >> shift_sub) & mask_sub) > (uint32_t)s))
                {
                    --idx;
                }
                if (((hashes[idx] >> shift_sub) & mask_sub) < (uint32_t)s)
                {
                    ++idx;
                }
            }
            // 4) if we’re already in split s, scan backward to its first entry
            else
            {
                while (idx > x1_start &&
                       (((hashes[idx - 1] >> shift_sub) & mask_sub) == (uint32_t)s))
                {
                    --idx;
                }
            }

            bounds[s] = idx;
        }

        // the final boundary is the end of the section
        bounds[num_splits] = x1_end;
        return bounds;
    }
    */

    // a simple (but working) version that has room for optimization
    // see: makeTaskBoundariesFast above, but it doesn't always yield correct results.
    std::vector<int> makeTaskBoundariesSimple(
        int x1_start, int x1_end,
        const std::span<uint32_t const> hashes,
        int num_split_bits)
    {
        int num_k_bits = params_.get_k();
        int num_section_bits = params_.get_num_section_bits();
        int num_split_sections = 1 << num_split_bits;

        std::vector<int> task_boundaries(num_split_sections + 1);
        std::fill(task_boundaries.begin(), task_boundaries.end(), -1);

        for (int i = x1_start; i < x1_end; i++)
        {
            uint32_t hash = hashes[i];
            uint32_t sub_section = (hash >> (num_k_bits - num_section_bits - num_split_bits));
            // zero out top num_section_bits from sub_section
            sub_section &= ((1 << num_split_bits) - 1);
            if (task_boundaries[sub_section] == -1)
            {
                // set boundary for this section
                task_boundaries[sub_section] = i;
            }
        }
        // set last task boundary to end of x1
        task_boundaries[num_split_sections] = x1_end;
        return task_boundaries;
    }

    std::vector<int>
    computeSectionBoundaries(std::span<uint32_t const> const hashes)
    {
        const int NUM_SECTIONS = params_.get_num_sections();
        const int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int shift = num_k_bits - num_section_bits;

        const int N = numeric_cast<int>(hashes.size());
        const int chunk = N / NUM_SECTIONS; // ideal block size

        std::vector<int> bounds(NUM_SECTIONS);

        if (N == 0)
            return bounds;

        for (int s = 0; s < NUM_SECTIONS; ++s)
        {
            // 1) jump to the “ideal” index
            int idx = std::min(s * chunk, N - 1);
            uint32_t const sec = hashes[idx] >> shift;

            // 2) if we’re too early, scan *forward* until we hit section s
            if (sec < (uint32_t)s)
            {
                while (idx < N && (hashes[idx] >> shift) < (uint32_t)s)
                {
                    ++idx;
                }
            }
            // 3) if we’re too late, scan *backward* until we drop below s,
            //    then step forward one to land on the first s
            else if (sec > (uint32_t)s)
            {
                while (idx > 0 && (hashes[idx] >> shift) > (uint32_t)s)
                {
                    --idx;
                }
                if ((hashes[idx] >> shift) < (uint32_t)s)
                {
                    ++idx;
                }
            }
            // 4) if we’re already inside section s, scan backward to its first hit
            else
            { // sec == s
                while (idx > 0 && ((hashes[idx - 1] >> shift) == (uint32_t)s))
                {
                    --idx;
                }
            }

            bounds[s] = idx;
        }

        return bounds;
    }

    void filterX2Candidates(std::span<uint32_t const> const x1_bitmask,
                            size_t num_x_pairs,
                            std::vector<uint32_t> &x2_potential_match_xs,
                            std::vector<uint32_t> &x2_potential_match_hashes)
    {
        const int num_k_bits = params_.get_k();
        const uint64_t NUM_XS = (1ULL << num_k_bits);

        // Determine “num_threads” much like TBB did
        unsigned num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0)
            num_threads = 4; // fallback
        const uint64_t per_thread = NUM_XS / num_threads;
        // round down to a multiple of 16
        const uint64_t chunk_size = per_thread - (per_thread % 16);

        const int x1_bits = num_k_bits / 2;
        const int x1_range_size = 1 << (num_k_bits - x1_bits);
        const size_t num_match_keys = params_.get_num_match_keys(1);
        const size_t num_match_target_hashes =
            num_x_pairs * x1_range_size * num_match_keys;

        const double hit_probability =
            double(num_match_target_hashes) /
            double(NUM_XS >> this->bitmask_shift_);
        // add extra safety margin for each reduction in k from 28
        const double extra_margin = (num_k_bits < 28) ? 1.0 + 0.01 * double(28 - num_k_bits) : 1.0;
        const uint64_t estimated_matches =
            uint64_t(hit_probability * static_cast<double>(NUM_XS) * extra_margin);

        // round down to multiple of 16
        const size_t MAX_RESULTS_PER_THREAD = (estimated_matches / num_threads) & ~size_t(0xf);

        if (false)
        {
            std::cout << "num x pairs: " << num_x_pairs << std::endl;
            std::cout << "num_match_target_hashes: " << num_match_target_hashes << std::endl;
            std::cout << "NUM_XS: " << NUM_XS << std::endl;
            std::cout << "hit_probability: " << hit_probability << std::endl;
            std::cout << "extra margin: " << extra_margin << std::endl;
            std::cout << "estimated_matches: " << estimated_matches << std::endl;
            std::cout << "esimtated matches calc:" << (double)hit_probability * (double)NUM_XS << std::endl;
        }

        // --- allocate output buffers just once ---
        Timer timer;
        timer.start("Allocating local potential matches");
        x2_potential_match_xs.resize(num_threads * MAX_RESULTS_PER_THREAD);
        x2_potential_match_hashes.resize(num_threads * MAX_RESULTS_PER_THREAD);
        timings_.allocating += timer.stop();

        // per-thread match counts
        std::vector<int> matches_per_thread(num_threads, 0);

        // build [0,1,2…num_threads-1]
        std::vector<int> thread_ids(num_threads);
        std::iota(thread_ids.begin(), thread_ids.end(), 0);
        std::atomic<bool> failed = false;

        use_prefetching_ = true;

        {
            timer.start("AES multi-threaded bitmask test");
            AesHash aes_hash(params_.get_plot_id_bytes(), params_.get_k());
            parallel_for_range(thread_ids.begin(), thread_ids.end(), [&](int t)
                               {
                int thread_matches = 0;
                uint64_t start = uint64_t(t) * chunk_size;
                uint64_t end = (t + 1 == (int)num_threads)
                                       ? NUM_XS
                                       : start + chunk_size;
                    
                if (!use_prefetching_) {
                    for (uint64_t x = start; x < end; x++) {

#if (HAVE_AES)
                        uint32_t g_hash = aes_hash.hash_x<false>(uint32_t(x));
#else
                        uint32_t g_hash = aes_hash.hash_x<true>(uint32_t(x));
#endif
                        
                        uint32_t bitmask_hash = g_hash >> this->bitmask_shift_;
                        int slot = bitmask_hash >> 5;
                        int bit = bitmask_hash & 31;
                        if (x1_bitmask[slot] & (1u << bit))
                        {
                            assert(thread_matches < static_cast<int>(MAX_RESULTS_PER_THREAD));
                            size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                            x2_potential_match_xs[idx] = uint32_t(x);
                            x2_potential_match_hashes[idx] = g_hash;
                            ++thread_matches;
                            if (thread_matches == static_cast<int>(MAX_RESULTS_PER_THREAD)) [[unlikely]]
                            {
                                failed.store(true);
                                goto done;
                            }
                        }
                    }
                } 
                else {
                    // Prefetching version
                    constexpr int PREFETCH_DIST = 128;  // must be a power of 2 for the mask below

                    if (end <= start) {
                        goto done;
                    }

                    // --- Prefetching pipeline ---
                    uint32_t hash_buf[PREFETCH_DIST];
                    uint32_t bitmask_hash_buf[PREFETCH_DIST];
                    int      slot_buf[PREFETCH_DIST];

                    // 1) Warm-up: compute and prefetch the first PREFETCH_DIST elements.
                    //    We won't *use* them yet; we're just filling the pipeline.
                    uint64_t x_pref = start;
                    for (int i = 0; i < PREFETCH_DIST; ++i, ++x_pref) {

#if (HAVE_AES)
                        uint32_t h = aes_hash.hash_x<false>(uint32_t(x_pref));
#else
                        uint32_t h = aes_hash.hash_x<true>(uint32_t(x_pref));
#endif

                        hash_buf[i] = h;
                        uint32_t bitmask_hash = h >> this->bitmask_shift_;
                        bitmask_hash_buf[i] = bitmask_hash;

                        int slot = bitmask_hash >> 5;
                        slot_buf[i] = slot;

                        //rx_prefetch_nta(&x1_bitmask[slot]);
                        PREFETCH(&x1_bitmask[slot]);
                    }

                    // 2) Main pipelined loop.
                    //
                    //    For each x in [start, end - PREFETCH_DIST):
                    //      - process the buffered entry for x
                    //      - compute hash/slot for x + PREFETCH_DIST
                    //      - prefetch x1_bitmask[slot(x + PREFETCH_DIST)]
                    //
                    uint64_t x      = start;
                    uint64_t limit  = end - PREFETCH_DIST;        // last x that still has a future x+PREFETCH_DIST
                    int      buf_ix = 0;                          // ring-buffer index

                    for (; x < limit; ++x, buf_ix = (buf_ix + 1) & (PREFETCH_DIST - 1)) {
                        // Process the element that was hashed & prefetched PREFETCH_DIST iterations ago.
                        uint32_t g_hash = hash_buf[buf_ix];
                        uint32_t bitmask_hash = bitmask_hash_buf[buf_ix];
                        int slot = slot_buf[buf_ix];
                        int bit  = bitmask_hash & 31;

                        if (x1_bitmask[slot] & (1u << bit)) {
                            assert(thread_matches < static_cast<int>(MAX_RESULTS_PER_THREAD));
                            size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                            x2_potential_match_xs[idx]     = uint32_t(x);
                            x2_potential_match_hashes[idx] = g_hash;
                            ++thread_matches;
                            if (thread_matches == static_cast<int>(MAX_RESULTS_PER_THREAD)) [[unlikely]] {
                                failed.store(true);
                                goto done;
                            }
                        }

                        // Now compute and prefetch for the future element at x_pref = x + PREFETCH_DIST.
                        uint64_t x_future = x + PREFETCH_DIST;

#if (HAVE_AES)
                        uint32_t h = aes_hash.hash_x<false>(uint32_t(x_future));
#else
                        uint32_t h = aes_hash.hash_x<true>(uint32_t(x_future));
#endif

                        hash_buf[buf_ix] = h;
                        uint32_t future_bitmask_hash = h >> this->bitmask_shift_;
                        bitmask_hash_buf[buf_ix] = future_bitmask_hash;

                        int future_slot = future_bitmask_hash >> 5;
                        slot_buf[buf_ix] = future_slot;

                        //rx_prefetch_nta(&x1_bitmask[future_slot]);
                        PREFETCH(&x1_bitmask[future_slot]);
                    }

                    // 3) Drain the remaining PREFETCH_DIST-1 buffered entries (no new prefetches).
                    for (; x < end; ++x, buf_ix = (buf_ix + 1) & (PREFETCH_DIST - 1)) {
                        uint32_t g_hash  = hash_buf[buf_ix];
                        uint32_t bitmask_hash = bitmask_hash_buf[buf_ix];
                        int slot = slot_buf[buf_ix];
                        int bit  = bitmask_hash & 31;

                        if (x1_bitmask[slot] & (1u << bit)) {
                            assert(thread_matches < static_cast<int>(MAX_RESULTS_PER_THREAD));
                            size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                            x2_potential_match_xs[idx]     = uint32_t(x);
                            x2_potential_match_hashes[idx] = g_hash;
                            ++thread_matches;
                            if (thread_matches == static_cast<int>(MAX_RESULTS_PER_THREAD)) [[unlikely]] {
                                failed.store(true);
                                goto done;
                            }
                        }
                    }
                }
            done:
                matches_per_thread[t] = thread_matches; });
            timings_.chachafilterx2sbybitmask += timer.stop();
        }

        if (failed.load())
        {
            throw std::runtime_error("Too many matches. This is unlikely to happen, so we won't be solving this");
        }

        // now sum up, compact, and resize just as before…
        timer.start("Counting total matches across threads");
        int total = 0;
        for (int m : matches_per_thread)
            total += m;
        timings_.misc += timer.stop();
        std::cout << "TOTAL x2 potential matches: " << total << std::endl;

        timer.start("Compacting x2 potential matches");
        int write_pos = matches_per_thread[0];
        for (unsigned t = 1; t < num_threads; ++t)
        {
            int cnt = matches_per_thread[t];
            auto src_x = x2_potential_match_xs.begin() + t * MAX_RESULTS_PER_THREAD;
            auto src_h = x2_potential_match_hashes.begin() + t * MAX_RESULTS_PER_THREAD;
            std::copy(src_x, src_x + cnt, x2_potential_match_xs.begin() + write_pos);
            std::copy(src_h, src_h + cnt, x2_potential_match_hashes.begin() + write_pos);
            write_pos += cnt;
        }
        x2_potential_match_xs.resize(total);
        x2_potential_match_hashes.resize(total);
        // std::cout << "x2_potential_match_xs size: " << x2_potential_match_xs.size() << std::endl;
        timings_.misc += timer.stop();
    }

    void hashX1Candidates(std::span<uint32_t const> const x_bits_list,
                          int const x1_bits,
                          int const x1_range_size,
                          std::vector<uint32_t> &x1s,
                          std::vector<uint32_t> &x1_hashes)
    {
        const size_t num_match_keys = params_.get_num_match_keys(1);
        const int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int num_match_key_bits = params_.get_num_match_key_bits(1);
        const int NUM_X1S = static_cast<int>(x_bits_list.size());

        // Pre-size output arrays:
        const std::size_t total_outputs =
            std::size_t(NUM_X1S) * x1_range_size * num_match_keys;
        x1s.resize(total_outputs);
        x1_hashes.resize(total_outputs);

        Timer timer;
        timer.start(
            "Hashing " + std::to_string(total_outputs) + " x1's groups " + std::to_string(NUM_X1S) + " with range size (" + std::to_string(x1_range_size) +
            ") and num match keys (" + std::to_string(num_match_keys) + ")");

        parallel_for_range(0, NUM_X1S, [&](int x1_index)
                           {
                // each thread in the pool runs this lambda
                ProofCore proof_core(params_);
                AesHash aes_hash(params_.get_plot_id_bytes(), params_.get_k());

                uint32_t x1_bit_dropped =
                    x_bits_list[static_cast<std::size_t>(x1_index)];
                uint32_t x1_range_start =
                    x1_bit_dropped << (num_k_bits - x1_bits);

                // flat base index for this x1_index
                std::size_t base = std::size_t(x1_index) * x1_range_size * num_match_keys;

                // Move match_key loop inside: compute chacha once per x and then emit entries for all match keys.
                for (uint32_t x = x1_range_start;
                     x < x1_range_start + x1_range_size;
                     ++x)
                {
                    uint32_t g_hash;
#if (HAVE_AES)
                        g_hash = aes_hash.hash_x<false>(uint32_t(x));
#else
                        g_hash = aes_hash.hash_x<true>(uint32_t(x));
#endif
                    

                    // offset within this x1 range for writing per-match_key blocks
                    std::size_t offset = static_cast<std::size_t>(x - x1_range_start);

                    // for each match_key compute target and final hash, write into precomputed slot
                    for (uint32_t match_key = 0; match_key < numeric_cast<uint32_t>(num_match_keys); ++match_key)
                    {
                        uint32_t matching_target = proof_core.matching_target(1, x, match_key);
                        uint32_t section_bits =
                            (g_hash >> (num_k_bits - num_section_bits)) & ((1u << num_section_bits) - 1);
                        uint32_t matching_section =
                            proof_core.matching_section(section_bits);
                        uint32_t hash = (matching_section << (num_k_bits - num_section_bits)) | (match_key << (num_k_bits - num_section_bits - num_match_key_bits)) | matching_target;

                        size_t write_idx = base + match_key * x1_range_size + offset;
                        x1s[write_idx] = x;
                        x1_hashes[write_idx] = hash;
                    }
                } });

        timings_.hashing_x1s += timer.stop();
    }

    // Phase 4 helper: Build a bitmask from the sorted x1 hashes.
    void buildX1Bitmask(std::span<uint32_t const> const x1_hashes,
                        std::vector<uint32_t> &x1_bitmask)
    {
        const int num_k_bits = params_.get_k();
        const int BITMASK_SIZE = 1UL << (num_k_bits - 5 - bitmask_shift_);

        Timer timer;
        timer.start("Allocating bitmask and setting to zero");
        x1_bitmask.assign(BITMASK_SIZE, 0);
        timings_.bitmaskfillzero += timer.stop();

        // TODO: could be multi-threaded
        timer.start("Setting bitmask hash");
        for (auto const &x1 : x1_hashes)
        {
            uint32_t hash = x1 >> bitmask_shift_;
            int slot = hash >> 5;
            int bit = hash & 31;
            x1_bitmask[slot] |= (1 << bit);
        }
        timings_.bitmasksetx1s += timer.stop();

#ifdef DEBUG_VERIFY
        if (false)
        {
            std::cout << "First 10 elements of bitmask:" << std::endl;
            for (int i = 0; i < 10; i++)
            {
                std::cout << "Bitmask[" << i << "]: " << x1_bitmask[i] << std::endl;
            }
            std::cout << "Last 10 elements of bitmask:" << std::endl;
            for (int i = BITMASK_SIZE - 10; i < BITMASK_SIZE; i++)
            {
                std::cout << "Bitmask[" << i << "]: " << x1_bitmask[i] << std::endl;
            }
        }
#endif
    }

    void setBitmaskShift(int shift)
    {
        bitmask_shift_ = shift;
    }

    ProofSolverTimings const &timings() const { return timings_; }

private:
    // ------------------------------------------------------------------------
    // Private member variables.
    // ------------------------------------------------------------------------
    ProofParams params_;
    ProofSolverTimings timings_;

    int bitmask_shift_ = 0;
    bool use_prefetching_ = true;
};
