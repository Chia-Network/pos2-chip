#pragma once

#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"

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

#include <execution>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
    #include <xmmintrin.h>
#endif

//#define DEBUG_VERIFY true

// Needed for macOS
typedef unsigned int uint;

struct T1_Match
{
    uint32_t x1;        // in T1 this is x1
    uint32_t x2;        // in T1 this is x2
    uint32_t pair_hash; // hash of x1 and x2 when paired.
};

// Structures used in later match stages
struct T2_match
{
    std::array<uint32_t, 4> x_values;
    // variables below could be passed along for optimization
    //uint32_t match_info;
    //uint64_t meta;
};

struct T3_match
{
    std::array<uint32_t, 8> x_values;
    // variables below could be passed along for optimization
    //uint32_t match_info;
    //uint64_t meta;
    //uint32_t partition;
};

struct T4_match
{
    std::array<uint32_t, 16> x_values;
    // variables below could be passed along for optimization
    //uint32_t match_info;
    //uint64_t meta;
};

struct T5_match
{
    std::array<uint32_t, 32> x_values;
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

    XBitGroupMappings compress_with_lookup(const std::vector<uint32_t> &x_bits_list,
                                           int x1_bits)
    {
        int total_ranges = 1 << x1_bits;
        // lookup[v] == -1  → we haven't seen v yet
        //         >= 0  → index into unique_values
        std::vector<int> lookup(total_ranges, -1);

        XBitGroupMappings out;

        int mapping_idx = 0;
        for (size_t i = 0; i < x_bits_list.size(); ++i)
        {
            uint32_t x_bits = x_bits_list[i];

            int idx = lookup[x_bits];
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
    // Input: an array of 128 x1 candidates.
    // Returns: a vector of complete proofs (each proof is an array of 256 uint64_t values).
    std::vector<std::vector<uint32_t>> solve(const std::vector<uint32_t> &x_bits_list, const std::vector<uint32_t> &x_solution)
    {
        XBitGroupMappings x_bits_group = compress_with_lookup(x_bits_list, params_.get_k() / 2);
#ifdef DEBUG_VERIFY
        if (true)
        {
            std::cout << "original x bits list: ";
            for (size_t i = 0; i < x_bits_list.size(); i++)
            {
                std::cout << x_bits_list[i] << ", ";
            }
            std::cout << std::endl;
            // output x1 list
            std::cout << "unique x bits list (" << x_bits_group.unique_x_bits_list.size() << "):" << std::endl;
            for (size_t i = 0; i < x_bits_group.unique_x_bits_list.size(); i++)
            {
                std::cout << x_bits_group.unique_x_bits_list[i] << ", ";
            }
            std::cout << std::endl;

            // output mappings
            std::cout << "x bits mapping (" << x_bits_group.mapping.size() << "):" << std::endl;
            for (size_t i = 0; i < x_bits_group.mapping.size(); i++)
            {
                std::cout << x_bits_group.mapping[i] << ", ";
            }
            std::cout << std::endl;

            std::cout << "x_solution (" << x_solution.size() << "):" << std::endl;
            for (size_t i = 0; i < x_solution.size(); i++)
            {
                std::cout << x_solution[i] << ", ";
            }
            std::cout << std::endl;
        }
#endif
        const int num_k_bits_ = params_.get_k();
        num_x_pairs_ = x_bits_list.size();

        // Derived parameters for phase 1:
        const int x1_bits = num_k_bits_ / 2;
        const int x1_range_size = 1 << (num_k_bits_ - x1_bits);

        const int num_unique_x_pairs = x_bits_group.unique_x_bits_list.size();
        const int num_match_keys = params_.get_num_match_keys(1);
        const int num_match_target_hashes = num_unique_x_pairs * x1_range_size * num_match_keys;

#ifdef DEBUG_VERIFY
        std::cout << "x1 bits: " << x1_bits << std::endl;
        std::cout << "x1 range size: " << x1_range_size << std::endl;
        std::cout << "num_match_keys: " << num_match_keys << std::endl;

        std::cout << "num_match_target_hashes: " << num_match_target_hashes << std::endl;
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
#ifdef NON_BIPARTITE_BEFORE_T3
        hashX1Candidates(x_bits_group.unique_x_bits_list, x1_bits, x1_range_size, x1s, x1_hashes);
#else
        hashX1CandidatesBiPartite(x_bits_group.unique_x_bits_list, x1_bits, x1_range_size, x1s, x1_hashes);
#endif

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
        buildX1Bitmask(num_match_target_hashes, x1_hashes, x1_bitmask);

        // Phase 5: Filter x2 candidates using the x1 bitmask.
        std::vector<uint32_t> x2_potential_match_xs;
        std::vector<uint32_t> x2_potential_match_hashes;
#ifdef NON_BIPARTITE_BEFORE_T3
        filterX2Candidates(x1_bitmask, num_unique_x_pairs, x2_potential_match_xs, x2_potential_match_hashes);
#else
        filterX2CandidatesBiPartite(x1_bitmask, num_x_pairs_, x2_potential_match_xs, x2_potential_match_hashes);
#endif

        // Phase 6: Sort the filtered x2 candidates.
        timer.start("Sorting matches (" + std::to_string(x2_potential_match_xs.size()) + ")");
        // resize sort buffer to match size so it can be used as switchable buffer
        x1s_sort_buffer.resize(x2_potential_match_xs.size());
        x1_hashes_sort_buffer.resize(x2_potential_match_xs.size());
        radixSort.sortByKey(x2_potential_match_hashes, x2_potential_match_xs, x1s_sort_buffer, x1_hashes_sort_buffer, num_k_bits_);
        timings_.sorting_filtered_x2s += timer.stop();

        // Phase 7: Match x1 and x2 entries within corresponding sections.
        std::vector<T1_Match> t1_matches = matchT1Candidates(x1_hashes, x1s, x2_potential_match_hashes, x2_potential_match_xs, num_match_target_hashes);

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
                for (size_t j = 0; j < t1_matches.size(); j++)
                {
                    if (t1_matches[j].x1 == x1 && t1_matches[j].x2 == x2)
                    {
                        found = true;
                        std::cout << "Found match for x pair: " << x1 << ", " << x2 << ", hash: " << t1_matches[j].pair_hash << std::endl;
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

                int x1_group = x_bits_group.mapping[i / 2];
                int x2_group = x_bits_group.mapping[i / 2 + 1];
                std::cout << "x1 group: " << x1_group << ", x2 group: " << x2_group << std::endl;

                bool found_l = false;
                for (int l = 0; l < t1_match_groups[x1_group].size(); l++)
                {
                    if (t1_match_groups[x1_group][l].x1 == x1 && t1_match_groups[x1_group][l].x2 == x2)
                    {
                        std::cout << "Found match for x pair: " << x1 << ", " << x2 << " hash: " << t1_match_groups[x1_group][l].pair_hash << std::endl;
                        found_l = true;
                    }
                }

                bool found_r = false;
                for (int r = 0; r < t1_match_groups[x2_group].size(); r++)
                {
                    if (t1_match_groups[x2_group][r].x1 == x3 && t1_match_groups[x2_group][r].x2 == x4)
                    {
                        std::cout << "Found match for x pair: " << x3 << ", " << x4 << " hash: " << t1_match_groups[x2_group][r].pair_hash << std::endl;
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
        std::vector<std::vector<T2_match>> t2_matches = matchT2Candidates(t1_match_groups, x_bits_group);
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

        const int t2_matches_size = t2_matches.size();

        // Phase 11: T3, T4, T5 Matching – Further pair T2 matches.
        std::vector<std::vector<T3_match>> t3_matches(t2_matches.size() / 2);
        std::vector<std::vector<T4_match>> t4_matches(t2_matches.size() / 4);
        std::vector<std::vector<T5_match>> t5_matches(t2_matches.size() / 8);
        matchT3T4T5Candidates(num_k_bits_, t2_matches, t3_matches, t4_matches, t5_matches);

#ifdef DEBUG_VERIFY
        std::cout << "T5 matches: " << t5_matches.size() << std::endl;
        for (size_t i = 0; i < t5_matches.size(); i++)
        {
            std::cout << "Group " << i << ":";
            for (size_t j = 0; j < t5_matches[i].size(); j++)
            {
                for (int x = 0; x < 32; x++)
                {
                    std::cout << t5_matches[i][j].x_values[x] << ", ";
                }
            }
            std::cout << std::endl;
        }
#endif

        // TODO: handle rare chance we get a false positive full proof
        auto all_proofs = constructProofs(t5_matches);

        timings_.printSummary();

        return all_proofs;
    }

    // Phase 11 helper: T3, T4, T5 matching – further pair and validate matches.
    void matchT3T4T5Candidates(int num_k_bits,
                               const std::vector<std::vector<T2_match>> &t2_matches,
                               std::vector<std::vector<T3_match>> &t3_matches,
                               std::vector<std::vector<T4_match>> &t4_matches,
                               std::vector<std::vector<T5_match>> &t5_matches)
    {

        Timer timer;
        timer.start("T3, T4, T5 Matching");

        // T3 matching.
        {
            ProofValidator validator(params_);
            for (int i = 0; i < t2_matches.size(); i += 2)
            {
                int t3_group = i / 2;
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
                            //t3.match_info = result.value().match_info_lower_partition;
                            //t3.meta = result.value().meta_lower_partition;
                            //t3.partition = result.value().lower_partition;
                            t3_matches[t3_group].push_back(t3);
                        }
                    }
                }
            }
        }

        // T4 matching.
        {
            ProofValidator validator(params_);
            for (int i = 0; i < t3_matches.size(); i += 2)
            {
                int t4_group = i / 2;
                const std::vector<T3_match> &groupA = t3_matches[i];
                const std::vector<T3_match> &groupB = t3_matches[i + 1];
                for (size_t j = 0; j < groupA.size(); j++)
                {
                    for (size_t k = 0; k < groupB.size(); k++)
                    {
                        uint32_t x_values[16] = {groupA[j].x_values[0], groupA[j].x_values[1],
                                                 groupA[j].x_values[2], groupA[j].x_values[3],
                                                 groupA[j].x_values[4], groupA[j].x_values[5],
                                                 groupA[j].x_values[6], groupA[j].x_values[7],
                                                 groupB[k].x_values[0], groupB[k].x_values[1],
                                                 groupB[k].x_values[2], groupB[k].x_values[3],
                                                 groupB[k].x_values[4], groupB[k].x_values[5],
                                                 groupB[k].x_values[6], groupB[k].x_values[7]};
                        std::vector<T4Pairing> t4_pairings = validator.validate_table_4_pairs(x_values);
                        if (t4_pairings.size() > 0)
                        {
                            // std::cout << t4_pairings.size() << " T4 pairings found." << std::endl;
                            for (const auto &pairing : t4_pairings)
                            {
                                T4_match t4;
                                t4.x_values = {groupA[j].x_values[0], groupA[j].x_values[1],
                                               groupA[j].x_values[2], groupA[j].x_values[3],
                                               groupA[j].x_values[4], groupA[j].x_values[5],
                                               groupA[j].x_values[6], groupA[j].x_values[7],
                                               groupB[k].x_values[0], groupB[k].x_values[1],
                                               groupB[k].x_values[2], groupB[k].x_values[3],
                                               groupB[k].x_values[4], groupB[k].x_values[5],
                                               groupB[k].x_values[6], groupB[k].x_values[7]};
                                //t4.match_info = pairing.match_info;
                                //t4.meta = pairing.meta;
                                t4_matches[t4_group].push_back(t4);
                            }
                        }
                    }
                }
            }
        }

        // T5 matching.
        {
            ProofValidator validator(params_);
            for (int i = 0; i < t4_matches.size(); i += 2)
            {
                int t5_group = i / 2;
                const std::vector<T4_match> &groupA = t4_matches[i];
                const std::vector<T4_match> &groupB = t4_matches[i + 1];
                for (size_t j = 0; j < groupA.size(); j++)
                {
                    for (size_t k = 0; k < groupB.size(); k++)
                    {
                        uint32_t x_values[32] = {groupA[j].x_values[0], groupA[j].x_values[1],
                                                 groupA[j].x_values[2], groupA[j].x_values[3],
                                                 groupA[j].x_values[4], groupA[j].x_values[5],
                                                 groupA[j].x_values[6], groupA[j].x_values[7],
                                                 groupA[j].x_values[8], groupA[j].x_values[9],
                                                 groupA[j].x_values[10], groupA[j].x_values[11],
                                                 groupA[j].x_values[12], groupA[j].x_values[13],
                                                 groupA[j].x_values[14], groupA[j].x_values[15],
                                                 groupB[k].x_values[0], groupB[k].x_values[1],
                                                 groupB[k].x_values[2], groupB[k].x_values[3],
                                                 groupB[k].x_values[4], groupB[k].x_values[5],
                                                 groupB[k].x_values[6], groupB[k].x_values[7],
                                                 groupB[k].x_values[8], groupB[k].x_values[9],
                                                 groupB[k].x_values[10], groupB[k].x_values[11],
                                                 groupB[k].x_values[12], groupB[k].x_values[13],
                                                 groupB[k].x_values[14], groupB[k].x_values[15]};
                        bool is_valid = validator.validate_table_5_pairs(x_values);
                        if (is_valid)
                        {
                            T5_match t5;
                            t5.x_values = {groupA[j].x_values[0], groupA[j].x_values[1],
                                           groupA[j].x_values[2], groupA[j].x_values[3],
                                           groupA[j].x_values[4], groupA[j].x_values[5],
                                           groupA[j].x_values[6], groupA[j].x_values[7],
                                           groupA[j].x_values[8], groupA[j].x_values[9],
                                           groupA[j].x_values[10], groupA[j].x_values[11],
                                           groupA[j].x_values[12], groupA[j].x_values[13],
                                           groupA[j].x_values[14], groupA[j].x_values[15],
                                           groupB[k].x_values[0], groupB[k].x_values[1],
                                           groupB[k].x_values[2], groupB[k].x_values[3],
                                           groupB[k].x_values[4], groupB[k].x_values[5],
                                           groupB[k].x_values[6], groupB[k].x_values[7],
                                           groupB[k].x_values[8], groupB[k].x_values[9],
                                           groupB[k].x_values[10], groupB[k].x_values[11],
                                           groupB[k].x_values[12], groupB[k].x_values[13],
                                           groupB[k].x_values[14], groupB[k].x_values[15]};
                            t5_matches[t5_group].push_back(t5);
                        }
                    }
                }
            }
        }
        timings_.misc += timer.stop();
    }

    // Phase 12 helper: Construct final proofs from T5 matches.
    // full proof is all t5 x-value collections, should be in same sequence order as quality chain
    std::vector<std::vector<uint32_t>> constructProofs(const std::vector<std::vector<T5_match>> &t5_matches)
    {
        std::vector<std::vector<uint32_t>> all_proofs;

        std::vector<uint32_t> full_proof;
        for (int g = 0; g < t5_matches.size(); g++)
        {
            for (const auto &match : t5_matches[g])
            {
                for (int x_pos = 0; x_pos < 32; x_pos++)
                {
                    full_proof.push_back(match.x_values[x_pos]);
                }
            }
        }
        all_proofs.push_back(full_proof);
        return all_proofs;
    }

    std::vector<std::vector<T2_match>> matchT2Candidates(
        const std::vector<std::vector<T1_Match>> &t1_match_groups,
        const XBitGroupMappings &x_bits_group)
    {
        Timer timer, sub_timer;
        timer.start("Matching T2 candidates");

        int num_k_bits = params_.get_k();
        int num_section_bits = params_.get_num_section_bits();
        int num_T2_match_key_bits = params_.get_num_match_key_bits(2);
        int num_T2_match_target_bits = params_.get_num_match_target_bits(2);

#ifdef DEBUG_VERIFY
        std::cout << "num_k_bits: " << num_k_bits << std::endl;
        std::cout << "num_section_bits: " << num_section_bits << std::endl;
        std::cout << "num_T2_match_key_bits: " << num_T2_match_key_bits << std::endl;
        std::cout << "num_T2_match_target_bits: " << num_T2_match_target_bits << std::endl;
#endif

        const int HASHES_BITMASK_SIZE_BITS = num_k_bits - 9;
        std::vector<uint32_t> hashes_bitmask(1u << HASHES_BITMASK_SIZE_BITS, 0);
        std::vector<T1_Match> L_short_list;

        int num_t2_groups = num_x_pairs_ / 2;
        std::vector<std::vector<T2_match>> t2_matches(num_t2_groups);

        // Process adjacent groups: group 0 with 1, 2 with 3, etc.
        for (int t2_group = 0; t2_group < num_t2_groups; ++t2_group)
        {
            int group_mapping_index_l = t2_group * 2;
            int group_mapping_index_r = group_mapping_index_l + 1;
            int t1_group_l = x_bits_group.mapping[group_mapping_index_l];
            int t1_group_r = x_bits_group.mapping[group_mapping_index_r];

            const auto &R_list = t1_match_groups[t1_group_r];

            // --- sort & bitmask R_list ---
            sub_timer.start();
            std::fill(hashes_bitmask.begin(), hashes_bitmask.end(), 0);
            auto R_sorted = R_list;
            std::sort(
#ifdef __cpp_lib_execution
                std::execution::par_unseq,
#endif
                      R_sorted.begin(), R_sorted.end(),
                      [](auto &a, auto &b)
                      { return a.pair_hash < b.pair_hash; });
            /*std::sort(R_sorted.begin(), R_sorted.end(),
                      [](auto &a, auto &b){ return a.pair_hash < b.pair_hash; });*/

            timings_.t2_sort_short_list += sub_timer.stop();

            for (size_t j = 0; j < R_sorted.size(); ++j)
            {
                uint32_t hash_reduced = R_sorted[j].pair_hash >> (num_k_bits - HASHES_BITMASK_SIZE_BITS);
                int slot = hash_reduced >> 5;
                int bit = hash_reduced & 31;
                hashes_bitmask[slot] |= (1 << bit);
            }

            const auto &L_list = t1_match_groups[t1_group_l];
            ProofCore proof_core(params_);
            uint32_t num_match_keys = 1u << num_T2_match_key_bits;

            // --- use C++20 parallel for to speed up the processing of L_list ---
            sub_timer.start();

            // prepare shared list and mutex
            L_short_list.clear();
            L_short_list.reserve(L_list.size() * 2);
            std::mutex list_mutex;

            // parallel loop over each L element
            std::for_each(
#ifdef __cpp_lib_execution
                std::execution::par,
#endif
                L_list.begin(), L_list.end(),
                [&](const T1_Match &lm)
                {
                    // each thread gets its own ProofCore instance
                    ProofCore thread_core(params_);

                    // collect matches for this lm
                    std::vector<T1_Match> local_matches;
                    local_matches.reserve(4);

                    for (uint32_t match_key = 0; match_key < num_match_keys; ++match_key)
                    {
                        uint64_t meta = (uint64_t(lm.x1) << num_k_bits) | lm.x2;
                        uint32_t L_hash = thread_core.matching_target(2, meta, match_key);
                        uint32_t sec_bits = lm.pair_hash >> (num_k_bits - num_section_bits);
                        #ifdef NON_BIPARTITE_BEFORE_T3
                        uint32_t R_sec = thread_core.matching_section(sec_bits);
                        uint32_t final_hash =
                            (R_sec << (num_k_bits - num_section_bits)) | (match_key << num_T2_match_target_bits) | L_hash;

                        uint32_t reduced = final_hash >> (num_k_bits - HASHES_BITMASK_SIZE_BITS);
                        if (hashes_bitmask[reduced >> 5] & (1u << (reduced & 31)))
                        {
                            local_matches.push_back({lm.x1, lm.x2, final_hash});
                        }
                        #else
                        uint32_t section1 = thread_core.matching_section(sec_bits);
                        uint32_t section2 = thread_core.inverse_matching_section(sec_bits);
                       
                        uint32_t final_hash =
                            (section1 << (num_k_bits - num_section_bits)) | (match_key << num_T2_match_target_bits) | L_hash;
                        uint32_t reduced = final_hash >> (num_k_bits - HASHES_BITMASK_SIZE_BITS);
                        
                        if (hashes_bitmask[reduced >> 5] & (1u << (reduced & 31)))
                        {
                            local_matches.push_back({lm.x1, lm.x2, final_hash});
                        }
                        
                        // now do for 2nd possible matching section
                        final_hash =
                            (section2 << (num_k_bits - num_section_bits)) | (match_key << num_T2_match_target_bits) | L_hash;

                        reduced = final_hash >> (num_k_bits - HASHES_BITMASK_SIZE_BITS);

                        if (hashes_bitmask[reduced >> 5] & (1u << (reduced & 31)))
                        {
                            local_matches.push_back({lm.x1, lm.x2, final_hash});
                        }
                        #endif
                    }

                    // merge thread-local results into shared vector
                    if (!local_matches.empty())
                    {
                        std::lock_guard<std::mutex> lock(list_mutex);
                        L_short_list.insert(
                            L_short_list.end(),
                            local_matches.begin(),
                            local_matches.end());
                    }
                });

            timings_.t2_gen_L_list += sub_timer.stop();

            // --- sort potential matches ---
            sub_timer.start();
            // sort parallel
            std::sort(
#ifdef __cpp_lib_execution
                std::execution::par_unseq,
#endif
                      L_short_list.begin(), L_short_list.end(),
                      [](auto &a, auto &b)
                      { return a.pair_hash < b.pair_hash; });
            /*std::sort(L_short_list.begin(), L_short_list.end(),
                      [](auto &a, auto &b){ return a.pair_hash < b.pair_hash; });*/
            timings_.t2_sort_short_list += sub_timer.stop();

            sub_timer.start();

            // --- two-pointer join L_short_list with R_sorted ---
            int L_pos = 0, R_pos = 0;
            auto &out = t2_matches[t2_group];
            while (L_pos < (int)L_short_list.size() &&
                   R_pos < (int)R_sorted.size())
            {
                uint32_t lhs_hash = L_short_list[L_pos].pair_hash;
                uint32_t rhs_hash = R_sorted[R_pos].pair_hash;

                if (lhs_hash == rhs_hash)
                {
                    size_t i = L_pos;
                    while (i < L_short_list.size() &&
                           L_short_list[i].pair_hash == rhs_hash)
                    {
                        // build stack-array for validator
                        uint32_t x_values[4] = {
                            L_short_list[i].x1,
                            L_short_list[i].x2,
                            R_sorted[R_pos].x1,
                            R_sorted[R_pos].x2};

                        // 4-bit filter
                        uint16_t lowL = uint16_t(x_values[1] & 0xFFFF);
                        uint16_t lowR = uint16_t(x_values[3] & 0xFFFF);
                        if (params_.get_k() < 16)
                        {
                            uint64_t ml = (uint64_t(x_values[0]) << num_k_bits) | x_values[1];
                            uint64_t mr = (uint64_t(x_values[2]) << num_k_bits) | x_values[3];
                            lowL = uint16_t(ml & 0xFFFF);
                            lowR = uint16_t(mr & 0xFFFF);
                        }

                        ProofCore pc(params_);
                        if (pc.match_filter_4(lowL, lowR))
                        {
                            ProofValidator validator(params_);
                            if (auto pairing = validator.validate_table_2_pairs(x_values))
                            {
                                T2_match t2;
                                t2.x_values = {x_values[0], x_values[1], x_values[2], x_values[3]};
                                //t2.match_info = pairing->match_info;
                                //t2.meta = pairing->meta;
                                out.push_back(t2);
                            }
                        }
                        ++i;
                    }
                    ++R_pos;
                }
                else if (lhs_hash < rhs_hash)
                {
                    ++L_pos;
                }
                else
                {
                    ++R_pos;
                }
            }

            timings_.t2_scan_for_matches += sub_timer.stop();
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
        // TODO: small chance some x's will have SAME range, but we can handle this later. For now this would be a bug.

        Timer timer;
        /*timer.start("Creating x1 ranges to index lookup table");
        int total_ranges = 1 << x1_bits; //(num_k_bits - x1_bits); // number of possible ranges an x1 can have is basically the number of bits it has.
        // std::cout << "Total ranges: " << total_ranges << " from x1_bits: " << x1_bits << " k_bits: " << num_k_bits << std::endl;
        std::vector<int> x1_ranges_to_index(total_ranges, 0);
        for (int i = 0; i < x_bits_list.size(); i++)
        {
            uint32_t x1_bit_dropped = x_bits_list[i];
            //uint32_t x1_bit_dropped = x1 >> (num_k_bits - x1_bits);
            // std::cout << "index: " << i << " x1: " << x1 << " x1_bit_dropped: " << x1_bit_dropped << std::endl;
            if (x1_bit_dropped >= total_ranges)
            {
                std::cout << "x1_bit_dropped: " << x1_bit_dropped << " OUT OF BOUNDS to total_ranges: " << total_ranges << std::endl;
            }
            else
            {
                x1_ranges_to_index[x1_bit_dropped] = i;
            }
        }
        timings_.misc += timer.stop();*/

        timer.start("Splitting matches into x1 groups");
        // Split concurrent_matches into separate match lists
        // We iterate over all matches to find the x1 part of the match, then we map that x1 by it's lower k/2 bits
        //  to find which of the 128 groups it belongs to.
        //  Then we push all matches into their own groups defined by x1.
        // A "group" is basically the nth x-pair in the proof.
        const int NUM_X1S = x_bit_group_mappings.unique_x_bits_list.size();
        int t1_num_matches = t1_matches.size();
        int max_matches_per_x_range = t1_num_matches * 2 / NUM_X1S;
        std::vector<std::vector<T1_Match>> match_lists(NUM_X1S, std::vector<T1_Match>());
        for (auto &list : match_lists)
        {
            list.reserve(max_matches_per_x_range);
        }

        for (int i = 0; i < t1_num_matches; i++)
        {
            T1_Match match = t1_matches[i];
            uint32_t x1_bit_dropped = match.x1 >> (num_k_bits - x1_bits);
            int lookup_index = x_bit_group_mappings.lookup[x1_bit_dropped];
#ifdef DEBUG_VERIFY
            if ((lookup_index == -1) || (lookup_index >= NUM_X1S))
            {
                // error
                std::cout << "x1_bit_dropped: " << x1_bit_dropped << " OUT OF BOUNDS to total_ranges: " << NUM_X1S << std::endl;
                continue;
            }
#endif
            // x1_ranges_to_index[x1_bit_dropped];
            //  std::vector<uint64_t> match_vec = { (match.x1 << num_k_bits) + match.x2, match.pair_hash };
            //  match_lists[lookup_index].push_back(match_vec);

            match_lists[lookup_index].push_back(match);
        }
        timings_.misc += timer.stop();

        return match_lists;
    }

    std::vector<T1_Match> matchT1Candidates(
        const std::vector<uint32_t> &x1_hashes,
        const std::vector<uint32_t> &x1s,
        const std::vector<uint32_t> &x2_match_hashes,
        const std::vector<uint32_t> &x2_match_xs,
        int num_match_target_hashes)
    {
        // 1) compute section boundaries
        Timer timer;
        timer.start("Computing section boundaries");

        #ifdef NON_BIPARTITE_BEFORE_T3
        auto section_boundaries_x1 = computeSectionBoundaries(x1_hashes);
        auto section_boundaries_x2 = computeSectionBoundaries(x2_match_hashes);
        #else
        auto section_boundaries_x1 = computeSectionBoundariesBiPartite(x1_hashes);
        auto section_boundaries_x2 = computeSectionBoundariesBiPartite(x2_match_hashes);
        #endif
        /*if (test_section_boundaries_x1 != section_boundaries_x1)
        {
            std::cout << "test_section_boundaries_x1 != section_boundaries_x1" << std::endl;
            // output both section boudnaries
            std::cout << "test_section_boundaries_x1: ";
            for (int i = 0; i < test_section_boundaries_x1.size(); i++)
            {
                std::cout << test_section_boundaries_x1[i] << ", ";
            }
            std::cout << std::endl;
            std::cout << "section_boundaries_x1: ";
            for (int i = 0; i < section_boundaries_x1.size(); i++)
            {
                std::cout << section_boundaries_x1[i] << ", ";
            }
            std::cout << std::endl;
            exit(23);
        }
        if (test_section_boundaries_x2 != section_boundaries_x2)
        {
            std::cout << "test_section_boundaries_x2 != section_boundaries_x2" << std::endl;
            exit(23);
        }*/
        timings_.misc += timer.stop();

        if (false)
        {
            // show section boundaries
            std::cout << "Section boundaries x1: ";
            for (int i = 0; i < section_boundaries_x1.size(); i++)
            {
                std::cout << section_boundaries_x1[i] << ", ";
            }
            std::cout << std::endl;
            std::cout << "Section boundaries x2: ";
            for (int i = 0; i < section_boundaries_x2.size(); i++)
            {
                std::cout << section_boundaries_x2[i] << ", ";
            }
            std::cout << std::endl;
            std::cout << "x1_hashes size: " << x1_hashes.size() << std::endl;
            std::cout << "x2_match_hashes size: " << x2_match_hashes.size() << std::endl;

            int k = params_.get_k();
            int num_section_bits = params_.get_num_section_bits();
            // verify section boundaries have section bits as part of hash range for section
            for (int i = 0; i < section_boundaries_x1.size(); i++)
            {
                int start_section = section_boundaries_x1[i];
                int end_section = (i + 1 == section_boundaries_x1.size())
                                      ? num_match_target_hashes
                                      : section_boundaries_x1[i + 1];
                std::cout << "section_boundaries_x1 section:" << i << " start_section: " << start_section << " end_section: " << end_section << std::endl;
                for (int j = start_section; j < end_section; j++)
                {
                    // std::cout << "x1 hash[" << j << "]: " << std::bitset<20>(x1_hashes[j]) << std::endl;
                    uint32_t hash = x1_hashes[j];
                    uint32_t section_bits = hash >> (k - num_section_bits);
                    if (section_bits != i)
                    {
                        std::cout << "Section bits: " << section_bits << " != " << i << std::endl;
                        std::cout << "x1     : " << x1s[j] << std::endl;
                        std::cout << "x1 hash: " << std::bitset<20>(hash) << std::endl;
                        std::cout << "i      : " << i << std::endl;
                        std::cout << "start  : " << start_section << std::endl;
                        std::cout << "end    : " << end_section << std::endl;
                        // exit(23);
                    }
                }
                std::cout << "Section " << i << ": [" << start_section << ", " << end_section << ")" << std::endl;
            }
            for (int i = 0; i < section_boundaries_x2.size(); i++)
            {
                int start_section = section_boundaries_x2[i];
                int end_section = (i + 1 == section_boundaries_x2.size())
                                      ? static_cast<int>(x2_match_hashes.size())
                                      : section_boundaries_x2[i + 1];
                for (int j = start_section; j < end_section; j++)
                {
                    uint32_t hash = x2_match_hashes[j];
                    uint32_t section_bits = hash >> (num_match_target_hashes - params_.get_num_section_bits());
                    if (section_bits != i)
                    {
                        std::cout << "Section bits: " << section_bits << " != " << i << std::endl;
                        // exit(23);
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

        // 3) build index array [0..NUM_SECTIONS-1]
        std::vector<int> sections(NUM_SECTIONS);
        std::iota(sections.begin(), sections.end(), 0);

        // 4) parallel match over each section
        timer.start("Matching x1 and x2 sorted lists");
        if (false)
        {
            std::for_each(
#ifdef __cpp_lib_execution
                std::execution::par,
#endif
                sections.begin(), sections.end(),
                [&](int section)
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

                    std::cout << "Section " << section << ": x1 [" << x1_start << ", " << x1_end << "), x2 [" << x2_start << ", " << x2_end << ") length: " << (x1_end - x1_start) << ", " << (x2_end - x2_start) << std::endl;

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
                    }
                });
        }
        else
        {
            int num_task_bit_splits = 8; // 256 splits

            for (int section = 0; section < NUM_SECTIONS; ++section)
            {
                int x1_start = section_boundaries_x1[section];
                int x1_end = (section + 1 == NUM_SECTIONS)
                                 ? num_match_target_hashes
                                 : section_boundaries_x1[section + 1];
                int x2_start = section_boundaries_x2[section];
                int x2_end = (section + 1 == NUM_SECTIONS)
                                 ? static_cast<int>(x2_match_hashes.size())
                                 : section_boundaries_x2[section + 1];

                auto task_boundaries_x1 = makeTaskBoundaries(
                    x1_start, x1_end,
                    x1_hashes,
                    num_task_bit_splits);
                auto task_boundaries_x2 = makeTaskBoundaries(
                    x2_start, x2_end,
                    x2_match_hashes,
                    num_task_bit_splits);

                if (false)
                {
                    // verify task boundaries
                    for (int i = 0; i < task_boundaries_x1.size(); i++)
                    {
                        std::cout << "Task boundaries x1[" << i << "]: " << task_boundaries_x1[i] << std::endl;
                        std::cout << "Task boundaries x2[" << i << "]: " << task_boundaries_x2[i] << std::endl;
                        uint32_t first_hash_x1 = x1_hashes[task_boundaries_x1[i]];
                        uint32_t first_hash_x2 = x2_match_hashes[task_boundaries_x2[i]];
                        std::cout << "Task boundaries x1[" << i << "] first hash: " << first_hash_x1 << std::endl;
                        std::cout << "Task boundaries x2[" << i << "] first hash: " << first_hash_x2 << std::endl;
                    }
                }

                int total_tasks = 1 << num_task_bit_splits;

                std::vector<int> task_ids(total_tasks);
                std::iota(task_ids.begin(), task_ids.end(), 0);

                std::for_each(
#ifdef __cpp_lib_execution
                    std::execution::par,
#endif
                    task_ids.begin(), task_ids.end(),
                    [&](int task_id)
                    {
                        ProofCore proof_core(params_);

                        int x1_start = task_boundaries_x1[task_id];
                        int x1_end = task_boundaries_x1[task_id + 1];
                        int x2_start = task_boundaries_x2[task_id];
                        int x2_end = task_boundaries_x2[task_id + 1];

                        // std::cout << "Task " << task_id << ": x1 [" << x1_start << ", " << x1_end << "), x2 [" << x2_start << ", " << x2_end << ") length: " << (x1_end - x1_start) << ", " << (x2_end - x2_start) << std::endl;

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
                        }
                    });
            }
            // exit(23);
        }
        timings_.match_x1_x2_sorted_lists += timer.stop();

        // 5) trim to actual match count and return
        int total = t1_num_matches.load(std::memory_order_relaxed);
        t1_matches.resize(total);

        return t1_matches;
    }

    std::vector<int> computeSectionBoundariesSimple(const std::vector<uint32_t> &hashes)
    {
        int NUM_SECTIONS = params_.get_num_sections();
        int num_k_bits = params_.get_k();
        int num_section_bits = params_.get_num_section_bits();
        std::vector<int> section_boundaries(NUM_SECTIONS);

        // set all to zero
        std::fill(section_boundaries.begin(), section_boundaries.end(), -1);

        // scan x1 hashes, get section and set boundary for it's index
        for (int i = 0; i < hashes.size(); i++)
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
    }

    std::vector<int> makeTaskBoundaries(
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

    /*std::vector<int> makeTaskBoundariesSimple(
        int x1_start, int x1_end,
        const std::vector<uint32_t> &hashes,
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
    }*/

    std::vector<int>
    computeSectionBoundaries(const std::vector<uint32_t> &hashes)
    {
        const int NUM_SECTIONS = params_.get_num_sections();
        const int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int shift = num_k_bits - num_section_bits;

        int N = (int)hashes.size();
        int chunk = N / NUM_SECTIONS; // ideal block size

        std::vector<int> bounds(NUM_SECTIONS);

        for (int s = 0; s < NUM_SECTIONS; ++s)
        {
            // 1) jump to the “ideal” index
            int idx = std::min(s * chunk, N - 1);
            uint32_t sec = hashes[idx] >> shift;

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

    std::vector<int>
    computeSectionBoundariesBiPartite(const std::vector<uint32_t> &hashes)
    {
        const int NUM_SECTIONS = params_.get_num_sections();
        const int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int shift = num_k_bits - num_section_bits;

        int N = (int)hashes.size();
        int chunk = N / (NUM_SECTIONS/2); // ideal block size

        std::vector<int> bounds(NUM_SECTIONS);

        // first half of sections shouldn't have any values.
        for (int s = 0; s < NUM_SECTIONS / 2; ++s) {
            bounds[s] = -1;
        }
        for (int s = NUM_SECTIONS/2; s < NUM_SECTIONS; ++s)
        {
            // 1) jump to the “ideal” index
            int idx = std::min((s - NUM_SECTIONS/2) * chunk, N - 1);
            uint32_t sec = hashes[idx] >> shift;

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

    void filterX2Candidates(const std::vector<uint32_t> &x1_bitmask,
                            int num_x_pairs,
                            std::vector<uint32_t> &x2_potential_match_xs,
                            std::vector<uint32_t> &x2_potential_match_hashes)
    {
        int num_k_bits = params_.get_k();
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
        const int num_match_keys = params_.get_num_match_keys(1);
        const int num_match_target_hashes =
            num_x_pairs * x1_range_size * num_match_keys;

        double hit_probability =
            double(num_match_target_hashes) /
            double(NUM_XS >> this->bitmask_shift_);
        const uint64_t estimated_matches =
            uint64_t((double)hit_probability * (double)NUM_XS);

        size_t MAX_RESULTS_PER_THREAD = estimated_matches / num_threads;

        if (false)
        {
            std::cout << "num x pairs: " << num_x_pairs << std::endl;
            std::cout << "num_match_target_hashes: " << num_match_target_hashes << std::endl;
            std::cout << "NUM_XS: " << NUM_XS << std::endl;
            std::cout << "hit_probability: " << hit_probability << std::endl;
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

        if (!use_prefetching_)
        {
            timer.start("Chacha multi-threaded bitmask test");
            std::for_each(
#ifdef __cpp_lib_execution
                std::execution::par,
#endif
                thread_ids.begin(), thread_ids.end(),
                [&](int t)
                {
                    int thread_matches = 0;
                    ProofCore proof_core(params_);
                    uint64_t start = uint64_t(t) * chunk_size;
                    uint64_t end = (t + 1 == (int)num_threads)
                                       ? NUM_XS
                                       : start + chunk_size;

                    uint32_t local_out[16];
                    for (uint64_t x = start; x < end; x += 16)
                    {
                        proof_core.hashing.g_range_16(uint32_t(x), local_out);
                        for (int i = 0; i < 16; ++i)
                        {
                            uint32_t chacha_hash = local_out[i];
                            uint32_t bitmask_hash = chacha_hash >> this->bitmask_shift_;
                            int slot = bitmask_hash >> 5;
                            int bit = bitmask_hash & 31;
                            if (x1_bitmask[slot] & (1u << bit))
                            {
                                size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                                x2_potential_match_xs[idx] = uint32_t(x + i);
                                x2_potential_match_hashes[idx] = chacha_hash;
                                ++thread_matches;
                            }
                        }
                    }
                    matches_per_thread[t] = thread_matches;
                });
            timings_.chachafilterx2sbybitmask += timer.stop();
        }
        else
        {
            timer.start("Chacha multi-threaded bitmask test with prefetching");
            std::for_each(
#ifdef __cpp_lib_execution
                std::execution::par,
#endif
                thread_ids.begin(), thread_ids.end(),
                [&](int t)
                {
                    int thread_matches = 0;
                    ProofCore proof_core(params_);
                    uint64_t start = uint64_t(t) * chunk_size;
                    uint64_t end = (t + 1 == (int)num_threads)
                                       ? NUM_XS
                                       : start + chunk_size;

                    constexpr int BATCH = 16;
                    uint32_t prior[BATCH], local[BATCH];

                    // initial batch
                    proof_core.hashing.g_range_16(uint32_t(start), prior);
                    for (int i = 0; i < BATCH; ++i)
                    {
                        uint32_t bitmask_hash = prior[i] >> this->bitmask_shift_;
                        int slot = bitmask_hash >> 5;
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
                        _mm_prefetch(reinterpret_cast<const char *>(&x1_bitmask[slot]), _MM_HINT_T0);
#elif defined(__arm__) || defined(__aarch64__)
                        __builtin_prefetch(&x1_bitmask[slot], 0, 0);
#endif
                    }

                    // main loop
                    for (uint64_t x = start + BATCH; x < end; x += BATCH)
                    {
                        proof_core.hashing.g_range_16(uint32_t(x), local);
                        // consume prior[]
                        for (int i = 0; i < BATCH; ++i)
                        {
                            uint32_t chacha_hash = prior[i];
                            uint32_t bitmash_hash = chacha_hash >> this->bitmask_shift_;
                            int slot = bitmash_hash >> 5, bit = bitmash_hash & 31;
                            if (x1_bitmask[slot] & (1u << bit))
                            {
                                size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                                x2_potential_match_xs[idx] = uint32_t((x - BATCH) + i);
                                x2_potential_match_hashes[idx] = chacha_hash;
                                ++thread_matches;
                            }
                        }
                        // prefetch for next round
                        for (int i = 0; i < BATCH; ++i)
                        {
                            uint32_t bitmask_hash = local[i] >> this->bitmask_shift_;
                            int slot = bitmask_hash >> 5;
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
                            _mm_prefetch(reinterpret_cast<const char *>(&x1_bitmask[slot]), _MM_HINT_T0);
#elif defined(__arm__) || defined(__aarch64__)
                            __builtin_prefetch(&x1_bitmask[slot], 0, 0);
#endif
                        }
                        std::copy(std::begin(local), std::end(local), std::begin(prior));
                    }

                    // final consume
                    for (int i = 0; i < BATCH; ++i)
                    {
                        uint32_t chacha_hash = prior[i];
                        uint32_t bitmask_hash = chacha_hash >> this->bitmask_shift_;
                        int slot = bitmask_hash >> 5, bit = bitmask_hash & 31;
                        if (x1_bitmask[slot] & (1u << bit))
                        {
                            size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                            x2_potential_match_xs[idx] = uint32_t((end - BATCH) + i);
                            x2_potential_match_hashes[idx] = chacha_hash;
                            ++thread_matches;
                        }
                    }

                    matches_per_thread[t] = thread_matches;
                });
            timings_.chachafilterx2sbybitmask += timer.stop();
        }

        // now sum up, compact, and resize just as before…
        timer.start("Counting total matches across threads");
        int total = 0;
        for (int m : matches_per_thread)
            total += m;
        timings_.misc += timer.stop();

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
        //std::cout << "x2_potential_match_xs size: " << x2_potential_match_xs.size() << std::endl;
        timings_.misc += timer.stop();
    }

    void filterX2CandidatesBiPartite(const std::vector<uint32_t> &x1_bitmask,
                                     int num_x_pairs,
                                     std::vector<uint32_t> &x2_potential_match_xs,
                                     std::vector<uint32_t> &x2_potential_match_hashes)
    {
        int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int last_section_l = params_.get_num_sections() / 2 - 1;
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
        const int num_match_keys = params_.get_num_match_keys(1);
        const int num_match_target_hashes =
            num_x_pairs * x1_range_size * num_match_keys;

        double hit_probability =
            double(num_match_target_hashes) /
            double(NUM_XS >> this->bitmask_shift_);
        const uint64_t estimated_matches =
            uint64_t(hit_probability * NUM_XS);

        size_t MAX_RESULTS_PER_THREAD = 2 * estimated_matches / num_threads;

        // --- allocate output buffers just once ---
        Timer timer;
        timer.start("Allocating local potential matches");
        x2_potential_match_xs.resize(num_threads * MAX_RESULTS_PER_THREAD);
        x2_potential_match_hashes.resize(num_threads * MAX_RESULTS_PER_THREAD);
        timings_.allocating += timer.stop();

        // per-thread match counts
        std::vector<int> matches_per_thread(num_threads, 0);
        std::vector<int> num_checks_per_thread(num_threads, 0);

        // build [0,1,2…num_threads-1]
        std::vector<int> thread_ids(num_threads);
        std::iota(thread_ids.begin(), thread_ids.end(), 0);

        if (!use_prefetching_)
        {
            timer.start("Chacha multi-threaded bitmask test (no prefetching)");
            std::for_each(
#ifdef __cpp_lib_execution
                std::execution::par,
#endif
                thread_ids.begin(), thread_ids.end(),
                [&](int t)
                {
                    int thread_matches = 0;
                    int num_checks = 0;
                    ProofCore proof_core(params_);
                    uint64_t start = uint64_t(t) * chunk_size;
                    uint64_t end = (t + 1 == (int)num_threads)
                                       ? NUM_XS
                                       : start + chunk_size;

                    uint32_t local_out[16];
                    for (uint64_t x = start; x < end; x += 16)
                    {
                        proof_core.hashing.g_range_16(uint32_t(x), local_out);
                        for (int i = 0; i < 16; ++i)
                        {
                            uint32_t chacha_hash = local_out[i];
                            uint32_t section = chacha_hash >> (num_k_bits - num_section_bits);

                            if (section <= last_section_l)
                            {
                                // std::cout << "skipping section: " << section << std::endl;
                                //  skip this section
                                continue;
                            }
                            else if (section > params_.get_num_sections())
                            {
                                std::cerr << "ERROR: section out of bounds: " << section << std::endl;
                                std::cout << "  k:" << num_k_bits << "  num_sections_bits: " << num_section_bits << std::endl;
                                // show chacha_hash as 32 bit binary
                                std::cout << "  chacha_hash: " << std::bitset<32>(chacha_hash) << std::endl;
                                // show section as 32 bit binary
                                std::cout << "  section: " << std::bitset<32>(section) << std::endl;
                                exit(23);
                            }

                            uint32_t bitmask_hash = chacha_hash >> this->bitmask_shift_;
                            int slot = bitmask_hash >> 5;
                            int bit = bitmask_hash & 31;
                            if (x1_bitmask[slot] & (1u << bit))
                            {
                                size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                                x2_potential_match_xs[idx] = uint32_t(x + i);
                                x2_potential_match_hashes[idx] = chacha_hash;
                                ++thread_matches;
                            }
                            ++num_checks;
                        }
                    }
                    matches_per_thread[t] = thread_matches;
                    num_checks_per_thread[t] = num_checks;
                });
            timings_.chachafilterx2sbybitmask += timer.stop();
        }
        else
        {
            timer.start("Chacha multi-threaded bitmask test with prefetching");
            std::for_each(
#ifdef __cpp_lib_execution
                std::execution::par,
#endif
                thread_ids.begin(), thread_ids.end(),
                [&](int t)
                {
                    int thread_matches = 0;
                    ProofCore proof_core(params_);
                    uint64_t start = uint64_t(t) * chunk_size;
                    uint64_t end = (t + 1 == (int)num_threads)
                                       ? NUM_XS
                                       : start + chunk_size;

                    constexpr int BATCH = 16;
                    uint32_t prior[BATCH], local[BATCH];

                    // initial batch
                    proof_core.hashing.g_range_16(uint32_t(start), prior);
                    for (int i = 0; i < BATCH; ++i)
                    {
                        uint32_t chacha_hash = prior[i];
                        uint32_t section = chacha_hash >> (num_k_bits - num_section_bits);
                        if (section <= last_section_l)
                        {
                            // skip this section
                            continue;
                        }
                        uint32_t bitmask_hash = chacha_hash >> this->bitmask_shift_;
                        int slot = bitmask_hash >> 5;
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
                        _mm_prefetch(reinterpret_cast<const char *>(&x1_bitmask[slot]), _MM_HINT_T0);
#elif defined(__arm__) || defined(__aarch64__)
                        __builtin_prefetch(&x1_bitmask[slot], 0, 0);
#endif
                    }

                    // main loop
                    for (uint64_t x = start + BATCH; x < end; x += BATCH)
                    {
                        proof_core.hashing.g_range_16(uint32_t(x), local);
                        // consume prior[]
                        for (int i = 0; i < BATCH; ++i)
                        {
                            uint32_t chacha_hash = prior[i];
                            uint32_t bitmash_hash = chacha_hash >> this->bitmask_shift_;
                            int slot = bitmash_hash >> 5, bit = bitmash_hash & 31;
                            if (x1_bitmask[slot] & (1u << bit))
                            {
                                size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                                x2_potential_match_xs[idx] = uint32_t((x - BATCH) + i);
                                x2_potential_match_hashes[idx] = chacha_hash;
                                ++thread_matches;
                            }
                        }
                        // prefetch for next round
                        for (int i = 0; i < BATCH; ++i)
                        {
                            uint32_t chacha_hash = local[i];
                            uint32_t section = chacha_hash >> (num_k_bits - num_section_bits);
                            if (section <= last_section_l)
                            {
                                // skip this section
                                continue;
                            }
                            uint32_t bitmask_hash = chacha_hash >> this->bitmask_shift_;
                            int slot = bitmask_hash >> 5;
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
                            _mm_prefetch(reinterpret_cast<const char *>(&x1_bitmask[slot]), _MM_HINT_T0);
#elif defined(__arm__) || defined(__aarch64__)
                            __builtin_prefetch(&x1_bitmask[slot], 0, 0);
#endif
                        }
                        std::copy(std::begin(local), std::end(local), std::begin(prior));
                    }

                    // final consume
                    for (int i = 0; i < BATCH; ++i)
                    {
                        uint32_t chacha_hash = prior[i];
                        uint32_t bitmask_hash = chacha_hash >> this->bitmask_shift_;
                        int slot = bitmask_hash >> 5, bit = bitmask_hash & 31;
                        if (x1_bitmask[slot] & (1u << bit))
                        {
                            size_t idx = size_t(t) * MAX_RESULTS_PER_THREAD + thread_matches;
                            x2_potential_match_xs[idx] = uint32_t((end - BATCH) + i);
                            x2_potential_match_hashes[idx] = chacha_hash;
                            ++thread_matches;
                        }
                    }

                    matches_per_thread[t] = thread_matches;
                });
            timings_.chachafilterx2sbybitmask += timer.stop();
        }

        // now sum up, compact, and resize just as before…
        timer.start("Counting total matches across threads");
        int total = 0;
        for (int m : matches_per_thread)
            total += m;
        timings_.misc += timer.stop();

        int total_checks = 0;
        for (int m : num_checks_per_thread)
            total_checks += m;

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

        //std::cout << "x2 potential matches: " << total << std::endl;
        //std::cout << "x2 total checks: " << total_checks << std::endl;
        //std::cout << "Pass rate: " << (double)total / (double)total_checks << std::endl;

        timings_.misc += timer.stop();
    }

    void hashX1Candidates(const std::vector<uint32_t> &x_bits_list,
                          int x1_bits,
                          int x1_range_size,
                          std::vector<uint32_t> &x1s,
                          std::vector<uint32_t> &x1_hashes)
    {
        const int num_match_keys = params_.get_num_match_keys(1);
        const int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int num_match_key_bits = params_.get_num_match_key_bits(1);
        const int NUM_X1S = static_cast<int>(x_bits_list.size());
        const uint32_t MATCH_BUCKET_TARGET_BITS =
            params_.get_num_match_target_bits(1);

        // Pre-size output arrays:
        std::size_t total_outputs =
            std::size_t(NUM_X1S) * x1_range_size * num_match_keys;
        x1s.resize(total_outputs);
        x1_hashes.resize(total_outputs);

#ifndef NON_BIPARTITE_BEFORE_T3
        const int last_section_l = params_.get_num_sections() / 2 - 1;
#endif

        Timer timer;
        timer.start(
            "Hashing " + std::to_string(total_outputs) + " x1's groups " + std::to_string(NUM_X1S) + " with range size (" + std::to_string(x1_range_size) +
            ") and num match keys (" + std::to_string(num_match_keys) + ")");

        // Build an index array [0, 1, 2, ..., NUM_X1S-1]
        std::vector<int> indices(NUM_X1S);
        std::iota(indices.begin(), indices.end(), 0);

        // Parallel for each index
        std::for_each(
#ifdef __cpp_lib_execution
            std::execution::par,
#endif
            indices.begin(), indices.end(),
            [&](int x1_index)
            {
                // each thread in the pool runs this lambda
                ProofCore proof_core(params_);
                uint32_t x_chachas[16];

                uint32_t x1_bit_dropped =
                    x_bits_list[static_cast<std::size_t>(x1_index)];
                uint32_t x1_range_start =
                    x1_bit_dropped << (num_k_bits - x1_bits);

                // flat base index for this x1_index
                std::size_t base = std::size_t(x1_index) * x1_range_size * num_match_keys;

                for (int match_key = 0; match_key < num_match_keys; ++match_key)
                {
                    std::size_t write_idx = base + std::size_t(match_key) * x1_range_size;

                    for (uint32_t x = x1_range_start;
                         x < x1_range_start + x1_range_size;
                         ++x, ++write_idx)
                    {
                        if ((x & 15) == 0)
                        {
                            proof_core.hashing.g_range_16(x, x_chachas);
                        }
                        uint32_t x_chacha = x_chachas[x & 15];

                        uint32_t hash = proof_core.matching_target(1, x, match_key);
                        uint32_t section_bits =
                            (x_chacha >> (num_k_bits - num_section_bits)) & ((1u << num_section_bits) - 1);
                        uint32_t matching_section =
                            proof_core.matching_section(section_bits);

                        hash = (matching_section << (num_k_bits - num_section_bits)) | (match_key << (num_k_bits - num_section_bits - num_match_key_bits)) | hash;

                        x1s[write_idx] = x;
                        x1_hashes[write_idx] = hash;
                    }
                }
            });

        timings_.hashing_x1s += timer.stop();
    }

    // k28 since it only has 4 sections with 0->2,1->3,2->1,3->0
    // means section 2 and 3 always both map to 0 and 1.
    // which means our bitmask only has to set section 0 and t2 filter will always check 0.
    void hashX1CandidatesBiPartite(
        const std::vector<uint32_t> &x_bits_list,
        int x1_bits,
        int x1_range_size,
        std::vector<uint32_t> &x1s,
        std::vector<uint32_t> &x1_hashes)
    {
        const int num_match_keys = params_.get_num_match_keys(1);
        const int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int num_match_key_bits = params_.get_num_match_key_bits(1);
        const int NUM_X1S = static_cast<int>(x_bits_list.size());
        const int num_sections = params_.get_num_sections();
        const int last_section_l = params_.get_num_sections() / 2 - 1;

        Timer timer;
        timer.start(
            "Hashing x1's with range size (" +
            std::to_string(x1_range_size) +
            ") and num match keys (" +
            std::to_string(num_match_keys) +
            ")");

        // Prepare per‐x1_index temporary storage
        // Each thread writes exclusively into its own slot here,
        // so no synchronization is needed.
        std::vector<std::vector<uint32_t>> tmp_x1s(NUM_X1S);
        std::vector<std::vector<uint32_t>> tmp_hashes(NUM_X1S);

        // Reserve a rough upper bound so we avoid repeated reallocations.
        for (int i = 0; i < NUM_X1S; ++i)
        {
            tmp_x1s[i].reserve(x1_range_size * num_match_keys);
            tmp_hashes[i].reserve(x1_range_size * num_match_keys);
        }

        // Build an index array [0,1,2,…,NUM_X1S-1]
        std::vector<int> indices(NUM_X1S);
        std::iota(indices.begin(), indices.end(), 0);

        // Parallel loop
        std::for_each(
#ifdef __cpp_lib_execution
            std::execution::par,
#endif
            indices.begin(), indices.end(),
            [&](int x1_index)
            {
                ProofCore proof_core(params_);
                uint32_t x_chachas[16];

                uint32_t x1_bit_dropped = x_bits_list[x1_index];
                uint32_t x1_range_start = x1_bit_dropped << (num_k_bits - x1_bits);

                auto &local_x1s = tmp_x1s[x1_index];
                auto &local_hashs = tmp_hashes[x1_index];

                for (int match_key = 0; match_key < num_match_keys; ++match_key)
                {
                    for (uint32_t x = x1_range_start;
                         x < x1_range_start + x1_range_size;
                         ++x)
                    {
                        if ((x & 15) == 0)
                        {
                            proof_core.hashing.g_range_16(x, x_chachas);
                        }
                        uint32_t x_chacha = x_chachas[x & 15];

                        // apply section filter
                        uint32_t section =
                            (x_chacha >> (num_k_bits - num_section_bits)) & ((1u << num_section_bits) - 1);

                        if (section > (uint32_t)last_section_l)
                        {
                            continue;
                        }

                        // compute the full hash
                        uint32_t hash = proof_core.matching_target(1, x, match_key);

                        uint32_t matching_section =
                            proof_core.matching_section(section);
                        uint32_t other_matching_section =
                            proof_core.inverse_matching_section(section);

                        // have to push to both sections
                        uint32_t matching_section_shifted =
                            matching_section << (num_k_bits - num_section_bits);
                        uint32_t match_key_shifted =
                            match_key << (num_k_bits - num_section_bits - num_match_key_bits);
                        uint32_t new_hash = matching_section_shifted | match_key_shifted | hash;

                        local_x1s.push_back(x);
                        local_hashs.push_back(new_hash);

                        matching_section_shifted = other_matching_section << (num_k_bits - num_section_bits);
                        new_hash = matching_section_shifted | match_key_shifted | hash;

                        local_x1s.push_back(x);
                        local_hashs.push_back(new_hash);
                    }
                }
            });

        // Now flatten all the per-thread buffers into the shared vectors
        size_t total = 0;
        for (auto &v : tmp_x1s)
            total += v.size();
        x1s.clear();
        x1_hashes.clear();
        x1s.reserve(total);
        x1_hashes.reserve(total);

        for (int i = 0; i < NUM_X1S; ++i)
        {
            auto &vx = tmp_x1s[i];
            auto &vh = tmp_hashes[i];
            x1s.insert(x1s.end(), vx.begin(), vx.end());
            x1_hashes.insert(x1_hashes.end(), vh.begin(), vh.end());
        }

        timings_.hashing_x1s += timer.stop();
    }

    // Phase 4 helper: Build a bitmask from the sorted x1 hashes.
    void buildX1Bitmask(int num_match_target_hashes,
                        const std::vector<uint32_t> &x1_hashes,
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
        for (int i = 0; i < x1_hashes.size(); i++)
        {
            uint32_t hash = x1_hashes[i] >> bitmask_shift_;
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

private:
    // ------------------------------------------------------------------------
    // Private member variables.
    // ------------------------------------------------------------------------
    ProofParams params_;
    ProofSolverTimings timings_;

    int num_x_pairs_ = 0;
    int bitmask_shift_ = 0;
    bool use_prefetching_ = true;
};
