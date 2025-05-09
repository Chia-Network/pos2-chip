#pragma once

#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"

#include "pos/ProofValidator.hpp"
#include "ProofSolverTimings.hpp"
#include "ParallelRadixSort.hpp"

#include <array>
#include <string>
#include <vector>
#include <sys/resource.h>
#include <tbb/parallel_for.h>
#include <tbb/blocked_range.h>
#include <tbb/parallel_sort.h>
#include <tbb/concurrent_vector.h>
#include <algorithm>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <bitset>

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
    uint32_t match_info;
    uint64_t meta;
};

struct T3_match
{
    std::array<uint32_t, 8> x_values;
    uint32_t match_info;
    uint64_t meta;
    uint32_t partition;
};

struct T4_match
{
    std::array<uint32_t, 16> x_values;
    uint32_t match_info;
    uint64_t meta;
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

        const int NUM_X1S = x_bits_group.unique_x_bits_list.size();
        const int num_match_keys = params_.get_num_match_keys(1);
        const int num_match_target_hashes = NUM_X1S * x1_range_size * num_match_keys;

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
        hashX1Candidates(x_bits_group.unique_x_bits_list, x1_bits, x1_range_size, x1s, x1_hashes);

        timer.start("Allocating buffer for sort");
        std::vector<uint32_t> x1s_sort_buffer(num_match_target_hashes);
        std::vector<uint32_t> x1_hashes_sort_buffer(num_match_target_hashes);
        timings_.allocating += timer.stop();

        // Phase 3: Sort x1 candidates using parallel radix sort.
        timer.start("Sorting " + std::to_string(num_match_target_hashes) + " x1's");
        ParallelRadixSort radixSort;
        radixSort.sortByKey(x1_hashes, x1s, x1_hashes_sort_buffer, x1s_sort_buffer, num_k_bits_);
        timings_.sorting_x1s += timer.stop();

        // Phase 4: Build a bitmask from the sorted x1 hashes.
        std::vector<uint32_t> x1_bitmask;
        buildX1Bitmask(num_match_target_hashes, x1_hashes, x1_bitmask);

        // Phase 5: Filter x2 candidates using the x1 bitmask.
        std::vector<uint32_t> x2_potential_match_xs;
        std::vector<uint32_t> x2_potential_match_hashes;
        filterX2Candidates(x1_bitmask, num_x_pairs_, x2_potential_match_xs, x2_potential_match_hashes);

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

// output all t2 matches and check if our x solutions are in them
#ifdef DEBUG_VERIFY
        if (true)
        {
            std::cout << "T2 matches:" << std::endl;
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
        }
        std::cout << "T2 match groups: " << t2_matches.size() << std::endl;
#endif

        const int t2_matches_size = t2_matches.size();

        // Phase 11: T3, T4, T5 Matching – Further pair T2 matches.
        std::vector<std::vector<T3_match>> t3_matches(t2_matches.size() / 2);
        std::vector<std::vector<T4_match>> t4_matches(t2_matches.size() / 4);
        std::vector<std::vector<T5_match>> t5_matches(t2_matches.size() / 8);
        matchT3T4T5Candidates(num_k_bits_, t2_matches, t3_matches, t4_matches, t5_matches);

        // Phase 12: Construct final proofs from T5 matches.
        std::vector<std::vector<uint32_t>> all_proofs;

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
        std::vector<uint32_t> full_proof = constructProof(t5_matches);
        all_proofs.push_back(full_proof);

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

                            std::cout << "T3 match found: " << std::endl;
                            std::cout << "L xs: " << groupA[j].x_values[0] << ", " << groupA[j].x_values[1] << ", "
                                      << groupA[j].x_values[2] << ", " << groupA[j].x_values[3] << std::endl;
                            std::cout << "R xs: " << groupB[k].x_values[0] << ", " << groupB[k].x_values[1] << ", "
                                      << groupB[k].x_values[2] << ", " << groupB[k].x_values[3] << std::endl;

                            // could match faster in T4 by adding both T3 matches and then doing more checks
                            // but probably negligible speedup than this simpler way.
                            T3_match t3_lower;
                            t3_lower.x_values = {groupA[j].x_values[0], groupA[j].x_values[1],
                                                 groupA[j].x_values[2], groupA[j].x_values[3],
                                                 groupB[k].x_values[0], groupB[k].x_values[1],
                                                 groupB[k].x_values[2], groupB[k].x_values[3]};
                            t3_lower.match_info = result.value().match_info_lower_partition;
                            t3_lower.meta = result.value().meta_lower_partition;
                            t3_lower.partition = result.value().lower_partition;
                            t3_matches[t3_group].push_back(t3_lower);

                            // T3_match t3_upper;
                            // t3_upper.x_values = { groupA[j].x_values[0], groupA[j].x_values[1],
                            //                groupA[j].x_values[2], groupA[j].x_values[3],
                            //                groupB[k].x_values[0], groupB[k].x_values[1],
                            //                groupB[k].x_values[2], groupB[k].x_values[3] };
                            // t3_upper.match_info = result.value().match_info_upper_partition;
                            // t3_upper.meta = result.value().meta_upper_partition;
                            // t3_upper.partition = result.value().upper_partition;
                            // t3_matches[t3_group].push_back(t3_upper);
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
                            std::cout << t4_pairings.size() << " T4 pairings found." << std::endl;
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
                                t4.match_info = pairing.match_info;
                                t4.meta = pairing.meta;
                                t4_matches[t4_group].push_back(t4);
                                std::cout << "T4 match found: ";
                                for (size_t i = 0; i < 16; i++)
                                {
                                    std::cout << t4.x_values[i] << ", ";
                                }
                                std::cout << std::endl;
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

                            std::cout << "T5 match found: ";
                            for (size_t i = 0; i < 32; i++)
                            {
                                std::cout << t5.x_values[i] << ", ";
                            }
                            std::cout << std::endl;
                        }
                    }
                }
            }
        }
        timings_.misc += timer.stop();
    }

    // Phase 12 helper: Construct final proofs from T5 matches.
    // full proof is all t5 x-value collections, should be in same sequence order as quality chain
    std::vector<uint32_t> constructProof(const std::vector<std::vector<T5_match>> &t5_matches)
    {
        std::vector<uint32_t> full_proof{};
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
        return full_proof;
    }

    // Phase 10 helper: T2 Matching – Process adjacent T1 groups to produce T2 matches.
    std::vector<std::vector<T2_match>> matchT2Candidates(const std::vector<std::vector<T1_Match>> &t1_match_groups, const XBitGroupMappings &x_bits_group)
    {
        Timer timer;
        Timer sub_timer;
        std::cout << "-------------- T2 Matching --------------" << std::endl;
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

        const int HASHES_BITMASK_SIZE_BITS = 19;
        std::vector<uint32_t> hashes_bitmask(1 << HASHES_BITMASK_SIZE_BITS, 0);
        std::vector<T1_Match> L_short_list;
        int num_t2_groups = num_x_pairs_ / 2;
        std::vector<std::vector<T2_match>> t2_matches(num_t2_groups);

        t2_matches.resize(num_t2_groups);
        // std::cout << "Num x-pairs: " << num_x_pairs_ << " Number of T2 groups: " << num_t2_groups << std::endl;

        // Process adjacent groups: group 0 with 1, 2 with 3, etc.
        for (int t2_group = 0; t2_group < num_t2_groups; t2_group++)
        {
            int group_mapping_index_l = (t2_group * 2);
            int group_mapping_index_r = (t2_group * 2) + 1;
            int t1_group_l = x_bits_group.mapping[group_mapping_index_l];
            int t1_group_r = x_bits_group.mapping[group_mapping_index_r];
            
            const std::vector<T1_Match> &R_list = t1_match_groups[t1_group_r];

            sub_timer.start("Sorting R list");
            std::fill(hashes_bitmask.begin(), hashes_bitmask.end(), 0);
            std::vector<T1_Match> R_sorted = R_list;
            std::sort(R_sorted.begin(), R_sorted.end(), [](const T1_Match &a, const T1_Match &b)
                      { return a.pair_hash < b.pair_hash; });
            

            for (size_t j = 0; j < R_sorted.size(); j++)
            {
                uint32_t hash_reduced = R_sorted[j].pair_hash >> (num_k_bits - HASHES_BITMASK_SIZE_BITS);
                int slot = hash_reduced >> 5;
                int bit = hash_reduced & 31;
                hashes_bitmask[slot] |= (1 << bit);
            }
            timings_.t2_sort_short_list += sub_timer.stop();
            const std::vector<T1_Match> &L_list = t1_match_groups[t1_group_l];
            int potential_matches = 0;
            // std::cout << "L_list size: " << L_list.size() << std::endl;
            L_short_list.resize(L_list.size() * 2);
            ProofCore proof_core(params_);
            uint32_t num_match_keys = 1 << num_T2_match_key_bits;

            sub_timer.start("Processing L list");
            for (size_t j = 0; j < L_list.size(); j++)
            {
                // std::cout << "Processing L_list[" << j << "]" << std::endl;
                for (uint32_t match_key = 0; match_key < num_match_keys; match_key++)
                {
                    uint64_t meta = ((uint64_t)L_list[j].x1 << num_k_bits) | L_list[j].x2;
                    uint32_t L_hash = proof_core.matching_target(2, meta, match_key);
                    uint32_t L_section_bits = L_list[j].pair_hash >> (num_k_bits - num_section_bits);
                    uint32_t R_section = proof_core.matching_section(L_section_bits);
                    uint32_t L_final_hash = (R_section << (num_k_bits - num_section_bits)) | (match_key << num_T2_match_target_bits) | L_hash;
                    // if ((l_x1 == L_list[j].x1 && l_x2 == L_list[j].x2))
                    //{
                    //     std::cout << "Found x1 = " << l_x1 << " and x2 = " << l_x2 << " in L list at pos " << j << std::endl;
                    //     std::cout << "Hash: " << L_final_hash << std::endl;
                    // }
                    uint32_t hash_reduced = L_final_hash >> (num_k_bits - HASHES_BITMASK_SIZE_BITS);
                    int slot = hash_reduced >> 5;
                    int bit = hash_reduced & 31;
                    if (hashes_bitmask[slot] & (1 << bit))
                    {
                        T1_Match m;
                        m.x1 = L_list[j].x1;
                        m.x2 = L_list[j].x2;
                        m.pair_hash = L_final_hash;
                        // std::cout << "Found potential match " << m.x1 << ", " << m.x2 << ", hash: " << m.pair_hash << std::endl;
                        L_short_list[potential_matches++] = m;
                        if (potential_matches >= L_short_list.size())
                        {
                            std::cout << "Potential matches exceeded size, resizing..." << potential_matches << std::endl;
                            //  double the size
                            //  TODO: this happens quite often, so we should probably use a better data structure
                            L_short_list.resize(L_short_list.size() * 2);
                            // std::cout << "Resized to: " << L_short_list.size() << std::endl;
                        }
                    }
                }
            }
            // std::cout << "Potential matches: " << potential_matches << std::endl;
            L_short_list.resize(potential_matches);
            timings_.t2_gen_L_list += sub_timer.stop();

            // std::cout << "Sorting..." << std::endl;
            Timer sort_short_list_timer;
            sort_short_list_timer.start("Sorting potential matches");
            std::sort(L_short_list.begin(), L_short_list.end(), [](const T1_Match &a, const T1_Match &b)
                      { return a.pair_hash < b.pair_hash; });
            timings_.t2_sort_short_list += sort_short_list_timer.stop();
            // std::cout << "Sorted potential matches: " << L_short_list.size() << std::endl;
            int L_pos = 0, R_pos = 0;

            while (L_pos < potential_matches && R_pos < (int)R_sorted.size())
            {
                auto lhs_hash = L_short_list[L_pos].pair_hash;
                auto rhs_hash = R_sorted[R_pos].pair_hash;

                // std::cout << "Evaluating L Lpos " << L_pos << " : (" << L_short_list[L_pos].x1 << ", " << L_short_list[L_pos].x2 << ") R pos " << R_pos << ": (" << R_sorted[R_pos].x1 << ", " << R_sorted[R_pos].x2 << ")" << std::endl;
                if (lhs_hash == rhs_hash)
                {
                    // --- begin GROUPING LOOP over all L's with this same hash ---
                    size_t i = L_pos;
                    while (i < potential_matches && L_short_list[i].pair_hash == rhs_hash)
                    {
                        // exactly the same matching + validation code you already have,
                        // but replace every L_short_list[L_pos] with L_short_list[i]:

                        uint16_t lower16_L = L_short_list[i].x2 & 0xFFFF;
                        uint16_t lower16_R = R_sorted[R_pos].x2 & 0xFFFF;
                        if (params_.get_k() < 16)
                        {
                            uint32_t meta_l = ((uint64_t)L_short_list[i].x1 << num_k_bits) | L_short_list[i].x2;
                            uint32_t meta_r = ((uint64_t)R_sorted[R_pos].x1 << num_k_bits) | R_sorted[R_pos].x2;
                            lower16_L = meta_l & 0xFFFF;
                            lower16_R = meta_r & 0xFFFF;
                        }

                        ProofCore proof_core_inner(params_);
                        if (proof_core_inner.match_filter_4(lower16_L, lower16_R))
                        {
                            const uint32_t x_values[4] = {
                                L_short_list[i].x1, L_short_list[i].x2,
                                R_sorted[R_pos].x1, R_sorted[R_pos].x2};
                            Timer validate_timer;
                            ProofValidator validator(params_);
                            if (auto result = validator.validate_table_2_pairs(x_values);
                                result.has_value())
                            {
                                T2_match t2;
                                t2.x_values = {
                                    L_short_list[i].x1, L_short_list[i].x2,
                                    R_sorted[R_pos].x1, R_sorted[R_pos].x2};
                                t2.match_info = result->match_info;
                                t2.meta = result->meta;
                                t2_matches[t2_group].push_back(t2);
                            }
                            timings_.t2_validate_matches += validate_timer.stop();
                            
                        }

                        ++i;
                    }
                    // --- end GROUPING LOOP ---

                    // now advance _only_ the right side, so the next R can also get
                    // paired against _all_ the L's in the same hash‐group.
                    ++R_pos;
                }
                else if (L_short_list[L_pos].pair_hash < R_sorted[R_pos].pair_hash)
                {
                    L_pos++;
                }
                else
                {
                    R_pos++;
                }
            }
            // if (debug_stop)
            //{
            //     std::cout << "Debug stop at T2 group: " << t2_group << std::endl;
            //  exit(23);
            //}
            // exit(23);
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

    // Phase 7: Match x1 and x2 entries within corresponding sections.
    std::vector<T1_Match> matchT1Candidates(const std::vector<uint32_t> &x1_hashes,
                                            const std::vector<uint32_t> &x1s,
                                            const std::vector<uint32_t> &x2_match_hashes,
                                            const std::vector<uint32_t> &x2_match_xs,
                                            const int num_match_target_hashes)
    {
        // First compute section boundaries, matching will traverse data in sections/keys
        Timer timer;
        timer.start("Computing section boundaries");
        // auto [section_boundaries_x1, section_boundaries_x2] = computeSectionBoundaries(num_match_target_hashes, x1_hashes, x2_match_hashes);
        // auto [section_test_x1, section_test_x2] = computeSectionBoundariesSimple(num_match_target_hashes, x1_hashes, x2_match_hashes);
        auto [section_boundaries_x1, section_boundaries_x2] = computeSectionBoundariesSimple(num_match_target_hashes, x1_hashes, x2_match_hashes);
        timings_.misc += timer.stop();

        const int NUM_SECTIONS = params_.get_num_sections();
        if (true)
        {

            // show all section boundaries
            std::cout << "Section boundaries (" << NUM_SECTIONS << "):" << std::endl;
            for (int i = 0; i < NUM_SECTIONS; i++)
            {
                std::cout << "Section " << i << " x1: " << section_boundaries_x1[i] << " x2: " << section_boundaries_x2[i] << std::endl;
                // std::cout << "Section test x1: " << section_test_x1[i] << " x2: " << section_test_x2[i] << std::endl;
            }
        }

        int max_matches = 0; // for k28, expected is 2^21 matches
        switch (params_.get_k())
        {
        case 28:
            max_matches = 2100000*2;
            break;
        case 30:
            max_matches = 4200000;
            break;
        case 32:
            max_matches = 8400000;
            break;
        default:
            max_matches = 2100000;
        }

        std::cout << " Max matches: " << max_matches << std::endl;
        std::vector<T1_Match> t1_matches(max_matches);

        std::atomic<int> t1_num_matches = 0;

        // limit tbb to 1 thread
        // tbb::task_arena limited_arena(1);

        // for (int section = 0; section < NUM_SECTIONS; section++)

        tbb::parallel_for(0, NUM_SECTIONS, [&](int section)
                          {
            ProofCore proof_core(params_);

            //std::cout << "Processing section " << section << std::endl;

            // Get the start and end indices for the current section in both lists
            int x1_start = section_boundaries_x1[section];
            int x1_end = (section == NUM_SECTIONS - 1) ? num_match_target_hashes : section_boundaries_x1[section + 1];
            int x2_start = section_boundaries_x2[section];
            int x2_end = (section == NUM_SECTIONS - 1) ? x2_match_hashes.size() : section_boundaries_x2[section + 1];

            // Use two pointers to find matching hash values between x1 and x2 in the current section
            int i = x1_start;
            int j = x2_start;

            while (j < x2_end && i < x1_end)
            {

                uint32_t hash_x1 = x1_hashes[i];
                uint32_t hash_x2 = x2_match_hashes[j];

                if (hash_x1 == hash_x2)
                {
                    // When hashes match, find all matches for the current x2 element
                    int temp_i = i;

                    while (temp_i < x1_end && x1_hashes[temp_i] == hash_x2)
                    {
                        uint32_t lower_16_x1_bits = x1s[temp_i] & 0xFFFF;
                        uint32_t lower_16_x2_bits = x2_match_xs[j] & 0xFFFF;

                        uint32_t x1 = x1s[temp_i];
                        uint32_t x2 = x2_match_xs[j];
                        // use test filter 16 in proof core
                        auto t1_pairing = proof_core.pairing_t1(x1, x2);

                        // bool pass = proof_core.match_filter_16(lower_16_x1_bits, lower_16_x2_bits);

                        // if (pass)
                        if (t1_pairing.has_value())
                        {
                            
                            // Store the match details in the struct
                            T1_Match match;
                            match.x1 = x1s[temp_i];
                            match.x2 = x2_match_xs[j];

                            // get pair hash match info
                            // auto t1_pairing = proof_core.pairing_t1(match.x1, match.x2);

                            // if (!t1_pairing.has_value()) {
                            //  throw error, this should never happen
                            //    std::cout << "ERROR: T1 pairing failed for x1: " << match.x1 << " x2: " << match.x2 << std::endl;
                            //}

                            match.pair_hash = t1_pairing.value().match_info;

                            int pos = t1_num_matches.fetch_add(1, std::memory_order_relaxed);
                            if (pos > max_matches)
                            {
                                std::cout << "ERROR: Too many matches found" << std::endl;
                                exit(23);
                            }
                            t1_matches[pos] = match;
                        }

                        ++temp_i;
                    }
                    // Move to the next element in x2 to find more matches
                    ++j;
                }
                else if (hash_x1 < hash_x2)
                {
                    // Advance x1 pointer
                    ++i;
                }
                else
                {
                    // Advance x2 pointer
                    ++j;
                }
            } });
        timings_.match_x1_x2_sorted_lists += timer.stop();
        t1_matches.resize(t1_num_matches);
        return t1_matches;
    }

    std::tuple<std::vector<int>, std::vector<int>> computeSectionBoundariesSimple(int num_match_target_hashes,
                                                                                  const std::vector<uint32_t> &x1_hashes,
                                                                                  const std::vector<uint32_t> &x2_match_hashes)
    {
        int NUM_SECTIONS = params_.get_num_sections();
        int num_k_bits = params_.get_k();
        int num_section_bits = params_.get_num_section_bits();
        std::vector<int> section_boundaries_x1(NUM_SECTIONS);
        std::vector<int> section_boundaries_x2(NUM_SECTIONS);

        // set all to zero
        std::fill(section_boundaries_x1.begin(), section_boundaries_x1.end(), -1);
        std::fill(section_boundaries_x2.begin(), section_boundaries_x2.end(), -1);

        // scan x1 hashes, get section and set boundary for it's index
        for (int i = 0; i < x1_hashes.size(); i++)
        {
            uint32_t hash = x1_hashes[i];
            uint32_t section = hash >> (num_k_bits - num_section_bits);
            if (section_boundaries_x1[section] == -1)
            {
                // set boundary for this section
                section_boundaries_x1[section] = i;
            }
        }
        // scan x2 hashes, get section and set boundary for it's index
        for (int i = 0; i < x2_match_hashes.size(); i++)
        {
            uint32_t hash = x2_match_hashes[i];
            uint32_t section = hash >> (num_k_bits - num_section_bits);
            if (section_boundaries_x2[section] == -1)
            {
                // set boundary for this section
                section_boundaries_x2[section] = i;
            }
        }
        return std::make_tuple(section_boundaries_x1, section_boundaries_x2);
    }

    std::tuple<std::vector<int>, std::vector<int>> computeSectionBoundaries(int num_match_target_hashes,
                                                                            const std::vector<uint32_t> &x1_hashes,
                                                                            const std::vector<uint32_t> &x2_match_hashes)
    {
        int NUM_SECTIONS = params_.get_num_sections();
        int num_k_bits = params_.get_k();
        int num_section_bits = params_.get_num_section_bits();
        std::vector<int> section_boundaries_x1(NUM_SECTIONS);
        std::vector<int> section_boundaries_x2(NUM_SECTIONS);
        section_boundaries_x1[0] = 0;
        section_boundaries_x2[0] = 0;
        int expected_per_section_x1 = num_match_target_hashes / NUM_SECTIONS;
        int total_x2_matches = x2_match_hashes.size();
        int expected_per_section_x2 = total_x2_matches / NUM_SECTIONS;
        for (int section = 1; section < NUM_SECTIONS; section++)
        {
            int estimated_index = section * expected_per_section_x1;
            if (estimated_index >= num_match_target_hashes)
                estimated_index = num_match_target_hashes - 1;
            uint32_t target = section;
            auto it = std::lower_bound(x1_hashes.begin() + estimated_index, x1_hashes.end(),
                                       target, [&](uint32_t hash, uint32_t sec)
                                       { return (hash >> (num_k_bits - num_section_bits)) < sec; });
            section_boundaries_x1[section] = std::distance(x1_hashes.begin(), it);
        }
        for (int section = 1; section < NUM_SECTIONS; section++)
        {
            int estimated_index = section * expected_per_section_x2;
            if (estimated_index >= total_x2_matches)
                estimated_index = total_x2_matches - 1;
            uint32_t target = section;
            auto it = std::lower_bound(x2_match_hashes.begin() + estimated_index, x2_match_hashes.end(),
                                       target, [&](uint32_t hash, uint32_t sec)
                                       { return (hash >> (num_k_bits - num_section_bits)) < sec; });
            section_boundaries_x2[section] = std::distance(x2_match_hashes.begin(), it);
        }
        return std::make_tuple(section_boundaries_x1, section_boundaries_x2);
    }

    // Phase 5 helper: Filter x2 candidates using the x1 bitmask.
    void filterX2Candidates(const std::vector<uint32_t> &x1_bitmask,
                            const int num_x_pairs,
                            std::vector<uint32_t> &x2_potential_match_xs,
                            std::vector<uint32_t> &x2_potential_match_hashes)
    {
        int num_k_bits = params_.get_k();
        const uint64_t NUM_XS = (1ULL << num_k_bits);
        const uint num_threads = tbb::this_task_arena::max_concurrency();
        const uint chunk_size = (NUM_XS / num_threads) - ((NUM_XS / num_threads) % 16);

        const int x1_bits = num_k_bits / 2;
        const int x1_range_size = 1 << (num_k_bits - x1_bits);
        const int num_match_keys = params_.get_num_match_keys(1); // 1 << num_match_key_bits_;
        const int num_match_target_hashes = num_x_pairs * x1_range_size * num_match_keys;
        double hit_probability = (double)(num_match_target_hashes) / (double)(NUM_XS >> this->bitmask_shift_);
        // std::cout << "NUM_XS: " << NUM_XS << " HIT PROBABILITY: " << hit_probability << std::endl;

        const uint estimated_matches = hit_probability * NUM_XS;

        // this should be under max, since bitmask will have some collisions so this should be more than beyond expected variance.
        size_t MAX_RESULTS_PER_THREAD = estimated_matches / num_threads;

        // make local buffers for each thread to store chacha results
        Timer timer;
        timer.start("Allocating local potential matches");

        x2_potential_match_xs.resize(num_threads * MAX_RESULTS_PER_THREAD);
        x2_potential_match_hashes.resize(num_threads * MAX_RESULTS_PER_THREAD);

        timings_.allocating += timer.stop();

        std::vector<int> matches_per_thread(num_threads, 0);

        if (!this->use_prefetching_)
        {
            timer.start("Chacha multi-threaded bitmask test");
            tbb::parallel_for(uint(0), num_threads, [&](uint t)
                              {
                                  int thread_matches_found = 0;
                                  ProofCore proof_core(params_);
                                  uint start = t * chunk_size;
                                  uint end = (t == num_threads - 1) ? NUM_XS : start + chunk_size;
                                  uint32_t local_out_hashes[16];
                                  for (uint x = start; x < end; x += 16)
                                  {
                                      proof_core.hashing.g_range_16(x, local_out_hashes);
                                      for (int i = 0; i < 16; ++i)
                                      {
                                          uint chacha_hash = local_out_hashes[i];
                                          uint bitmask_hash = chacha_hash >> this->bitmask_shift_;
                                          int bitmask_slot = (bitmask_hash >> 5);
                                          int bitmask_bit = bitmask_hash & 31;
                                          uint32_t bitmask_slot_value = x1_bitmask[bitmask_slot];
                                          if (bitmask_slot_value & (1 << bitmask_bit))
                                          {

                                              x2_potential_match_xs[t * MAX_RESULTS_PER_THREAD + thread_matches_found] = x + i;
                                              x2_potential_match_hashes[t * MAX_RESULTS_PER_THREAD + thread_matches_found] = chacha_hash;

                                              thread_matches_found++;
                                          }
                                      }
                                  }
                                  matches_per_thread[t] = thread_matches_found;
                                  // std::cout << "Thread " << t << " x2_potential_matches found: " << thread_matches_found << std::endl;
                              });
            timings_.chachafilterx2sbybitmask += timer.stop();
        }
        else
        {
            // use prefetching

            timer.start("Chacha multi-threaded bitmask test with prefetching");
            tbb::parallel_for(uint(0), num_threads, [&](uint t)
                              {
                                  int thread_matches_found = 0;
                                  ProofCore proof_core(params_);
                                  uint start = t * chunk_size;
                                  uint end = (t == num_threads - 1) ? NUM_XS : start + chunk_size;

                                  // Initial prefetch for the starting range
                                  const int NUM_XS_PER_CHACHA = 16;
                                  uint32_t prior_local_out_hashes[NUM_XS_PER_CHACHA];
                                  uint32_t local_out_hashes[NUM_XS_PER_CHACHA];

                                  // prefetch the first chacha hashes
                                  proof_core.hashing.g_range_16(start, prior_local_out_hashes);
                                  for (int i = 0; i < NUM_XS_PER_CHACHA; i++)
                                  {
                                      uint bitmask_hash = prior_local_out_hashes[i] >> this->bitmask_shift_;
                                      int bitmask_slot = (bitmask_hash >> 5);
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
                                      _mm_prefetch(reinterpret_cast<const char *>(&x1_bitmask[bitmask_slot]), _MM_HINT_T0);
#elif defined(__arm__) || defined(__aarch64__)
                                      __builtin_prefetch(reinterpret_cast<const char *>(&x1_bitmask[bitmask_slot]), 0, 0);
#else
// Do nothing for unknown architectures
#endif
                                  }

                                  // Main loop for processing ranges
                                  for (uint x = start + NUM_XS_PER_CHACHA; x < end; x += NUM_XS_PER_CHACHA)
                                  {
                                      for (int i = 0; i < 1; i++)
                                      {
                                          proof_core.hashing.g_range_16(x, local_out_hashes);
                                      }

                                      // First handle all prior hashes that have hopefully been prefetched
                                      for (int i = 0; i < NUM_XS_PER_CHACHA; ++i)
                                      {
                                          uint chacha_hash = prior_local_out_hashes[i];
                                          uint bitmask_hash = chacha_hash >> this->bitmask_shift_;

                                          // Check if the bitmask bit is set
                                          int bitmask_slot = (bitmask_hash >> 5);
                                          int bitmask_bit = bitmask_hash & 31;
                                          uint32_t bitmask_slot_value = x1_bitmask[bitmask_slot];
                                          if (bitmask_slot_value & (1 << bitmask_bit))
                                          {

                                              x2_potential_match_xs[t * MAX_RESULTS_PER_THREAD + thread_matches_found] = (x - NUM_XS_PER_CHACHA) + i;
                                              x2_potential_match_hashes[t * MAX_RESULTS_PER_THREAD + thread_matches_found] = chacha_hash;

                                              thread_matches_found++;
                                          }
                                      }

                                      // Prefetch bitmask values for the next iteration
                                      for (int i = 0; i < NUM_XS_PER_CHACHA; i++)
                                      {
                                          uint bitmask_hash = local_out_hashes[i] >> this->bitmask_shift_;
                                          int bitmask_slot = (bitmask_hash >> 5);
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
                                          _mm_prefetch(reinterpret_cast<const char *>(&x1_bitmask[bitmask_slot]), _MM_HINT_T0);
#elif defined(__arm__) || defined(__aarch64__)
                                          __builtin_prefetch(reinterpret_cast<const char *>(&x1_bitmask[bitmask_slot]), 0, 0);
#else
                        // Do nothing for unknown architectures
#endif
                                      }

                                      // Move the current hashes to prior hashes for the next iteration
                                      std::copy(std::begin(local_out_hashes), std::end(local_out_hashes), std::begin(prior_local_out_hashes));
                                  }

                                  // Handle the remaining hashes from the last batch
                                  for (int i = 0; i < NUM_XS_PER_CHACHA; i++)
                                  {
                                      uint chacha_hash = prior_local_out_hashes[i];
                                      uint bitmask_hash = chacha_hash >> this->bitmask_shift_;
                                      int bitmask_slot = (bitmask_hash >> 5);
                                      int bitmask_bit = bitmask_hash & 31;

                                      uint32_t bitmask_slot_value = x1_bitmask[bitmask_slot];
                                      if (bitmask_slot_value & (1 << bitmask_bit))
                                      {

                                          x2_potential_match_xs[t * MAX_RESULTS_PER_THREAD + thread_matches_found] = (end - NUM_XS_PER_CHACHA) + i;
                                          x2_potential_match_hashes[t * MAX_RESULTS_PER_THREAD + thread_matches_found] = chacha_hash;

                                          thread_matches_found++;
                                      }
                                  }

                                  matches_per_thread[t] = thread_matches_found;

                                  // std::cout << "Thread x2_potential_matches found: " << thread_matches_found << std::endl;
                              });
            timings_.chachafilterx2sbybitmask += timer.stop();
        }

        timer.start("Counting total matches across threads");
        // get total matches across all buckets
        int total_matches = 0;
        for (int i = 0; i < num_threads; i++)
        {
            total_matches += matches_per_thread[i];
        }
        timings_.misc += timer.stop();
        // std::cout << "Total x2 potential matches: " << total_matches << std::endl;

        timer.start("Compacting x2 potential matches");
        // now fill in x2_potential_matches_vector with the results from each thread
        int copy_pos = matches_per_thread[0];
        for (int t = 1; t < num_threads; t++)
        {
            int thread_matches = matches_per_thread[t];

            std::copy(x2_potential_match_xs.begin() + t * MAX_RESULTS_PER_THREAD,
                      x2_potential_match_xs.begin() + t * MAX_RESULTS_PER_THREAD + thread_matches,
                      x2_potential_match_xs.begin() + copy_pos);
            std::copy(x2_potential_match_hashes.begin() + t * MAX_RESULTS_PER_THREAD,
                      x2_potential_match_hashes.begin() + t * MAX_RESULTS_PER_THREAD + thread_matches,
                      x2_potential_match_hashes.begin() + copy_pos);

            copy_pos += thread_matches;
        }

        // resize the final vectors
        x2_potential_match_xs.resize(total_matches);
        x2_potential_match_hashes.resize(total_matches);

        timings_.misc += timer.stop();
    }

    // Phase 2 helper: Hash each x1 candidate into its match bucket.
    void hashX1Candidates(const std::vector<uint32_t> &x_bits_list,
                          const int x1_bits,
                          const int x1_range_size,
                          std::vector<uint32_t> &x1s,
                          std::vector<uint32_t> &x1_hashes)
    {
        const int num_match_keys = params_.get_num_match_keys(1);
        const int num_k_bits = params_.get_k();
        const int num_section_bits = params_.get_num_section_bits();
        const int num_match_key_bits = params_.get_num_match_key_bits(1);
        const int NUM_X1S = x_bits_list.size();

        Timer timer;
        timer.start("Hashing x1's with range size (" + std::to_string(x1_range_size) + ") and num match keys (" + std::to_string(num_match_keys) + ")");

        tbb::parallel_for(tbb::blocked_range<int>(0, NUM_X1S), [&](const tbb::blocked_range<int> &range)
                          {
            ProofCore proof_core(params_); // make sure each thread get's it's own instance of proof core
            
            uint32_t x_chachas[16];
            for (int x1_index = range.begin(); x1_index < range.end(); x1_index++)
            {
                //uint32_t x1 = x_bits_list[x1_index];
                //uint32_t x1_bit_dropped = x1 >> (num_k_bits - x1_bits);
                uint32_t x1_bit_dropped = x_bits_list[x1_index];
                uint32_t x1_range_start = x1_bit_dropped << (num_k_bits - x1_bits);

                int local_thread_index = x1_index * x1_range_size * num_match_keys;

                const uint32_t MATCH_BUCKET_TARGET_BITS = params_.get_num_match_target_bits(1);
                const uint32_t MATCH_BUCKET_TARGET_BITS_MASK = (1 << MATCH_BUCKET_TARGET_BITS) - 1;

                for (int match_key = 0; match_key < num_match_keys; match_key++)
                {
                    for (uint32_t x = x1_range_start; x < x1_range_start + x1_range_size; x++)
                    {

                        if (x % 16 == 0)
                        {
                            // do chacha for x group
                            for (int i=0;i<1;i++)
                            {
                                proof_core.hashing.g_range_16(x, x_chachas);
                            }
                        }
                        uint32_t x_chacha = x_chachas[x % 16];
                        
                        uint32_t hash = proof_core.matching_target(1, x, match_key);
                        uint32_t section_bits = (x_chacha >> (num_k_bits - num_section_bits)) & ((1 << num_section_bits) - 1);
                        uint32_t matching_section = proof_core.matching_section(section_bits);

                        hash = matching_section << (num_k_bits - num_section_bits) | (match_key << (num_k_bits - num_section_bits - num_match_key_bits)) | hash;
                        
                        x1s[local_thread_index] = x;
                        x1_hashes[local_thread_index] = hash;
                        
                        local_thread_index++;

                    }
                }
            } });

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
        for (int i = 0; i < num_match_target_hashes; i++)
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