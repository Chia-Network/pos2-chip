#pragma once

#include <cstdint>
#include <iostream>
#include <vector>
#include <span>
#include <array>
#include <algorithm>
#include <unordered_set>
#include <iomanip>
#include <bitset>

#include "pos/ProofParams.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofValidator.hpp"
#include "RadixSort.hpp"

template <typename PairingCandidate, typename T_Pairing, typename T_Result>
class TableConstructorGeneric
{
public:
    TableConstructorGeneric(int table_id, const ProofParams &proof_params)
        : table_id_(table_id), params_(proof_params),
          proof_core_(proof_params)
    {
    }

    virtual ~TableConstructorGeneric() = default;

    std::vector<std::vector<uint64_t>> find_candidates_prefixes(const std::vector<PairingCandidate> &pairing_candidates) const
    {
        const size_t num_sections = params_.get_num_sections();
        const size_t num_match_keys = params_.get_num_match_keys(table_id_);
        // Allocate a 2D counts array: dimensions [num_sections][num_match_keys]
        std::vector<std::vector<uint64_t>> counts(num_sections, std::vector<uint64_t>(num_match_keys, 0ULL));

        // For each candidate, use its public member "match_info"
        for (const auto &candidate : pairing_candidates)
        {
            uint32_t section = params_.extract_section_from_match_info(table_id_, candidate.match_info);
            uint32_t match_key = params_.extract_match_key_from_match_info(table_id_, candidate.match_info);
            counts[section][match_key]++;
        }

        // Now compute the prefix sums.
        // Each row (for a section) will have (num_match_keys_ + 1) values.
        std::vector<std::vector<uint64_t>> prefixes(num_sections, std::vector<uint64_t>(num_match_keys + 1, 0ULL));

        uint64_t total_prefix = 0ULL;
        for (size_t section = 0; section < num_sections; section++)
        {
            for (size_t mk = 0; mk < num_match_keys; mk++)
            {
                prefixes[section][mk] = total_prefix;
                total_prefix += counts[section][mk];
            }
            // The last element for each row is the overall "end" prefix.
            prefixes[section][num_match_keys] = total_prefix;
        }

        return prefixes;
    }

    std::vector<T_Pairing> find_pairs(
        const std::span<PairingCandidate const> &l_targets,
        const std::span<PairingCandidate const> &r_candidates)
    {
        std::vector<T_Pairing> pairs;
        pairs.reserve(std::max(l_targets.size(), r_candidates.size()));

        size_t left_index = 0;
        size_t right_index = 0;
        const size_t r_size = r_candidates.size();

        size_t num_match_target_bits = params_.get_num_match_target_bits(table_id_);
        uint32_t match_target_mask = (1 << num_match_target_bits) - 1;

        // We treat r_candidates like an iterator:
        bool have_r_candidate = (r_size > 0);
        size_t current_r_idx = 0;

        while (left_index < l_targets.size() && have_r_candidate)
        {
            uint32_t match_target_l = l_targets[left_index].match_info;
            uint32_t match_target_r = (r_candidates[current_r_idx].match_info & match_target_mask);

            if (match_target_l == match_target_r)
            {
                // we match all left items that share the same match_target_l
                size_t start_i = left_index;
                while (start_i < l_targets.size() &&
                       (l_targets[start_i].match_info == match_target_r))
                {
                    handle_pair(l_targets[start_i], r_candidates[current_r_idx], pairs, start_i, right_index);
                    start_i++;
                }
                // Advance the right side
                right_index++;
                if (right_index < r_size)
                {
                    current_r_idx = right_index;
                }
                else
                {
                    have_r_candidate = false;
                }
            }
            else if (match_target_r < match_target_l)
            {
                // Advance the right side
                right_index++;
                if (right_index < r_size)
                {
                    current_r_idx = right_index;
                }
                else
                {
                    have_r_candidate = false;
                }
            }
            else
            {
                // match_target_r > match_target_l => advance left side
                left_index++;
            }
        }
        return pairs;
    }

    virtual PairingCandidate matching_target(const PairingCandidate &/*prev_table_pair*/, uint32_t /*match_key_r*/)
    {
        throw std::runtime_error("matching_target not implemented");
    }

    virtual void handle_pair(const PairingCandidate &/*l_candidate*/,
                             const PairingCandidate &/*r_candidate*/,
                             std::vector<T_Pairing> &/*pairs*/,
                             size_t /*left_index*/,
                             size_t /*right_index*/)
    {
        throw std::runtime_error("handle_pair not implemented");
    }

    T_Result construct(const std::vector<PairingCandidate> &previous_table_pairs)
    {
        auto pairing_candidates_offsets = find_candidates_prefixes(previous_table_pairs);

        std::vector<T_Pairing> new_table_pairs;

        const size_t num_match_keys = params_.get_num_match_keys(table_id_);

        for (uint32_t section = 0; section < params_.get_num_sections(); section++)
        {
            #ifdef NON_BIPARTITE_BEFORE_T3
            uint32_t section_l = section;
            uint32_t section_r = proof_core_.matching_section(section_l);
            if (table_id_ > 3) {
                if (section_r < section_l) {
                    // swap
                    std::swap(section_l, section_r);
                }
            }
            #else
            // TODO: as section_l is always lower, we can speedup plotting by re-using the same section_r hashes
            // for each section_l (two total) they compare against.
            uint32_t other_section = proof_core_.matching_section(section);
            uint32_t section_l = std::min(section, other_section);
            uint32_t section_r = std::max(section, other_section);
            #endif

            // l_start..l_end in the previous_table_pairs
            uint64_t l_start = pairing_candidates_offsets[section_l][0];
            uint64_t l_end = pairing_candidates_offsets[section_l][num_match_keys];

            // For each match_key in [0..num_match_keys_-1]
            for (uint32_t match_key_r = 0; match_key_r < num_match_keys; match_key_r++)
            {
                uint64_t r_start = pairing_candidates_offsets[section_r][match_key_r];
                uint64_t r_end = pairing_candidates_offsets[section_r][match_key_r + 1];

                // copy out the R slice
                std::vector<PairingCandidate> r_candidates;
                r_candidates.reserve(r_end - r_start);
                for (uint64_t i = r_start; i < r_end; i++)
                {
                    r_candidates.push_back(previous_table_pairs[i]);
                }

                // Build the L candidates by calling matching_target
                std::vector<PairingCandidate> l_candidates;
                l_candidates.reserve(l_end - l_start);
                for (uint64_t i = l_start; i < l_end; i++)
                {
                    // matching_target(...) is virtual => implemented by each subclass
                    l_candidates.push_back(matching_target(previous_table_pairs[i], match_key_r));
                }

                // sort by match_target (default setting for RadixSort)
                // RadixSort<T_Target, decltype(&T_Target::match_target)> radix_sort(&T_Target::match_target);
                RadixSort<PairingCandidate, uint32_t> radix_sort;

                // create a temporary buffer as before:
                std::vector<PairingCandidate> temp_buffer(l_candidates.size());
                std::span<PairingCandidate> buffer(temp_buffer.data(), temp_buffer.size());
                radix_sort.sort(l_candidates, buffer);

                // Now pair them
                auto found_pairs = find_pairs(l_candidates, r_candidates);
                // Append found_pairs to new_table_pairs
                new_table_pairs.insert(new_table_pairs.end(), found_pairs.begin(), found_pairs.end());
            }
        }

        return post_construct(new_table_pairs);
    }

    // called following construct method - typically sort operations
    virtual T_Result post_construct(std::vector<T_Pairing> &/*pairings*/) const
    {
        throw std::runtime_error("post_construct not implemented");
    }

protected:
    int table_id_;
    ProofParams params_;

public:
    // Provide direct access to the underlying ProofCore if needed:
    ProofCore proof_core_;
};

struct Xs_Candidate
{
    uint32_t match_info; // k-bit match info.
    uint32_t x;          // k-bit x value.
};

class XsConstructor
{
public:
    XsConstructor(const ProofParams &proof_params)
        : params_(proof_params),
          proof_core_(proof_params)
    {
    }

    virtual ~XsConstructor() = default;

    std::vector<Xs_Candidate> construct()
    {
        std::vector<Xs_Candidate> x_candidates;
        // We'll have 2^(k-4) groups, each group has 16 x-values
        // => total of 2^(k-4)*16 x-values
        
        
        uint64_t num_groups = (1ULL << (params_.get_k() - 4));
        
        // hack to make smaller plot for debugging
        //num_groups = (uint64_t) ((double) num_groups * 0.75);

        x_candidates.reserve(num_groups * 16ULL);

        for (uint32_t x_group = 0; x_group < num_groups; x_group++)
        {
            uint32_t base_x = x_group * 16;
            uint32_t out_hashes[16];

            proof_core_.hashing.g_range_16(base_x, out_hashes);
            for (uint32_t i = 0; i < 16; i++)
            {
                uint32_t x = base_x + i;
                uint32_t match_info = out_hashes[i];
                // Store [ x, match_info ]
                x_candidates.push_back({match_info, x});
            }
        }
        RadixSort<Xs_Candidate, uint32_t> radix_sort;
        std::vector<Xs_Candidate> temp_buffer(x_candidates.size());
        // Create a span over the temporary buffer
        std::span<Xs_Candidate> buffer(temp_buffer.data(), temp_buffer.size());
        radix_sort.sort(x_candidates, buffer);

        return x_candidates;
    }

protected:
    ProofParams params_;
    ProofCore proof_core_;
};

class Table1Constructor : public TableConstructorGeneric<Xs_Candidate, T1Pairing, std::vector<T1Pairing>>
{
public:
    Table1Constructor(const ProofParams &proof_params)
        : TableConstructorGeneric(1, proof_params)
    {
    }

    // matching_target => (meta_l, r_match_target)
    Xs_Candidate matching_target(const Xs_Candidate &prev_table_pair, uint32_t match_key_r) override
    {
        // The "prev_table_pair" from Xs is: [ x, match_info ]
        // But for T1 we only need x => call matching_target(1, x, match_key_r).
        uint32_t x = prev_table_pair.x;
        uint32_t r_match_target = proof_core_.matching_target(1, x, match_key_r);
        // Return [ meta_l, match_target ]
        // Here meta_l = x

        // note: match_info is only the lower match_target_bits, rest is not used.
        return Xs_Candidate{.match_info = r_match_target, .x = x};
    }

    void handle_pair(const Xs_Candidate &l_candidate,
                     const Xs_Candidate &r_candidate,
                     std::vector<T1Pairing> &pairs,
                     size_t /*left_index*/,
                     size_t /*right_index*/) override
    {
        uint32_t x_left = l_candidate.x;
        uint32_t x_right = r_candidate.x;
        std::optional<T1Pairing> res = proof_core_.pairing_t1(x_left, x_right);
        if (res.has_value())
        {
            pairs.push_back(res.value());
        }
    }

    std::vector<T1Pairing> post_construct(std::vector<T1Pairing> &pairings) const override
    {
        RadixSort<T1Pairing, uint32_t> radix_sort;
        std::vector<T1Pairing> temp_buffer(pairings.size());
        // Create a span over the temporary buffer
        std::span<T1Pairing> buffer(temp_buffer.data(), temp_buffer.size());

        // sort by match_info (default)
        radix_sort.sort(pairings, buffer);

        return pairings;
    }
};

class Table2Constructor : public TableConstructorGeneric<T1Pairing, T2Pairing, std::vector<T2Pairing>>
{
public:
    Table2Constructor(const ProofParams &proof_params)
        : TableConstructorGeneric(2, proof_params)
    {
    }

    // matching_target => (meta_l, r_match_target)
    T1Pairing matching_target(const T1Pairing &prev_table_pair, uint32_t match_key_r) override
    {
        uint64_t meta_l = prev_table_pair.meta;
        uint32_t r_match_target = proof_core_.matching_target(2, meta_l, match_key_r);
        return T1Pairing{
            .meta = meta_l,
            .match_info = r_match_target};
    }

    void handle_pair(const T1Pairing &l_candidate,
                     const T1Pairing &r_candidate,
                     std::vector<T2Pairing> &pairs,
                     size_t /*left_index*/,
                     size_t /*right_index*/) override
    {
        uint64_t meta_l = l_candidate.meta;
        uint64_t meta_r = r_candidate.meta;
        auto opt_res = proof_core_.pairing_t2(meta_l, meta_r);
        if (opt_res.has_value())
        {
            auto r = opt_res.value();

            // x_bits becomes x1 >> k/2 bits, x3 >> k/2 bits.
            uint32_t x_bits_l = numeric_cast<uint32_t>((meta_l >> params_.get_k()) >> (params_.get_k() / 2));
            uint32_t x_bits_r = numeric_cast<uint32_t>((meta_r >> params_.get_k()) >> (params_.get_k() / 2));
            uint32_t x_bits = x_bits_l << (params_.get_k() / 2) | x_bits_r;

            T2Pairing pairing{
                .meta = r.meta,
                .match_info = r.match_info,
                .x_bits = x_bits,
#ifdef RETAIN_X_VALUES_TO_T3
                .xs = {
                    static_cast<uint32_t>(meta_l >> params_.get_k()),
                    static_cast<uint32_t>(meta_l & ((1 << params_.get_k()) - 1)),
                    static_cast<uint32_t>(meta_r >> params_.get_k()),
                    static_cast<uint32_t>(meta_r & ((1 << params_.get_k()) - 1))}
#endif
            };

            pairs.push_back(pairing);
        }
    }

    std::vector<T2Pairing> post_construct(std::vector<T2Pairing> &pairings) const override
    {
        RadixSort<T2Pairing, uint32_t> radix_sort;
        std::vector<T2Pairing> temp_buffer(pairings.size());
        // Create a span over the temporary buffer
        std::span<T2Pairing> buffer(temp_buffer.data(), temp_buffer.size());

        // sort by match_info (default)
        radix_sort.sort(pairings, buffer);

        return pairings;
    }
};

class Table3Constructor : public TableConstructorGeneric<T2Pairing, T3Pairing, std::vector<T3Pairing>>
{
public:
    Table3Constructor(const ProofParams &proof_params)
        : TableConstructorGeneric(3, proof_params)
    {
    }

    T2Pairing matching_target(const T2Pairing &prev_table_pair, uint32_t match_key_r) override
    {
        uint32_t r_match_target = proof_core_.matching_target(3, prev_table_pair.meta, match_key_r);
        return T2Pairing{
            .meta = prev_table_pair.meta,
            .match_info = r_match_target,
            .x_bits = prev_table_pair.x_bits,
#ifdef RETAIN_X_VALUES_TO_T3
            .xs = {
                static_cast<uint32_t>(prev_table_pair.xs[0]),
                static_cast<uint32_t>(prev_table_pair.xs[1]),
                static_cast<uint32_t>(prev_table_pair.xs[2]),
                static_cast<uint32_t>(prev_table_pair.xs[3])}
#endif
        };
    }

    void handle_pair(const T2Pairing &l_candidate,
                     const T2Pairing &r_candidate,
                     std::vector<T3Pairing> &pairs,
                     size_t /*left_index*/,
                     size_t /*right_index*/) override
    {
        uint64_t meta_l = l_candidate.meta;
        uint64_t meta_r = r_candidate.meta;
        std::optional<T3Pairing> opt_res = proof_core_.pairing_t3(meta_l, meta_r, l_candidate.x_bits, r_candidate.x_bits);
        if (opt_res.has_value())
        {
            T3Pairing pairing = opt_res.value();
#ifdef RETAIN_X_VALUES_TO_T3
            for (int i = 0; i < 4; i++)
            {
                pairing.xs[i] = l_candidate.xs[i];
                pairing.xs[i + 4] = r_candidate.xs[i];
            }
#endif
            pairs.push_back(pairing);
        }
    }

    std::vector<T3Pairing> post_construct(std::vector<T3Pairing> &pairings) const override
    {
        // do a radix sort on fragments
        RadixSort<T3Pairing, uint64_t, decltype(&T3Pairing::proof_fragment)> radix_sort(&T3Pairing::proof_fragment);

        // 1) sort by fragments
        std::vector<T3Pairing> temp_buffer(pairings.size());
        // Create a span over the temporary buffer
        std::span<T3Pairing> buffer(temp_buffer.data(), temp_buffer.size());
        radix_sort.sort(pairings, buffer, params_.get_k() * 2); // don't forget to sort full 2k bits

        return pairings;
    }
};