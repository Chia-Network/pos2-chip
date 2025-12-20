#pragma once

#include <algorithm>
#include <array>
#include <bitset>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <span>
#include <unordered_set>
#include <vector>

#include "RadixSort.hpp"
#include "common/ParallelForRange.hpp"
#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofParams.hpp"
#include "pos/ProofValidator.hpp"

template <typename PairingCandidate, typename T_Pairing, typename T_Result>
class TableConstructorGeneric {
public:
    TableConstructorGeneric(int table_id, ProofParams const& proof_params)
        : table_id_(table_id)
        , params_(proof_params)
        , proof_core_(proof_params)
    {
    }

    virtual ~TableConstructorGeneric() = default;

    std::vector<std::vector<uint64_t>> find_candidates_prefixes(
        std::vector<PairingCandidate> const& pairing_candidates) const
    {
        size_t const num_sections = params_.get_num_sections();
        size_t const num_match_keys = params_.get_num_match_keys(table_id_);
        // Allocate a 2D counts array: dimensions [num_sections][num_match_keys]
        std::vector<std::vector<uint64_t>> counts(
            num_sections, std::vector<uint64_t>(num_match_keys, 0ULL));

        // For each candidate, use its public member "match_info"
        for (auto const& candidate: pairing_candidates) {
            uint32_t section
                = params_.extract_section_from_match_info(table_id_, candidate.match_info);
            uint32_t match_key
                = params_.extract_match_key_from_match_info(table_id_, candidate.match_info);
            counts[section][match_key]++;
        }

        // Now compute the prefix sums.
        // Each row (for a section) will have (num_match_keys_ + 1) values.
        std::vector<std::vector<uint64_t>> prefixes(
            num_sections, std::vector<uint64_t>(num_match_keys + 1, 0ULL));

        uint64_t total_prefix = 0ULL;
        for (size_t section = 0; section < num_sections; section++) {
            for (size_t mk = 0; mk < num_match_keys; mk++) {
                prefixes[section][mk] = total_prefix;
                total_prefix += counts[section][mk];
            }
            // The last element for each row is the overall "end" prefix.
            prefixes[section][num_match_keys] = total_prefix;
        }

        return prefixes;
    }

    std::vector<T_Pairing> find_pairs(std::span<PairingCandidate const> const& l_targets,
        std::span<PairingCandidate const> const& r_candidates)
    {
        std::vector<T_Pairing> pairs;
        pairs.reserve(std::max(l_targets.size(), r_candidates.size()));

        size_t left_index = 0;
        size_t right_index = 0;
        size_t const r_size = r_candidates.size();

        size_t num_match_target_bits = params_.get_num_match_target_bits(table_id_);
        uint32_t match_target_mask = (1 << num_match_target_bits) - 1;

        // We treat r_candidates like an iterator:
        bool have_r_candidate = (r_size > 0);
        size_t current_r_idx = 0;

        while (left_index < l_targets.size() && have_r_candidate) {
            uint32_t match_target_l = l_targets[left_index].match_info;
            uint32_t match_target_r = (r_candidates[current_r_idx].match_info & match_target_mask);

            if (match_target_l == match_target_r) {
                // we match all left items that share the same match_target_l
                size_t start_i = left_index;
                while (start_i < l_targets.size()
                    && (l_targets[start_i].match_info == match_target_r)) {
                    handle_pair(l_targets[start_i],
                        r_candidates[current_r_idx],
                        pairs,
                        start_i,
                        right_index);
                    start_i++;
                }
                // Advance the right side
                right_index++;
                if (right_index < r_size) {
                    current_r_idx = right_index;
                }
                else {
                    have_r_candidate = false;
                }
            }
            else if (match_target_r < match_target_l) {
                // Advance the right side
                right_index++;
                if (right_index < r_size) {
                    current_r_idx = right_index;
                }
                else {
                    have_r_candidate = false;
                }
            }
            else {
                // match_target_r > match_target_l => advance left side
                left_index++;
            }
        }
        return pairs;
    }

    virtual PairingCandidate matching_target(
        PairingCandidate const& /*prev_table_pair*/, uint32_t /*match_key_r*/)
    {
        throw std::runtime_error("matching_target not implemented");
    }

    virtual void handle_pair(PairingCandidate const& /*l_candidate*/,
        PairingCandidate const& /*r_candidate*/,
        std::vector<T_Pairing>& /*pairs*/,
        size_t /*left_index*/,
        size_t /*right_index*/)
    {
        throw std::runtime_error("handle_pair not implemented");
    }

    struct SplitRange {
        std::size_t l_begin;
        std::size_t l_end;
        std::size_t r_begin;
        std::size_t r_end;
    };
    // Make T split ranges for (l_candidates, r_candidates) for use in T threads.
    // Strategy:
    //  1) Split L evenly by index.
    //  2) For each internal boundary, move it DOWN so we don't split equal keys in L.
    //  3) For each L-boundary, map to an approximate position in R by proportion,
    //     then scan up/down locally until we find the matching key in R.
    std::vector<SplitRange> make_splits_simple(std::span<PairingCandidate const> l_candidates,
        std::span<PairingCandidate const> r_candidates,
        unsigned num_threads,
        uint32_t match_target_mask)
    {
        using std::size_t;

        std::vector<SplitRange> result;

        size_t const l_size = l_candidates.size();
        size_t const r_size = r_candidates.size();

        if (l_size == 0 || r_size == 0 || num_threads == 0) {
            return result;
        }

        // Clamp thread count
        num_threads = std::min<unsigned>(num_threads, static_cast<unsigned>(l_size));
        if (num_threads == 0) {
            return result;
        }

        auto key = [match_target_mask](PairingCandidate const& c) -> uint32_t {
            return c.match_info & match_target_mask;
        };

        // 1) Build L split indices: l_splits[0..num_splits], where
        //    l_splits[0] = 0, l_splits[num_splits] = l_size.
        unsigned const num_splits = num_threads; // one chunk per thread
        std::vector<size_t> l_splits(num_splits + 1);
        l_splits[0] = 0;
        l_splits[num_splits] = l_size;

        // Base even split size
        size_t const base_chunk = l_size / num_splits;

        for (unsigned i = 1; i < num_splits; ++i) {
            // Initial even index
            size_t idx = i * base_chunk;
            if (idx >= l_size)
                idx = l_size - 1; // clamp just in case

            // 2) Move DOWN if we are in the middle of a run of equal keys in L.
            uint32_t k = key(l_candidates[idx]);
            while (idx > 0 && key(l_candidates[idx - 1]) == k) {
                --idx;
            }

            // Ensure monotonicity
            if (idx < l_splits[i - 1]) {
                idx = l_splits[i - 1];
            }

            l_splits[i] = idx;
        }

        // 3) Build corresponding R split indices: r_splits[0..num_splits]
        std::vector<size_t> r_splits(num_splits + 1);
        r_splits[0] = 0;
        r_splits[num_splits] = r_size;

        for (unsigned i = 1; i < num_splits; ++i) {
            size_t l_idx = l_splits[i];
            // r_idx starts at proportional position to split
            size_t r_idx = r_size * i / num_splits;

            // If this L boundary is at the very end, R boundary is also at the end.
            if (l_idx >= l_size) {
                r_splits[i] = r_size;
                continue;
            }

            // if l size is less than r side, then scan down from r side
            while (l_candidates[l_idx].match_info
                < (r_candidates[r_idx].match_info & match_target_mask)) {
                if (r_idx == 0) {
                    break;
                }
                --r_idx;
            }
            // if they are same, then scan r down to the first of that key
            if (l_candidates[l_idx].match_info
                == (r_candidates[r_idx].match_info & match_target_mask)) {
                while (r_idx > 0
                    && (r_candidates[r_idx - 1].match_info & match_target_mask)
                        == l_candidates[l_idx].match_info) {
                    --r_idx;
                }
            }
            // if l size is greater than r side, then scan up from r side
            while (l_candidates[l_idx].match_info
                > (r_candidates[r_idx].match_info & match_target_mask)) {
                if (r_idx == r_size) {
                    break;
                }
                ++r_idx;
            }
            // end result is R is always >= L side match key.
            r_splits[i] = r_idx;
        }

        // 4) Build per-thread ranges
        result.reserve(num_splits);
        for (unsigned i = 0; i < num_splits; ++i) {
            size_t l_begin = l_splits[i];
            size_t l_end = l_splits[i + 1];
            size_t r_begin = r_splits[i];
            size_t r_end = r_splits[i + 1];

            result.push_back(SplitRange { l_begin, l_end, r_begin, r_end });
        }

        return result;
    }

    T_Result construct(std::vector<PairingCandidate> const& previous_table_pairs)
    {
        auto pairing_candidates_offsets = find_candidates_prefixes(previous_table_pairs);

        std::vector<T_Pairing> new_table_pairs;
        std::mutex new_table_pairs_mutex;

        size_t const num_match_keys = params_.get_num_match_keys(table_id_);

        // parallel across sections
        // parallel_for_range(uint64_t(0), uint64_t(params_.get_num_sections()), [&](uint64_t
        // section)
        for (uint32_t section = 0; section < params_.get_num_sections(); section++) {
            uint32_t section_l = section;
            uint32_t section_r = proof_core_.matching_section(section_l);

            // l_start..l_end in the previous_table_pairs
            uint64_t l_start = pairing_candidates_offsets[section_l][0];
            uint64_t l_end = pairing_candidates_offsets[section_l][num_match_keys];

            // For each match_key in [0..num_match_keys_-1]
            for (uint32_t match_key_r = 0; match_key_r < num_match_keys; match_key_r++) {
                uint64_t r_start = pairing_candidates_offsets[section_r][match_key_r];
                uint64_t r_end = pairing_candidates_offsets[section_r][match_key_r + 1];

                // std::cout << "Range is: " << r_start << " to " << r_end <<  " length " << (r_end
                // - r_start) << std::endl;

                // Build the L candidates by calling matching_target
                timer_.start("Build L candidates");
                std::vector<PairingCandidate> l_candidates;
                l_candidates.resize(l_end - l_start);
                timings.setup_time_ms += timer_.stop();
                timer_.start("Hash matching L candidates");
                parallel_for_range(uint64_t(0),
                    uint64_t(l_end - l_start),
                    [this, &l_candidates, &previous_table_pairs, l_start, match_key_r](
                        uint64_t idx) {
                        l_candidates[idx]
                            = matching_target(previous_table_pairs[l_start + idx], match_key_r);
                    });
                timings.hash_time_ms += timer_.stop();

                // Setup R candidates as a span (no copy)
                timer_.start("Setup R candidates span");
                auto r_candidates = std::span<PairingCandidate const>(
                    previous_table_pairs.data() + r_start, r_end - r_start);
                timings.misc_time_ms += timer_.stop();

                // sort by match_target (default setting for RadixSort)
                // RadixSort<T_Target, decltype(&T_Target::match_target)>
                // radix_sort(&T_Target::match_target);
                RadixSort<PairingCandidate, uint32_t> radix_sort;

                timer_.start("Setup temp sort buffer");
                // create a temporary buffer as before:
                std::vector<PairingCandidate> temp_buffer(l_candidates.size());
                std::span<PairingCandidate> buffer(temp_buffer.data(), temp_buffer.size());
                timings.setup_time_ms += timer_.stop();
                timer_.start("Sorting L candidates");
                radix_sort.sort(l_candidates, buffer);
                timings.sort_time_ms += timer_.stop();

                int num_threads = std::thread::hardware_concurrency();
                if (num_threads > 1) {
                    timer_.start("Make Splits Simple");
                    auto splits = make_splits_simple(l_candidates,
                        r_candidates,
                        num_threads,
                        (1 << params_.get_num_match_target_bits(table_id_)) - 1);
                    timings.misc_time_ms += timer_.stop();
                    timer_.start("Finding pairs (parallel)");
                    // Now parallel across splits
                    parallel_for_range(uint64_t(0),
                        uint64_t(splits.size()),
                        [this,
                            &splits,
                            &l_candidates,
                            &r_candidates,
                            &new_table_pairs,
                            &new_table_pairs_mutex](uint64_t split_idx) {
                            auto const& split = splits[split_idx];
                            auto found_pairs = find_pairs(std::span<PairingCandidate const>(
                                                              l_candidates.data() + split.l_begin,
                                                              split.l_end - split.l_begin),
                                std::span<PairingCandidate const>(
                                    r_candidates.data() + split.r_begin,
                                    split.r_end - split.r_begin));
                            {
                                std::lock_guard<std::mutex> lock(new_table_pairs_mutex);
                                new_table_pairs.insert(
                                    new_table_pairs.end(), found_pairs.begin(), found_pairs.end());
                            }
                        });
                    timings.find_pairs_time_ms += timer_.stop();
                }
                else {
                    // Now pair them
                    timer_.start("Finding pairs");
                    auto found_pairs = find_pairs(l_candidates, r_candidates);

                    // Append found_pairs to new_table_pairs
                    new_table_pairs.insert(
                        new_table_pairs.end(), found_pairs.begin(), found_pairs.end());

                    timings.find_pairs_time_ms += timer_.stop();
                }
            }
        }

        return post_construct(new_table_pairs);
    }

    // called following construct method - typically sort operations
    virtual T_Result post_construct(std::vector<T_Pairing>& /*pairings*/)
    {
        throw std::runtime_error("post_construct not implemented");
    }

protected:
    int table_id_;
    ProofParams params_;
    Timer timer_;

public:
    // Provide direct access to the underlying ProofCore if needed:
    ProofCore proof_core_;
    struct Timings {
        double hash_time_ms = 0.0;
        double setup_time_ms = 0.0;
        double sort_time_ms = 0.0;
        double find_pairs_time_ms = 0.0;
        double misc_time_ms = 0.0;
        double post_sort_time_ms = 0.0;

        void show(std::string header) const
        {
            std::cout << header << std::endl;
            std::cout << "  Hash time: " << hash_time_ms << " ms" << std::endl;
            std::cout << "  Setup time: " << setup_time_ms << " ms" << std::endl;
            std::cout << "  Sort time: " << sort_time_ms << " ms" << std::endl;
            std::cout << "  Find pairs time: " << find_pairs_time_ms << " ms" << std::endl;
            std::cout << "  Post-sort time: " << post_sort_time_ms << " ms" << std::endl;
            std::cout << "  Misc time: " << misc_time_ms << " ms" << std::endl;
            double total = hash_time_ms + setup_time_ms + sort_time_ms + find_pairs_time_ms
                + post_sort_time_ms + misc_time_ms;
            std::cout << "  ------------" << std::endl;
            std::cout << "  Total time: " << total << " ms" << std::endl;
        }
    } timings;
};

struct Xs_Candidate {
    uint32_t match_info; // k-bit match info.
    uint32_t x; // k-bit x value.
};

class XsConstructor {
public:
    XsConstructor(ProofParams const& proof_params)
        : params_(proof_params)
        , proof_core_(proof_params)
    {
    }

    virtual ~XsConstructor() = default;

    std::vector<Xs_Candidate> construct()
    {
        std::vector<Xs_Candidate> x_candidates;
        // We'll have 2^(k-4) groups, each group has 16 x-values
        // => total of 2^(k-4)*16 x-values

        uint64_t num_xs = (1ULL << params_.get_k());
        x_candidates.resize(num_xs);

        Timer timer;
        timer.start("Hashing Xs_Candidate");

        parallel_for_range(uint64_t(0), num_xs, [this, &x_candidates](uint64_t x_val) {
            uint32_t x = static_cast<uint32_t>(x_val);
            uint32_t match_info = this->proof_core_.hashing.g(x);
            x_candidates[x_val] = Xs_Candidate { match_info, x };
        });
        timings.hash_time_ms = timer.stop();

        timer.start("Setup RadixSort");
        RadixSort<Xs_Candidate, uint32_t> radix_sort;
        std::vector<Xs_Candidate> temp_buffer(x_candidates.size());
        // Create a span over the temporary buffer
        std::span<Xs_Candidate> buffer(temp_buffer.data(), temp_buffer.size());
        timer.stop();
        timings.setup_time_ms = timer.stop();

        timer.start("Sorting Xs_Candidate");
        radix_sort.sort(x_candidates, buffer);
        timer.stop();
        timings.sort_time_ms = timer.stop();

        return x_candidates;
    }

    struct Timings {
        double hash_time_ms = 0.0;
        double setup_time_ms = 0.0;
        double sort_time_ms = 0.0;

        void show() const
        {
            std::cout << "XsConstructor Timings:" << std::endl;
            std::cout << "  Hash time: " << hash_time_ms << " ms" << std::endl;
            std::cout << "  Setup time: " << setup_time_ms << " ms" << std::endl;
            std::cout << "  Sort time: " << sort_time_ms << " ms" << std::endl;
            std::cout << "  ------------" << std::endl;
            double total = hash_time_ms + setup_time_ms + sort_time_ms;
            std::cout << "  Total time: " << total << " ms" << std::endl;
        }
    } timings;

protected:
    ProofParams params_;
    ProofCore proof_core_;
};

class Table1Constructor
    : public TableConstructorGeneric<Xs_Candidate, T1Pairing, std::vector<T1Pairing>> {
public:
    Table1Constructor(ProofParams const& proof_params) : TableConstructorGeneric(1, proof_params) {}

    // matching_target => (meta_l, r_match_target)
    Xs_Candidate matching_target(Xs_Candidate const& prev_table_pair, uint32_t match_key_r) override
    {
        // The "prev_table_pair" from Xs is: [ x, match_info ]
        // But for T1 we only need x => call matching_target(1, x, match_key_r).
        uint32_t x = prev_table_pair.x;
        uint32_t r_match_target = proof_core_.matching_target(1, x, match_key_r);
        // Return [ meta_l, match_target ]
        // Here meta_l = x

        // note: match_info is only the lower match_target_bits, rest is not used.
        return Xs_Candidate { .match_info = r_match_target, .x = x };
    }

    void handle_pair(Xs_Candidate const& l_candidate,
        Xs_Candidate const& r_candidate,
        std::vector<T1Pairing>& pairs,
        size_t /*left_index*/,
        size_t /*right_index*/) override
    {
        uint32_t x_left = l_candidate.x;
        uint32_t x_right = r_candidate.x;
        std::optional<T1Pairing> res = proof_core_.pairing_t1(x_left, x_right);
        if (res.has_value()) {
            pairs.push_back(res.value());
        }
    }

    std::vector<T1Pairing> post_construct(std::vector<T1Pairing>& pairings) override
    {
        RadixSort<T1Pairing, uint32_t> radix_sort;
        timer_.start("Setup temp sort buffer for T1Pairing");
        std::vector<T1Pairing> temp_buffer(pairings.size());
        // Create a span over the temporary buffer
        std::span<T1Pairing> buffer(temp_buffer.data(), temp_buffer.size());
        timings.setup_time_ms += timer_.stop();

        // sort by match_info (default)
        timer_.start("Sorting T1Pairing");
        radix_sort.sort(pairings, buffer);
        timings.post_sort_time_ms += timer_.stop();

        return pairings;
    }
};

class Table2Constructor
    : public TableConstructorGeneric<T1Pairing, T2Pairing, std::vector<T2Pairing>> {
public:
    Table2Constructor(ProofParams const& proof_params) : TableConstructorGeneric(2, proof_params) {}

    // matching_target => (meta_l, r_match_target)
    T1Pairing matching_target(T1Pairing const& prev_table_pair, uint32_t match_key_r) override
    {
        uint64_t meta_l = prev_table_pair.meta;
        uint32_t r_match_target = proof_core_.matching_target(2, meta_l, match_key_r);
        return T1Pairing { .meta = meta_l, .match_info = r_match_target };
    }

    void handle_pair(T1Pairing const& l_candidate,
        T1Pairing const& r_candidate,
        std::vector<T2Pairing>& pairs,
        size_t /*left_index*/,
        size_t /*right_index*/) override
    {
        uint64_t meta_l = l_candidate.meta;
        uint64_t meta_r = r_candidate.meta;
        auto opt_res = proof_core_.pairing_t2(meta_l, meta_r);
        if (opt_res.has_value()) {
            auto r = opt_res.value();

            // x_bits becomes x1 >> k/2 bits, x3 >> k/2 bits.
            uint32_t x_bits_l
                = numeric_cast<uint32_t>((meta_l >> params_.get_k()) >> (params_.get_k() / 2));
            uint32_t x_bits_r
                = numeric_cast<uint32_t>((meta_r >> params_.get_k()) >> (params_.get_k() / 2));
            uint32_t x_bits = x_bits_l << (params_.get_k() / 2) | x_bits_r;

            T2Pairing pairing { .meta = r.meta,
                .match_info = r.match_info,
                .x_bits = x_bits,
#ifdef RETAIN_X_VALUES_TO_T3
                .xs = { static_cast<uint32_t>(meta_l >> params_.get_k()),
                    static_cast<uint32_t>(meta_l & ((1 << params_.get_k()) - 1)),
                    static_cast<uint32_t>(meta_r >> params_.get_k()),
                    static_cast<uint32_t>(meta_r & ((1 << params_.get_k()) - 1)) }
#endif
            };

            pairs.push_back(pairing);
        }
    }

    std::vector<T2Pairing> post_construct(std::vector<T2Pairing>& pairings) override
    {
        RadixSort<T2Pairing, uint32_t> radix_sort;
        timer_.start("Setup temp sort buffer for T2Pairing");
        std::vector<T2Pairing> temp_buffer(pairings.size());
        // Create a span over the temporary buffer
        std::span<T2Pairing> buffer(temp_buffer.data(), temp_buffer.size());
        timings.setup_time_ms += timer_.stop();

        // sort by match_info (default)
        timer_.start("Sorting T2Pairing");
        radix_sort.sort(pairings, buffer);
        timings.post_sort_time_ms += timer_.stop();

        return pairings;
    }
};

class Table3Constructor
    : public TableConstructorGeneric<T2Pairing, T3Pairing, std::vector<T3Pairing>> {
public:
    Table3Constructor(ProofParams const& proof_params) : TableConstructorGeneric(3, proof_params) {}

    T2Pairing matching_target(T2Pairing const& prev_table_pair, uint32_t match_key_r) override
    {
        uint32_t r_match_target = proof_core_.matching_target(3, prev_table_pair.meta, match_key_r);
        return T2Pairing { .meta = prev_table_pair.meta,
            .match_info = r_match_target,
            .x_bits = prev_table_pair.x_bits,
#ifdef RETAIN_X_VALUES_TO_T3
            .xs = { static_cast<uint32_t>(prev_table_pair.xs[0]),
                static_cast<uint32_t>(prev_table_pair.xs[1]),
                static_cast<uint32_t>(prev_table_pair.xs[2]),
                static_cast<uint32_t>(prev_table_pair.xs[3]) }
#endif
        };
    }

    void handle_pair(T2Pairing const& l_candidate,
        T2Pairing const& r_candidate,
        std::vector<T3Pairing>& pairs,
        size_t /*left_index*/,
        size_t /*right_index*/) override
    {
        uint64_t meta_l = l_candidate.meta;
        uint64_t meta_r = r_candidate.meta;
        std::optional<T3Pairing> opt_res
            = proof_core_.pairing_t3(meta_l, meta_r, l_candidate.x_bits, r_candidate.x_bits);
        if (opt_res.has_value()) {
            T3Pairing pairing = opt_res.value();
#ifdef RETAIN_X_VALUES_TO_T3
            for (int i = 0; i < 4; i++) {
                pairing.xs[i] = l_candidate.xs[i];
                pairing.xs[i + 4] = r_candidate.xs[i];
            }
#endif
            pairs.push_back(pairing);
        }
    }

    std::vector<T3Pairing> post_construct(std::vector<T3Pairing>& pairings) override
    {
        // do a radix sort on fragments
        RadixSort<T3Pairing, uint64_t, decltype(&T3Pairing::proof_fragment)> radix_sort(
            &T3Pairing::proof_fragment);

        timer_.start("Setup temp sort buffer for T3Pairing");
        // 1) sort by fragments
        std::vector<T3Pairing> temp_buffer(pairings.size());
        // Create a span over the temporary buffer
        std::span<T3Pairing> buffer(temp_buffer.data(), temp_buffer.size());
        timings.setup_time_ms += timer_.stop();

        timer_.start("Sorting T3Pairing");
        radix_sort.sort(pairings, buffer, params_.get_k() * 2); // don't forget to sort full 2k bits
        timings.post_sort_time_ms += timer_.stop();

        return pairings;
    }
};
