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
#include "ResettableArenaResource.hpp"
#include "common/ParallelForRange.hpp"
#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofParams.hpp"
#include "pos/ProofValidator.hpp"

static std::size_t max_pairs_per_table_possible(ProofParams const& params)
{
    // Your heuristic kept (but please revisit; if too small you'll overflow output span).
    if (params.get_k() < 28) {
        return (1ULL << (params.get_k() + 1));
    }
    return ((1ULL << params.get_k())) + (1ULL << (params.get_k() - 10));
}

template <typename PairingCandidate, typename T_Pairing, typename T_Result>
class TableConstructorGeneric {
public:
    TableConstructorGeneric(
        int table_id, ProofParams const& proof_params, ResettableArenaResource& scratch)
        : table_id_(table_id)
        , params_(proof_params)
        , scratch_arena_(&scratch)
        , proof_core_(proof_params)
    {
    }

    virtual ~TableConstructorGeneric() = default;

    // =========================
    // Prefix (flat 2D) structure
    // =========================
    struct Prefix2D {
        std::span<uint64_t> data;
        std::size_t num_sections = 0;
        std::size_t row_stride = 0; // = num_match_keys+1

        uint64_t* row(std::size_t s) { return data.data() + s * row_stride; }
        uint64_t const* row(std::size_t s) const { return data.data() + s * row_stride; }
    };

    Prefix2D find_candidates_prefixes(std::span<PairingCandidate const> pairing_candidates,
        std::pmr::memory_resource* scratch_mr) const
    {
        std::size_t const num_sections = params_.get_num_sections();
        std::size_t const num_match_keys = params_.get_num_match_keys(table_id_);
        std::size_t const stride = num_match_keys + 1;

        // counts: [num_sections][num_match_keys]
        uint64_t* counts = arena_alloc_n<uint64_t>(scratch_mr, num_sections * num_match_keys);
        std::fill(counts, counts + num_sections * num_match_keys, 0ULL);

        for (auto const& candidate: pairing_candidates) {
            uint32_t section
                = params_.extract_section_from_match_info(table_id_, candidate.match_info);
            uint32_t mk
                = params_.extract_match_key_from_match_info(table_id_, candidate.match_info);
            counts[std::size_t(section) * num_match_keys + std::size_t(mk)]++;
        }

        // prefixes: [num_sections][num_match_keys+1]
        uint64_t* prefixes = arena_alloc_n<uint64_t>(scratch_mr, num_sections * stride);

        uint64_t total_prefix = 0ULL;
        for (std::size_t s = 0; s < num_sections; ++s) {
            for (std::size_t mk = 0; mk < num_match_keys; ++mk) {
                prefixes[s * stride + mk] = total_prefix;
                total_prefix += counts[s * num_match_keys + mk];
            }
            prefixes[s * stride + num_match_keys] = total_prefix;
        }

        return Prefix2D {
            std::span<uint64_t>(prefixes, num_sections * stride), num_sections, stride
        };
    }

    // =========================
    // Split ranges for parallel
    // =========================
    struct SplitRange {
        std::size_t l_begin;
        std::size_t l_end;
        std::size_t r_begin;
        std::size_t r_end;
    };

    // Returns a span allocated from scratch_mr.
    std::span<SplitRange> make_splits_simple(std::span<PairingCandidate const> l_candidates,
        std::span<PairingCandidate const> r_candidates,
        unsigned num_threads,
        uint32_t match_target_mask) const
    {
        using std::size_t;

        size_t const l_size = l_candidates.size();
        size_t const r_size = r_candidates.size();

        if (l_size == 0 || r_size == 0 || num_threads == 0) {
            return {};
        }

        num_threads = std::min<unsigned>(num_threads, static_cast<unsigned>(l_size));
        if (num_threads == 0) {
            return {};
        }

        auto key = [match_target_mask](PairingCandidate const& c) -> uint32_t {
            return c.match_info & match_target_mask;
        };

        unsigned const num_splits = num_threads; // one chunk per thread

        // Allocate split arrays from scratch
        size_t* l_splits = arena_alloc_n<size_t>(scratch_arena_, num_splits + 1);
        size_t* r_splits = arena_alloc_n<size_t>(scratch_arena_, num_splits + 1);

        l_splits[0] = 0;
        l_splits[num_splits] = l_size;

        size_t const base_chunk = l_size / num_splits;

        for (unsigned i = 1; i < num_splits; ++i) {
            size_t idx = i * base_chunk;
            if (idx >= l_size)
                idx = l_size - 1;

            uint32_t k = key(l_candidates[idx]);
            while (idx > 0 && key(l_candidates[idx - 1]) == k) {
                --idx;
            }
            if (idx < l_splits[i - 1])
                idx = l_splits[i - 1];

            l_splits[i] = idx;
        }

        r_splits[0] = 0;
        r_splits[num_splits] = r_size;

        for (unsigned i = 1; i < num_splits; ++i) {
            size_t const l_idx = l_splits[i];
            size_t r_idx = r_size * i / num_splits;
            if (r_idx >= r_size)
                r_idx = r_size ? (r_size - 1) : 0;

            if (l_idx >= l_size) {
                r_splits[i] = r_size;
                continue;
            }

            // scan down if L key is less
            while (r_idx > 0
                && l_candidates[l_idx].match_info
                    < (r_candidates[r_idx].match_info & match_target_mask)) {
                --r_idx;
            }

            // if equal, scan to first equal on R
            if (r_size > 0
                && l_candidates[l_idx].match_info
                    == (r_candidates[r_idx].match_info & match_target_mask)) {
                while (r_idx > 0
                    && ((r_candidates[r_idx - 1].match_info & match_target_mask)
                        == l_candidates[l_idx].match_info)) {
                    --r_idx;
                }
            }

            // scan up if L key is greater
            while (r_idx < r_size
                && l_candidates[l_idx].match_info
                    > (r_candidates[r_idx].match_info & match_target_mask)) {
                ++r_idx;
            }

            r_splits[i] = r_idx;
        }

        SplitRange* ranges = arena_alloc_n<SplitRange>(scratch_arena_, num_splits);
        for (unsigned i = 0; i < num_splits; ++i) {
            ranges[i] = SplitRange { l_splits[i], l_splits[i + 1], r_splits[i], r_splits[i + 1] };
        }

        return std::span<SplitRange>(ranges, num_splits);
    }

    // =========================
    // Pair finding into output span
    // =========================

    // Derived class should create 1..N pairings for a match.
    // out_count is an atomic cursor; derived must reserve slots via fetch_add.
    virtual void handle_pair_into(PairingCandidate const& /*l_candidate*/,
        PairingCandidate const& /*r_candidate*/,
        std::span<T_Pairing> /*out_pairs*/,
        std::atomic<std::size_t>& /*out_count*/,
        std::size_t /*left_index*/,
        std::size_t /*right_index*/)
    {
        throw std::runtime_error("handle_pair_into not implemented");
    }

    virtual PairingCandidate matching_target(
        PairingCandidate const& /*prev_table_pair*/, uint32_t /*match_key_r*/)
    {
        throw std::runtime_error("matching_target not implemented");
    }

    // Writes pairs into out_pairs using atomic cursor.
    void find_pairs_into(std::span<PairingCandidate const> l_targets,
        std::span<PairingCandidate const> r_candidates,
        std::span<T_Pairing> out_pairs,
        std::atomic<std::size_t>& out_count)
    {
        std::size_t left_index = 0;
        std::size_t right_index = 0;
        std::size_t const r_size = r_candidates.size();

        std::size_t const num_match_target_bits = params_.get_num_match_target_bits(table_id_);
        uint32_t const match_target_mask = (uint32_t(1) << num_match_target_bits) - 1u;

        bool have_r_candidate = (r_size > 0);
        std::size_t current_r_idx = 0;

        while (left_index < l_targets.size() && have_r_candidate) {
            uint32_t match_target_l = l_targets[left_index].match_info;
            uint32_t match_target_r = (r_candidates[current_r_idx].match_info & match_target_mask);

            if (match_target_l == match_target_r) {
                std::size_t start_i = left_index;
                while (start_i < l_targets.size()
                    && (l_targets[start_i].match_info == match_target_r)) {
                    handle_pair_into(l_targets[start_i],
                        r_candidates[current_r_idx],
                        out_pairs,
                        out_count,
                        start_i,
                        right_index);
                    ++start_i;
                }

                ++right_index;
                if (right_index < r_size)
                    current_r_idx = right_index;
                else
                    have_r_candidate = false;
            }
            else if (match_target_r < match_target_l) {
                ++right_index;
                if (right_index < r_size)
                    current_r_idx = right_index;
                else
                    have_r_candidate = false;
            }
            else {
                ++left_index;
            }
        }
    }

    // =========================
    // Main construct using arenas
    // =========================
    BufferSpan<T_Result> construct(BufferSpan<PairingCandidate> previous_table_pairs,
        BufId out_id,
        ResettableArenaResource& in_arena, // previous table pairs is in here...
        ResettableArenaResource& out_arena)
    {
        scratch_arena_->reset();

        // Prefixes live in scratch
        Prefix2D prefix = find_candidates_prefixes(previous_table_pairs.view, scratch_arena_);

        std::size_t const max_pairs_guess = max_pairs_per_table_possible(params_);
        std::cout << "T" << table_id_ << ": max_pairs_guess=" << max_pairs_guess
                  << " sizeof(T_Pairing)=" << sizeof(T_Pairing)
                  << " bytes=" << (max_pairs_guess * sizeof(T_Pairing))
                  << " out_cap=" << out_arena.capacity_bytes()
                  << " out_rem=" << out_arena.remaining_bytes() << "\n";

        // Output array for pairings lives in OUT arena
        T_Pairing* out_ptr = arena_alloc_n<T_Pairing>(&out_arena, max_pairs_guess);
        std::span<T_Pairing> out_pairs(out_ptr, max_pairs_guess);

        std::atomic<std::size_t> out_count { 0 };

        std::size_t const num_match_keys = params_.get_num_match_keys(table_id_);
        uint32_t const match_target_mask
            = (uint32_t(1) << params_.get_num_match_target_bits(table_id_)) - 1u;

        uint32_t const num_sections = static_cast<uint32_t>(params_.get_num_sections());

        for (uint32_t section = 0; section < num_sections; ++section) {
            uint32_t const section_l = section;
            uint32_t const section_r = proof_core_.matching_section(section_l);

            uint64_t const l_start_u64 = prefix.row(section_l)[0];
            uint64_t const l_end_u64 = prefix.row(section_l)[num_match_keys];

            for (uint32_t match_key_r = 0; match_key_r < num_match_keys; ++match_key_r) {
                auto m = scratch_arena_->mark();

                uint64_t const r_start_u64 = prefix.row(section_r)[match_key_r];
                uint64_t const r_end_u64 = prefix.row(section_r)[match_key_r + 1];

                std::size_t const l_start = static_cast<std::size_t>(l_start_u64);
                std::size_t const l_end = static_cast<std::size_t>(l_end_u64);
                std::size_t const r_start = static_cast<std::size_t>(r_start_u64);
                std::size_t const r_end = static_cast<std::size_t>(r_end_u64);

                std::size_t const l_count = l_end - l_start;
                std::size_t const r_count = r_end - r_start;

                if (l_count == 0 || r_count == 0) {
                    scratch_arena_->rewind(m);
                    continue;
                }

                PairingCandidate* l_ptr = arena_alloc_n<PairingCandidate>(scratch_arena_, l_count);
                std::span<PairingCandidate> l_candidates(l_ptr, l_count);

                timer_.start("Hash matching L candidates");
                parallel_for_range(uint64_t(0),
                    uint64_t(l_count),
                    [this, l_ptr, prev = previous_table_pairs.view, l_start, match_key_r](
                        uint64_t idx) {
                        l_ptr[static_cast<std::size_t>(idx)] = matching_target(
                            prev[l_start + static_cast<std::size_t>(idx)], match_key_r);
                    });
                timings.hash_time_ms += timer_.stop();

                // R is a view into previous table pairs
                auto r_candidates = std::span<PairingCandidate const>(
                    previous_table_pairs.view.data() + r_start, r_count);

                // Sort L using temp buffer in scratch
                PairingCandidate* tmp_ptr
                    = arena_alloc_n<PairingCandidate>(scratch_arena_, l_count);
                std::span<PairingCandidate> tmp(tmp_ptr, l_count);

                RadixSort<PairingCandidate, uint32_t> radix_sort;

                timer_.start("Sorting L candidates");
                bool l_sorted_in_place
                    = radix_sort.sort(l_candidates, tmp, 28, false, scratch_arena_);
                timings.sort_time_ms += timer_.stop();

                // RadixSort alternates between the two spans; for 28 bits (3 passes)
                // the sorted output lives in `tmp`, not `l_candidates`.
                std::span<PairingCandidate const> l_sorted = l_sorted_in_place
                    ? std::span<PairingCandidate const>(l_candidates)
                    : std::span<PairingCandidate const>(tmp);

                unsigned num_threads = std::thread::hardware_concurrency();
                if (num_threads == 0)
                    num_threads = 1;

                if (num_threads > 1) {
                    timer_.start("Make Splits Simple");
                    auto splits = make_splits_simple(
                        l_sorted, r_candidates, num_threads, match_target_mask);
                    timings.misc_time_ms += timer_.stop();

                    timer_.start("Finding pairs (parallel)");
                    parallel_for_range(uint64_t(0),
                        uint64_t(splits.size()),
                        [this, &splits, &l_sorted, &r_candidates, out_pairs, &out_count](
                            uint64_t split_idx) {
                            auto const& split = splits[static_cast<std::size_t>(split_idx)];

                            auto l_span = std::span<PairingCandidate const>(
                                l_sorted.data() + split.l_begin, split.l_end - split.l_begin);

                            auto r_span = std::span<PairingCandidate const>(
                                r_candidates.data() + split.r_begin, split.r_end - split.r_begin);

                            this->find_pairs_into(l_span, r_span, out_pairs, out_count);
                        });
                    timings.find_pairs_time_ms += timer_.stop();
                }
                else {
                    timer_.start("Finding pairs");
                    find_pairs_into(
                        std::span<PairingCandidate const>(l_sorted.data(), l_sorted.size()),
                        r_candidates,
                        out_pairs,
                        out_count);
                    timings.find_pairs_time_ms += timer_.stop();
                }
                // output how big scratch got
                std::cout << "  Scratch used bytes after section " << section << " match_key_r "
                          << match_key_r << ": " << scratch_arena_->used_bytes() << "\n";
                scratch_arena_->rewind(m);
            }
        }

        std::size_t const produced = out_count.load(std::memory_order_relaxed);
        if (produced > out_pairs.size()) {
            std::cout << "Produced: " << produced << ", capacity: " << out_pairs.size() << "\n";
            // This indicates the estimate was too small or handle_pair_into wrote past capacity.
            throw std::runtime_error("TableConstructorGeneric: output arena capacity exceeded (bad "
                                     "max_pairs_per_table_possible)");
        }

        // post_construct must allocate its returned result in out_arena and return
        // BufferSpan<T_Result> note in_arena is now depleted (used for previous table pairs)
        return post_construct_span(out_pairs.first(produced), out_id, out_arena, in_arena);
    }

    // called following construct method - typically sort operations
    virtual BufferSpan<T_Result> post_construct_span(std::span<T_Pairing> /*pairings*/,
        BufId /*out_id*/,
        ResettableArenaResource& /*out_arena*/,
        ResettableArenaResource& /*previous in_arena*/)
    {
        throw std::runtime_error("post_construct_span not implemented");
    }

public:
    struct Timings {
        double hash_time_ms = 0.0;
        double setup_time_ms = 0.0;
        double sort_time_ms = 0.0;
        double find_pairs_time_ms = 0.0;
        double misc_time_ms = 0.0;
        double post_sort_time_ms = 0.0;

        void show(std::string header) const
        {
            std::cout << header << "\n";
            std::cout << "  Hash time: " << hash_time_ms << " ms\n";
            std::cout << "  Setup time: " << setup_time_ms << " ms\n";
            std::cout << "  Sort time: " << sort_time_ms << " ms\n";
            std::cout << "  Find pairs time: " << find_pairs_time_ms << " ms\n";
            std::cout << "  Post-sort time: " << post_sort_time_ms << " ms\n";
            std::cout << "  Misc time: " << misc_time_ms << " ms\n";
            double total = hash_time_ms + setup_time_ms + sort_time_ms + find_pairs_time_ms
                + post_sort_time_ms + misc_time_ms;
            std::cout << "  ------------\n";
            std::cout << "  Total time: " << total << " ms\n";
        }
    } timings;

protected:
    int table_id_;
    ProofParams params_;
    Timer timer_;
    ResettableArenaResource* scratch_arena_;

public:
    ProofCore proof_core_;
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

    BufferSpan<Xs_Candidate> construct(
        std::pmr::memory_resource* out_mr, std::pmr::memory_resource* scratch_mr)
    {
        if (!out_mr || !scratch_mr) {
            throw std::runtime_error("XsConstructor: null memory_resource");
        }

        uint64_t const num_xs_u64 = (1ULL << params_.get_k());
        size_t const num_xs = static_cast<size_t>(num_xs_u64);

        // Allocate output + temp from the provided arenas
        std::pmr::vector<Xs_Candidate> out(out_mr);
        std::pmr::vector<Xs_Candidate> tmp(scratch_mr);

        try {
            out.resize(num_xs);
            tmp.resize(num_xs);
        }
        catch (std::bad_alloc const&) {
            throw std::runtime_error("XsConstructor: buffers too small");
        }

        std::span<Xs_Candidate> out_span(out.data(), out.size());
        std::span<Xs_Candidate> tmp_span(tmp.data(), tmp.size());

        Timer timer;
        timer.start("Hashing Xs_Candidate");

        parallel_for_range(uint64_t(0), num_xs_u64, [this, out_span](uint64_t x_val) mutable {
            uint32_t x = static_cast<uint32_t>(x_val);
            uint32_t match_info = this->proof_core_.hashing.g(x);
            out_span[static_cast<size_t>(x_val)] = Xs_Candidate { match_info, x };
        });
        timings.hash_time_ms = timer.stop();

        RadixSort<Xs_Candidate, uint32_t> radix_sort;

        timer.start("Sorting Xs_Candidate");
        // auto sorted = radix_sort.sort_to(out, tmp);
        bool sorted_in_place = radix_sort.sort(out_span, tmp_span, 28, false, scratch_mr);
        timings.sort_time_ms = timer.stop();

        return BufferSpan<Xs_Candidate> {
            .where = sorted_in_place ? BufId::A : BufId::B,
            .view = sorted_in_place ? out_span : tmp_span,
        };
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

class Table1Constructor : public TableConstructorGeneric<Xs_Candidate, T1Pairing, T1Pairing> {
public:
    // NOTE: this base now requires a scratch arena reference
    explicit Table1Constructor(ProofParams const& proof_params, ResettableArenaResource& scratch)
        : TableConstructorGeneric<Xs_Candidate, T1Pairing, T1Pairing>(1, proof_params, scratch)
    {
    }

    // matching_target => (meta_l, r_match_target)
    Xs_Candidate matching_target(Xs_Candidate const& prev_table_pair, uint32_t match_key_r) override
    {
        uint32_t x = prev_table_pair.x;
        uint32_t r_match_target = proof_core_.matching_target(1, x, match_key_r);

        // note: match_info is only the lower match_target_bits, rest is not used.
        return Xs_Candidate { .match_info = r_match_target, .x = x };
    }

    void handle_pair_into(Xs_Candidate const& l_candidate,
        Xs_Candidate const& r_candidate,
        std::span<T1Pairing> out_pairs,
        std::atomic<std::size_t>& out_count,
        std::size_t /*left_index*/,
        std::size_t /*right_index*/) override
    {
        uint32_t x_left = l_candidate.x;
        uint32_t x_right = r_candidate.x;

        std::optional<T1Pairing> res = proof_core_.pairing_t1(x_left, x_right);
        if (!res.has_value())
            return;

        // Reserve one slot in the shared output array
        std::size_t idx = out_count.fetch_add(1, std::memory_order_relaxed);

        // IMPORTANT: If idx >= out_pairs.size(), you're out of capacity.
        // You cannot safely throw from worker threads. Choose a policy.
        // Here: hard fail (writes are prevented); after construct we throw if overflow happened.
        if (idx >= out_pairs.size())
            return;

        out_pairs[idx] = *res;
    }

    // Sort the produced pairings into OUT arena and return them as the stage result span.
    BufferSpan<T1Pairing> post_construct_span(std::span<T1Pairing> pairings,
        BufId out_id,
        ResettableArenaResource& /*out_arena*/,
        ResettableArenaResource& previous_in_arena) override
    {
        previous_in_arena.reset();
        T1Pairing* tmp_ptr = arena_alloc_n<T1Pairing>(&previous_in_arena, pairings.size());
        std::span<T1Pairing> tmp(tmp_ptr, pairings.size());

        RadixSort<T1Pairing, uint32_t> radix_sort;

        timer_.start("Sorting T1Pairing");
        bool sorted_in_place = radix_sort.sort(pairings, tmp, 28, false, scratch_arena_);
        timings.post_sort_time_ms += timer_.stop();

        // Result is the sorted span in out_arena.
        BufId out_buffer = sorted_in_place ? out_id : other(out_id);
        return BufferSpan<T1Pairing> { out_buffer, sorted_in_place ? pairings : tmp };
    }
};

class Table2Constructor : public TableConstructorGeneric<T1Pairing, T2Pairing, T2Pairing> {
public:
    explicit Table2Constructor(ProofParams const& proof_params, ResettableArenaResource& scratch)
        : TableConstructorGeneric<T1Pairing, T2Pairing, T2Pairing>(2, proof_params, scratch)
    {
    }

    // matching_target => (meta_l, r_match_target)
    T1Pairing matching_target(T1Pairing const& prev_table_pair, uint32_t match_key_r) override
    {
        uint64_t meta_l = prev_table_pair.meta;
        uint32_t r_match_target = proof_core_.matching_target(2, meta_l, match_key_r);
        return T1Pairing { .meta = meta_l, .match_info = r_match_target };
    }

    void handle_pair_into(T1Pairing const& l_candidate,
        T1Pairing const& r_candidate,
        std::span<T2Pairing> out_pairs,
        std::atomic<std::size_t>& out_count,
        std::size_t /*left_index*/,
        std::size_t /*right_index*/) override
    {
        uint64_t const meta_l = l_candidate.meta;
        uint64_t const meta_r = r_candidate.meta;

        auto opt_res = proof_core_.pairing_t2(meta_l, meta_r);
        if (!opt_res.has_value())
            return;

        auto r = opt_res.value();

        // x_bits becomes x1 >> k/2 bits, x3 >> k/2 bits.
        uint32_t const x_bits_l
            = numeric_cast<uint32_t>((meta_l >> params_.get_k()) >> (params_.get_k() / 2));
        uint32_t const x_bits_r
            = numeric_cast<uint32_t>((meta_r >> params_.get_k()) >> (params_.get_k() / 2));
        uint32_t const x_bits = (x_bits_l << (params_.get_k() / 2)) | x_bits_r;

        T2Pairing pairing { .meta = r.meta,
            .match_info = r.match_info,
            .x_bits = x_bits,
#ifdef RETAIN_X_VALUES_TO_T3
            .xs = { static_cast<uint32_t>(meta_l >> params_.get_k()),
                static_cast<uint32_t>(meta_l & ((uint64_t(1) << params_.get_k()) - 1)),
                static_cast<uint32_t>(meta_r >> params_.get_k()),
                static_cast<uint32_t>(meta_r & ((uint64_t(1) << params_.get_k()) - 1)) }
#endif
        };

        // Reserve one slot in shared output
        std::size_t const idx = out_count.fetch_add(1, std::memory_order_relaxed);

        // Capacity policy: prevent OOB write; base will sanity-check after the fact.
        if (idx >= out_pairs.size())
            return;

        out_pairs[idx] = pairing;
    }

    BufferSpan<T2Pairing> post_construct_span(std::span<T2Pairing> pairings,
        BufId out_id,
        ResettableArenaResource& /*out_arena*/,
        ResettableArenaResource& previous_out_arena) override
    {
        previous_out_arena.reset();
        T2Pairing* tmp_ptr = arena_alloc_n<T2Pairing>(&previous_out_arena, pairings.size());
        std::span<T2Pairing> tmp(tmp_ptr, pairings.size());

        RadixSort<T2Pairing, uint32_t> radix_sort;

        timer_.start("Sorting T2Pairing");
        bool sorted_in_place = radix_sort.sort(pairings, tmp, 28, false, scratch_arena_);
        timings.post_sort_time_ms += timer_.stop();

        // Return sorted data (lives in out_arena)
        BufId out_buffer = sorted_in_place ? out_id : other(out_id);
        return BufferSpan<T2Pairing> { out_buffer, sorted_in_place ? pairings : tmp };
    }
};

class Table3Constructor : public TableConstructorGeneric<T2Pairing, T3Pairing, T3Pairing> {
public:
    explicit Table3Constructor(ProofParams const& proof_params, ResettableArenaResource& scratch)
        : TableConstructorGeneric<T2Pairing, T3Pairing, T3Pairing>(3, proof_params, scratch)
    {
    }

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

    void handle_pair_into(T2Pairing const& l_candidate,
        T2Pairing const& r_candidate,
        std::span<T3Pairing> out_pairs,
        std::atomic<std::size_t>& out_count,
        std::size_t /*left_index*/,
        std::size_t /*right_index*/) override
    {
        uint64_t const meta_l = l_candidate.meta;
        uint64_t const meta_r = r_candidate.meta;

        std::optional<T3Pairing> opt_res
            = proof_core_.pairing_t3(meta_l, meta_r, l_candidate.x_bits, r_candidate.x_bits);

        if (!opt_res.has_value())
            return;

        T3Pairing pairing = *opt_res;

#ifdef RETAIN_X_VALUES_TO_T3
        for (int i = 0; i < 4; ++i) {
            pairing.xs[i] = l_candidate.xs[i];
            pairing.xs[i + 4] = r_candidate.xs[i];
        }
#endif

        const std::size_t idx = out_count.fetch_add(1, std::memory_order_relaxed);
        if (idx >= out_pairs.size())
            return; // prevent OOB; base will detect overflow by count

        out_pairs[idx] = pairing;
    }

    BufferSpan<T3Pairing> post_construct_span(std::span<T3Pairing> pairings,
        BufId out_id,
        ResettableArenaResource& /*out_arena*/,
        ResettableArenaResource& previous_out_arena) override
    {
        previous_out_arena.reset();

        // do a radix sort on fragments
        RadixSort<T3Pairing, uint64_t, decltype(&T3Pairing::proof_fragment)> radix_sort(
            &T3Pairing::proof_fragment);

        T3Pairing* tmp_ptr = arena_alloc_n<T3Pairing>(&previous_out_arena, pairings.size());
        std::span<T3Pairing> tmp(tmp_ptr, pairings.size());

        timer_.start("Sorting T3Pairing");
        bool sorted_in_place
            = radix_sort.sort(pairings, tmp, params_.get_k() * 2, false, scratch_arena_);
        timings.post_sort_time_ms += timer_.stop();

        BufId out_buffer = sorted_in_place ? out_id : other(out_id);
        return BufferSpan<T3Pairing> { out_buffer, sorted_in_place ? pairings : tmp };
    }
};
