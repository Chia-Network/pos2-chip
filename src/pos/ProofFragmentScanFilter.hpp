#pragma once

#include <cstdint>
#include "ProofCore.hpp"
#include "BlakeHash.hpp"
#include <vector>

const uint64_t PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS = 13; // 2^13 = 8192

class ProofFragmentScanFilter
{
private:
    static constexpr int NUM_SEED_BLAKE_WORDS = 2;
public:
    struct ScanRange
    {
        uint64_t start;
        uint64_t end;
    };

    ProofFragmentScanFilter(const ProofParams &proof_params, const std::array<uint8_t, 32> &challenge)
        : params_(proof_params),
          challenge_(challenge),
          proof_core_(proof_params),
          blake_hash_(params_.get_plot_id_bytes(), 32)
    {

        /*uint64_t challenge_plot_id_hash = proof_core_.hashing.challengeWithPlotIdHash(challenge_.data());

        // TODO: blake hash should update with the 256-bit result of the challenge plot id hash
        // set the first 64 bits of the challenge plot id hash
        blake_hash_.set_data(0, static_cast<uint32_t>(challenge_plot_id_hash & 0xFFFFFFFF));
        blake_hash_.set_data(1, static_cast<uint32_t>(challenge_plot_id_hash >> 32));

        // if changes are made to the number of seed words, update this constant
        static_assert(NUM_SEED_BLAKE_WORDS == 2, "NUM_SEED_BLAKE_WORDS must be 2");*/

        // Initialize the first 4 words (32*4 = 128 bits) of the Blake hash with the challenge
        // TODO: may want to make a blake hash seed from full hash of plot and all 256 bits of challenge
        for (int i = 0; i < 4; ++i)
        {
            uint32_t block_word =
                (static_cast<uint32_t>(challenge_[i * 4 + 0])) |
                (static_cast<uint32_t>(challenge_[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(challenge_[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(challenge_[i * 4 + 3]) << 24);

            blake_hash_.set_data(i, block_word);
        }

        // compute our hashing threshold for the scan filter
        double t3_exp = proof_core_.num_expected_pruned_entries_for_t3();
        double per_range = t3_exp / numScanRanges();
        double filter = 1 / (per_range * PROOF_FRAGMENT_SCAN_FILTER);
        filter_32bit_hash_threshold_ = static_cast<uint32_t>(filter * 0xFFFFFFFF);
    }

    ~ProofFragmentScanFilter() = default;


    struct ScanResult
    {
        uint64_t fragment;
        uint64_t index;
    };

    // Scan the plot data for fragments that pass the scan filter
    std::vector<ScanResult> scan(const std::vector<uint64_t> &fragments)
    {
        ScanRange range = getScanRangeForFilter();
        auto in_range = collectFragmentsInRange(fragments, range);

        return filterFragmentsByHash(in_range);
    }

    // 2) Apply hash threshold to the pre‐filtered fragments
    std::vector<ScanResult> filterFragmentsByHash(
        const std::vector<ScanResult> &candidates)
    {
        std::vector<ScanResult> filtered;
        for (auto &r : candidates)
        {
            //blake_hash_.set_data(NUM_SEED_BLAKE_WORDS + 0, r.fragment >> 32);
            //blake_hash_.set_data(NUM_SEED_BLAKE_WORDS + 1, r.fragment & 0xFFFFFFFF);
            blake_hash_.set_data(4, r.fragment >> 32);
            blake_hash_.set_data(5, r.fragment & 0xFFFFFFFF);
            uint32_t h = blake_hash_.generate_hash().r0;
            if (h < filter_32bit_hash_threshold_)
                filtered.push_back(r);
        }
        return filtered;
    }

    uint64_t
    getLSBFromChallenge(int num_bits)
    {
        if (num_bits > 64)
        {
            throw std::invalid_argument("num_bits must be less than or equal to 64");
        }

        // Get the least significant bits from the challenge
        uint64_t lsb = 0;
        for (int i = 0; i < num_bits; ++i)
        {
            uint64_t bit = (challenge_[i / 8] >> (i % 8)) & 1;
            lsb |= (bit << i);
        }

        return lsb;
    }

    // The span (or range) of values for proof fragment scan filters
    uint64_t getScanSpan()
    {
        return (1ULL << (params_.get_k() + PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS));
    }

    uint64_t numScanRanges() 
    {
        // The number of scan ranges is 2^(k - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS)
        return (1ULL << (params_.get_k() - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS));
    }

    ScanRange getScanRangeForFilter()
    {
        // Calculate the scan range based on the filter
        // A filter range of PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS (set to 13, value 8192) means we want to scan approximately 8192 entries (before pruning metric) at a time.
        // To find the range across approximately 2^k entries that span across proof fragment values 0..2^(2k) - 1, then the number of possible scan ranges is 2^k / 8192, or 2^(k - 13)
        //   -> this becomes scan_range_filter_bits = k - 13.
        // and thus the value of that span is 2^(2k) / (2^k / 8192) = 2^k * 8192 = 2^(k + 13).
        int scan_range_filter_bits = params_.get_k() - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS;

        // scan range id should be 0..(2^scan_range_filter_bits - 1)
        uint64_t scan_range_id = getLSBFromChallenge(scan_range_filter_bits);

        uint64_t scan_span = getScanSpan();

        // TODO: make sure k32 doesn't overflow
        ScanRange range;
        range.start = scan_span * scan_range_id;
        range.end = scan_span * (scan_range_id + 1) - 1;
        // debug out
        if (true)
        {
            std::cout << "Scan range id: " << scan_range_id << std::endl;
            std::cout << "Scan range: " << range.start << " - " << range.end << std::endl;
            std::cout << "Scan range filter bits: " << scan_range_filter_bits << std::endl;
            std::cout << "Scan range selection bits: " << PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS << std::endl;
        }
        return range;
    }

private:
    // Scan filter parameters
    ProofParams params_;
    ProofCore proof_core_;
    BlakeHash blake_hash_;
    std::array<uint8_t, 32> challenge_;
    uint32_t filter_32bit_hash_threshold_;

    // 1) Gather all fragments in the scan range
    std::vector<ScanResult> collectFragmentsInRange(
        const std::vector<uint64_t> &fragments,
        const ScanRange &range)
    {
        std::vector<ScanResult> result;

        // smart seek start of range, given we have a uniform distribution of fragments
        size_t n = fragments.size();
        uint64_t full_range = (1ULL << (2 * params_.get_k()));
        double perc_position_start = (double)range.start / (double) (full_range);
        double estimated_position = perc_position_start * (double) n;
        size_t start_index = static_cast<size_t>(estimated_position);

        // check start_index, and then adjust position to find first fragment in beginning of range
        if (start_index >= n)
        {
            start_index = n - 1; // Ensure we don't go out of bounds
        }
        if (fragments[start_index] < range.start)
        {
            // Move forward until we find a fragment within the range
            while (start_index < n && fragments[start_index] < range.start)
            {
                ++start_index;
            }
        }
        else if (fragments[start_index] > range.start)
        {
            // Move back until we find a fragment for start of range
            while (start_index > 0 && fragments[start_index] > range.start)
            {
                --start_index;
            }
            start_index++; // Move to the next fragment that is within the range
        }

        // Now we can start scanning from the adjusted start_index
        uint64_t pos = start_index;
        // instead of hashing here, just collect every fragment in [start,end)
        while (pos < n && fragments[pos] < range.end)
        {
            uint64_t fragment = fragments[pos];
            if (fragment >= range.start && fragment < range.end)
            {
                result.push_back({fragment, pos});
            }
            ++pos;
        }
        return result;
    }

    
};