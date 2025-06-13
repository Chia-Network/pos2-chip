#pragma once

#include <cstdint>
#include "pos/ProofCore.hpp"
#include "pos/BlakeHash.hpp"
#include <vector>

const uint64_t PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS = 13; // 2^13 = 8192

class ProofFragmentScanFilter
{
public:
    struct ScanRange
    {
        uint64_t start;
        uint64_t end;
    };

    ProofFragmentScanFilter(const ProofParams &proof_params, const std::array<uint8_t, 32> &challenge, int scan_filter)
        : params_(proof_params),
          challenge_(challenge),
          scan_filter_(scan_filter),
          proof_core_(proof_params)
    {
    }

    ~ProofFragmentScanFilter() = default;


    struct ScanResult
    {
        uint64_t fragment;
        uint64_t index;
    };

    // Scan the plot data for fragments that pass the scan filter
    std::vector<ScanResult> scan(const std::vector<uint64_t> fragments)
    {
        std::vector<ScanResult> filtered_fragments;
        // Scan the fragments and filter based on the challenge

        ScanRange range = getScanRangeForFilter();

        double t3_expected_entries = proof_core_.num_expected_pruned_entries_for_t3();
        std::cout << "Expected T3 entries: " << (uint64_t)t3_expected_entries << std::endl;
        double t3_expected_num_entries_per_range = t3_expected_entries / numScanRanges();
        std::cout << "Expected T3 entries per range: " << t3_expected_num_entries_per_range << std::endl;

        double filter = 1 / (t3_expected_num_entries_per_range * (double)scan_filter_);
        std::cout << "Filter: 1/" << (1 / filter) << std::endl;
        uint32_t hash_threshold = (uint32_t)(filter * 0xFFFFFFFF);
        std::cout << "Hash threshold: " << hash_threshold << std::endl;

        // hash sets 256 plot id bits and lower 128 bits from challenge
        // later we set the 64 bits (2*k bits) from the fragment
        BlakeHash blake_hash(params_.get_plot_id_bytes(), 32);
        for (int i = 0; i < 4; ++i)
        {
            uint32_t block_word =
                (static_cast<uint32_t>(challenge_[i * 4 + 0])) |
                (static_cast<uint32_t>(challenge_[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(challenge_[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(challenge_[i * 4 + 3]) << 24);

            blake_hash.set_data(i, block_word);
        }
       
        // smart seek start of range, given we have a uniform distribution of fragments
        size_t n = fragments.size();
        uint64_t full_range = (1ULL << (2 * params_.get_k()));
        double perc_position_start = (double)range.start / (double) (full_range);
        double estimated_position = perc_position_start * (double) n;
        size_t start_index = static_cast<size_t>(estimated_position);

        std::cout << "N Fragments: " << n << std::endl;
        std::cout << "Full range: " << full_range << std::endl;
        std::cout << "Percentage of range start: " << perc_position_start << std::endl;
        std::cout << "Estimated position: " << estimated_position << std::endl;
        std::cout << "Range start: " << range.start << ", end: " << range.end << std::endl;
        std::cout << "Percentage position start: " << perc_position_start << std::endl;
        std::cout << "Start index: " << start_index << std::endl;

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

        std::cout << "Adjusted start index: " << start_index << std::endl;
        std::cout << "Fragment at adjusted start index: " << fragments[start_index] << std::endl;
        
        // Now we can start scanning from the adjusted start_index
        uint64_t pos = start_index;
        int test_num_fragments_scanned = 0;
        while (pos < n && fragments[pos] < range.end)
        {
            uint64_t fragment = fragments[pos];
            // Check if the fragment is within the scan range
            if (fragment >= range.start && fragment < range.end)
            {
                // now we check if the fragment passes the filter
                blake_hash.set_data(4, fragment >> 32);
                blake_hash.set_data(5, fragment & 0xFFFFFFFF);
                uint32_t hash_result = blake_hash.generate_hash().r0;
                if (hash_result < hash_threshold)
                {
                    // If it passes, add it to the filtered fragments
                    ScanResult result;
                    result.fragment = fragment;
                    result.index = pos;
                    filtered_fragments.push_back(result);
                }
                test_num_fragments_scanned++;
            }
            else {
                // error
                std::cerr << "Fragment out of range: " << fragment << " at position " << pos << std::endl;
            }
            ++pos;
        }

        std::cout << "Total fragments scanned: " << test_num_fragments_scanned << std::endl;
        std::cout << "Filtered fragments found: " << filtered_fragments.size() << std::endl;
        

        /*for (size_t i = 0; i < fragments.size(); ++i)
        {
            uint64_t fragment = fragments[i];
            // Check if the fragment is within the scan range
            if (fragment >= range.start && fragment < range.end)
            {
                // now we check if the fragment passes the filter
                blake_hash.set_data(4, fragment >> 32);
                blake_hash.set_data(5, fragment & 0xFFFFFFFF);
                uint32_t hash_result = blake_hash.generate_hash().r0;
                if (hash_result < hash_threshold)
                {
                    // If it passes, add it to the filtered fragments
                    ScanResult result;
                    result.fragment = fragment;
                    result.index = i;
                    filtered_fragments.push_back(result);
                }
            }
            if (fragment >= range.end)
            {
                break; // No need to check further if the fragment is out of range
            }
        }*/

        return filtered_fragments;
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
    int scan_filter_;
    ProofParams params_;
    ProofCore proof_core_;
    std::array<uint8_t, 32> challenge_;
};