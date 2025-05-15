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
        double t3_expected_num_entries_per_range = t3_expected_entries / (1ULL << PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS);
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
       
        for (size_t i = 0; i < fragments.size(); ++i)
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
        }

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
            lsb |= ((challenge_[i / 8] >> (i % 8)) & 1) << i;
        }

        return lsb;
    }

    ScanRange getScanRangeForFilter()
    {
        // Calculate the scan range based on the filter
        // The scan range filter bits determine the msb of the fragment
        // The number of possible scan ranges is the rest of the 2k bits
        //   aka the scan_range_selection_bits
        // We get the scan_range_selection_bits by looking at the lsb of the challenge
        // The scan range becomes those msb range of bits after the selection

        int scan_range_filter_bits = 2 * params_.get_k() - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS;
        uint64_t scan_range_id = getLSBFromChallenge(scan_range_filter_bits);

        // TODO: make sure k32 doesn't overflow
        ScanRange range;
        range.start = scan_range_id << scan_range_filter_bits;
        range.end = ((scan_range_id + 1) << scan_range_filter_bits) - 1;

        // debug out
        if (true)
        {
            std::cout << "Scan range: " << range.start << " - " << range.end << std::endl;
            std::cout << "Scan range filter bits: " << scan_range_filter_bits << std::endl;
            std::cout << "Scan range id: " << scan_range_id << std::endl;
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