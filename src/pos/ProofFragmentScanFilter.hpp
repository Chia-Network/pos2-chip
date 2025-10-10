#pragma once

#include <cstdint>
#include "ProofCore.hpp"
#include "BlakeHash.hpp"
#include <vector>

#define DEBUG_PROOF_FRAGMENT_SCAN_FILTER true

const uint64_t PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS = 13; // 2^13 = 8192

class ProofFragmentScanFilter
{
public:
    struct ScanRange
    {
        uint64_t start;
        uint64_t end;

        bool isInRange(ProofFragment fragment) const
        {
            return (fragment >= start && fragment <= end);
        }
    };

    ProofFragmentScanFilter(const ProofParams &proof_params, const BlakeHash::Result256 &challenge, const int proof_fragment_scan_filter_bits)
        : params_(proof_params),
          proof_core_(proof_params),
          challenge_(challenge)
    {

        // math needed:
        // - per_range = t3_exp / numScanRanges()
        // - filter = 1 / (per_range * (1 << proof_fragment_scan_filter_bits))
        // - filter_32bit_hash_threshold_ = static_cast<uint32_t>(filter * 0xFFFFFFFF)
        // in one formula:
        // filter_32bit_hash_threshold_ = static_cast<uint32_t>( (1 << 32) / (t3_exp / numScanRanges() * (1 << proof_fragment_scan_filter_bits)) )
        // which simplifies to:
        // filter_32bit_hash_threshold_ = static_cast<uint32_t>( (1 << 32) * numScanRanges() / (t3_exp * (1 << proof_fragment_scan_filter_bits)) )
        
        // compute our hashing threshold for the scan filter
        auto t3_expected_entries = proof_core_.nd_expected_pruned_entries_for_t3();

         // per range = t3_expected_entries / numScanRanges()
        // filter = 1 / (per_range * (1 << proof_fragment_scan_filter_bits))
        // filter_32bit_hash_threshold_ = static_cast<uint32_t>(filter * 0xFFFFFFFF)
        
        auto num_per_range = SafeFractionMath::mul_fraction_u64(t3_expected_entries, 1, numScanRanges());
        auto frac = SafeFractionMath::invert_fraction_u64(num_per_range);
        frac = SafeFractionMath::mul_fraction_u64(frac, 1, (1ULL << proof_fragment_scan_filter_bits));
        filter_32bit_hash_threshold_ = SafeFractionMath::map_fraction_to_u32(frac);

        //uint64_t t3_exp_num = t3_expected_entries.first;
        //uint64_t t3_exp_denom = t3_expected_entries.second;
        
        //uint64_t per_range_numerator = t3_exp_num;
        //uint64_t per_range_denominator = t3_exp_denom * numScanRanges();
        //uint64_t filter_numerator = (per_range_denominator >> 20) * (1ULL << 32);
        //uint64_t filter_denominator = (per_range_numerator >> 20) * (1ULL << proof_fragment_scan_filter_bits);
        //uint32_t test_threshold = static_cast<uint32_t>(filter_numerator / filter_denominator);

        //double t3_exp = proof_core_.num_expected_pruned_entries_for_t3();
        //double per_range = t3_exp / numScanRanges();
        //double filter = 1 / (per_range * (1 << proof_fragment_scan_filter_bits));
        //filter_32bit_hash_threshold_ = static_cast<uint32_t>(filter * 0xFFFFFFFF);

        //std::cout << "test threshold: " << test_threshold << std::endl;
        //std::cout << "computed filter threshold: " << filter_32bit_hash_threshold_ << std::endl;
        //if (test_threshold != filter_32bit_hash_threshold_)
        //{
        //    std::cerr << "Warning: Test threshold does not match computed filter threshold!" << std::endl;
        //    exit(23);
        //}
    }

    ~ProofFragmentScanFilter() = default;


    struct ScanResult
    {
        ProofFragment fragment;
        uint64_t index;
    };

    // Scan the plot data for fragments that pass the scan filter
    std::vector<ScanResult> scan(const std::vector<ProofFragment> &fragments)
    {
        /*#ifdef DEBUG_PROOF_FRAGMENT_SCAN_FILTER
            //std::cout << "Scanning " << fragments.size() << " fragments." << std::endl;
            /or (const auto &fragment : fragments)
            {
                std::cout << "  Fragment: " << std::hex << fragment << std::dec << std::endl;
            }
        }
        #endif*/

        ScanRange range = getScanRangeForFilter();
        auto in_range = collectFragmentsInRange(fragments, range);

        return filterFragmentsByHash(in_range);
    }

    // 2) Apply hash threshold to the pre‐filtered fragments
    std::vector<ScanResult> filterFragmentsByHash(
        const std::vector<ScanResult> &candidates)
    {
        // output candidates
        if (false)
        {
            std::cout << "Filtering " << candidates.size() << " candidates by hash threshold." << std::endl;
            for (const auto &candidate : candidates)
            {
                std::cout << "  Candidate fragment: " << std::hex << candidate.fragment << std::dec << std::endl;
            }
        }

        //BlakeHash::Result256 challenge_plot_id_hash = proof_core_.hashing.challengeWithPlotIdHash(challenge_.data());
        uint32_t block_words[16];
        // Fill the first 8 words with the challenge plot ID hash.
        for (int i = 0; i < 8; ++i)
        {
            block_words[i] = challenge_.r[i];
        }
        for (int i = 8; i < 16; ++i)
        {
            block_words[i] = 0; // Zero the remaining words
        }

        std::vector<ScanResult> filtered;
        for (auto &r : candidates)
        {
            // Set the next 2 words of the Blake hash with the fragment
            block_words[8] = static_cast<uint32_t>(r.fragment >> 32);
            block_words[9] = static_cast<uint32_t>(r.fragment & 0xFFFFFFFF);
            BlakeHash::Result64 result = BlakeHash::hash_block_64(block_words);
            if (result.r[0] < filter_32bit_hash_threshold_)
                filtered.push_back(r);
        }
        return filtered;
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
        // Calculate the scan range based on the challenge
        // A filter range of PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS (set to 13, value 8192) means we want to scan approximately 8192 entries (before pruning metric) at a time.
        // To find the range across approximately 2^k entries that span across proof fragment values 0..2^(2k) - 1, then the number of possible scan ranges is 2^k / 8192, or 2^(k - 13)
        //   -> this becomes scan_range_filter_bits = k - 13.
        // and thus the value of that span is 2^(2k) / (2^k / 8192) = 2^k * 8192 = 2^(k + 13).
        int scan_range_filter_bits = params_.get_k() - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS;

        // the scan range bits are the 13 bits from the challenge r[3] (the last word of the challenge)
        // after the highest order bit which defines the pattern.
        // challenge 256 bits: [highest order bit is pattern][next scan range bits]...
        uint32_t scan_range_id = (challenge_.r[3] >> (32 - scan_range_filter_bits - 1)) & ((1U << scan_range_filter_bits) - 1);
       
        uint64_t scan_span = getScanSpan();

        // TODO: make sure k32 doesn't overflow
        ScanRange range;
        range.start = scan_span * scan_range_id;
        range.end = scan_span * (scan_range_id + 1) - 1;
        #ifdef DEBUG_PROOF_FRAGMENT_SCAN_FILTER
        {
            std::cout << "Scan range id: " << scan_range_id << std::endl;
            std::cout << "Scan range: " << range.start << " - " << range.end << std::endl;
            std::cout << "Scan range filter bits: " << scan_range_filter_bits << std::endl;
            std::cout << "Scan range selection bits: " << PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS << std::endl;
        }
        #endif
        return range;
    }

private:
    // Scan filter parameters
    ProofParams params_;
    ProofCore proof_core_;
    BlakeHash::Result256 challenge_;
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
        // if we are not at the front of the list, then scan backwards until we find a fragment that is within the range
        else if ((start_index > 0) && (fragments[start_index] > range.start))
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
