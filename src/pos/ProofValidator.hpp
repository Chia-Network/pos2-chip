#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <optional>
#include <iostream>
#include <sstream>
#include <string>

#include "ProofCore.hpp"
#include "pos/ProofFragmentScanFilter.hpp"

#define DEBUG_PROOF_VALIDATOR true

class ProofValidator
{
public:
    ProofValidator(const ProofParams &proof_params)
        : params_(proof_params), 
          proof_core_(proof_params),
          sub_proof_core_(ProofParams(proof_params.get_plot_id_bytes(), proof_params.get_sub_k()))
    {
        // sub params are used in T4/5
    }

    /**
     * validate_table_1_pair(x_pair):
     *   - x_pair has exactly 2 x-values: x_l, x_r
     *
     * @return std::optional<ProofCore::T1Result>
     *         If valid, T1Result{ match_info, meta }, else nullopt.
     */
    std::optional<T1Pairing>
    validate_table_1_pair(const uint32_t *x_pair)
    {
        uint32_t x_l = x_pair[0];
        uint32_t x_r = x_pair[1];

        // g(x_l) and g(x_r)
        uint32_t match_info_l = proof_core_.hashing.g(static_cast<uint32_t>(x_l));
        uint32_t match_info_r = proof_core_.hashing.g(static_cast<uint32_t>(x_r));

        if (!proof_core_.validate_match_info_pairing(
                1, static_cast<uint64_t>(x_l), match_info_l, match_info_r))
        {
            return std::nullopt;
        }

        return proof_core_.pairing_t1(x_l, x_r);
    }

    /**
     * validate_table_2_pairs(x_values):
     *   - We expect exactly 4 x-values: the first 2 are the "left" pair,
     *     the next 2 are the "right" pair
     */
    std::optional<T2Pairing>
    validate_table_2_pairs(const uint32_t *x_values)
    {
        const uint32_t *l_xs = x_values;
        const uint32_t *r_xs = x_values + 2;

        // Validate each side as table 1
        std::optional<T1Pairing> result_l = validate_table_1_pair(l_xs);
        if (!result_l.has_value())
        {
            return std::nullopt;
        }
        std::optional<T1Pairing> result_r = validate_table_1_pair(r_xs);
        if (!result_r.has_value())
        {
            return std::nullopt;
        }
        //  Validate table 2 pairing
        if (!proof_core_.validate_match_info_pairing(
                2, result_l->meta, result_l->match_info, result_r->match_info))
        {
            return std::nullopt;
        }
        return proof_core_.pairing_t2(result_l->meta, result_r->meta);
    }

    /**
     * validate_table_3_pairs(x_values):
     *   - We expect 8 x-values total:
     *     first 4 => left half, next 4 => right half
     */
    std::optional<T3Pairing>
    validate_table_3_pairs(const uint32_t *x_values)
    {
        // left half => first 4
        const uint32_t *l_xs = x_values;
        const uint32_t *r_xs = x_values + 4;
        // Validate each side as table 2
        std::optional<T2Pairing> result_l = validate_table_2_pairs(l_xs);
        if (!result_l.has_value())
        {
            return std::nullopt;
        }
        std::optional<T2Pairing> result_r = validate_table_2_pairs(r_xs);
        if (!result_r.has_value())
        {
            return std::nullopt;
        }
        // Validate table 3 pairing
        if (!proof_core_.validate_match_info_pairing(
                3, result_l->meta, result_l->match_info, result_r->match_info))
        {
            return std::nullopt;
        }
        return proof_core_.pairing_t3(result_l->meta, result_r->meta, result_l->x_bits, result_r->x_bits);
    }

    /**
     * validate_table_4_pairs(x_values):
     *   - We expect 16 x-values:
     *     first 8 => left half, next 8 => right half
     */
    // will return 0, 1, or 2 pairs (rare)
    std::vector<T4Pairing>
    validate_table_4_pairs(const uint32_t *x_values)
    {
        std::vector<T4Pairing> t4_pairs;

        const uint32_t *l_xs = x_values;
        const uint32_t *r_xs = x_values + 8;

        // Validate each side as table 3
        std::optional<T3Pairing> result_l = validate_table_3_pairs(l_xs);
        if (!result_l.has_value())
        {
            return t4_pairs; // will be empty
        }
        std::optional<T3Pairing> result_r = validate_table_3_pairs(r_xs);
        if (!result_r.has_value())
        {
            return t4_pairs; // will be empty
        }

        if (!proof_core_.fragment_codec.validate_proof_fragment(result_l->proof_fragment, l_xs))
        {
            std::cerr << "Validation failed for left proof_fragment: ["
                      << result_l->proof_fragment << "] vs ["
                      << show_xs(l_xs, 8) << "]\n";
            return t4_pairs; // std::nullopt;
        }

        if (!proof_core_.fragment_codec.validate_proof_fragment(result_r->proof_fragment, r_xs))
        {
            std::cerr << "Validation failed for right proof_fragment: ["
                      << result_r->proof_fragment << "] vs ["
                      << show_xs(r_xs, 8) << "]\n";
            return t4_pairs; // std::nullopt;
        }

        // at least one of the lower and upper partitions must be the same
        if (result_l->lower_partition != result_r->lower_partition &&
            result_l->upper_partition != result_r->upper_partition)
        {
            std::cerr << "Validation failed for partition mismatch: ["
                      << result_l->lower_partition << ", " << result_l->upper_partition << "] vs ["
                      << result_r->lower_partition << ", " << result_r->upper_partition << "]\n";
            return t4_pairs; // std::nullopt;
        }

        // get partitioned pairing vector and add it if it's match. could be a false positive so want to return 1 or 2 of these
        // note challenge might specify the partition to use, not sure if relevant here.
        if (result_l->lower_partition == result_r->lower_partition)
        {
            // Validate table 4 pairing
            if (sub_proof_core_.validate_match_info_pairing(
                    4, result_l->meta_lower_partition, result_l->match_info_lower_partition, result_r->match_info_lower_partition))
            {
                std::optional<T4Pairing> result = sub_proof_core_.pairing_t4(result_l->meta_lower_partition, result_r->meta_lower_partition, result_l->order_bits, result_r->order_bits);
                if (result.has_value())
                {
                    t4_pairs.push_back(result.value());
                }
            }
        }
        if (result_l->upper_partition == result_r->upper_partition)
        {
            // Validate table 4 pairing
            if (sub_proof_core_.validate_match_info_pairing(
                    4, result_l->meta_upper_partition, result_l->match_info_upper_partition, result_r->match_info_upper_partition))
            {
                std::optional<T4Pairing> result = sub_proof_core_.pairing_t4(result_l->meta_upper_partition, result_r->meta_upper_partition, result_l->order_bits, result_r->order_bits);
                if (result.has_value())
                {
                    t4_pairs.push_back(result.value());
                }
            }
        }

        // if (result_l->lower_partition == result_r->lower_partition &&
        //     result_l->upper_partition == result_r->upper_partition) {
        //         std::cout << "Validation had both partitions match" << std::endl;
        //     }

        return t4_pairs;
    }

    /**
     * validate_table_5_pairs(x_values):
     *   - We expect 32 x-values:
     *     first 16 => left half, next 16 => right half
     */
    bool
    validate_table_5_pairs(const uint32_t *x_values)
    {
        std::vector<T4Pairing> result_l = validate_table_4_pairs(x_values + 0);
        if (result_l.empty())
        {
            return false;
        }
        auto result_r = validate_table_4_pairs(x_values + 16);
        if (result_r.empty())
        {
            return false;
        }

        // infrequent, but possible to have multiple valid table 4 pairs
        // so we need to check all combinations
        // and only if all fail is it invalid.
        for (int l_index = 0; l_index < result_l.size(); l_index++)
        {
            for (int r_index = 0; r_index < result_r.size(); r_index++)
            {
                if (sub_proof_core_.validate_match_info_pairing(
                        5, result_l[l_index].meta, result_l[l_index].match_info, result_r[r_index].match_info))
                {
                    return true;
                }
            }
        }

        return false;
    }

    // validates a full proof consisting of 32 x-values of k-bits (in 32 bit element array)
    bool validate_full_proof(const std::vector<uint32_t> &full_proof, const std::array<uint8_t, 32> &challenge, int proof_fragment_scan_filter_bits)
    {
        if (full_proof.size() != 32 * NUM_CHAIN_LINKS)
        {
            std::cerr << "Invalid number of x-values for full proof validation: " << full_proof.size() << std::endl;
            return false;
        }

        // First test if passes plot id filter. We hash the plot id with the challenge, and
        // use this 256-bit result for the next challenge.
        uint32_t plot_id_filter = 0; // TODO: set appropriately.
        auto plot_id_challenge_result = proof_core_.check_plot_id_filter(plot_id_filter, challenge);
        if (!plot_id_challenge_result.has_value())
        {
            // failed to pass plot id filter
            return false;
        }
        BlakeHash::Result256 next_challenge = plot_id_challenge_result.value();

        // next we check all the single proofs. We verify if all the x-pairs pair,
        // and construct all the proof fragments needed to build and verify the Quality String.
        size_t num_sub_proofs = full_proof.size() / 32;
        std::vector<ProofFragment> full_proof_fragments;
        for (size_t i = 0; i < num_sub_proofs; ++i)
        {
            // extract the 32 x-values from the proof
            uint32_t x_values[32];
            for (size_t j = 0; j < 32; ++j)
            {
                x_values[j] = full_proof[i * 32 + j];
            }

            // validate the x-values
            if (!validate_table_5_pairs(x_values))
            {
                std::cerr << "Validation failed for sub-proof " << i << std::endl;
                return 1;
            }

            // Each set of 32 x-values from a sub-proof will produce 4 proof fragments from 8 x-values each
            for (int fragment_id = 0; fragment_id < 4; ++fragment_id)
            {
                // create a sub-proof fragment
                ProofFragment proof_fragment = proof_core_.fragment_codec.encode(x_values + fragment_id * 8);
                full_proof_fragments.push_back(proof_fragment);
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cout << "Sub-proof fragment " << fragment_id << " for sub-proof " << i << ": "
                          << "x-values: [";
                for (size_t j = 0; j < 8; ++j)
                {
                    std::cout << x_values[fragment_id * 8 + j] << " ";
                }
                std::cout << "] | Proof Fragment: " << std::hex << proof_fragment << std::dec << std::endl;
                #endif
            }
        }

        // Now we have all the proof fragments, we can build the Quality String.
        // First, test for the Proof Fragment Scan Filter, which finds the first set of fragments (Quality Link) in the Quality Chain.
        ProofFragmentScanFilter scan_filter(params_, next_challenge, proof_fragment_scan_filter_bits);

        // The first challenge defines the pattern, scan range, and scan filter for the first fragment.
        FragmentsPattern pattern = proof_core_.requiredPatternFromChallenge(next_challenge);
        int fragment_position = pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR
                                    ? static_cast<int>(QualityLinkProofFragmentPositions::RR)
                                    : static_cast<int>(QualityLinkProofFragmentPositions::LR);
        ProofFragment fragment_passing_scan_filter = full_proof_fragments[fragment_position];
        ProofFragmentScanFilter::ScanRange range = scan_filter.getScanRangeForFilter();

        // Fragment chosen from pattern must be in the scan range defined by the challenge
        if (!range.isInRange(fragment_passing_scan_filter))
        {
            return false;
        }

        // Fragment is in scan range, and must also pass the scan filter hash threshold.
        auto filtered_fragments = scan_filter.filterFragmentsByHash(
            {{fragment_passing_scan_filter, static_cast<uint64_t>(fragment_position)}});
        if (filtered_fragments.empty())
        {
            std::cerr << "No fragments passed the scan filter." << std::endl;
            return false;
        }
        #ifdef DEBUG_PROOF_VALIDATOR
        std::cout << "Filtered fragments after scan filter: " << filtered_fragments.size() << std::endl;
        #endif

        // the passing fragment implicitly holds the lateral and cross partitions.
        uint32_t l_partition = proof_core_.fragment_codec.get_lateral_to_t4_partition(
            filtered_fragments[0].fragment);
        uint32_t r_partition = proof_core_.fragment_codec.get_r_t4_partition(
            filtered_fragments[0].fragment);

        #ifdef DEBUG_PROOF_VALIDATOR
        std::cout << "Lateral partition: " << l_partition
                  << ", R partition: " << r_partition << std::endl;
        #endif

        for (int quality_chain_index = 0; quality_chain_index < NUM_CHAIN_LINKS; quality_chain_index++)
        {
            auto result = checkLink(full_proof_fragments, next_challenge, l_partition, r_partition, quality_chain_index);
            if (!result.has_value())
            {
                std::cerr << "Invalid link at chain index " << quality_chain_index << std::endl;
                return false; // invalid link, return false
            }
            else
            {
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cout << "Valid link found at chain index " << quality_chain_index << std::endl;
                #endif
                // update the challenge for the next iteration
                next_challenge = result.value();
            }
            
        }

        #ifdef DEBUG_PROOF_VALIDATOR
        std::cout << "Chain verified successfully with quality string: " << next_challenge.toString() << std::endl;
        #endif
        return true;
    }

    // checks whether a challenge is valid for a given link in the quality chain.
    // Returns the next challenge if valid, or std::nullopt if invalid.
    std::optional<BlakeHash::Result256> checkLink(const std::vector<ProofFragment> &proof_fragments, BlakeHash::Result256 &challenge, uint32_t partition_A, uint32_t partition_B, int chain_index)
    {
        FragmentsPattern pattern = proof_core_.requiredPatternFromChallenge(challenge);

        #ifdef DEBUG_PROOF_VALIDATOR
        std::cout << "Checking link at chain index " << chain_index
                  << " with pattern: " << FragmentsPatternToString(pattern) << std::endl
                  << " and challenge: " << challenge.toString() << std::endl;
        #endif

        // depending on pattern, our Quality Link composes 3 fragments that follow the order LL,LR,RL,RR
        QualityLink quality_link;
        if (pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR)
        {
            quality_link.fragments[0] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::LL)];
            quality_link.fragments[1] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::RL)];
            quality_link.fragments[2] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::RR)];
            quality_link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;
        }
        else
        {
            quality_link.fragments[0] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::LL)];
            quality_link.fragments[1] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::LR)];
            quality_link.fragments[2] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::RL)];
            quality_link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;
        }
        BlakeHash::Result256 next_challenge = proof_core_.hashing.chainHash(challenge, quality_link.fragments);

        if (chain_index == 0) {
            return next_challenge;
        }
        uint32_t qc_pass_threshold = proof_core_.quality_chain_pass_threshold(chain_index);

        if (next_challenge.r[0] < qc_pass_threshold)
        {
            // if the next challenge is below the pass threshold, we have a valid link
            #ifdef DEBUG_PROOF_VALIDATOR
            std::cout << "Valid link found at chain index " << chain_index << std::endl 
                        << "Next challenge: " << next_challenge.toString() << std::endl;
            #endif
            return next_challenge; // return the next challenge as the new hash
        }
        else
        {
            std::cout << "Invalid link at chain index " << chain_index << std::endl
                        << "Next challenge: " << next_challenge.toString() << std::endl
                        << "Pass threshold: " << qc_pass_threshold << std::endl;
            return std::nullopt; // invalid link, return nullopt
        }

    }


private:
    ProofParams params_;
    ProofCore proof_core_;
    ProofCore sub_proof_core_;

    // Utility function to print a list of xs in the style [x0, x1, x2, ...].
    static std::string show_xs(const uint32_t *v, int length)
    {
        std::ostringstream oss;
        oss << "[";
        for (int i = 0; i < length; i++)
        {
            if (i > 0)
                oss << ", ";
            oss << v[i];
        }
        oss << "]";
        return oss.str();
    }
};
