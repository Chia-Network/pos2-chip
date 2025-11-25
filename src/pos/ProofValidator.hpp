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

// #define DEBUG_PROOF_VALIDATOR true

class ProofValidator
{
public:
    ProofValidator(const ProofParams &proof_params)
        : params_(proof_params), 
          proof_core_(proof_params)
    {

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
    bool
    validate_table_4_pairs(const uint32_t *x_values)
    {
        return false;
    }

    // validates a full proof consisting of 512 x-values of k-bits (in 32 bit element array)
    // Note that harvester/farmer/node are responsible for checking plot id filter
    // returns QualityChainLinks if valid, else std::nullopt
    std::optional<QualityChainLinks> validate_full_proof(std::span<uint32_t const, 512> const full_proof, std::span<uint8_t const, 32> const challenge, int proof_fragment_scan_filter_bits)
    {
        if (full_proof.size() != 32 * NUM_CHAIN_LINKS)
        {
            std::cerr << "Invalid number of x-values for full proof validation: " << full_proof.size() << std::endl;
            return std::nullopt;
        }
        // initial challenge is hash of plot id and challenge
        BlakeHash::Result256 next_challenge = proof_core_.hashing.challengeWithPlotIdHash(challenge.data());

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
            //if (!validate_table_5_pairs(x_values))
            {
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cerr << "Validation failed for sub-proof " << i << std::endl;
                #endif
                return std::nullopt;
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
        const size_t fragment_position = pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR
                                    ? QualityLinkProofFragmentPositions::RR
                                    : QualityLinkProofFragmentPositions::LR;
        ProofFragment fragment_passing_scan_filter = full_proof_fragments[fragment_position];
        ProofFragmentScanFilter::ScanRange range = scan_filter.getScanRangeForFilter();

        // Fragment chosen from pattern must be in the scan range defined by the challenge
        if (!range.isInRange(fragment_passing_scan_filter))
        {
            return std::nullopt;
        }

        // Fragment is in scan range, and must also pass the scan filter hash threshold.
        auto filtered_fragments = scan_filter.filterFragmentsByHash(
            {{fragment_passing_scan_filter, static_cast<uint64_t>(fragment_position)}});
        if (filtered_fragments.empty())
        {
            #ifdef DEBUG_PROOF_VALIDATOR
            std::cerr << "No fragments passed the scan filter." << std::endl;
            #endif
            return std::nullopt;
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

        // build the Quality Chain by checking each link in sequence.
        QualityChainLinks chain_links;

        for (size_t quality_chain_index = 0; quality_chain_index < NUM_CHAIN_LINKS; quality_chain_index++)
        {
            auto result = checkLink(full_proof_fragments, next_challenge, l_partition, r_partition, quality_chain_index);
            if (!result.has_value())
            {
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cerr << "Invalid link at chain index " << quality_chain_index << std::endl;
                #endif
                return std::nullopt; // invalid link, return false
            }
            else
            {
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cout << "Valid link found at chain index " << quality_chain_index << std::endl;
                #endif
                // update the challenge for the next iteration
                next_challenge = result.value().next_challenge;

                // update the chain links
                chain_links[quality_chain_index] = result.value().quality_link;
            }
            
        }

        #ifdef DEBUG_PROOF_VALIDATOR
        std::cout << "Chain verified successfully with quality string: " << next_challenge.toString() << std::endl;
        #endif
        return chain_links;
    }

    // checks whether a challenge is valid for a given link in the quality chain.
    // Returns the next challenge if valid, or std::nullopt if invalid.
    struct CheckLinkResult
    {
        BlakeHash::Result256 next_challenge;
        QualityLink quality_link;
    };
    std::optional<CheckLinkResult> checkLink(const std::vector<ProofFragment> &proof_fragments, BlakeHash::Result256 &challenge, uint32_t partition_A, uint32_t partition_B, size_t chain_index)
    {
        FragmentsPattern pattern = proof_core_.requiredPatternFromChallenge(challenge);

        #ifdef DEBUG_PROOF_VALIDATOR
        std::cout << "Checking link at chain index " << chain_index
                  << " with pattern: " << FragmentsPatternToString(pattern) << std::endl
                  << " and challenge: " << challenge.toString() << std::endl;
        #endif

        // depending on pattern, our Quality Link composes 3 fragments that follow the order LL,LR,RL,RR
        QualityLink quality_link;
        quality_link.outside_t3_index = 0; // unused, prevents compiler warnings.
        if (pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR)
        {
            quality_link.fragments[0] = proof_fragments[chain_index * 4 + QualityLinkProofFragmentPositions::LL];
            quality_link.fragments[1] = proof_fragments[chain_index * 4 + QualityLinkProofFragmentPositions::RL];
            quality_link.fragments[2] = proof_fragments[chain_index * 4 + QualityLinkProofFragmentPositions::RR];
            quality_link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;
            // check our data aligns with expected partitions
            uint32_t lateral_partition_ll = proof_core_.fragment_codec.get_lateral_to_t4_partition(quality_link.fragments[0]);
            uint32_t lateral_partition_rl = proof_core_.fragment_codec.get_lateral_to_t4_partition(quality_link.fragments[1]);
            uint32_t lateral_partition_rr = proof_core_.fragment_codec.get_lateral_to_t4_partition(quality_link.fragments[2]);
            uint32_t cross_partition_rr = proof_core_.fragment_codec.get_r_t4_partition(quality_link.fragments[2]);
            // RR lateral and cross must both be in partition A and B, but either order.
            if (!((lateral_partition_rr == partition_A && cross_partition_rr == partition_B) ||
                  (lateral_partition_rr == partition_B && cross_partition_rr == partition_A)))
            {
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cerr << "RR fragment partitions do not match expected partitions." << std::endl;
                #endif
                return std::nullopt;
            }
            // lateral ll and lateral rl must be same as cross rr
            if (lateral_partition_ll != cross_partition_rr ||
                lateral_partition_rl != cross_partition_rr)
            {
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cerr << "Lateral partitions of LL and RL do not match Cross partition of RR." << std::endl;
                #endif
                return std::nullopt;
            }

            #ifdef DEBUG_PROOF_VALIDATOR
            uint32_t cross_partition_ll = proof_core_.fragment_codec.get_r_t4_partition(quality_link.fragments[0]);
            uint32_t cross_partition_rl = proof_core_.fragment_codec.get_r_t4_partition(quality_link.fragments[1]);
            std::cout << "Pattern: " << FragmentsPatternToString(quality_link.pattern) << std::endl;
            std::cout << "partition A: " << partition_A
                      << ", partition B: " << partition_B << std::endl;
            std::cout << "Partitions for LL: (" << lateral_partition_ll << ", " << cross_partition_ll << ")\n"
                      << "Partitions for RL: (" << lateral_partition_rl << ", " << cross_partition_rl << ")\n"
                      << "Partitions for RR: (" << lateral_partition_rr << ", " << cross_partition_rr << ")\n";
            std::cout << "cross_rr: " << cross_partition_rr << " should be same as lateral_ll: " << lateral_partition_ll
                      << " and lateral_rl: " << lateral_partition_rl << std::endl;
            #endif
        }
        else
        {
            quality_link.fragments[0] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::LL)];
            quality_link.fragments[1] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::LR)];
            quality_link.fragments[2] = proof_fragments[chain_index * 4 + static_cast<int>(QualityLinkProofFragmentPositions::RL)];
            quality_link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;
            // check our data aligns with expected partitions
            uint32_t lateral_partition_ll = proof_core_.fragment_codec.get_lateral_to_t4_partition(quality_link.fragments[0]);
            uint32_t lateral_partition_lr = proof_core_.fragment_codec.get_lateral_to_t4_partition(quality_link.fragments[1]);
            uint32_t cross_partition_lr = proof_core_.fragment_codec.get_r_t4_partition(quality_link.fragments[1]);
            uint32_t lateral_partition_rl = proof_core_.fragment_codec.get_lateral_to_t4_partition(quality_link.fragments[2]);
            
            // lr lateral and cross must both be in partition A and B, but either order.
            if (!((lateral_partition_lr == partition_A && cross_partition_lr == partition_B) ||
                  (lateral_partition_lr == partition_B && cross_partition_lr == partition_A)))
            {   
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cerr << "LR fragment partitions do not match expected partitions." << std::endl;
                #endif
                return std::nullopt;
            }
            // lateral ll and lateral rl must be same as cross lr
            if (lateral_partition_ll != cross_partition_lr ||
                lateral_partition_rl != cross_partition_lr)
            {
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cerr << "LL/RL fragment partitions do not match expected partitions." << std::endl;
                #endif
                return std::nullopt;
            }
            #ifdef DEBUG_PROOF_VALIDATOR
            uint32_t cross_partition_ll = proof_core_.fragment_codec.get_r_t4_partition(quality_link.fragments[0]);
            uint32_t cross_partition_rl = proof_core_.fragment_codec.get_r_t4_partition(quality_link.fragments[2]);
            std::cout << "Pattern: " << FragmentsPatternToString(quality_link.pattern) << std::endl;
            std::cout << "partition A: " << partition_A
                      << ", partition B: " << partition_B << std::endl;
            std::cout << "Partitions for LL: (" << lateral_partition_ll << ", " << cross_partition_ll << ")\n"
                      << "Partitions for LR: (" << lateral_partition_lr << ", " << cross_partition_lr << ")\n"
                      << "Partitions for RL: (" << lateral_partition_rl << ", " << cross_partition_rl << ")\n";
            std::cout << "cross_lr: " << cross_partition_lr << " should be same as lateral_ll: " << lateral_partition_ll
                      << " and lateral_rl: " << lateral_partition_rl << std::endl;
            #endif
        }
        BlakeHash::Result256 next_challenge = proof_core_.hashing.chainHash(challenge, quality_link.fragments);

        if (chain_index == 0) {
            // for the first link, we don't check the threshold, just return the next challenge
            return CheckLinkResult{.next_challenge = next_challenge, .quality_link = quality_link};
        }
        uint32_t qc_pass_threshold = proof_core_.quality_chain_pass_threshold(chain_index);

        if (next_challenge.r[0] < qc_pass_threshold)
        {
            // if the next challenge is below the pass threshold, we have a valid link
            #ifdef DEBUG_PROOF_VALIDATOR
            std::cout << "Valid link found at chain index " << chain_index << std::endl 
                        << "Next challenge: " << next_challenge.toString() << std::endl;
            #endif
            // return the next challenge as the new hash
            return CheckLinkResult{.next_challenge = next_challenge, .quality_link = quality_link};

        }
        else
        {
            #ifdef DEBUG_PROOF_VALIDATOR
            std::cout << "Invalid link at chain index " << chain_index << std::endl
                        << "Next challenge: " << next_challenge.toString() << std::endl
                        << "Pass threshold: " << qc_pass_threshold << std::endl;
            #endif
            return std::nullopt; // invalid link, return nullopt
        }

    }


private:
    ProofParams params_;
    ProofCore proof_core_;

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
