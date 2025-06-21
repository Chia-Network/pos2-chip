#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <optional>
#include <iostream>
#include <sstream>
#include <string>

#include "ProofCore.hpp"
#include "prove/Prover.hpp"
#include "pos/ProofFragmentScanFilter.hpp"

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
        // std::cout << "Passed validation" << std::endl;
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

        // make sure encrypted xs are valid
        if (!proof_core_.xs_encryptor.validate_encrypted_xs(result_l->encrypted_xs, l_xs))
        {
            std::cerr << "Validation failed for left encrypted_xs: ["
                      << result_l->encrypted_xs << "] vs ["
                      << show_xs(l_xs, 8) << "]\n";
            return t4_pairs; // std::nullopt;
        }

        if (!proof_core_.xs_encryptor.validate_encrypted_xs(result_r->encrypted_xs, r_xs))
        {
            std::cerr << "Validation failed for right encrypted_xs: ["
                      << result_r->encrypted_xs << "] vs ["
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

    bool validate_full_proof(const std::vector<uint32_t> &full_proof, const std::array<uint8_t, 32> &challenge)
    {
        if (full_proof.size() != 32 * NUM_CHAIN_LINKS)
        {
            std::cerr << "Invalid number of x-values for full proof validation: " << full_proof.size() << std::endl;
            return false;
        }

        size_t num_sub_proofs = full_proof.size() / 32;
        std::vector<uint64_t> full_proof_fragments;
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
            else
            {
                std::cout << "Sub-proof " << i << " validated successfully." << std::endl;
            }

            // Each set of 32 x-values from a sub-proof will produce 4 proof fragments from 8 x-values each
            for (int fragment_id = 0; fragment_id < 4; ++fragment_id)
            {
                // create a sub-proof fragment
                uint64_t proof_fragment = proof_core_.xs_encryptor.encrypt(x_values + fragment_id * 8);
                full_proof_fragments.push_back(proof_fragment);
                std::cout << "Sub-proof fragment " << fragment_id << " for sub-proof " << i << ": "
                          << "x-values: [";
                for (size_t j = 0; j < 8; ++j)
                {
                    std::cout << x_values[fragment_id * 8 + j] << " ";
                }
                std::cout << "] | Proof Fragment: " << std::hex << proof_fragment << std::dec << std::endl;
            }
        }

        ProofFragmentScanFilter scan_filter(params_, challenge);

        // The first Quality Link of a proof could originate from either LR or RR fragments.
        // Add these to a scan fragments list to test against the scan filter.
        std::vector<ProofFragmentScanFilter::ScanResult> scan_fragments;
        {
            ProofFragmentScanFilter::ScanResult first_fragment;
            first_fragment.fragment = full_proof_fragments[static_cast<int>(QualityLinkProofFragmentPositions::LR)];
            first_fragment.index = static_cast<int>(QualityLinkProofFragmentPositions::LR); 
            scan_fragments.push_back(first_fragment);
        }
        {
            ProofFragmentScanFilter::ScanResult second_fragment;
            second_fragment.fragment = full_proof_fragments[static_cast<int>(QualityLinkProofFragmentPositions::RR)];
            second_fragment.index = static_cast<int>(QualityLinkProofFragmentPositions::RR);
            scan_fragments.push_back(second_fragment);
        }

        auto filtered_fragments = scan_filter.filterFragmentsByHash(scan_fragments);
        if (filtered_fragments.empty())
        {
            std::cerr << "No fragments passed the scan filter." << std::endl;
            return false;
        }
        std::cout << "Filtered fragments after scan filter: " << filtered_fragments.size() << std::endl; 

        //QualityChainer quality_chainer(params_, challenge, proof_core_.quality_chain_pass_threshold());
        if (verifyDepth(0, 0, full_proof_fragments, challenge))
        {
            std::cout << "Chain verified successfully." << std::endl;
            return true; // if we reach here, the chain is valid
        }
        return false;
    }

    bool verifyDepth(int depth, uint64_t current_hash, const std::vector<uint64_t> &proof_fragments, const std::array<uint8_t, 32> &challenge, uint32_t partition_A = 0, uint32_t partition_B = 0)
    {
        if (depth == NUM_CHAIN_LINKS)
        {
            return true; // if we are at end of chain, we've validated everything
        }

        // get the proof fragments for the current depth
        if (depth < 0 || depth >= NUM_CHAIN_LINKS)
        {
            throw std::out_of_range("Depth out of range");
        }
        if (proof_fragments.size() < 4 * (depth + 1))
        {
            throw std::invalid_argument("Not enough proof fragments for depth");
        }
        // Extract the proof fragments for the current depth
        std::vector<uint64_t> current_depth_fragments(proof_fragments.begin() + depth * 4,
                                                     proof_fragments.begin() + (depth + 1) * 4);


        // Build RL and RR Quality Links from the proof fragments
        QualityLink lr_outside_link;
        lr_outside_link.fragments[0] = current_depth_fragments[static_cast<int>(QualityLinkProofFragmentPositions::LL)]; 
        lr_outside_link.fragments[1] = current_depth_fragments[static_cast<int>(QualityLinkProofFragmentPositions::RL)]; 
        lr_outside_link.fragments[2] = current_depth_fragments[static_cast<int>(QualityLinkProofFragmentPositions::RR)];
        lr_outside_link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR; 
        QualityLink rr_outside_link;
        rr_outside_link.fragments[0] = current_depth_fragments[static_cast<int>(QualityLinkProofFragmentPositions::LL)];
        rr_outside_link.fragments[1] = current_depth_fragments[static_cast<int>(QualityLinkProofFragmentPositions::LR)];
        rr_outside_link.fragments[2] = current_depth_fragments[static_cast<int>(QualityLinkProofFragmentPositions::RL)];
        rr_outside_link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR; 

        // TODO: partition check, we can invalidate a fragment if not part of partitions
        std::vector<ProofCore::NewLinksResult> new_links;
        if (depth == 0)
        {
            // For the first depth, we only have the first link. We extract the lateral and cross partitions, and run depth on each of them making sure their partitions align in subsequent fragments.

            // First test if the rl_link passes, and if not, then return result for rr_link.
            uint32_t partition_A = proof_core_.xs_encryptor.get_lateral_to_t4_partition(lr_outside_link.fragments[2]); // rr fragment
            uint32_t partition_B = proof_core_.xs_encryptor.get_r_t4_partition(lr_outside_link.fragments[2]);
            bool success = verifyDepth(depth + 1, proof_core_.firstLinkHash(lr_outside_link, challenge), proof_fragments, challenge, partition_A, partition_B);
            if (success)
            {
                return true; // if we reach here, the chain is valid
            }
            // If rl_outside_link failed, we try rr_outside_link
            partition_A = proof_core_.xs_encryptor.get_lateral_to_t4_partition(rr_outside_link.fragments[1]); // lr fragment
            partition_B = proof_core_.xs_encryptor.get_r_t4_partition(rr_outside_link.fragments[1]);
            return verifyDepth(depth + 1, proof_core_.firstLinkHash(rr_outside_link, challenge), proof_fragments, challenge, partition_A, partition_B);
        }
        else
        {
            // first filter QualityLinks by partition pattern (faster than hash). In most cases this will reduce number of links to 1 instead of 2.
            auto filtered_links = proof_core_.filterLinkSetToPartitions({lr_outside_link, rr_outside_link}, partition_A, partition_B);
            new_links = proof_core_.getNewLinksForChain(current_hash, filtered_links);
            
            std::cout << "new links count: " << new_links.size() << std::endl;
            std::cout << "filtered links count: " << filtered_links.size() << std::endl;
        }
        if (new_links.empty())
        {
            std::cerr << "No new links found for depth " << depth << " with current hash: " << current_hash << std::endl;
            return false;
        }

        for (const auto &new_link : new_links)
        {
            // Recursively verify the next depth
            if (verifyDepth(depth + 1, new_link.new_hash, proof_fragments, challenge, partition_A, partition_B))
            {
                return true;
            }
        }
        // if all links failed, we don't have a valid chain
        return false;
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
