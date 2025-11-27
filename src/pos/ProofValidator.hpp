#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <optional>
#include <iostream>
#include <sstream>
#include <string>

#include "pos/ProofCore.hpp"
#include "pos/Chainer.hpp"

// #define DEBUG_PROOF_VALIDATOR true

class ProofValidator
{
public:
    ProofValidator(const ProofParams &proof_params)
        : params_(proof_params), 
          proof_core_(proof_params)
    {

    }

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

    // validates a full proof consisting of 128 x-values of k-bits (in 32 bit element array)
    // Note that harvester/farmer/node are responsible for checking plot id filter
    // returns QualityChainLinks if valid, else std::nullopt
    std::optional<QualityChainLinks> validate_full_proof(std::span<uint32_t const, TOTAL_XS_IN_PROOF> const full_proof, std::span<uint8_t const, 32> const challenge)
    {
        if (full_proof.size() != 8 * NUM_CHAIN_LINKS)
        {
            std::cerr << "Invalid number of x-values for full proof validation: " << full_proof.size() << std::endl;
            return std::nullopt;
        }

        // make challenge into std::array<uint8_t,32>
        std::array<uint8_t, 32> challenge_array;
        for (size_t i = 0; i < 32; ++i)
        {
            challenge_array[i] = challenge[i];
        }

        // next we check all the single proofs. We verify if all the x-pairs pair,
        // and construct the two proof fragment sets needed to build and verify the Quality String.
        size_t num_proof_fragments = full_proof.size() / 8;
        Chain chain;
        for (size_t i = 0; i < num_proof_fragments; ++i)
        {
            // extract the 8 x-values from the proof
            uint32_t x_values[8];
            for (size_t j = 0; j < 8; ++j)
            {
                x_values[j] = full_proof[i * 8 + j];
            }

            // validate the x-values
            if (!validate_table_3_pairs(x_values))
            {
                #ifdef DEBUG_PROOF_VALIDATOR
                std::cerr << "Validation failed for sub-proof " << i << std::endl;
                #endif
                return std::nullopt;
            }

            // Create the proof fragment and add to list
            ProofFragment proof_fragment = proof_core_.fragment_codec.encode(x_values);
            chain.fragments[i] = proof_fragment;
            //proof_fragments.push_back(proof_fragment);
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

        // determine the fragment ranges for A and B
        ProofCore::SelectedChallengeSets selected_sets = proof_core_.selectChallengeSets(challenge_array);

        // validate the chain of proof fragments.
        Chainer chainer(params_, challenge_array);
        bool valid = chainer.validate(chain, selected_sets.fragment_set_A_range, selected_sets.fragment_set_B_range);
        if (!valid) {
            #ifdef DEBUG_PROOF_VALIDATOR
            std::cerr << "Full proof chain validation failed." << std::endl;
            #endif
            return std::nullopt;
        }
        QualityChainLinks chain_links = chain.fragments;
        
        return chain_links;
    }


private:
    ProofParams params_;
    ProofCore proof_core_;
};
