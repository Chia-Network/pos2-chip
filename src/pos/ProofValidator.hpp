#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <optional>
#include <iostream>
#include <sstream>
#include <string>

#include "ProofCore.hpp"

class ProofValidator
{
public:
    ProofValidator(const ProofParams &proof_params)
        : proof_core_(proof_params),
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
            1, static_cast<uint64_t>(x_l), match_info_l, match_info_r)) {
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
        const uint32_t* l_xs = x_values; 
        const uint32_t* r_xs = x_values + 2;

        // Validate each side as table 1
        std::optional<T1Pairing> result_l = validate_table_1_pair(l_xs);
        if (!result_l.has_value()) {
            return std::nullopt;
        }
        std::optional<T1Pairing> result_r = validate_table_1_pair(r_xs);
        if (!result_r.has_value()) {
            return std::nullopt;
        }
        //std::cout << "Passed validation" << std::endl;
        // Validate table 2 pairing
        if (!proof_core_.validate_match_info_pairing(
            2, result_l->meta, result_l->match_info, result_r->match_info)) {
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
        const uint32_t* l_xs = x_values; 
        const uint32_t* r_xs = x_values + 4;
        // Validate each side as table 2
        std::optional<T2Pairing> result_l = validate_table_2_pairs(l_xs);
        if (!result_l.has_value()) {
            return std::nullopt;
        }
        std::optional<T2Pairing> result_r = validate_table_2_pairs(r_xs);
        if (!result_r.has_value()) {
            return std::nullopt;
        }
        // Validate table 3 pairing
        if (!proof_core_.validate_match_info_pairing(
            3, result_l->meta, result_l->match_info, result_r->match_info)) {
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

        const uint32_t* l_xs = x_values; 
        const uint32_t* r_xs = x_values + 8;

        // Validate each side as table 3
        std::optional<T3Pairing> result_l = validate_table_3_pairs(l_xs);
        if (!result_l.has_value()) {
            return t4_pairs;//std::nullopt;
        }
        std::optional<T3Pairing> result_r = validate_table_3_pairs(r_xs);
        if (!result_r.has_value()) {
            return t4_pairs;//std::nullopt;
        }

        // make sure encrypted xs are valid
        if (!proof_core_.xs_encryptor.validate_encrypted_xs(result_l->encrypted_xs, l_xs)) {
            std::cerr << "Validation failed for left encrypted_xs: ["
                      << result_l->encrypted_xs << "] vs ["
                      << show_xs(l_xs, 8) << "]\n";
            return t4_pairs;//std::nullopt;
        }

        if (!proof_core_.xs_encryptor.validate_encrypted_xs(result_r->encrypted_xs, r_xs)) {
            std::cerr << "Validation failed for right encrypted_xs: ["
                      << result_r->encrypted_xs << "] vs ["
                      << show_xs(r_xs, 8) << "]\n";
            return t4_pairs;//std::nullopt;
        }

        // at least one of the lower and upper partitions must be the same
        if (result_l->lower_partition != result_r->lower_partition &&
            result_l->upper_partition != result_r->upper_partition) {
            std::cerr << "Validation failed for partition mismatch: ["
                      << result_l->lower_partition << ", " << result_l->upper_partition << "] vs ["
                      << result_r->lower_partition << ", " << result_r->upper_partition << "]\n";
            return t4_pairs;//std::nullopt;
        }

        // get partitioned pairing vector and add it if it's match. could be a false positive so want to return 1 or 2 of these
        // note challenge might specify the partition to use, not sure if relevant here.
        if (result_l->lower_partition == result_r->lower_partition) {
            // Validate table 4 pairing
            if (sub_proof_core_.validate_match_info_pairing(
                4, result_l->meta, result_l->match_info_lower_partition, result_r->match_info_lower_partition)) {
                    std::optional<T4Pairing> result = sub_proof_core_.pairing_t4(result_l->meta, result_r->meta, result_l->order_bits, result_r->order_bits);
                    if (result.has_value()) {
                        t4_pairs.push_back(result.value());
                    }
            }
        }
        if (result_l->upper_partition == result_r->upper_partition) {
            // Validate table 4 pairing
            if (sub_proof_core_.validate_match_info_pairing(
                4, result_l->meta, result_l->match_info_upper_partition, result_r->match_info_upper_partition)) {
                    std::optional<T4Pairing> result = sub_proof_core_.pairing_t4(result_l->meta, result_r->meta, result_l->order_bits, result_r->order_bits);
                    if (result.has_value()) {
                        t4_pairs.push_back(result.value());
                    }
            }
        }

        //if (result_l->lower_partition == result_r->lower_partition &&
        //    result_l->upper_partition == result_r->upper_partition) {
        //        std::cout << "Validation had both partitions match" << std::endl;
        //    }

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
        if (!result_l.empty()) {
            return false;
        }
        auto result_r = validate_table_4_pairs(x_values + 16);
        if (!result_r.empty()) {
            return false;
        }

        if (result_l.size() > 1 || result_r.size() > 1) {
            std::cerr << "Validation has multiple valid pairs: ["
                      << result_l.size() << ", " << result_r.size() << "]\n";
            std::cerr << "NOT IMPLEMENTED YET" << std::endl;
            exit(23);
        }

        if (!proof_core_.validate_match_info_pairing(
            5, result_l[0].meta, result_l[0].match_info, result_r[0].match_info)) {
            return false;
        }

        return true;
    }


private:
    ProofCore proof_core_;
    ProofCore sub_proof_core_;

    // Utility function to print a list of xs in the style [x0, x1, x2, ...].
    static std::string show_xs(const uint32_t *v, int length)
    {
        std::ostringstream oss;
        oss << "[";
        for (int i = 0; i < length; i++) {
            if (i > 0) oss << ", ";
            oss << v[i];
        }
        oss << "]";
        return oss.str();
    }
};
