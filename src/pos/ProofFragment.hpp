#pragma once

#include <cstdint>
#include <cstddef>

#include "ProofParams.hpp"
#include "FeistelCipher.hpp"



// A “proof fragment” is 2k bits of the chiphertext
using ProofFragment = uint64_t;

// ProofFragment provides methods for encrypting/decrypting an x-value block and 
// extracting partition bits from the resulting encrypted value.
class ProofFragmentCodec {
public:
    // Constructor: uses the provided ProofParams.
    ProofFragmentCodec(const ProofParams& proof_params)
        : params_(proof_params),
          cipher_(proof_params.get_plot_id_bytes(), proof_params.get_k())
    {
    }

    // Encrypt: Input is a 2*k‑bit integer containing bit-dropped x1/3/5/7 
    // values (in the format [x1 (k/2 bits)][x3 (k/2 bits)][x5 (k/2 bits)][x7 (k/2 bits)]).
    // Returns the encryption result as a uint64_t.
    uint64_t encode(uint64_t all_x_bits) {
        return cipher_.encrypt(all_x_bits);
    }

    ProofFragment encode(const uint32_t x_values[8]) {
        // Combine the upper halves of x1, x3, x5, and x7 into a single 2*k bit value.
        uint32_t x1 = x_values[0] >> (params_.get_k() / 2);
        uint32_t x3 = x_values[2] >> (params_.get_k() / 2);
        uint32_t x5 = x_values[4] >> (params_.get_k() / 2);
        uint32_t x7 = x_values[6] >> (params_.get_k() / 2);
        uint64_t all_x_bits = 0;
        all_x_bits |= (static_cast<uint64_t>(x1) << (params_.get_k() * 3 / 2));
        all_x_bits |= (static_cast<uint64_t>(x3) << (params_.get_k() * 2 / 2));
        all_x_bits |= (static_cast<uint64_t>(x5) << (params_.get_k() * 1 / 2));
        all_x_bits |= (static_cast<uint64_t>(x7) << (params_.get_k() * 0 / 2));
        return cipher_.encrypt(all_x_bits);
    }

    // Decrypt: Given a ciphertext (2*k bits) returns the decrypted value as a uint64_t.
    uint64_t decode(uint64_t ciphertext) {
        return cipher_.decrypt(ciphertext);
    }

    // Returns the specified number of bits extracted from proof fragment
    // The extraction treats the MSB as bit 0.
    uint64_t get_proof_fragment_bits_with_msb_as_zero(ProofFragment proof_fragment, size_t start_bits_incl, size_t len) const {
        size_t total_bits = params_.get_k() * 2;
        return (proof_fragment >> (total_bits - start_bits_incl - len)) & ((uint64_t(1) << len) - 1);
    }

    // Extracts 2 order bits following the partition as a uint32_t.
    uint32_t extract_t3_order_bits(ProofFragment proof_fragment) const {
        return static_cast<uint32_t>(
            get_proof_fragment_bits_with_msb_as_zero(proof_fragment, params_.get_num_partition_bits(), 2)
        );
    }

    // Extracts the T3 right partition bits (the LSB partition) as a uint32_t.
    uint32_t extract_t3_r_partition_bits(ProofFragment proof_fragment) const {
        return static_cast<uint32_t>(
            proof_fragment & ((uint64_t(1) << params_.get_num_partition_bits()) - 1)
        );
    }

    // Extracts the T3 left partition bits (from the MSB side) as a uint32_t.
    uint32_t extract_t3_l_partition_bits(ProofFragment proof_fragment) const {
        return static_cast<uint32_t>(
            get_proof_fragment_bits_with_msb_as_zero(proof_fragment, 0, params_.get_num_partition_bits())
        );
    }

    uint32_t get_lateral_to_t4_partition(ProofFragment proof_fragment) const {
        uint32_t top_order_bit = extract_t3_order_bits(proof_fragment) >> 1;
        if (top_order_bit == 0)
        {
            return extract_t3_l_partition_bits(proof_fragment);
        }
        else
        {
            return extract_t3_l_partition_bits(proof_fragment) + params_.get_num_partitions();
        }
    }

    uint32_t get_r_t4_partition(ProofFragment proof_fragment) const {
        uint32_t top_order_bit = extract_t3_order_bits(proof_fragment) >> 1;
        if (top_order_bit == 0)
        {
            return extract_t3_r_partition_bits(proof_fragment) + params_.get_num_partitions();
        }
        else
        {
            return extract_t3_r_partition_bits(proof_fragment);
        }
    }

    // checks that the decoded x-values match the provided x_values.
    // x_values is an array of 8 uint32_t values (each representing a k-bit number).
    // It compares the upper halves (k/2 bits) of x_values[0], [2], [4], and [6] with those
    // recovered from the decrypted ciphertext.
    bool validate_proof_fragment(ProofFragment proof_fragment, const uint32_t x_values[8]) const {
        size_t half_k = params_.get_k() / 2;  // Each x-value is k bits, so its high half is k/2 bits.
        uint32_t x1 = x_values[0] >> half_k;
        uint32_t x3 = x_values[2] >> half_k;
        uint32_t x5 = x_values[4] >> half_k;
        uint32_t x7 = x_values[6] >> half_k;
        
        uint64_t decrypted_xs = cipher_.decrypt(proof_fragment);
        uint32_t decrypted_x1 = static_cast<uint32_t>((decrypted_xs >> (half_k * 3)) & ((uint64_t(1) << half_k) - 1));
        uint32_t decrypted_x3 = static_cast<uint32_t>((decrypted_xs >> (half_k * 2)) & ((uint64_t(1) << half_k) - 1));
        uint32_t decrypted_x5 = static_cast<uint32_t>((decrypted_xs >> (half_k * 1)) & ((uint64_t(1) << half_k) - 1));
        uint32_t decrypted_x7 = static_cast<uint32_t>(decrypted_xs & ((uint64_t(1) << half_k) - 1));
        
        if (x1 != decrypted_x1 || x3 != decrypted_x3 || x5 != decrypted_x5 || x7 != decrypted_x7) {
            // If desired, one can add logging here.
            return false;
        }
        return true;
    }

    std::array<uint32_t, 4> get_x_bits_from_proof_fragment(ProofFragment proof_fragment) const {
        uint64_t decrypted_xs = cipher_.decrypt(proof_fragment);
        size_t half_k = params_.get_k() / 2;
        uint32_t x1 = static_cast<uint32_t>((decrypted_xs >> (half_k * 3)) & ((uint64_t(1) << half_k) - 1));
        uint32_t x3 = static_cast<uint32_t>((decrypted_xs >> (half_k * 2)) & ((uint64_t(1) << half_k) - 1));
        uint32_t x5 = static_cast<uint32_t>((decrypted_xs >> (half_k * 1)) & ((uint64_t(1) << half_k) - 1));
        uint32_t x7 = static_cast<uint32_t>(decrypted_xs & ((uint64_t(1) << half_k) - 1));
        return {x1, x3, x5, x7};
    }

private:
    ProofParams params_;
    FeistelCipher cipher_;
};

