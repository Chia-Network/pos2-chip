#pragma once

#include "common/Utils.hpp"
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <array>
#include <cassert>

class ProofParams
{
public:
    // Constructor.
    //   plot_id_bytes: pointer to a 32-byte plot ID.
    //   k: number of bits per x, must be even
    //   match_key_bits: the number of match key bits for table 3
    ProofParams(const uint8_t * const plot_id_bytes,
                const uint8_t k,
                const uint8_t strength)
        : k_(k), strength_(strength)
    {
        // strength must be >= 2
        if (strength_ < 2) {
            throw std::invalid_argument("ProofParams: strength must be at least 2.");
        }
        if (get_sub_k() > k) {
            throw std::invalid_argument("ProofParams: k must be at least 12");
        }
        // Copy the 32-byte plot ID.
        for (int i = 0; i < 32; ++i)
            plot_id_bytes_[i] = plot_id_bytes[i];
    }

    // Destructor – nothing to free since we use a fixed-size array.
    //__host__ __device__
    ~ProofParams() {}

    // Returns the number of sections, calculated as 2^(num_section_bits).
    inline uint32_t get_num_sections() const
    {
        assert(get_num_section_bits() < 32);
        return uint32_t(1) << get_num_section_bits();
    }

    // Number of match key bits based on table_id (1-5).
    inline int get_num_match_key_bits(size_t table_id) const
    {
        assert(table_id >= 1);
        assert(table_id <= 5);
        if (table_id == 3) {
            return strength_;
        }
        else {
            return 2;
        }
    }

    uint8_t get_strength() const {
        return strength_;
    }

    // Returns the number of section bits.
    // If k is less than 28, returns 2; otherwise returns (k - 26).
    inline uint32_t get_num_section_bits() const
    {
        return (k_ < 28 ? 2 : (k_ - 26));
    }

    // Returns the number of match keys (2^(num_match_key_bits)).
    inline size_t get_num_match_keys(size_t table_id) const
    {
        return 1ULL << get_num_match_key_bits(table_id);
    }

    // Returns the number of match target bits.
    // (Double-check this calculation for T3+ and partition variants if necessary.)
    inline size_t get_num_match_target_bits(size_t table_id) const
    {
        return k_ - get_num_section_bits() - get_num_match_key_bits(table_id);
    }

    // Returns the number of meta bits.
    // For table_id 1, returns k; otherwise returns 2*k.
    inline size_t get_num_meta_bits(size_t table_id) const
    {
        return (table_id == 1 ? k_ : k_ * 2);
    }

    // Extracts the section (msb) from match_info by shifting right by (k - num_section_bits).
    inline uint32_t extract_section_from_match_info(size_t /*table_id*/, uint32_t match_info) const
    {
        const auto section_bits = get_num_section_bits();
        assert(section_bits <= k_);
        return match_info >> (k_ - section_bits);
    }

    // Extracts the match key (middle bits) from match_info.
    // Shifts right by (k - num_section_bits - num_match_key_bits) and masks out the key bits.
    inline uint32_t extract_match_key_from_match_info(size_t table_id, uint32_t match_info) const
    {
        const auto match_bits = get_num_match_key_bits(table_id);
        const auto section_bits = get_num_section_bits();
        assert(section_bits + match_bits <= k_);
        return (match_info >> (k_ - section_bits - match_bits)) & ((1ULL << match_bits) - 1);
    }

    // Extracts the match target (lower bits) from match_info by masking the lower bits.
    inline uint32_t extract_match_target_from_match_info(size_t table_id, uint64_t match_info) const
    {
        const auto match_bits = get_num_match_target_bits(table_id);
        assert(match_bits <= 32);
        return numeric_cast<uint32_t>(match_info & ((1ULL << match_bits) - 1));
    }

    // Displays the plot parameters and a hexadecimal representation of the plot ID.
    void show() const
    {
        std::cout << "Plot parameters: k=" << k_
                  << ", sub_k=" << get_sub_k();
        std::cout << " | Plot ID: ";
        for (int i = 0; i < 32; ++i)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(plot_id_bytes_[i]);
        }
        std::cout << std::dec << std::endl;
    }

    // Returns the plot ID as a byte array.
    //__host__ __device__
    const uint8_t *get_plot_id_bytes() const
    {
        return plot_id_bytes_;
    }

    int get_k() const
    {
        return numeric_cast<int>(k_);
    }

    int get_num_partition_bits() const
    {
        return numeric_cast<int>(k_ - get_sub_k());
    }

    int get_num_pairing_meta_bits() const
    {
        return 2 * k_;
    }

    int get_num_partitions() const
    {
        return 1ULL << get_num_partition_bits();
    }

    int get_sub_k() const
    {
        // k32/k30/k28/26...18 use sub_k of 23/22/20/19...15
        if (k_ == 30) return 22;
        if (k_ == 32) return 23;
        return numeric_cast<int>(k_ / 2 + 6);
    }

    // Returns the number of match key bits for table 3
    uint8_t get_match_key_bits() const
    {
        return strength_;
    }

    void debugPrint() const
    {
        std::cout << "Plot ID: ";
        for (int i = 0; i < 32; ++i)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(plot_id_bytes_[i]);
        }
        std::cout << std::dec << std::endl;

        std::cout << "k: " << (int) k_ << std::endl;
        std::cout << "num_pairing_meta_bits: " << get_num_pairing_meta_bits() << std::endl;
        std::cout << "num_partition_bits: " << get_num_partition_bits() << std::endl;
        std::cout << "num_partitions: " << get_num_partitions() << std::endl;
        std::cout << "sub_k: " << get_sub_k() << std::endl;
        std::cout << "num sections: " << get_num_sections() << std::endl;
        std::cout << "strength: " << (int) strength_ << std::endl;
    }

    bool operator==(ProofParams const &other) const = default;
    bool operator!=(ProofParams const &other) const = default;

private:
    uint8_t plot_id_bytes_[32];    // Fixed-size storage for the 32-byte plot ID.
    uint8_t k_;                     // Half of the block size (i.e., 2*k bits total).
    uint8_t strength_;             // strength of the plot
};
