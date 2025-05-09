#pragma once

#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <array>

class ProofParams
{
public:
    // Constructor.
    //   plot_id_bytes: pointer to a 32-byte plot ID.
    //   k: number of bits per x, must be even
    //   sub_k_val: optional sub_k parameter; if sub_k_val is 0, sub_k is not used.
    //   match_key_bits: array of 5 values specifying the number of match key bits for tables 1..5.
    //                   Default is {2,2,2,2,2}.
    ProofParams(const uint8_t *plot_id_bytes,
                size_t k,
                size_t sub_k_val = 0,
                const std::array<uint8_t, 5> &match_key_bits = {2, 2, 2, 2, 2})
        : k_(k), num_pairing_meta_bits_(2 * k), sub_k_(sub_k_val), match_key_bits_(match_key_bits)
    {
        // Copy the 32-byte plot ID.
        for (int i = 0; i < 32; ++i)
            plot_id_bytes_[i] = plot_id_bytes[i];

        // Partitioning setup if sub_k is used.
        if (sub_k_ != 0)
        {
            num_partition_bits_ = k_ - sub_k_;
            num_partitions_ = 1ULL << num_partition_bits_;
        }
        else
        {
            num_partition_bits_ = 0;
            num_partitions_ = 0;
        }
    }

    // Destructor – nothing to free since we use a fixed-size array.
    //__host__ __device__
    ~ProofParams() {}

    // Returns the number of sections, calculated as 2^(num_section_bits).
    inline size_t get_num_sections() const
    {
        return 1ULL << get_num_section_bits();
    }

    // Number of match key bits based on table_id (1-5).
    inline size_t get_num_match_key_bits(size_t table_id) const
    {
        return match_key_bits_[table_id - 1];
    }

    // Returns the number of section bits.
    // If k is less than 28, returns 2; otherwise returns (k - 26).
    inline size_t get_num_section_bits() const
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
    inline uint64_t extract_section_from_match_info(size_t table_id, uint64_t match_info) const
    {
        return match_info >> (k_ - get_num_section_bits());
    }

    // Extracts the match key (middle bits) from match_info.
    // Shifts right by (k - num_section_bits - num_match_key_bits) and masks out the key bits.
    inline uint64_t extract_match_key_from_match_info(size_t table_id, uint64_t match_info) const
    {
        return (match_info >> (k_ - get_num_section_bits() - get_num_match_key_bits(table_id))) & ((1ULL << get_num_match_key_bits(table_id)) - 1);
    }

    // Extracts the match target (lower bits) from match_info by masking the lower bits.
    inline uint64_t extract_match_target_from_match_info(size_t table_id, uint64_t match_info) const
    {
        return match_info & ((1ULL << get_num_match_target_bits(table_id)) - 1);
    }

    // Displays the plot parameters and a hexadecimal representation of the plot ID.
    void show() const
    {
        std::cout << "Plot parameters: k=" << k_;
        if (sub_k_ != 0)
            std::cout << ", sub_k=" << sub_k_;
        else
            std::cout << ", sub_k=n/a";
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
        return k_;
    }

    int get_num_partition_bits() const
    {
        return num_partition_bits_;
    }

    int get_num_pairing_meta_bits() const
    {
        return num_pairing_meta_bits_;
    }

    int get_num_partitions() const
    {
        return num_partitions_;
    }

    int get_sub_k() const
    {
        return sub_k_;
    }

    // Returns the number of match key bits for tables 1..5.
    const std::array<uint8_t, 5> &get_match_key_bits() const
    {
        return match_key_bits_;
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

        std::cout << "k: " << k_ << std::endl;
        std::cout << "num_pairing_meta_bits: " << num_pairing_meta_bits_ << std::endl;
        std::cout << "num_partition_bits: " << num_partition_bits_ << std::endl;
        std::cout << "num_partitions: " << num_partitions_ << std::endl;
        std::cout << "sub_k: " << sub_k_ << std::endl;
        std::cout << "match_key_bits: [";
        for (size_t i = 0; i < match_key_bits_.size(); ++i)
        {
            std::cout << (int)match_key_bits_[i];
            if (i + 1 < match_key_bits_.size())
                std::cout << ", ";
        }
        std::cout << "]" << std::endl;
    }

    bool operator==(ProofParams const &other) const
    {
        return k_ == other.k_ && sub_k_ == other.sub_k_ && match_key_bits_ == other.match_key_bits_ && std::memcmp(plot_id_bytes_, other.plot_id_bytes_, sizeof(plot_id_bytes_)) == 0;
    }

    bool operator!=(ProofParams const &other) const
    {
        return !(*this == other);
    }

private:
    uint8_t plot_id_bytes_[32];    // Fixed-size storage for the 32-byte plot ID.
    size_t k_;                     // Half of the block size (i.e., 2*k bits total).
    size_t num_pairing_meta_bits_; // Equals 2*k.

    // Optional sub_k parameters. If sub_k_ is 0, then it is not used.
    size_t sub_k_;
    size_t num_partition_bits_;
    size_t num_partitions_;
    std::array<uint8_t, 5> match_key_bits_; // match key bits for tables 1..5
};
