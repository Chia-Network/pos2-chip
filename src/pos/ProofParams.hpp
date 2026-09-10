#pragma once

#include "common/Utils.hpp"
#include "pos/ProofConstants.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <bit>

extern "C" {
    #include "sha/sha256.h"
}

struct PlotId {
    PlotId() : data_{}
    {}

    PlotId(std::string const& id)
    {
        *this = from_hex_str(id);
    }
    
    PlotId(std::array<uint8_t const, 32> const& id)
        : data_(copy(id))
    {}

    PlotId(std::span<uint8_t const, 32> const& id)
        : data_(copy(id))
    {}

    PlotId(std::array<uint8_t, 32> const& id)
        : data_(copy(id))
    {}

    PlotId(std::span<uint8_t, 32> const& id)
        : data_(copy(id))
    {}

    PlotId(uint8_t const* id)
        : data_(copy(id))
    {}

    static PlotId from_hex_str(std::string const& hex) {
        if(hex.size() != 64) {
            throw std::invalid_argument("PlotId hex string must of length 64");
        }

        return PlotId(Utils::hexToBytes(hex));
    }

    inline std::array<uint8_t, 32> const& data() const {
        return data_;
    }

    inline std::array<uint8_t const, 32> const& const_data() const {
        return *std::bit_cast<std::array<uint8_t const, 32>*>(&data_);
    }

    inline uint8_t const* bytes() const { return data_.data(); }

    inline std::span<uint8_t const, 32> span() const {
        return std::span<uint8_t const, 32>(&data_[0], 32);
    }

    inline operator std::span<uint8_t const, 32>() const {
        return span();
    }

    uint8_t operator[](size_t i) const noexcept {
        return data_[i];
    }

    std::string to_string() const {
        return Utils::bytesToHex(span());
    }

    bool operator==(PlotId const& other) const = default;

private:
    inline static std::array<uint8_t, 32> copy(std::span<uint8_t const, 32> id) {
        std::array<uint8_t, 32> result;
        std::memcpy(result.data(), id.data(), result.size());
        return result;
    }

    inline static std::array<uint8_t, 32> copy(uint8_t const* id) {
        std::array<uint8_t, 32> result;
        std::memcpy(result.data(), id, 32);
        return result;
    }

    std::array<uint8_t, 32> data_;
};

#pragma pack(push, 1)
struct PlotGroupId {

    PlotGroupId() : data_{}
    {}

    PlotGroupId(std::string const& id)
    {
        *this = from_hex_str(id);
    }

    PlotGroupId(std::array<uint8_t const, 32> const& id)
        : data_(copy(id))
    {}

    PlotGroupId(std::span<uint8_t const, 32> const& id)
        : data_(copy(id))
    {}

    PlotGroupId(std::array<uint8_t, 32> const& id)
        : data_(copy(id))
    {}

    PlotGroupId(std::span<uint8_t, 32> const& id)
        : data_(copy(id))
    {}

    PlotGroupId(uint8_t const* id)
        : data_(copy(id))
    {}

    static PlotGroupId from_hex_str(std::string const& hex) {
        if(hex.size() != 64) {
            throw std::invalid_argument("PlotGroupId hex string must of length 64");
        }

        return PlotGroupId(Utils::hexToBytes(hex));
    }

    inline std::array<uint8_t, 32> const& data() const {
        return data_;
    }

    inline std::array<uint8_t const, 32> const& const_data() const {
        return *std::bit_cast<std::array<uint8_t const, 32>*>(&data_);
    }

    inline uint8_t const* bytes() const { return data_.data(); }

    inline std::span<uint8_t const, 32> span() const {
        return std::span<uint8_t const, 32>(&data_[0], 32);
    }

    inline operator std::span<uint8_t const, 32>() const {
        return span();
    }

    uint8_t operator[](size_t i) const noexcept {
        return data_[i];
    }

    std::string to_string() const {
        return Utils::bytesToHex(span());
    }

    bool operator==(PlotGroupId const& other) const = default;

private:
    inline static std::array<uint8_t, 32> copy(std::span<uint8_t const, 32> id) {
        std::array<uint8_t, 32> result;
        std::memcpy(result.data(), id.data(), result.size());
        return result;
    }

    inline static std::array<uint8_t, 32> copy(uint8_t const* id) {
        std::array<uint8_t, 32> result;
        std::memcpy(result.data(), id, 32);
        return result;
    }

    std::array<uint8_t, 32> data_;
};
#pragma pack(pop)
static_assert(sizeof(PlotGroupId) == 32);
static_assert(std::is_standard_layout_v<PlotGroupId>);

struct Range {
    uint64_t start;
    uint64_t end;

    // ranges are INCLUSIVE
    bool isInRange(uint64_t value) const { return value >= start && value <= end; }

    bool operator==(Range const& other) const = default;
};

void posCalculatePlotIdForIndex(
    std::span<uint8_t const, 32> plot_group_id,
    std::span<uint8_t, 32> out_plot_id,
    uint16_t plot_index,
    uint8_t  meta_group);

/// For raw (ungrouped) plot files
class PlotProofParams {
    friend class PlotGroupParams;

    // This is declared private to force creation through PlotGroupParams.
    // However, it is exposed via static interface explicitly for usage in Solver,
    // which only requires the raw plot id.
    PlotProofParams(PlotId plot_id,
        uint8_t const k,
        uint8_t const strength,
        uint16_t const plot_index)  // TODO: Do we need to store this here??
    : plot_id_(plot_id)
    , plot_index_(plot_index)
    , k_(k)
    , strength_(strength)
    {
        // strength must be >= 2
        if (strength_ < 2) {
            throw std::invalid_argument("PlotProofParams: strength must be at least 2.");
        }
        if (strength_ > 63) {
            throw std::invalid_argument("PlotProofParams: strength must be less than 64.");
        }
        if (strength_ > k - get_num_section_bits() - 1) {
            throw std::invalid_argument(
                "PlotProofParams: strength must be less than k - section_bits - 1");
        }
    }

public:

    static PlotProofParams create_raw(
        PlotId plot_id,
        uint8_t const k,
        uint8_t const strength)
    {
        return PlotProofParams(plot_id, k, strength, 0);
    }

    int get_k() const { return numeric_cast<int>(k_); }

    inline uint8_t get_strength() const { return strength_; }

    uint16_t get_plot_index() const { return plot_index_; }

    inline PlotId const& get_plot_id() const { return plot_id_; }

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
        assert(table_id <= 3);
        if (table_id == 1) {
            return 2;
        }
        return strength_;
    }

    // Returns the number of section bits.
    // If k is less than 28, returns 2; otherwise returns (k - 26).
    inline uint32_t get_num_section_bits() const { return (k_ < 28 ? 2 : (k_ - 26)); }

    // Returns the number of match keys (2^(num_match_key_bits)).
    inline size_t get_num_match_keys(size_t table_id) const
    {
        return 1ULL << get_num_match_key_bits(table_id);
    }

    // Returns the number of match target bits.
    // (Double-check this calculation for T3+ and partition variants if necessary.)
    inline size_t get_num_match_target_bits(size_t const table_id) const
    {
        auto const match_bits = get_num_match_key_bits(table_id);
        auto const section_bits = get_num_section_bits();
        assert(section_bits + match_bits <= k_);
        return k_ - section_bits - match_bits;
    }

    // Returns the number of meta bits.
    // For table_id 1, returns k; otherwise returns 2*k.
    inline size_t get_num_meta_bits(size_t table_id) const { return (table_id == 1 ? k_ : k_ * 2); }

    // Extracts the section (msb) from match_info by shifting right by (k - num_section_bits).
    inline uint32_t extract_section_from_match_info(size_t /*table_id*/, uint32_t match_info) const
    {
        auto const section_bits = get_num_section_bits();
        assert(section_bits <= k_);
        return match_info >> (k_ - section_bits);
    }

    // Extracts the match key (middle bits) from match_info.
    // Shifts right by (k - num_section_bits - num_match_key_bits) and masks out the key bits.
    inline uint32_t extract_match_key_from_match_info(size_t table_id, uint32_t match_info) const
    {
        auto const match_bits = get_num_match_key_bits(table_id);
        auto const section_bits = get_num_section_bits();
        assert(section_bits + match_bits <= k_);
        return (match_info >> (k_ - section_bits - match_bits)) & ((1ULL << match_bits) - 1);
    }

    // Extracts the match target (lower bits) from match_info by masking the lower bits.
    inline uint32_t extract_match_target_from_match_info(size_t table_id, uint64_t match_info) const
    {
        auto const match_bits = get_num_match_target_bits(table_id);
        assert(match_bits <= 32);
        return numeric_cast<uint32_t>(match_info & ((1ULL << match_bits) - 1));
    }

    int get_num_pairing_meta_bits() const { return 2 * k_; }

    // Returns the number of match key bits for table 3
    uint8_t get_match_key_bits() const { return strength_; }

        int get_chaining_set_bits() const
    {
        // 9 bits (512) tuned as security/hdd usage sweet spot
        return CHAIN_SET_BITS;
    }

    uint32_t get_chaining_set_size() const { return 1 << get_chaining_set_bits(); }

    int get_num_chaining_sets_bits() const { return k_ - get_chaining_set_bits(); }

    uint32_t get_num_chaining_sets() const { return 1 << get_num_chaining_sets_bits(); }


    // Displays the plot parameters and a hexadecimal representation of the plot ID.
    void show() const
    {
        std::cout << "Plot parameters: k=" << k_;
        std::cout << " | Plot ID: ";
        for (int i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(plot_id_[i]);
        }
        std::cout << std::dec << std::endl;
    }

    void debugPrint() const
    {
        std::cout << "Plot ID: ";
        for (int i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(plot_id_[i]);
        }
        std::cout << std::dec << std::endl;

        std::cout << "k: " << (int)k_ << std::endl;
        std::cout << "num_pairing_meta_bits: " << get_num_pairing_meta_bits() << std::endl;
        std::cout << "num sections: " << get_num_sections() << std::endl;
        std::cout << "strength: " << (int)strength_ << std::endl;
    }

    bool operator==(PlotProofParams const& other) const = default;
    bool operator!=(PlotProofParams const& other) const = default;

private:
    // Fixed-size storage for the 32-byte plot ID. Used to generate plot data.
    // This is derived from the plot group id of the group this plot belongs to.
    PlotId   plot_id_;
    uint16_t plot_index_;   // Index of this plot in the group
    uint8_t  k_;            // Half of the block size (i.e., 2*k bits total).
    uint8_t  strength_;     // strength of the plot
};

/// For plot group files
/// These 2 serve 2 different semantic puroposes,
/// to avoid confusion as to where they are to be used,
/// they have been divided into their own ProofParams.
class PlotGroupParams {
public:
    PlotGroupParams(PlotGroupId plot_group_id,
        uint8_t const k,
        uint8_t const strength,
        uint8_t const meta_group)
    : plot_group_id_(plot_group_id)
    , k_(k)
    , strength_(strength)
    , meta_group_(meta_group)
    {
        // strength must be >= 2
        if (strength_ < 2) {
            throw std::invalid_argument("PlotGroupParams: strength must be at least 2.");
        }
        if (strength_ > 63) {
            throw std::invalid_argument("PlotGroupParams: strength must be less than 64.");
        }

        // TODO: validate this here?
        // if (strength_ > k - get_num_section_bits() - 1) {
        //     throw std::invalid_argument(
        //         "ProofParams: strength must be less than k - section_bits - 1");
        // }
    }

public:
    inline int get_k() const { return numeric_cast<int>(k_); }

    inline int get_meta_group() const { return numeric_cast<int>(meta_group_); }

    inline int get_strength() const { return numeric_cast<int>(strength_); }

    inline PlotGroupId const& get_plot_group_id() const { return plot_group_id_; }

    int get_chaining_set_bits() const
    {
        // 9 bits (512) tuned as security/hdd usage sweet spot
        return CHAIN_SET_BITS;
    }

    uint32_t get_chaining_set_size() const { return 1 << get_chaining_set_bits(); }

    int get_num_chaining_sets_bits() const { return k_ - get_chaining_set_bits(); }

    uint32_t get_num_chaining_sets() const { return 1 << get_num_chaining_sets_bits(); }

    Range get_chaining_set_range(size_t chaining_set_index) const
    {
        uint64_t range = (uint64_t)1 << (k_ + get_chaining_set_bits());
        uint64_t start = chaining_set_index * range;
        uint64_t end = start + range - 1;
        return Range { start, end };
    }

    // Derives a plot id from the plot group id and meta group,
    // and returns a instance of ProofParams given the plot index.
    PlotProofParams get_plot_params_for_index(uint16_t plot_index) const {

        std::array<uint8_t, 32> plot_id_bytes;
        posCalculatePlotIdForIndex(plot_group_id_.span(), plot_id_bytes, plot_index, meta_group_);

        return PlotProofParams(PlotId(plot_id_bytes), k_, strength_, plot_index);
    }


    // Displays the plot parameters and a hexadecimal representation of the plot ID.
    void show() const
    {
        std::cout << "Plot parameters: k=" << k_;
        std::cout << " | Plot Group ID: ";
        for (int i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(plot_group_id_[i]);
        }
        std::cout << std::dec << std::endl;
    }

    bool operator==(PlotGroupParams const& other) const = default;
    bool operator!=(PlotGroupParams const& other) const = default;

private:
    PlotGroupId plot_group_id_; // Fixed-size storage for the 32-byte plot group ID. Used to derive plot IDs.
    uint8_t k_;                 // Half of the block size (i.e., 2*k bits total).
    uint8_t strength_;          // Strength of the whole plot group
    uint8_t meta_group_;        // Metagroup for the whole plot group
};

class ProofParams {
public:
    // Constructor.
    //   plot_id_bytes: pointer to a 32-byte plot ID.
    //   k: number of bits per x, must be even
    //   match_key_bits: the number of match key bits for table 3
    ProofParams(uint8_t const* const plot_id_bytes,
        uint8_t const k,
        uint8_t const strength)
        : k_(k)
        , strength_(strength)
    {
        // strength must be >= 2
        if (strength_ < 2) {
            throw std::invalid_argument("ProofParams: strength must be at least 2.");
        }
        if (strength_ > 63) {
            throw std::invalid_argument("ProofParams: strength must be less than 64.");
        }
        if (strength_ > k - get_num_section_bits() - 1) {
            throw std::invalid_argument(
                "ProofParams: strength must be less than k - section_bits - 1");
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
        assert(table_id <= 3);
        if (table_id == 1) {
            return 2;
        }
        return strength_;
    }

    uint8_t get_strength() const { return strength_; }

    // Returns the number of section bits.
    // If k is less than 28, returns 2; otherwise returns (k - 26).
    inline uint32_t get_num_section_bits() const { return (k_ < 28 ? 2 : (k_ - 26)); }

    // Returns the number of match keys (2^(num_match_key_bits)).
    inline size_t get_num_match_keys(size_t table_id) const
    {
        return 1ULL << get_num_match_key_bits(table_id);
    }

    // Returns the number of match target bits.
    // (Double-check this calculation for T3+ and partition variants if necessary.)
    inline size_t get_num_match_target_bits(size_t const table_id) const
    {
        auto const match_bits = get_num_match_key_bits(table_id);
        auto const section_bits = get_num_section_bits();
        assert(section_bits + match_bits <= k_);
        return k_ - section_bits - match_bits;
    }

    // Returns the number of meta bits.
    // For table_id 1, returns k; otherwise returns 2*k.
    inline size_t get_num_meta_bits(size_t table_id) const { return (table_id == 1 ? k_ : k_ * 2); }

    // Extracts the section (msb) from match_info by shifting right by (k - num_section_bits).
    inline uint32_t extract_section_from_match_info(size_t /*table_id*/, uint32_t match_info) const
    {
        auto const section_bits = get_num_section_bits();
        assert(section_bits <= k_);
        return match_info >> (k_ - section_bits);
    }

    // Extracts the match key (middle bits) from match_info.
    // Shifts right by (k - num_section_bits - num_match_key_bits) and masks out the key bits.
    inline uint32_t extract_match_key_from_match_info(size_t table_id, uint32_t match_info) const
    {
        auto const match_bits = get_num_match_key_bits(table_id);
        auto const section_bits = get_num_section_bits();
        assert(section_bits + match_bits <= k_);
        return (match_info >> (k_ - section_bits - match_bits)) & ((1ULL << match_bits) - 1);
    }

    // Extracts the match target (lower bits) from match_info by masking the lower bits.
    inline uint32_t extract_match_target_from_match_info(size_t table_id, uint64_t match_info) const
    {
        auto const match_bits = get_num_match_target_bits(table_id);
        assert(match_bits <= 32);
        return numeric_cast<uint32_t>(match_info & ((1ULL << match_bits) - 1));
    }

    // Displays the plot parameters and a hexadecimal representation of the plot ID.
    void show() const
    {
        std::cout << "Plot parameters: k=" << k_;
        std::cout << " | Plot ID: ";
        for (int i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(plot_id_bytes_[i]);
        }
        std::cout << std::dec << std::endl;
    }

    // Returns the plot ID as a byte array.
    //__host__ __device__
    uint8_t const* get_plot_id_bytes() const { return plot_id_bytes_; }

    std::array<uint8_t, 32> get_plot_id() const
    {
        // plot id is the unique identifier for a plot
        // generated from a hash of the group plot id, plot index, and meta group
        // The caller is responsible for generating the plot id from the group plot id, plot index,
        // and meta group
        std::array<uint8_t, 32> plot_id_array;
        std::memcpy(plot_id_array.data(), plot_id_bytes_, 32);
        return plot_id_array;
    }

    int get_k() const { return numeric_cast<int>(k_); }

    int get_chaining_set_bits() const
    {
        // 9 bits (512) tuned as security/hdd usage sweet spot
        return CHAIN_SET_BITS;
    }

    uint32_t get_chaining_set_size() const { return 1 << get_chaining_set_bits(); }

    int get_num_chaining_sets_bits() const { return k_ - get_chaining_set_bits(); }

    uint32_t get_num_chaining_sets() const { return 1 << get_num_chaining_sets_bits(); }

    Range get_chaining_set_range(size_t chaining_set_index) const
    {
        uint64_t range = (uint64_t)1 << (k_ + get_chaining_set_bits());
        uint64_t start = chaining_set_index * range;
        uint64_t end = start + range - 1;
        return Range { start, end };
    }

    int get_num_pairing_meta_bits() const { return 2 * k_; }

    // Returns the number of match key bits for table 3
    uint8_t get_match_key_bits() const { return strength_; }

    // Derives a plot id from the plot group id
    // and returns a instance of ProofParams given
    // the plot index and meta group.
    // NOTE: This expects the current ProofParams to
    //       be using a plot group id.
    ProofParams derive_params_for_plot_index(uint16_t plot_index, uint8_t meta_group) const {
        ProofParams params = *this;
        std::span<uint8_t const, 32> plot_group_id(&plot_id_bytes_[0], 32);
        std::span<uint8_t, 32> plot_id(&params.plot_id_bytes_[0], 32);

        posCalculatePlotIdForIndex(plot_group_id, plot_id, plot_index, meta_group);

        return params;
    }

    void debugPrint() const
    {
        std::cout << "Plot ID: ";
        for (int i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(plot_id_bytes_[i]);
        }
        std::cout << std::dec << std::endl;

        std::cout << "k: " << (int)k_ << std::endl;
        std::cout << "num_pairing_meta_bits: " << get_num_pairing_meta_bits() << std::endl;
        std::cout << "num sections: " << get_num_sections() << std::endl;
        std::cout << "strength: " << (int)strength_ << std::endl;
    }

    bool operator==(ProofParams const& other) const = default;
    bool operator!=(ProofParams const& other) const = default;

private:
    uint8_t plot_id_bytes_[32]; // Fixed-size storage for the 32-byte plot ID.
    uint8_t k_; // Half of the block size (i.e., 2*k bits total).
    uint8_t strength_; // strength of the plot
};

void posCalculatePlotIdForIndex(
    std::span<uint8_t const, 32> plot_group_id,
    std::span<uint8_t, 32> out_plot_id,
    uint16_t plot_index,
    uint8_t  meta_group)
{
    #pragma pack(push, 1)
    struct Plot_Id_Hash_Input {
        std::array<uint8_t, 32> plot_group_id;
        uint16_t                plot_index_in_group;
        uint8_t                 meta_group;
    };
    #pragma pack(pop)
    static_assert(sizeof(Plot_Id_Hash_Input) == 32 + 2 + 1);

    #define bswap16(x) uint16_t((x >> 8) | (x << 8))

    Plot_Id_Hash_Input hash_input;
    memcpy(&hash_input.plot_group_id[0], &plot_group_id[0], 32);
    hash_input.plot_index_in_group = bswap16(plot_index);
    hash_input.meta_group          = meta_group;

    // Revert byteswap on big endian platforms (honestly, should never happen...)
    if constexpr (std::endian::native != std::endian::little) {
        hash_input.plot_index_in_group = bswap16(hash_input.plot_index_in_group);
    }

    sha256 sha_ctx = {};
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, &hash_input, sizeof(hash_input));
    sha256_sum(&sha_ctx, out_plot_id.data());

    #undef bswap16
}
