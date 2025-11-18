#pragma once

#include <string>
#include <fstream>
#include <stdexcept>
#include <type_traits>
#include "PlotData.hpp"
#include "pos/ProofParams.hpp"
#include "pos/ProofCore.hpp"

//#define DEBUG_PLOT_FILE true
#ifdef DEBUG_PLOT_FILE
#include <iostream>
#include <filesystem>
#endif

class PlotFormat
{
public:
    // Current on-disk format version, update this when the format changes.
    #ifdef RETAIN_X_VALUES_TO_T3
    static constexpr uint8_t FORMAT_VERSION = 3;
    #else
    static constexpr uint8_t FORMAT_VERSION = 1;
    #endif

    // num_partitions is the partition bits
    static size_t map_t4_to_t3_lateral_partition(size_t t4_partition, size_t num_partitions) {
        return (t4_partition < num_partitions) ? (t4_partition * 2) : ((t4_partition - num_partitions) * 2 + 1);
    }

    static size_t map_t3_lateral_partition_to_t4(size_t t3_lateral_partition, size_t num_partitions) {
        return (t3_lateral_partition % 2 == 0) ? (t3_lateral_partition / 2) : (num_partitions + (t3_lateral_partition - 1) / 2);
    }

    struct PlotFormatContents {
        PartitionedPlotData data;
        ProofParams params;
        // Offsets to each partition's data on disk; each partition contains
        // t3 proof fragments, t4_to_t3 back pointers followed immediately by t5_to_t4 back pointers.
        std::vector<uint64_t> partition_offsets;

        // Provide a default ctor so PlotFormatContents can be default-constructed.
        // Construct params with an all-zero plot-id to satisfy ProofParams' ctor.
        static inline constexpr std::array<uint8_t, 32> ZERO_PLOT_ID{}; 
        PlotFormatContents()
            : data()
            , params(ZERO_PLOT_ID.data(), 28, 2)
            , partition_offsets()
        {}
    };

    // New: stateful constructors, inputs params, memo, and plot data
    PlotFormat(const ProofParams& params, std::span<uint8_t const, 32 + 48 + 32> const memo, const PartitionedPlotData& data)
    {
        contents_.params = params;
        contents_.data = data;
        // copy memo data
        std::memcpy(memo_.data(), memo.data(), memo.size());
    }

    PlotFormat(const std::string &filename)
    {
        std::cout << "Plot format init: " << filename << std::endl;
        std::array<uint8_t, 32> ZERO_PLOT_ID{}; // all-zero plot ID
        contents_.params = ProofParams(ZERO_PLOT_ID.data(), 28, 2); // dummy init
        memo_.fill(0); // initialize memo to zeros
        readHeadersFromFile(filename);
    }

    void readHeadersFromFile(const std::string &filename)
    {
        std::cout << "PlotFormat:: readHeadersFromFile " << filename << std::endl;
        std::ifstream in(filename, std::ios::binary);
        readHeadersFromFile(in);

        if (!in)
            throw std::runtime_error("Failed to read plot file headers from " + filename);
    }

    static PartitionedPlotData convertFromPlotData(PlotData &plot_data, const ProofParams &params) {
    
        PartitionedPlotData partitioned_data;
        partitioned_data.t3_proof_fragments.resize(params.get_num_partitions() * 2);
        partitioned_data.t4_to_t3_back_pointers.resize(params.get_num_partitions() * 2);
        partitioned_data.t5_to_t4_back_pointers.resize(params.get_num_partitions() * 2);

        // first distribute t3 proof fragments into partitions
        for (size_t t4_partition_id = 0; t4_partition_id < params.get_num_partitions() * 2; ++t4_partition_id)
        {
            Range const &range = plot_data.t4_to_t3_lateral_ranges[t4_partition_id];
            for (uint32_t t3_index = range.start; t3_index <= range.end; ++t3_index)
            {
                partitioned_data.t3_proof_fragments[t4_partition_id].push_back(plot_data.t3_proof_fragments[t3_index]);
            }
        }

        // then process t4 to t3 back pointers into partitioned format
        for (size_t partition_id = 0; partition_id < params.get_num_partitions() * 2; ++partition_id)
        {
            size_t expected_t3_l_partition = PlotFormat::map_t4_to_t3_lateral_partition(partition_id, params.get_num_partitions());
            std::cout << "T4 partition " << partition_id << " expected T3 partition " << expected_t3_l_partition << std::endl;
        
            // check that all t4tot3 back pointers are in the t3 partition range
            Range t3_partition_range = plot_data.t4_to_t3_lateral_ranges[partition_id];
            std::cout << "T4 to T3 lateral range: " << t3_partition_range.start << " - " << t3_partition_range.end << std::endl;

            uint64_t t3_range_per_partition = (static_cast<uint64_t>(1) << (2 * params.get_k())) / (2 * params.get_num_partitions());
            uint64_t t3_partition_start_value = t3_range_per_partition * (static_cast<uint64_t>(expected_t3_l_partition));
            uint64_t t3_partition_end_value = t3_partition_start_value + t3_range_per_partition - 1;
            std::cout << "T3 partition " << expected_t3_l_partition << " value range: "
                  << t3_partition_start_value << " - " << t3_partition_end_value << std::endl;

            size_t count = 0;
            uint32_t max_l_index = 0;
            uint32_t max_r_index = 0;
            for (const auto &t4_entry : plot_data.t4_to_t3_back_pointers[partition_id])
            {
                ProofFragment t3_l = plot_data.t3_proof_fragments[t4_entry.l];
                ProofFragment t3_r = plot_data.t3_proof_fragments[t4_entry.r];
            
                if ((count < 5) || (count > plot_data.t4_to_t3_back_pointers[partition_id].size() - 5))
                {
                    std::cout << "  T4 entry l: " << t4_entry.l << " r: " << t4_entry.r << std::endl;
                    std::cout << "    T3 proof fragment at l: " << t3_l << std::endl;
                    std::cout << "    T3 proof fragment at r: " << t3_r << std::endl;
                }
            

                // find t3_r partition by scanning ranges
                uint32_t t3_r_partition = 0;
                uint32_t t3_r_partition_start_value = 0;

                size_t mapped_r_partition = 0;

                for (size_t range_index = 0; range_index < plot_data.t4_to_t3_lateral_ranges.size(); ++range_index)
                {
                    const auto &range = plot_data.t4_to_t3_lateral_ranges[range_index];
                    if (range.isInRange(t4_entry.r))
                    {
                        //t3_r_partition = (range_index < read_plot.data.t4_to_t3_back_pointers.size() / 2) ? (range_index * 2) : ((range_index - read_plot.data.t4_to_t3_back_pointers.size() / 2) * 2 + 1);
                        t3_r_partition = PlotFormat::map_t4_to_t3_lateral_partition(range_index, params.get_num_partitions());
                        mapped_r_partition = range_index;
                        t3_r_partition_start_value = range.start;
                        break;
                    }
                }

                PartitionedBackPointer partitioned_back_pointer;
                PartitionedBackPointer::Input input;
                input.l_absolute_t3_index = t4_entry.l;
                input.r_absolute_t3_index = t4_entry.r;
                input.t3_l_partition_range_start = t3_partition_range.start;
                input.t3_r_partition = mapped_r_partition;//t3_r_partition;
                input.t3_r_partition_range_start = t3_r_partition_start_value;
                input.num_partition_bits = params.get_num_partition_bits();
                partitioned_back_pointer.setPointer(input);

                // now add to partitioned data set
                partitioned_data.t4_to_t3_back_pointers[partition_id].push_back(partitioned_back_pointer);

            }
        }

        // t5 partitions stay the same
        partitioned_data.t5_to_t4_back_pointers = plot_data.t5_to_t4_back_pointers;

        return partitioned_data;
    }

    /// Read PlotData from a binary file. The v2 plot header format is as
    // follows:
    // 4 bytes:  "pos2"
    // 1 byte:   version. 0=invalid, 1=fat plots, 2=benesh plots (compressed)
    // 32 bytes: plot ID
    // 1 byte:   k-size
    // 1 byte:   strength, defaults to 16
    // 32 bytes: puzzle hash
    // 48 bytes: farmer public key
    // 32 bytes: local secret key
    // Write PartitionedPlotData to a binary file.
    static void writeData(const std::string &filename, PartitionedPlotData const &data, ProofParams const &params, std::span<uint8_t const, 32 + 48 + 32> const memo)
    {
        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        out.write("pos2", 4);
        out.write(reinterpret_cast<const char*>(&FORMAT_VERSION), 1);

        // Write plot ID
        out.write(reinterpret_cast<const char*>(params.get_plot_id_bytes()), 32);

        // Write k and strength
        const uint8_t k = numeric_cast<uint8_t>(params.get_k());
        const uint8_t match_key_bits = numeric_cast<uint8_t>(params.get_match_key_bits());
        out.write(reinterpret_cast<const char*>(&k), 1);
        out.write(reinterpret_cast<const char*>(&match_key_bits), 1);

        // Write memo
        out.write(reinterpret_cast<char const*>(memo.data()), memo.size());

        // Use a single outer count for partition pairs (t4,t5) and placeholders
        // for their offsets. Each partition region will hold t4 vector then t5 vector.
        uint64_t outer = data.t4_to_t3_back_pointers.size();
        if (data.t5_to_t4_back_pointers.size() != outer)
            throw std::runtime_error("Mismatched partition outer sizes for t4/t5");

        #ifdef DEBUG_PLOT_FILE
        std::cout << "Writing partitions (outer): " << outer << std::endl;
        #endif

        out.write(reinterpret_cast<char const*>(&outer), sizeof(outer));
        uint64_t zero = 0;
        std::streampos offsets_pos = out.tellp();
        for (uint64_t i = 0; i < outer; ++i)
            out.write(reinterpret_cast<char const*>(&zero), sizeof(zero));

        // Write plot data (non-partitioned)
        //writeVector(out, data.t3_proof_fragments);
        //writeRanges(out, data.t4_to_t3_lateral_ranges);

        // Now write each partition's t4 then t5 vectors and remember file offsets
        std::vector<uint64_t> offsets;
        offsets.reserve(outer);
        for (uint64_t i = 0; i < outer; ++i)
        {
            uint64_t offset = static_cast<uint64_t>(out.tellp());
            offsets.push_back(offset);
            //size_t mapped_t3_partition = map_t4_to_t3_lateral_partition(i, params.get_num_partitions());
            writeVector(out, data.t3_proof_fragments[i]);
            writeVector(out, data.t4_to_t3_back_pointers[i]);
            writeVector(out, data.t5_to_t4_back_pointers[i]);
        }

        #ifdef RETAIN_X_VALUES_TO_T3
        // throw not supported
        throw std::runtime_error("RETAIN_X_VALUES_TO_T3 is not supported");
        // writeVector(out, data.xs_correlating_to_proof_fragments);
        #endif

        // Backfill offsets
        if (outer)
        {
            out.seekp(offsets_pos);
            for (auto off : offsets)
                out.write(reinterpret_cast<char const*>(&off), sizeof(off));
        }

        // Seek to end for finalization
        out.seekp(0, std::ios::end);

        if (!out)
            throw std::runtime_error("Failed to write " + filename);
    }

void readHeadersFromFile(std::ifstream &in)
    {
        if (!in)
            throw std::runtime_error("Failed to open plot file");

        char magic[4] = {};
        in.read(magic, sizeof(magic));
        if (memcmp(magic, "pos2", 4) != 0)
            throw std::runtime_error("Plot file invalid magic bytes, not a plot file");

        uint8_t version;
        in.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (version != FORMAT_VERSION) {
            throw std::runtime_error("Plot file format version " + std::to_string(version) + " is not supported.");
        }

        uint8_t plot_id_bytes[32];
        in.read(reinterpret_cast<char*>(plot_id_bytes), 32);

        uint8_t k;
        in.read(reinterpret_cast<char*>(&k), sizeof(k));

        uint8_t strength;
        in.read(reinterpret_cast<char*>(&strength), sizeof(strength));
        std::cout << "READ STRENGTH: " << static_cast<int>(strength) << std::endl;
        contents_.params = ProofParams(plot_id_bytes, k, strength);

        // Read the memo into internal storage instead of skipping it
        in.read(reinterpret_cast<char*>(memo_.data()), memo_.size());

        uint64_t outer = 0;
        in.read(reinterpret_cast<char*>(&outer), sizeof(outer));
        #ifdef DEBUG_PLOT_FILE
        std::cout << "Read outer partitions: " << outer << std::endl;
        #endif
        contents_.partition_offsets.assign(outer, 0);
        for (uint64_t i = 0; i < outer; ++i)
            in.read(reinterpret_cast<char*>(&contents_.partition_offsets[i]), sizeof(contents_.partition_offsets[i]));
        #ifdef DEBUG_PLOT_FILE
        std::cout << "Read partition offsets." << std::endl;
        for (uint64_t i = 0; i < outer; ++i)
            std::cout << "  offset[" << i << "] = " << contents_.partition_offsets[i] << std::endl;
        #endif
        if (!in)
            throw std::runtime_error("Failed to read plot file headers");
    } 

    // Read both t4 and t5 back-pointer vectors for a specific partition.
    void ensurePartitionT4T5BackPointersLoaded(const std::string &filename, size_t partition_index)
    {
        #ifdef DEBUG_PLOT_FILE
        std::cout << "PlotFile::readPartition requested: file='" << filename << "' partition=" << partition_index << std::endl;
        std::cout << "  partition_offsets.size() = " << contents.partition_offsets.size() << std::endl;
        #endif
        if (partition_index >= contents_.partition_offsets.size())
            throw std::out_of_range("Partition index out of range");

        //size_t reverse_mapped_t3_partition = map_t3_lateral_partition_to_t4(partition_index, contents.params.get_num_partitions());
        // If either vector is non-empty assume the partition is loaded.
        if (!contents_.data.t3_proof_fragments[partition_index].empty() ||
            !contents_.data.t4_to_t3_back_pointers[partition_index].empty() ||
            !contents_.data.t5_to_t4_back_pointers[partition_index].empty())
            return; // already loaded

        std::ifstream in(filename, std::ios::binary);
        #ifdef DEBUG_PLOT_FILE
        std::cout << "  file exists: " << std::boolalpha << std::filesystem::exists(filename) << std::noboolalpha << std::endl;
        #endif
        if (!in) {
            std::cerr << "  Failed to open file '" << filename << "' for partition read." << std::endl;
            throw std::runtime_error("Failed to open " + filename);
        }

        uint64_t offset = contents_.partition_offsets[partition_index];
        in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        contents_.data.t3_proof_fragments[partition_index] = readVector<ProofFragment>(in);
        contents_.data.t4_to_t3_back_pointers[partition_index] = readVector<PartitionedBackPointer>(in);
        contents_.data.t5_to_t4_back_pointers[partition_index] = readVector<T5PlotBackPointers>(in);
        #ifdef DEBUG_PLOT_FILE
        std::cout << "  loaded t3 vector size: " << contents_.data.t3_proof_fragments[partition_index].size() << std::endl;
        std::cout << "  loaded t4 vector size: " << contents_.data.t4_to_t3_back_pointers[partition_index].size() << std::endl;
        std::cout << "  loaded t5 vector size: " << contents_.data.t5_to_t4_back_pointers[partition_index].size() << std::endl;
        #endif

        if (!in)
        {
            std::cerr << "  stream error after reading partition " << partition_index << ", failbit=" << in.fail() << " eofbit=" << in.eof() << std::endl;
            throw std::runtime_error("Failed to read partition " + std::to_string(partition_index));
        }
    }

    ProofParams getParams() const {
        return contents_.params;
    }

    PlotFormatContents getContents() const {
        return contents_;
    }

private:
    PlotFormatContents contents_;
    std::array<uint8_t, 32 + 48 + 32> memo_;

    // Helper: construct a minimal valid ProofParams without needing a default ctor
    static ProofParams makeDummyParams()
    {
        uint8_t zeros[32] = {};
        return ProofParams(zeros, 0, 0);
    }

    template <typename T>
    static void writeVector(std::ofstream &out, std::vector<T> const &v)
    {
        static_assert(std::is_trivially_copyable_v<T>);
        uint64_t n = v.size();
        out.write((char *)&n, sizeof(n));
        if (n)
            out.write((char *)v.data(), n * sizeof(T));
    }

    template <typename T>
    static std::vector<T> readVector(std::ifstream &in)
    {
        static_assert(std::is_trivially_copyable_v<T>);
        uint64_t n;
        in.read((char *)&n, sizeof(n));
        std::vector<T> v(n);
        if (n)
            in.read((char *)v.data(), n * sizeof(T));
        return v;
    }

    template <typename T>
    static void writeArray(std::ofstream &out, std::array<T, 8> const &a)
    {
        static_assert(std::is_trivially_copyable_v<T>);
        out.write((char *)a.data(), sizeof(T) * 8);
    }

    template <typename T>
    static void writeNestedVector(std::ofstream &out, std::vector<std::vector<T>> const &nested)
    {
        uint64_t outer = nested.size();
        out.write((char *)&outer, sizeof(outer));
        for (auto const &inner : nested)
            writeVector(out, inner);
    }

    template <typename T>
    static std::vector<std::vector<T>> readNestedVector(std::ifstream &in)
    {
        uint64_t outer;
        in.read((char *)&outer, sizeof(outer));
        std::vector<std::vector<T>> nested(outer);
        for (size_t i = 0; i < outer; ++i)
            nested[i] = readVector<T>(in);
        return nested;
    }

    // Ranges serialization
    static void writeRanges(std::ofstream &out, T4ToT3LateralPartitionRanges const &r)
    {
        uint64_t n = r.size();
        out.write((char *)&n, sizeof(n));
        for (auto const &e : r)
        {
            out.write((char *)&e.start, sizeof(e.start));
            out.write((char *)&e.end, sizeof(e.end));
        }
    }

    static T4ToT3LateralPartitionRanges readRanges(std::ifstream &in)
    {
        uint64_t n;
        in.read((char *)&n, sizeof(n));
        T4ToT3LateralPartitionRanges r(n);
        for (size_t i = 0; i < n; ++i)
        {
            in.read((char *)&r[i].start, sizeof(r[i].start));
            in.read((char *)&r[i].end, sizeof(r[i].end));
        }
        return r;
    }
};
