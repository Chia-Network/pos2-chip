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
    };

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

    static PlotFormatContents readHeaderData(const std::string &filename)
    {
        std::ifstream in(filename, std::ios::binary);
        if (!in)
            throw std::runtime_error("Failed to open " + filename);

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
        ProofParams params = ProofParams(plot_id_bytes, k, strength);

        // Skip the memo (puzzle hash, farmer PK, local SK) before reading partition
        // counts which the writer placed immediately after the memo.
        in.seekg(32 + 48 + 32, std::ifstream::cur);

        uint64_t outer = 0;
        in.read(reinterpret_cast<char*>(&outer), sizeof(outer));
        #ifdef DEBUG_PLOT_FILE
        std::cout << "Read outer partitions: " << outer << std::endl;
        #endif
        std::vector<uint64_t> offsets(outer);
        for (uint64_t i = 0; i < outer; ++i)
            in.read(reinterpret_cast<char*>(&offsets[i]), sizeof(offsets[i]));
        #ifdef DEBUG_PLOT_FILE
        std::cout << "Read partition offsets." << std::endl;
        for (uint64_t i = 0; i < outer; ++i)
            std::cout << "  offset[" << i << "] = " << offsets[i] << std::endl;
        #endif

        if (!in)
            throw std::runtime_error("Failed to read plot file" + filename);

        PartitionedPlotData data;
        data.t4_to_t3_back_pointers.resize(outer);
        data.t5_to_t4_back_pointers.resize(outer);
        data.t3_proof_fragments.resize(outer);

        return {
            .data = data,
            .params = params,
            .partition_offsets = std::move(offsets)
        };
    }

    // Read both t4 and t5 back-pointer vectors for a specific partition.
    static void readPartition(const std::string &filename, PlotFormatContents &contents, size_t partition_index)
    {
        #ifdef DEBUG_PLOT_FILE
        std::cout << "PlotFile::readPartition requested: file='" << filename << "' partition=" << partition_index << std::endl;
        std::cout << "  partition_offsets.size() = " << contents.partition_offsets.size() << std::endl;
        #endif
        if (partition_index >= contents.partition_offsets.size())
            throw std::out_of_range("Partition index out of range");

        //size_t reverse_mapped_t3_partition = map_t3_lateral_partition_to_t4(partition_index, contents.params.get_num_partitions());
        // If either vector is non-empty assume the partition is loaded.
        if (!contents.data.t3_proof_fragments[partition_index].empty() ||
            !contents.data.t4_to_t3_back_pointers[partition_index].empty() ||
            !contents.data.t5_to_t4_back_pointers[partition_index].empty())
            return; // already loaded

        std::ifstream in(filename, std::ios::binary);
        #ifdef DEBUG_PLOT_FILE
        std::cout << "  file exists: " << std::boolalpha << std::filesystem::exists(filename) << std::noboolalpha << std::endl;
        #endif
        if (!in) {
            std::cerr << "  Failed to open file '" << filename << "' for partition read." << std::endl;
            throw std::runtime_error("Failed to open " + filename);
        }

        uint64_t offset = contents.partition_offsets[partition_index];
        in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        contents.data.t3_proof_fragments[partition_index] = readVector<ProofFragment>(in);
        contents.data.t4_to_t3_back_pointers[partition_index] = readVector<PartitionedBackPointer>(in);
        contents.data.t5_to_t4_back_pointers[partition_index] = readVector<T5PlotBackPointers>(in);
        #ifdef DEBUG_PLOT_FILE
        std::cout << "  loaded t3 vector size: " << contents.data.t3_proof_fragments[partition_index].size() << std::endl;
        std::cout << "  loaded t4 vector size: " << contents.data.t4_to_t3_back_pointers[partition_index].size() << std::endl;
        std::cout << "  loaded t5 vector size: " << contents.data.t5_to_t4_back_pointers[partition_index].size() << std::endl;
        #endif

        if (!in)
        {
            std::cerr << "  stream error after reading partition " << partition_index << ", failbit=" << in.fail() << " eofbit=" << in.eof() << std::endl;
            throw std::runtime_error("Failed to read partition " + std::to_string(partition_index));
        }
    }

private:
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
