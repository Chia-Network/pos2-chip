#pragma once

#include <string>
#include <fstream>
#include <stdexcept>
#include <type_traits>
#include "PlotData.hpp"
#include "pos/ProofParams.hpp"

//#define DEBUG_PLOT_FILE true
#ifdef DEBUG_PLOT_FILE
#include <iostream>
#include <filesystem>
#endif
#include <span>
#include <cstring>
#include <array> // added

class PlotFile
{
public:
    // Current on-disk format version, update this when the format changes.
    #ifdef RETAIN_X_VALUES_TO_T3
    static constexpr uint8_t FORMAT_VERSION = 3;
    #else
    static constexpr uint8_t FORMAT_VERSION = 1;
    #endif

    struct PlotFileContents {
        PlotData    data;
        ProofParams params;
        // Offsets to each partition's data on disk; each partition contains
        // t4_to_t3 back pointers followed immediately by t5_to_t4 back pointers.
        std::vector<uint64_t> partition_offsets;

        // Provide a default ctor so PlotFileContents can be default-constructed.
        // Construct params with an all-zero plot-id to satisfy ProofParams' ctor.
        static inline constexpr std::array<uint8_t, 32> ZERO_PLOT_ID{}; 
        PlotFileContents()
            : data()
            , params(ZERO_PLOT_ID.data(), 28, 2)
            , partition_offsets()
        {}
    };

    // New: stateful constructors, inputs params, memo, and plot data
    PlotFile(const ProofParams& params, std::span<uint8_t const, 32 + 48 + 32> const memo, const PlotData& data)
    {
        contents_.params = params;
        contents_.data = data;
        // copy memo data
        std::memcpy(memo_.data(), memo.data(), memo.size());
    }

    PlotFile(const std::string &filename)
    {
        std::cout << "Plot file init: " << filename << std::endl;
        std::array<uint8_t, 32> ZERO_PLOT_ID{}; // all-zero plot ID
        contents_.params = ProofParams(ZERO_PLOT_ID.data(), 28, 2); // dummy init
        memo_.fill(0); // initialize memo to zeros
        readHeadersFromFile(filename);
    }

    void readHeadersFromFile(const std::string &filename)
    {
        std::cout << "PlotFile:: readHeadersFromFile " << filename << std::endl;
        std::ifstream in(filename, std::ios::binary);
        readHeadersFromFile(in);

        if (!in)
            throw std::runtime_error("Failed to read plot file headers from " + filename);
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

    // New: write using internal state (no external memo param)
    void writeToFile(const std::string &filename) const
    {
        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        // our headers
        out.write("pos2", 4);
        out.write(reinterpret_cast<const char*>(&FORMAT_VERSION), 1);

        // Write plot ID
        out.write(reinterpret_cast<const char*>(contents_.params.get_plot_id_bytes()), 32);

        // Write k and strength (match_key_bits)
        const uint8_t k = numeric_cast<uint8_t>(contents_.params.get_k());
        const uint8_t match_key_bits = numeric_cast<uint8_t>(contents_.params.get_match_key_bits());
        out.write(reinterpret_cast<const char*>(&k), 1);
        out.write(reinterpret_cast<const char*>(&match_key_bits), 1);

        // Write memo (from internal storage)
        out.write(reinterpret_cast<char const*>(memo_.data()), memo_.size());

        // Use a single outer count for partition pairs (t4,t5) and placeholders
        // for their offsets. Each partition region will hold t4 vector then t5 vector.
        uint64_t outer = contents_.data.t4_to_t3_back_pointers.size();
        if (outer != contents_.params.get_num_partitions()*2) {
            throw std::runtime_error("Partition count mismatch when writing plot file");
        }
        if (contents_.data.t5_to_t4_back_pointers.size() != outer)
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
        writeVector(out, contents_.data.t3_proof_fragments);
        writeRanges(out, contents_.data.t4_to_t3_lateral_ranges);

        // Now write each partition's t4 then t5 vectors and remember file offsets
        std::vector<uint64_t> offsets;
        offsets.reserve(outer);
        for (uint64_t i = 0; i < outer; ++i)
        {
            uint64_t offset = static_cast<uint64_t>(out.tellp());
            offsets.push_back(offset);
            writeVector(out, contents_.data.t4_to_t3_back_pointers[i]);
            writeVector(out, contents_.data.t5_to_t4_back_pointers[i]);
        }

        #ifdef RETAIN_X_VALUES_TO_T3
        writeVector(out, contents_.data.xs_correlating_to_proof_fragments);
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

    // New: load into this PlotFile from disk (reads memo into internal storage)
    void readEntireT3FromFile(const std::string &filename)
    {
        std::ifstream in(filename, std::ios::binary);
        if (!in)
            throw std::runtime_error("Failed to open " + filename);

        // TODO: if headers already read, then need to seek to data start.
        readHeadersFromFile(in);

        // Read plot data (non-partitioned parts)
        contents_.data = PlotData{};
        contents_.data.t3_proof_fragments = readVector<uint64_t>(in);
        contents_.data.t4_to_t3_lateral_ranges = readRanges(in);

        // Initialize empty outer vectors sized to the partition counts
        size_t outer = contents_.params.get_num_partitions()*2;
        contents_.data.t4_to_t3_back_pointers = std::vector<std::vector<T4PlotBackPointers>>(outer);
        contents_.data.t5_to_t4_back_pointers = std::vector<std::vector<T5PlotBackPointers>>(outer);

        #ifdef RETAIN_X_VALUES_TO_T3
        contents_.data.xs_correlating_to_proof_fragments = readVector<std::array<uint32_t,8>>(in);
        #endif

        if (!in)
            throw std::runtime_error("Failed to read plot file" + filename);
    }

    // New: Read both t4 and t5 back-pointer vectors for a specific partition.
    void ensurePartitionT4T5BackPointersLoaded(const std::string &filename, size_t partition_index)
    {
        #ifdef DEBUG_PLOT_FILE
        std::cout << "PlotFile::ensurePartitionT4T5BackPointersLoaded requested: file='" << filename << "' partition=" << partition_index << std::endl;
        std::cout << "  partition_offsets.size() = " << contents_.partition_offsets.size() << std::endl;
        #endif
        if (partition_index >= contents_.partition_offsets.size())
            throw std::out_of_range("Partition index out of range");
        // If either vector is non-empty assume the partition is loaded.
        if (!contents_.data.t4_to_t3_back_pointers[partition_index].empty() ||
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

        contents_.data.t4_to_t3_back_pointers[partition_index] = readVector<T4PlotBackPointers>(in);
        contents_.data.t5_to_t4_back_pointers[partition_index] = readVector<T5PlotBackPointers>(in);
        #ifdef DEBUG_PLOT_FILE
        std::cout << "  loaded t4 vector size: " << contents_.data.t4_to_t3_back_pointers[partition_index].size() << std::endl;
        std::cout << "  loaded t5 vector size: " << contents_.data.t5_to_t4_back_pointers[partition_index].size() << std::endl;
        #endif

        if (!in)
        {
            std::cerr << "  stream error after reading partition " << partition_index << ", failbit=" << in.fail() << " eofbit=" << in.eof() << std::endl;
            throw std::runtime_error("Failed to read partition " + std::to_string(partition_index));
        }
    }

    // New: accessors
    void setPlotData(const PlotData &data) { contents_.data = data; }
    const PlotFileContents& getContents() const { return contents_; }
    PlotFileContents& getContents() { return contents_; }
    const ProofParams& getParams() const { return contents_.params; }

    // New: memo accessors
    void setMemo(std::span<uint8_t const, 32 + 48 + 32> const memo) {
        std::memcpy(memo_.data(), memo.data(), memo.size());
    }
    const std::array<uint8_t, 32 + 48 + 32>& getMemo() const { return memo_; }

    // New: testing helper to inject contents
    void setContents(const PlotFileContents& contents) { contents_ = contents; }

private:
    PlotFileContents contents_;
    std::array<uint8_t, 32 + 48 + 32> memo_{}; // internal memo storage

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
