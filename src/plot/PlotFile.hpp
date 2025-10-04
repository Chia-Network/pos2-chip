#pragma once

#include <string>
#include <fstream>
#include <stdexcept>
#include <type_traits>
#include "PlotData.hpp"
#include "pos/ProofParams.hpp"

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
    // Write PlotData to a binary file.
    static void writeData(const std::string &filename, PlotData const &data, ProofParams const &params)
    {
        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        out.write("pos2", 4);
        out.write(reinterpret_cast<const char*>(&FORMAT_VERSION), 1);

        // Write plot ID
        out.write(reinterpret_cast<const char*>(params.get_plot_id_bytes()), 32);

        // Write k and strength
        const uint8_t k = static_cast<uint8_t>(params.get_k());
        const uint8_t match_key_bits = params.get_match_key_bits();
        out.write(reinterpret_cast<const char*>(&k), 1);
        out.write(reinterpret_cast<const char*>(&match_key_bits), 1);

        // TODO: write memo
        std::vector<char> memo(32 + 48 + 32, 0);
        out.write(memo.data(), memo.size());

        // Write plot data
        writeVector(out, data.t3_proof_fragments);
        writeRanges(out, data.t4_to_t3_lateral_ranges);
        writeNestedVector(out, data.t4_to_t3_back_pointers);
        writeNestedVector(out, data.t5_to_t4_back_pointers);
        #ifdef RETAIN_X_VALUES_TO_T3
        writeVector(out, data.xs_correlating_to_proof_fragments);
        #endif

        if (!out)
            throw std::runtime_error("Failed to write " + filename);
    }

    static PlotFileContents readData(const std::string &filename)
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

        // skip puzzle hash, farmer PK and local SK
        in.seekg(32 + 48 + 32, std::ifstream::cur);

        // 5) Read plot data
        PlotData data;
        data.t3_proof_fragments = readVector<uint64_t>(in);
        data.t4_to_t3_lateral_ranges = readRanges(in);
        data.t4_to_t3_back_pointers = readNestedVector<T4BackPointers>(in);
        data.t5_to_t4_back_pointers = readNestedVector<T5Pairing>(in);
        #ifdef RETAIN_X_VALUES_TO_T3
        data.xs_correlating_to_proof_fragments    = readVector<std::array<uint32_t,8>>(in);
        #endif

        if (!in)
            throw std::runtime_error("Failed to read plot file" + filename);

        return {
            .data = data,
            .params = params
        };
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
