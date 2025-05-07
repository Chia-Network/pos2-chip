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
    static constexpr uint32_t X_VALUES_VERSION_ADD = 100;
    #ifdef RETAIN_X_VALUES_TO_T3
    static constexpr uint32_t FORMAT_VERSION = X_VALUES_VERSION_ADD+1;
    #else
    static constexpr uint32_t FORMAT_VERSION = 1;
    #endif

    struct PlotFileContents {
        PlotData    data;
        ProofParams params;
    };
    
    // Write PlotData to a binary file.
    static void writeData(const std::string &filename, PlotData const &data, ProofParams const &params)
    {
        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        // 1) Write format version, note this will be different if we are writting x values for debugging.
        uint32_t version = FORMAT_VERSION;
        out.write((char *)&version, sizeof(version));
        // 2) Write plot ID
        out.write((char *)params.get_plot_id_bytes(), 32);
        // 3) Write k and sub_k
        uint32_t k = params.get_k();
        uint32_t sub_k = params.get_sub_k();
        out.write((char *)&k, sizeof(k));
        out.write((char *)&sub_k, sizeof(sub_k));

        // 4) Write plot data
        writeVector(out, data.t3_encrypted_xs);
        writeRanges(out, data.t4_to_t3_lateral_ranges);
        writeNestedVector(out, data.t4_to_t3_back_pointers);
        writeNestedVector(out, data.t5_to_t4_back_pointers);
        #ifdef RETAIN_X_VALUES_TO_T3
        writeVector(out, data.xs_correlating_to_encrypted_xs);
        #endif
    }

    /// Read PlotData from a binary file.
    static PlotFileContents readData(const std::string &filename)
    {
        std::ifstream in(filename, std::ios::binary);
        if (!in)
            throw std::runtime_error("Failed to open " + filename);

        // 1) Read format version
        uint32_t version;
        in.read((char *)&version, sizeof(version));
        if (version != FORMAT_VERSION) {
            // version mismatch, check if plot requires RETAIN_X_VALUES_TO_T3
            #ifdef RETAIN_X_VALUES_TO_T3
            if (version == FORMAT_VERSION - X_VALUES_VERSION_ADD) {
                throw std::runtime_error("Plot file format version " + std::to_string(version) + " written without x-values. Compile without RETAIN_X_VALUES_TO_T3.");
            }
            else {
                throw std::runtime_error("Plot file format version " + std::to_string(version) + " is not supported.");
            }
            #else
            if (version == FORMAT_VERSION + X_VALUES_VERSION_ADD) {
                throw std::runtime_error("Plot file format version " + std::to_string(version) + " contains x-values. Compile with RETAIN_X_VALUES_TO_T3.");
            }
            else {
                throw std::runtime_error("Plot file format version " + std::to_string(version) + " is not supported.");
            }
            #endif
        }
        // 2) Read plot ID
        uint8_t plot_id_bytes[32];
        in.read((char *)plot_id_bytes, 32);
        // 3) Read k and sub_k
        uint32_t k;
        uint32_t sub_k;
        in.read((char *)&k, sizeof(k));
        in.read((char *)&sub_k, sizeof(sub_k));
        // 4) Set proof parameters - creates set fault!
        ProofParams params = ProofParams(plot_id_bytes, k, sub_k);
        // 5) Read plot data
        PlotData data;
        data.t3_encrypted_xs = readVector<uint64_t>(in);
        data.t4_to_t3_lateral_ranges = readRanges(in);
        data.t4_to_t3_back_pointers = readNestedVector<T4BackPointers>(in);
        data.t5_to_t4_back_pointers = readNestedVector<T5Pairing>(in);
        #ifdef RETAIN_X_VALUES_TO_T3
        data.xs_correlating_to_encrypted_xs    = readVector<std::array<uint32_t,8>>(in);
        #endif
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