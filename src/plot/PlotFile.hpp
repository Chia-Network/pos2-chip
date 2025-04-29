#pragma once

#include <string>
#include <fstream>
#include <stdexcept>
#include <type_traits>
#include "PlotData.hpp"

class PlotFile
{
public:
    /// Write PlotData to a binary file.
    static void writeData(const std::string &filename, PlotData const &data)
    {
        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        writeVector(out, data.t3_encrypted_xs);
        writeRanges(out, data.t4_to_t3_lateral_ranges);
        writeNestedVector(out, data.t4_to_t3_back_pointers);
        writeNestedVector(out, data.t5_to_t4_back_pointers);
        #ifdef RETAIN_X_VALUES_TO_T3
        writeVector(out, data.xs_correlating_to_encrypted_xs);
        #endif
    }

    /// Read PlotData from a binary file.
    static PlotData readData(const std::string &filename)
    {
        std::ifstream in(filename, std::ios::binary);
        if (!in)
            throw std::runtime_error("Failed to open " + filename);

        PlotData data;
        data.t3_encrypted_xs = readVector<uint64_t>(in);
        data.t4_to_t3_lateral_ranges = readRanges(in);
        data.t4_to_t3_back_pointers = readNestedVector<T4BackPointers>(in);
        data.t5_to_t4_back_pointers = readNestedVector<T5Pairing>(in);
        #ifdef RETAIN_X_VALUES_TO_T3
        data.xs_correlating_to_encrypted_xs    = readVector<std::array<uint32_t,8>>(in);
        #endif
        return data;
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