#pragma once

#include <array>
#include <cstdint>
#include <fstream>
#include <type_traits>
#include <vector>
#include "PlotData.hpp"

template <typename T>
inline void writeVector(std::ofstream& out, std::vector<T> const& v)
{
    static_assert(std::is_trivially_copyable_v<T>,
                  "writeVector requires trivially copyable type");
    uint64_t n = static_cast<uint64_t>(v.size());
    out.write(reinterpret_cast<char*>(&n), sizeof(n));
    if (n) {
        out.write(reinterpret_cast<char const*>(v.data()),
                  n * sizeof(T));
    }
}

template <typename T>
inline std::vector<T> readVector(std::ifstream& in)
{
    static_assert(std::is_trivially_copyable_v<T>,
                  "readVector requires trivially copyable type");
    uint64_t n = 0;
    in.read(reinterpret_cast<char*>(&n), sizeof(n));
    std::vector<T> v(static_cast<size_t>(n));
    if (n) {
        in.read(reinterpret_cast<char*>(v.data()),
                n * sizeof(T));
    }
    return v;
}

template <typename T, size_t N>
inline void writeArray(std::ofstream& out, std::array<T, N> const& a)
{
    static_assert(std::is_trivially_copyable_v<T>,
                  "writeArray requires trivially copyable type");
    out.write(reinterpret_cast<char const*>(a.data()),
              sizeof(T) * N);
}

inline void writeRanges(std::ofstream& out,
                        T4ToT3LateralPartitionRanges const& r)
{
    uint64_t n = static_cast<uint64_t>(r.size());
    out.write(reinterpret_cast<char*>(&n), sizeof(n));
    for (auto const& e : r) {
        out.write(reinterpret_cast<char const*>(&e.start),
                  sizeof(e.start));
        out.write(reinterpret_cast<char const*>(&e.end),
                  sizeof(e.end));
    }
}

inline T4ToT3LateralPartitionRanges readRanges(std::ifstream& in)
{
    uint64_t n = 0;
    in.read(reinterpret_cast<char*>(&n), sizeof(n));
    T4ToT3LateralPartitionRanges r(static_cast<size_t>(n));
    for (size_t i = 0; i < static_cast<size_t>(n); ++i) {
        in.read(reinterpret_cast<char*>(&r[i].start),
                sizeof(r[i].start));
        in.read(reinterpret_cast<char*>(&r[i].end),
                sizeof(r[i].end));
    }
    return r;
}
