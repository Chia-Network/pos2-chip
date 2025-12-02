#pragma once

#include <array>
#include <cstdint>
#include <fstream>
#include <type_traits>
#include <vector>

template <typename T>
void writeVector(std::ofstream& out, std::vector<T> const& v)
{
    static_assert(std::is_trivially_copyable_v<T>,
                  "writeVector requires trivially copyable type");
    static_assert(std::has_unique_object_representations_v<T>,
                  "writeVector does not allow padding bits");
    uint64_t n = static_cast<uint64_t>(v.size());
    out.write(reinterpret_cast<char*>(&n), sizeof(n));
    if (n) {
        out.write(reinterpret_cast<char const*>(v.data()),
                  n * sizeof(T));
    }
}

template <typename T>
std::vector<T> readVector(std::ifstream& in)
{
    static_assert(std::is_trivially_copyable_v<T>,
                  "readVector requires trivially copyable type");
    static_assert(std::has_unique_object_representations_v<T>,
                  "readVector does not allow padding bits");
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
void writeArray(std::ofstream& out, std::array<T, N> const& a)
{
    static_assert(std::is_trivially_copyable_v<T>,
                  "writeArray requires trivially copyable type");
    static_assert(std::has_unique_object_representations_v<T>,
                  "writeArray does not allow padding bits");
    out.write(reinterpret_cast<char const*>(a.data()),
              sizeof(T) * N);
}
