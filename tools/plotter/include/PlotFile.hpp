#pragma once

// File: tools/plotter/include/plotter/PlotFile.hpp

#pragma once

#include <string>
#include <fstream>
#include <stdexcept>
#include <type_traits>
#include "PlotData.hpp"

class PlotFile {
public:
    /// Write PlotData to a binary file.
    static void writeData(const std::string& filename, const PlotData& data) {
        std::ofstream out(filename, std::ios::binary);
        if (!out) {
            throw std::runtime_error("Failed to open file for writing: " + filename);
        }
        writeVector<uint64_t>(out, data.t3_encrypted_xs);
        writeNestedVector<T4BackPointers>(out, data.t4_to_t3_back_pointers);
        writeNestedVector<T5Pairing>(out, data.t5_to_t4_back_pointers);
    }

    /// Read PlotData from a binary file.
    static PlotData readData(const std::string& filename) {
        std::ifstream in(filename, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open file for reading: " + filename);
        }
        PlotData data;
        data.t3_encrypted_xs           = readVector<uint64_t>(in);
        data.t4_to_t3_back_pointers   = readNestedVector<T4BackPointers>(in);
        data.t5_to_t4_back_pointers   = readNestedVector<T5Pairing>(in);
        return data;
    }

private:
    template <typename T>
    static void writeVector(std::ofstream& out, const std::vector<T>& vec) {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
        uint64_t n = vec.size();
        out.write(reinterpret_cast<const char*>(&n), sizeof(n));
        if (n) {
            out.write(reinterpret_cast<const char*>(vec.data()), n * sizeof(T));
        }
    }

    template <typename T>
    static std::vector<T> readVector(std::ifstream& in) {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
        uint64_t n;
        in.read(reinterpret_cast<char*>(&n), sizeof(n));
        std::vector<T> vec(n);
        if (n) {
            in.read(reinterpret_cast<char*>(vec.data()), n * sizeof(T));
        }
        return vec;
    }

    template <typename T>
    static void writeNestedVector(std::ofstream& out, const std::vector<std::vector<T>>& nested) {
        uint64_t outer = nested.size();
        out.write(reinterpret_cast<const char*>(&outer), sizeof(outer));
        for (const auto& inner : nested) {
            writeVector(out, inner);
        }
    }

    template <typename T>
    static std::vector<std::vector<T>> readNestedVector(std::ifstream& in) {
        uint64_t outer;
        in.read(reinterpret_cast<char*>(&outer), sizeof(outer));
        std::vector<std::vector<T>> nested(outer);
        for (uint64_t i = 0; i < outer; ++i) {
            nested[i] = readVector<T>(in);
        }
        return nested;
    }
};
