#pragma once

#include <string>
#include <fstream>
#include <stdexcept>
#include <type_traits>
#include "PlotData.hpp"
#include "pos/ProofParams.hpp"
#include "PlotIO.hpp"

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
    static void writeData(const std::string &filename, PlotData const &data, ProofParams const &params, std::span<uint8_t const, 32 + 48 + 32> const memo)
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

        out.write(reinterpret_cast<char const*>(memo.data()), memo.size());

        // Write plot data
        writeVector(out, data.t3_proof_fragments);
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
};
