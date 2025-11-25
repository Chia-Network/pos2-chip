#pragma once

#include <string>
#include <fstream>
#include <stdexcept>
#include <type_traits>
#include <vector>
#include <cstdint>
#include <cstring>
#include "PlotData.hpp"
#include "pos/ProofParams.hpp"
#include "pos/ProofFragmentScanFilter.hpp"
#include "PlotIO.hpp"
#include "ChunkCompressor.hpp"

class PlotFile
{
public:
    static constexpr int CHUNK_SPAN_RANGE_BITS = 16; // 65k entries per chunk
    static constexpr int MINUS_STUB_BITS = 2; // proof fragments get k stub bits minus this many extra bits
    // Current on-disk format version, update this when the format changes.
    #ifdef RETAIN_X_VALUES_TO_T3
    static constexpr uint8_t FORMAT_VERSION = 3;
    #else
    static constexpr uint8_t FORMAT_VERSION = 1;
    #endif

    struct PlotFileContents {
        ChunkedProofFragments data;
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
    static size_t writeData(const std::string &filename, PlotData const &data, ProofParams const &params, std::span<uint8_t const, 32 + 48 + 32> const memo)
    {
        uint64_t range_per_chunk = (1ULL << (params.get_k() + CHUNK_SPAN_RANGE_BITS));
        ChunkedProofFragments chunked_data = ChunkedProofFragments::convertToChunkedProofFragments(
            data,
            range_per_chunk
        );
        return writeData(filename, chunked_data, params, memo);
    }

    // returns bytes written
    static size_t writeData(const std::string &filename, ChunkedProofFragments const &data, ProofParams const &params, std::span<uint8_t const, 32 + 48 + 32> const memo)
    {
        size_t bytes_written = 0;

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

        #ifdef RETAIN_X_VALUES_TO_T3
        writeVector(out, data.xs_correlating_to_proof_fragments);
        #endif

        // Write chunked proof fragments index followed by chunk bodies.
        // We write:
        //  uint64_t num_chunks
        //  num_chunks * uint64_t offsets (placeholders, overwritten later)
        //  chunk_0 data...
        //  chunk_1 data...
        //  ...
        {
            const uint64_t num_chunks = static_cast<uint64_t>(data.proof_fragments_chunks.size());
            // Position right after memo / x-values: offsets_start will point to first placeholder
            // Write num_chunks
            out.write(reinterpret_cast<const char*>(&num_chunks), sizeof(num_chunks));
            if (!out) throw std::runtime_error("Failed to write chunk count to " + filename);

            // Remember where offsets will be written
            std::streampos offsets_start_pos = out.tellp();

            // Write placeholder zero offsets
            uint64_t zero = 0;
            for (uint64_t i = 0; i < num_chunks; ++i) {
                out.write(reinterpret_cast<const char*>(&zero), sizeof(zero));
            }
            if (!out) throw std::runtime_error("Failed to write chunk offset placeholders to " + filename);

            // Collect real offsets as we write chunks
            std::vector<uint64_t> offsets;
            offsets.resize(num_chunks);

            for (uint64_t i = 0; i < num_chunks; ++i) {
                // record offset for this chunk (absolute offset from file start)
                std::streampos pos = out.tellp();
                offsets[i] = static_cast<uint64_t>(pos);

                // write the chunk (assumes writeVector can serialize each chunk container)
                int stub_bits = params.get_k() - MINUS_STUB_BITS;
                uint64_t range_per_chunk = (1ULL << (params.get_k() + CHUNK_SPAN_RANGE_BITS));
                uint64_t start_proof_fragment_range = i * range_per_chunk;
                std::vector<uint8_t> compressed_chunk = ChunkCompressor::compressProofFragments(data.proof_fragments_chunks[i], start_proof_fragment_range, stub_bits);
                writeVector(out, compressed_chunk);
                if (!out) throw std::runtime_error("Failed to write chunk " + std::to_string(i) + " to " + filename);
            }

            bytes_written = static_cast<size_t>(out.tellp());

            // Seek back and overwrite placeholders with actual offsets
            out.seekp(offsets_start_pos);
            if (!out) throw std::runtime_error("Failed to seek to chunk offsets in " + filename);

            for (uint64_t i = 0; i < num_chunks; ++i) {
                out.write(reinterpret_cast<const char*>(&offsets[i]), sizeof(offsets[i]));
            }
            if (!out) throw std::runtime_error("Failed to write chunk offsets to " + filename);

            // Seek back to end so file finalization is consistent
            out.seekp(0, std::ios::end);
        }

        if (!out)
            throw std::runtime_error("Failed to write " + filename);

        return bytes_written;
    }

    static PlotFileContents readAllChunkedData(const std::string &filename)
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
        // Read into the chunked structure: xs (if retained) first, then index and chunk bodies.
        ChunkedProofFragments chunked;

        #ifdef RETAIN_X_VALUES_TO_T3
        // writeData writes xs_correlating_to_proof_fragments before the chunk index,
        // so read them first.
        chunked.xs_correlating_to_proof_fragments = readVector<std::array<uint32_t,8>>(in);
        #endif

        // Read number of chunks
        uint64_t num_chunks = 0;
        in.read(reinterpret_cast<char*>(&num_chunks), sizeof(num_chunks));
        if (!in) throw std::runtime_error("Failed to read number of chunks in " + filename);

        // Read offsets
        std::vector<uint64_t> offsets;
        offsets.resize(num_chunks);
        for (uint64_t i = 0; i < num_chunks; ++i) {
            in.read(reinterpret_cast<char*>(&offsets[i]), sizeof(offsets[i]));
        }
        if (!in) throw std::runtime_error("Failed to read chunk offsets in " + filename);

        // Read each chunk by seeking to its offset and using readVector for the per-chunk container.
        chunked.proof_fragments_chunks.clear();
        chunked.proof_fragments_chunks.resize(num_chunks);
        for (uint64_t i = 0; i < num_chunks; ++i) {
            // note seeking should be redundant, should already be at correct position if reading all sequentially.
            in.seekg(static_cast<std::streamoff>(offsets[i]), std::ios::beg);
            if (!in) throw std::runtime_error("Failed to seek to chunk " + std::to_string(i) + " in " + filename);
            // each chunk was written with writeVector( out, data.proof_fragments_chunks[i] )

            int stub_bits = params.get_k() - MINUS_STUB_BITS;
            uint64_t range_per_chunk = (1ULL << (params.get_k() + CHUNK_SPAN_RANGE_BITS));
            uint64_t start_proof_fragment_range = i * range_per_chunk;
            chunked.proof_fragments_chunks[i] = ChunkCompressor::decompressProofFragments(readVector<uint8_t>(in), start_proof_fragment_range, stub_bits);
            if (!in) throw std::runtime_error("Failed to read chunk " + std::to_string(i) + " from " + filename);
        }

        if (!in)
            throw std::runtime_error("Failed to read plot file" + filename);

        return {
            .data = chunked,
            .params = params
        };
    }

    // Read a single chunk's data from the file by index. Returns the per-chunk container.
    // This helper only reads the requested chunk by using the on-disk index.
    static std::vector<uint64_t> readChunk(const std::string &filename, uint64_t chunk_index)
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

        // skip plot id, k, strength, and memo area
        in.seekg(32 + 1 + 1, std::ifstream::cur); // plot id (32), k (1), strength (1)
        // skip puzzle hash, farmer PK and local SK
        in.seekg(32 + 48 + 32, std::ifstream::cur);

        // Read number of chunks
        uint64_t num_chunks = 0;
        in.read(reinterpret_cast<char*>(&num_chunks), sizeof(num_chunks));
        if (!in) throw std::runtime_error("Failed to read number of chunks in " + filename);

        if (chunk_index >= num_chunks) {
            throw std::out_of_range("chunk_index out of range");
        }

        // Read offsets until we reach the desired chunk offset
        // We can read all offsets (cheap) and then seek to the requested offset.
        std::vector<uint64_t> offsets;
        offsets.resize(num_chunks);
        for (uint64_t i = 0; i < num_chunks; ++i) {
            in.read(reinterpret_cast<char*>(&offsets[i]), sizeof(offsets[i]));
        }
        if (!in) throw std::runtime_error("Failed to read chunk offsets in " + filename);

        // Seek to the requested chunk and read it
        in.seekg(static_cast<std::streamoff>(offsets[chunk_index]), std::ios::beg);
        if (!in) throw std::runtime_error("Failed to seek to chunk " + std::to_string(chunk_index) + " in " + filename);

        auto chunk = readVector<uint64_t>(in);
        if (!in) throw std::runtime_error("Failed to read chunk " + std::to_string(chunk_index) + " from " + filename);
        return chunk;
    }

};
