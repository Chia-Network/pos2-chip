#pragma once

#include <string>
#include <fstream>
#include <stdexcept>
#include <type_traits>
#include <vector>
#include <span>
#include <cstdint>
#include <cstring>
#include <optional>
#include <utility>

#include "PlotData.hpp"
#include "pos/ProofParams.hpp"
#include "PlotIO.hpp"
#include "ChunkCompressor.hpp"

class PlotFile
{
public:
    static constexpr int CHUNK_SPAN_RANGE_BITS = 16; // 65k entries per chunk
    static constexpr int MINUS_STUB_BITS = 2;        // proof fragments get k stub bits minus this many extra bits

    // Current on-disk format version, update this when the format changes.
#ifdef RETAIN_X_VALUES_TO_T3
    static constexpr uint8_t FORMAT_VERSION = 3;
#else
    static constexpr uint8_t FORMAT_VERSION = 1;
#endif

    struct PlotFileContents {
        ChunkedProofFragments data;
        ProofParams           params;
    };

    // Construct a PlotFile bound to a specific filename (for reading).
    explicit PlotFile(std::string filename)
        : filename_(std::move(filename))
    {}

    /// Write PlotData to disk, converting to chunked + compressed representation first.
    static size_t writeData(const std::string &filename,
                            PlotData const &data,
                            ProofParams const &params,
                            std::span<uint8_t const, 32 + 48 + 32> const memo)
    {
        uint64_t const range_per_chunk = (1ULL << (params.get_k() + CHUNK_SPAN_RANGE_BITS));
        ChunkedProofFragments chunked_data = ChunkedProofFragments::convertToChunkedProofFragments(
            data,
            range_per_chunk
        );
        return writeData(filename, chunked_data, params, memo);
    }

    // returns bytes written
    static size_t writeData(const std::string &filename,
                            ChunkedProofFragments const &data,
                            ProofParams const &params,
                            std::span<uint8_t const, 32 + 48 + 32> const memo)
    {
        size_t bytes_written = 0;

        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        out.write("pos2", 4);
        out.write(reinterpret_cast<const char*>(&FORMAT_VERSION), 1);

        // Write plot ID
        out.write(reinterpret_cast<const char*>(params.get_plot_id_bytes()), 32);

        // Write k and strength (match_key_bits)
        const uint8_t k = numeric_cast<uint8_t>(params.get_k());
        const uint8_t match_key_bits = numeric_cast<uint8_t>(params.get_match_key_bits());
        out.write(reinterpret_cast<const char*>(&k), 1);
        out.write(reinterpret_cast<const char*>(&match_key_bits), 1);

        out.write(reinterpret_cast<const char*>(memo.data()), memo.size());

#ifdef RETAIN_X_VALUES_TO_T3
        writeVector(out, data.xs_correlating_to_proof_fragments);
#endif

        // Write chunk index + chunk bodies:
        //  uint64_t num_chunks
        //  num_chunks * uint64_t offsets (placeholders, overwritten later)
        //  chunk_0 data...
        //  chunk_1 data...
        {
            const uint64_t num_chunks = static_cast<uint64_t>(data.proof_fragments_chunks.size());

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
            std::vector<uint64_t> offsets(num_chunks);

            int const stub_bits = params.get_k() - MINUS_STUB_BITS;
            uint64_t const range_per_chunk = (1ULL << (params.get_k() + CHUNK_SPAN_RANGE_BITS));

            for (uint64_t i = 0; i < num_chunks; ++i) {
                // record offset for this chunk (absolute offset from file start)
                std::streampos pos = out.tellp();
                offsets[i] = static_cast<uint64_t>(pos);

                uint64_t start_proof_fragment_range = i * range_per_chunk;
                std::vector<uint8_t> compressed_chunk =
                    ChunkCompressor::compressProofFragments(
                        data.proof_fragments_chunks[i],
                        start_proof_fragment_range,
                        stub_bits
                    );

                writeVector(out, compressed_chunk);
                if (!out) {
                    throw std::runtime_error("Failed to write chunk " + std::to_string(i) +
                                             " to " + filename);
                }
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

    // -------- Instance reading API --------

    // Read header + xs (if present) + chunk index (num_chunks + offsets) and cache locally.
    // Safe to call multiple times; only does work once.
    void readHeadersAndIndexes()
    {
        if (plot_file_header_) {
            return; // already loaded
        }

        std::ifstream in(filename_, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open " + filename_);
        }

        char magic[4] = {};
        in.read(magic, sizeof(magic));
        if (std::memcmp(magic, "pos2", 4) != 0) {
            throw std::runtime_error("Plot file invalid magic bytes, not a plot file");
        }

        uint8_t version;
        in.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (version != FORMAT_VERSION) {
            throw std::runtime_error("Plot file format version " + std::to_string(version) +
                                     " is not supported.");
        }

        uint8_t plot_id_bytes[32];
        in.read(reinterpret_cast<char*>(plot_id_bytes), 32);

        uint8_t k;
        in.read(reinterpret_cast<char*>(&k), sizeof(k));

        uint8_t strength;
        in.read(reinterpret_cast<char*>(&strength), sizeof(strength));

        ProofParams params(plot_id_bytes, k, strength);

        // skip puzzle hash, farmer PK and local SK
        in.seekg(32 + 48 + 32, std::ifstream::cur);

        PlotFileHeader header(params);

#ifdef RETAIN_X_VALUES_TO_T3
        // xs_correlating_to_proof_fragments were written before the chunk index.
        header.xs_correlating_to_proof_fragments = readVector<std::array<uint32_t,8>>(in);
#endif

        // Read number of chunks
        uint64_t num_chunks = 0;
        in.read(reinterpret_cast<char*>(&num_chunks), sizeof(num_chunks));
        if (!in) {
            throw std::runtime_error("Failed to read number of chunks in " + filename_);
        }

        header.num_chunks = num_chunks;

        // Read offsets
        header.offsets.resize(num_chunks);
        for (uint64_t i = 0; i < num_chunks; ++i) {
            in.read(reinterpret_cast<char*>(&header.offsets[i]), sizeof(header.offsets[i]));
        }
        if (!in) {
            throw std::runtime_error("Failed to read chunk offsets in " + filename_);
        }

        plot_file_header_ = std::move(header);
    }

    // Reads all chunked data + params.
    PlotFileContents readAllChunkedData()
    {
        readHeadersAndIndexes();
        if (!plot_file_header_) {
            throw std::runtime_error("PlotFileHeader not loaded");
        }

        const auto &header = *plot_file_header_;

        ChunkedProofFragments chunked;

#ifdef RETAIN_X_VALUES_TO_T3
        chunked.xs_correlating_to_proof_fragments = header.xs_correlating_to_proof_fragments;
#endif

        const uint64_t num_chunks = header.num_chunks;
        chunked.proof_fragments_chunks.clear();
        chunked.proof_fragments_chunks.resize(num_chunks);

        std::ifstream in(filename_, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open " + filename_);
        }

        int const stub_bits = header.params.get_k() - MINUS_STUB_BITS;
        uint64_t const range_per_chunk = (1ULL << (header.params.get_k() + CHUNK_SPAN_RANGE_BITS));

        for (uint64_t i = 0; i < num_chunks; ++i) {
            in.seekg(static_cast<std::streamoff>(header.offsets[i]), std::ios::beg);
            if (!in) {
                throw std::runtime_error("Failed to seek to chunk " + std::to_string(i) +
                                         " in " + filename_);
            }

            uint64_t start_proof_fragment_range = i * range_per_chunk;
            std::vector<uint8_t> compressed_chunk = readVector<uint8_t>(in);
            if (!in) {
                throw std::runtime_error("Failed to read compressed chunk " +
                                         std::to_string(i) + " from " + filename_);
            }

            chunked.proof_fragments_chunks[i] =
                ChunkCompressor::decompressProofFragments(
                    compressed_chunk,
                    start_proof_fragment_range,
                    stub_bits
                );
        }

        return {
            .data   = std::move(chunked),
            .params = header.params
        };
    }

    // Read a single chunk's decompressed proof fragments by index.
    std::vector<uint64_t> readChunk(uint64_t chunk_index)
    {
        readHeadersAndIndexes();
        if (!plot_file_header_) {
            throw std::runtime_error("PlotFileHeader not loaded");
        }

        const auto &header = *plot_file_header_;

        if (chunk_index >= header.num_chunks) {
            throw std::out_of_range("chunk_index out of range");
        }

        std::ifstream in(filename_, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open " + filename_);
        }

        in.seekg(static_cast<std::streamoff>(header.offsets[chunk_index]), std::ios::beg);
        if (!in) {
            throw std::runtime_error("Failed to seek to chunk " + std::to_string(chunk_index) +
                                     " in " + filename_);
        }

        int const stub_bits = header.params.get_k() - MINUS_STUB_BITS;
        uint64_t const range_per_chunk = (1ULL << (header.params.get_k() + CHUNK_SPAN_RANGE_BITS));
        uint64_t const start_proof_fragment_range = chunk_index * range_per_chunk;

        std::vector<uint8_t> compressed_chunk = readVector<uint8_t>(in);
        if (!in) {
            throw std::runtime_error("Failed to read chunk " + std::to_string(chunk_index) +
                                     " from " + filename_);
        }

        return ChunkCompressor::decompressProofFragments(
            compressed_chunk,
            start_proof_fragment_range,
            stub_bits
        );
    }

    // -------- Static convenience wrappers for reading --------

    static PlotFileContents readAllChunkedData(const std::string &filename)
    {
        PlotFile pf(filename);
        return pf.readAllChunkedData();
    }

    static std::vector<uint64_t> readChunk(const std::string &filename, uint64_t chunk_index)
    {
        PlotFile pf(filename);
        return pf.readChunk(chunk_index);
    }

    const ProofParams& getProofParams()
    {
        readHeadersAndIndexes();
        if (!plot_file_header_) {
            throw std::runtime_error("PlotFileHeader not loaded");
        }
        return plot_file_header_->params;
    }

    std::vector<ProofFragment> getProofFragmentsInRange(Range const& range)
    {
        uint64_t const range_per_chunk = getRangePerChunk();
        uint64_t const chunk_index = range.start / range_per_chunk;
        uint64_t const end_chunk = (range.end - 1) / range_per_chunk;
        if (chunk_index != end_chunk) {
            throw std::invalid_argument("getProofFragmentsInRange: range spans multiple chunks");
        }

        std::vector<ProofFragment> result;

        std::vector<uint64_t> chunk_fragments = readChunk(chunk_index);
        for (const auto& fragment : chunk_fragments) {
            if (fragment >= range.start && fragment < range.end) {
                result.push_back(fragment);
            }
        }

        return result;
    }

private:
    struct PlotFileHeader {
        ProofParams params;
    #ifdef RETAIN_X_VALUES_TO_T3
        std::vector<std::array<uint32_t,8>> xs_correlating_to_proof_fragments;
    #endif
        uint64_t num_chunks = 0;
        std::vector<uint64_t> offsets;

        // Explicit constructor so this type can be constructed
        explicit PlotFileHeader(const ProofParams& p)
            : params(p)
        {}
    };

    uint64_t getRangePerChunk()
    {
        readHeadersAndIndexes();
        if (!plot_file_header_) {
            throw std::runtime_error("PlotFileHeader not loaded");
        }
        // TODO: this will be written with plot eventually, tunable by groupings and disk seq. read speed.
        return (1ULL << (plot_file_header_->params.get_k() + CHUNK_SPAN_RANGE_BITS));
    }

    std::string filename_;
    std::optional<PlotFileHeader> plot_file_header_;
};
