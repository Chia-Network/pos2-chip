#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <bit>

#include "ChunkCompression.hpp"
#include "PlotData.hpp"
#include "PlotIO.hpp"
#include "pos/ProofParams.hpp"
#include "fse.h"
#include "error_public.h"

extern "C" {
    #include "pos/sha/sha256.h"
}

#if defined(_MSC_VER)
#include <intrin.h>
#endif

class PlotFile {
public:
    static constexpr int CHUNK_SPAN_RANGE_BITS = 16; // 65k entries per chunk
    static constexpr int MINUS_STUB_BITS = 2; // proof fragments get k stub bits minus this many extra bits
    static constexpr const char* MAGIC = "pos2";

    // Current on-disk format version, update this when the format changes.
    static constexpr uint8_t FORMAT_VERSION = 2;

    struct PlotFileContents {
        ChunkedProofFragments data;
        PlotGroupParams params;
    };

    // Construct a PlotFile bound to a specific filename (for reading).
    explicit PlotFile(std::string filename) : filename_(std::move(filename)) {}

    /// Write PlotData to disk, converting to chunked + compressed representation first.
    static size_t writeData(std::string const& filename,
        PlotData const& data,
        PlotGroupParams const& params,
        uint16_t const index,
        std::span<uint8_t const> const memo)
    {
        uint64_t const range_per_chunk = (1ULL << (params.get_k() + CHUNK_SPAN_RANGE_BITS));
        ChunkedProofFragments chunked_data
            = ChunkedProofFragments::convertToChunkedProofFragments(data, range_per_chunk);
        return writeData(filename, chunked_data, params, index, memo);
    }

    // returns bytes written
    static size_t writeData(std::string const& filename,
        ChunkedProofFragments const& data,
        PlotGroupParams const& params,
        uint16_t const index,
        std::span<uint8_t const> const memo)
    {
        size_t bytes_written = 0;

        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        uint8_t version = FORMAT_VERSION;

        out.write(MAGIC, 4);
        out.write(reinterpret_cast<char const*>(&version), 1);

        // Write plot group id
        out.write(reinterpret_cast<char const*>(params.get_plot_group_id().bytes()), 32);

        // Write k and strength (match_key_bits)
        uint8_t const k = numeric_cast<uint8_t>(params.get_k());
        uint8_t const strength = numeric_cast<uint8_t>(params.get_strength());
        uint8_t const meta_group = numeric_cast<uint8_t>(params.get_meta_group());
        out.write(reinterpret_cast<char const*>(&k), 1);
        out.write(reinterpret_cast<char const*>(&strength), 1);

        out.write(reinterpret_cast<char const*>(&index), 2);
        out.write(reinterpret_cast<char const*>(&meta_group), 1);

        uint8_t const memo_size = static_cast<uint8_t>(memo.size());
        out.write(reinterpret_cast<char const*>(&memo_size), 1);
        out.write(reinterpret_cast<char const*>(memo.data()), memo.size());

        // Write chunk index + chunk bodies:
        //  uint64_t num_chunks
        //  num_chunks * uint64_t offsets (placeholders, overwritten later)
        //  chunk_0 data...
        //  chunk_1 data...
        {
            uint64_t const num_chunks = static_cast<uint64_t>(data.proof_fragments_chunks.size());

            // Write num_chunks
            out.write(reinterpret_cast<char const*>(&num_chunks), sizeof(num_chunks));
            if (!out)
                throw std::runtime_error("Failed to write chunk count to " + filename);

            // Remember where offsets will be written
            std::streampos offsets_start_pos = out.tellp();

            // Write placeholder zero offsets
            uint64_t zero = 0;
            for (uint64_t i = 0; i < num_chunks; ++i) {
                out.write(reinterpret_cast<char const*>(&zero), sizeof(zero));
            }
            if (!out)
                throw std::runtime_error(
                    "Failed to write chunk offset placeholders to " + filename);

            // Collect real offsets as we write chunks
            std::vector<uint64_t> offsets(num_chunks);

            int const stub_bits = params.get_k() - MINUS_STUB_BITS;
            uint64_t const range_per_chunk = (1ULL << (params.get_k() + CHUNK_SPAN_RANGE_BITS));

            for (uint64_t i = 0; i < num_chunks; ++i) {
                // record offset for this chunk (absolute offset from file start)
                std::streampos pos = out.tellp();
                offsets[i] = static_cast<uint64_t>(pos);

                uint64_t start_proof_fragment_range = i * range_per_chunk;
                std::vector<uint8_t> compressed_chunk = ChunkCompressor::compressProofFragments(
                    data.proof_fragments_chunks[i], start_proof_fragment_range, stub_bits);

                writeVector(out, compressed_chunk);
                if (!out) {
                    throw std::runtime_error(
                        "Failed to write chunk " + std::to_string(i) + " to " + filename);
                }
            }

            bytes_written = static_cast<size_t>(out.tellp());

            // Seek back and overwrite placeholders with actual offsets
            out.seekp(offsets_start_pos);
            if (!out)
                throw std::runtime_error("Failed to seek to chunk offsets in " + filename);

            for (uint64_t i = 0; i < num_chunks; ++i) {
                out.write(reinterpret_cast<char const*>(&offsets[i]), sizeof(offsets[i]));
            }
            if (!out)
                throw std::runtime_error("Failed to write chunk offsets to " + filename);

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
            throw std::runtime_error(
                "Plot file format version " + std::to_string(version) + " is not supported.");
        }

        std::array<uint8_t, 32> plot_group_id_bytes;
        in.read(reinterpret_cast<char*>(plot_group_id_bytes.data()), 32);

        uint8_t k;
        in.read(reinterpret_cast<char*>(&k), sizeof(k));

        uint8_t strength;
        in.read(reinterpret_cast<char*>(&strength), sizeof(strength));

        uint16_t index;
        in.read(reinterpret_cast<char*>(&index), sizeof(index));

        uint8_t meta_group;
        in.read(reinterpret_cast<char*>(&meta_group), sizeof(meta_group));

        PlotGroupParams params(PlotGroupId(plot_group_id_bytes), k, strength, meta_group);

        uint8_t memo_length = 0;
        in.read(reinterpret_cast<char*>(&memo_length), sizeof(memo_length));
        // skip memo
        in.seekg(memo_length, std::ifstream::cur);

        PlotFileHeader header(params);
        header.index = index;

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

        auto const& header = *plot_file_header_;

        ChunkedProofFragments chunked;

        uint64_t const num_chunks = header.num_chunks;
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
                throw std::runtime_error(
                    "Failed to seek to chunk " + std::to_string(i) + " in " + filename_);
            }

            uint64_t start_proof_fragment_range = i * range_per_chunk;
            std::vector<uint8_t> compressed_chunk = readVector<uint8_t>(in);
            if (!in) {
                throw std::runtime_error(
                    "Failed to read compressed chunk " + std::to_string(i) + " from " + filename_);
            }

            chunked.proof_fragments_chunks[i] = ChunkCompressor::decompressProofFragments(
                compressed_chunk, start_proof_fragment_range, stub_bits);
        }

        return { .data = std::move(chunked), .params = header.params };
    }

    // Read a single chunk's decompressed proof fragments by index.
    std::vector<uint64_t> readChunk(uint64_t chunk_index)
    {
        readHeadersAndIndexes();
        if (!plot_file_header_) {
            throw std::runtime_error("PlotFileHeader not loaded");
        }

        auto const& header = *plot_file_header_;

        if (chunk_index >= header.num_chunks) {
            throw std::out_of_range("chunk_index out of range");
        }

        std::ifstream in(filename_, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open " + filename_);
        }

        in.seekg(static_cast<std::streamoff>(header.offsets[chunk_index]), std::ios::beg);
        if (!in) {
            throw std::runtime_error(
                "Failed to seek to chunk " + std::to_string(chunk_index) + " in " + filename_);
        }

        int const stub_bits = header.params.get_k() - MINUS_STUB_BITS;
        uint64_t const range_per_chunk = (1ULL << (header.params.get_k() + CHUNK_SPAN_RANGE_BITS));
        uint64_t const start_proof_fragment_range = chunk_index * range_per_chunk;

        std::vector<uint8_t> compressed_chunk = readVector<uint8_t>(in);
        if (!in) {
            throw std::runtime_error(
                "Failed to read chunk " + std::to_string(chunk_index) + " from " + filename_);
        }

        return ChunkCompressor::decompressProofFragments(
            compressed_chunk, start_proof_fragment_range, stub_bits);
    }

    // -------- Static convenience wrappers for reading --------

    static PlotFileContents readAllChunkedData(std::string const& filename)
    {
        PlotFile pf(filename);
        return pf.readAllChunkedData();
    }

    static std::vector<uint64_t> readChunk(std::string const& filename, uint64_t chunk_index)
    {
        PlotFile pf(filename);
        return pf.readChunk(chunk_index);
    }

    PlotGroupParams const& getGroupParams()
    {
        readHeadersAndIndexes();
        if (!plot_file_header_) {
            throw std::runtime_error("PlotFileHeader not loaded");
        }
        return plot_file_header_->params;
    }

    PlotProofParams getProofParams()
    {
        auto& groupParams = getGroupParams();

        return groupParams.get_plot_params_for_index(plot_file_header_->index);
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
        for (auto const& fragment: chunk_fragments) {
            if (fragment >= range.start && fragment < range.end) {
                result.push_back(fragment);
            }
        }

        return result;
    }

    struct PlotFileHeader {
        PlotGroupParams params;
        uint16_t index;
        uint64_t num_chunks = 0;
        std::vector<uint64_t> offsets;
        
        #ifdef RETAIN_X_VALUES_TO_T3
            std::vector<std::array<uint32_t, 8>> xs_correlating_to_proof_fragments;
        #endif

        // Explicit constructor so this type can be constructed
        explicit PlotFileHeader(PlotGroupParams const& p) : params(p) {}
    };

    PlotFileHeader getHeader() {
        readHeadersAndIndexes();
        if (!plot_file_header_) {
            throw std::runtime_error("PlotFileHeader not loaded");
        }

        return plot_file_header_.value();
    }

private:
    uint64_t getRangePerChunk()
    {
        readHeadersAndIndexes();
        if (!plot_file_header_) {
            throw std::runtime_error("PlotFileHeader not loaded");
        }
        // TODO: this will be written with plot eventually, tunable by groupings and disk seq. read
        // speed.
        return (1ULL << (plot_file_header_->params.get_k() + CHUNK_SPAN_RANGE_BITS));
    }

    std::string filename_;
    std::optional<PlotFileHeader> plot_file_header_;
};

template<typename T, typename U>
inline T cdiv( T a, U b ) {
    return ( a + T(b) - T(1) ) / T(b);
}

class PlotGroupFile {
public:
    static constexpr uint8_t          FORMAT_VERSION   = 2;
    static constexpr std::string_view MAGIC_STR        = "PoS2";
    static constexpr uint32_t         MAGIC            = 0x32536f50;   // PoS2
    static constexpr uint8_t          PROOFS_PER_CHUNK_BITS = 6;

    #pragma pack(push, 1)
    struct Header {
        uint32_t    magic;
        uint8_t     version;
        PlotGroupId group_id;
        uint8_t     k;
        uint8_t     strength;
        uint16_t    group_size;
        uint8_t     meta_group;
        uint64_t    chunk_index_offset;
        uint8_t     memo_length;
        // uint8_t[] memo;
    };
    #pragma pack(pop)
    static_assert(sizeof(Header) == 51);
    static_assert(offsetof(Header, chunk_index_offset) == 42);
    static_assert(std::is_standard_layout_v<Header>);

    struct Info {
        uint64_t    chunks_pos;                    // Where the chunk data starts.
        uint64_t    chunk_index_offset;            // Where the index table starts.
        uint64_t    chunk_index_compressed_size;   // Size of the chunk index table.
        PlotGroupId group_id;
        uint16_t    group_size;
        uint8_t     version;
        uint8_t     k;
        uint8_t     strength;
        uint8_t     meta_group;
        uint8_t     memo_length;
    };

    static PlotGroupFile open(std::string const& path)
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open plot group file at " + path);
        }

        in.exceptions(std::ios::badbit | std::ios::failbit);

        Header header = {};
        in.read(reinterpret_cast<char*>(&header), sizeof(header));

        if (header.magic != MAGIC) {
            throw std::runtime_error("Plot file invalid magic bytes, not a plot file");
        }
        if (header.version != FORMAT_VERSION) {
            throw std::runtime_error(
                "Plot file format version " + std::to_string(header.version) + " is not supported.");
        }
        if (header.group_size < 1) {
            throw std::runtime_error("Plot group has no individual plots");
        }

        in.seekg(header.memo_length, std::ifstream::cur); // Skip memo for now


        Info info = {
            .chunks_pos                  = 0,
            .chunk_index_offset          = header.chunk_index_offset,
            .chunk_index_compressed_size = 0,
            .group_id                    = header.group_id,
            .group_size                  = header.group_size,
            .version                     = header.version,
            .k                           = header.k,
            .strength                    = header.strength,
            .meta_group                  = header.meta_group,
            .memo_length                 = header.memo_length,
        };

        info.chunks_pos = static_cast<uint64_t>(in.tellg());


        // Find the file size to ensure the chunks sizes pos is valid
        in.seekg(0, std::ifstream::end);
        auto const file_size = static_cast<size_t>(in.tellg());

        if (info.chunk_index_offset >= file_size) {
            throw std::runtime_error("Invalid chunk index offset");
        }

        info.chunk_index_compressed_size = file_size - info.chunk_index_offset;

        return PlotGroupFile(std::move(in), std::move(info));
    }

    std::vector<uint8_t> readMemo()
    {
        // TODO: Just use fixed-size packed header struct to determine this
        uint64_t const memo_size_offset = info_.chunks_pos - info_.memo_length;

        file_.seekg(memo_size_offset, std::ifstream::beg);

        std::vector<uint8_t> memo((size_t)info_.memo_length);
        file_.read(reinterpret_cast<char*>(memo.data()), (size_t)info_.memo_length);

        return memo;
    }

    // Write a single-plot group file.
    // This merely meant to be used as a helper to satisfy tests.
    static uint64_t writeData(
        std::string const& filename,
        PlotData const& data,
        PlotGroupParams const& params,
        uint8_t const chunk_range_bits,
        std::span<uint8_t const> const memo
    ) {
        uint64_t const range_per_chunk = (1ULL << (params.get_k() + chunk_range_bits));
        auto chunked_data = ChunkedProofFragments::convertToChunkedProofFragments(data, range_per_chunk);
        return writeData(filename, chunked_data, params, chunk_range_bits, memo);
    }

    static uint64_t writeData(
        std::string const& filename,
        ChunkedProofFragments const& data,
        PlotGroupParams const& params,
        uint8_t const chunk_range_bits,
        std::span<uint8_t const> const memo
    ) {
        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        out.exceptions(std::ios::badbit | std::ios::failbit);

        Header header = {
            .magic              = MAGIC,
            .version            = FORMAT_VERSION,
            .group_id           = params.get_plot_group_id(),
            .k                  = numeric_cast<uint8_t>(params.get_k()),
            .strength           = numeric_cast<uint8_t>(params.get_strength()),
            .group_size         = 1,
            .meta_group         = numeric_cast<uint8_t>(params.get_meta_group()),
            .chunk_index_offset = 0,    // Placeholder
            .memo_length        = numeric_cast<uint8_t>(memo.size()),
        };

        // We won't know the real size until we write it at the end of the file.
        // We then seek back to this position and overwrite it with the real value.
        std::streampos const offset_chunk_offsets_ptr = offsetof(Header, chunk_index_offset);

        // Write fixed-size header portion.
        out.write(reinterpret_cast<char const*>(&header), sizeof(header));

        // Write variable-sized memo.
        out.write(reinterpret_cast<char const*>(memo.data()), memo.size());


        /// Write chunks
        uint64_t const range_per_chunk = getRangePerChunkForK(header.k);
        assert(range_per_chunk == (1ull << (uint64_t(header.k) + chunk_range_bits)));

        uint32_t const chunk_count = numeric_cast<uint32_t>(data.proof_fragments_chunks.size());
        if (chunk_count != getChunkCountForK(header.k)) {
            throw std::runtime_error("Unexpected chunk count: " + 
                    std::to_string(chunk_count) + " != " + std::to_string(getChunkCountForK(header.k)));
        }

        uint8_t  const LOW_BITS  = header.k - 8;
        uint64_t const THRESHOLD = (178ull << (header.k-8));
        uint64_t const LOW_MASK  = ((1ull << LOW_BITS) - 1);

        std::vector<uint64_t> chunk_offsets(chunk_count);

        std::vector<uint64_t> chunk_deltas;
        chunk_deltas.reserve(1ull << (PROOFS_PER_CHUNK_BITS+1));

        std::vector<uint8_t> ans_buffer;
        ans_buffer.resize(1ull << chunk_range_bits);

        std::vector<uint8_t>  high_bytes;
        BitWriter unary_and_low_bits;

        FSE_CTable* ct = createFSECTable(); assert(ct);
        Guard ctable_guard([=](){ 
            POS2_FSE_freeCTable(ct); 
        });

        for (size_t chunk_index = 0; chunk_index < data.proof_fragments_chunks.size(); chunk_index++) {
            chunk_deltas = data.proof_fragments_chunks[chunk_index];

            // Record offset for this chunk (absolute offset from file start)
            chunk_offsets[chunk_index] = static_cast<uint64_t>(out.tellp());

            /// Deltafy fragments
            assert(!chunk_deltas.empty());

            uint64_t const start_proof_fragment_range = chunk_index * range_per_chunk;

            // Add the first one in case it is equal to start_proof_fragment_range
            // which we ought not skip as a duplicate.
            uint64_t prev_value = chunk_deltas[0];
            chunk_deltas[0] = prev_value - start_proof_fragment_range;

            size_t chunk_frag_count = 1;

            for (size_t i = 1; i < chunk_deltas.size(); i++) {
                uint64_t const fragment = chunk_deltas[i];

                // Ensure no duplicate proof fragment exists
                if (fragment == prev_value) {
                    continue;
                }

                uint64_t const delta = fragment - prev_value;
                prev_value = fragment;

                chunk_deltas[chunk_frag_count++] = delta;
            }

            chunk_deltas.resize(chunk_frag_count);

            /// Encode deltas
            high_bytes.resize(chunk_deltas.size());
            unary_and_low_bits.clear();

            for (size_t i = 0; i < chunk_deltas.size(); i++) {
                uint64_t const d = chunk_deltas[i];

                uint64_t const quotient  = d / THRESHOLD;
                uint64_t const remainder = d - quotient * THRESHOLD; // Same: quotient % THRESHOLD

                uint64_t unary_value = (1ull << quotient) - 1;
                assert(quotient + 1 + LOW_BITS <= 64);

                uint64_t low_bits                 = remainder & LOW_MASK;
                uint64_t unary_and_low_bits_field = (unary_value << LOW_BITS) | low_bits;

                unary_and_low_bits.append(unary_and_low_bits_field, uint32_t(1 + quotient + LOW_BITS));

                uint64_t const high_byte = remainder >> LOW_BITS;
                assert(high_byte < 256);

                high_bytes[i] = uint8_t(high_byte);
            }

            // Compress high bytes with FSE
            size_t ans_size = 0;

            constexpr int MAX_RETRIES = 5;
            for (int retry = 0; retry < MAX_RETRIES; retry++) {

                ans_size = POS2_FSE_compress_usingCTable(
                    ans_buffer.data(), ans_buffer.capacity(), 
                    high_bytes.data(), high_bytes.size(), ct);

                bool buffer_too_small = ans_size == 0 ||
                    (POS2_FSE_isError(ans_size) && 
                        -FSE_ErrorCode(ans_size) == FSE_error_dstSize_tooSmall);

                if (buffer_too_small) {
                    if (retry+1 < MAX_RETRIES)  {
                        ans_buffer.resize(ans_buffer.capacity() * 2);
                        continue;
                    }

                    std::string error = "Buffer too small after " + std::to_string(MAX_RETRIES) + " tries";
                    if (POS2_FSE_isError(ans_size)) {
                        error = POS2_FSE_getErrorName(ans_size);
                    }

                    throw std::runtime_error("FSE_compress_usingCTable error: " + error);
                }
                else if (ans_size > chunk_deltas.size()) {
                    throw std::runtime_error("ANS is larger than raw bytes");
                }

                // OK
                break;
            }

            assert(ans_size > 0);
            assert(ans_size <= chunk_deltas.size());

            // LEB128-encode the ans_size
            {
                uint64_t const ans_size_bit_count      = (sizeof(ans_size) * 8) - std::countl_zero(ans_size);
                uint64_t const ans_size_leb_byte_count = cdiv(ans_size_bit_count, 7);

                assert(ans_size_leb_byte_count <= 16);

                uint8_t ans_size_leb[16] = {};

                for (size_t i = 0; i < ans_size_leb_byte_count; i++) {
                    ans_size_leb[i] = 0x80 | uint8_t((ans_size >> (i * 7)) & 0x7f);
                }

                // Clear last byte's MSbit
                ans_size_leb[ans_size_leb_byte_count-1] &= 0x7f;

                out.write(reinterpret_cast<char const*>(ans_size_leb), ans_size_leb_byte_count);
            }

            // Write ANS portion
            out.write(reinterpret_cast<char const*>(ans_buffer.data()), ans_size);

            // Write non-ANS bits
            std::span<uint8_t const> non_ans_bytes = unary_and_low_bits.asBytes();
            out.write(reinterpret_cast<char const*>(non_ans_bytes.data()), non_ans_bytes.size());
        }

        assert(chunk_offsets.size() == chunk_count);

        auto const chunk_index_offset = static_cast<uint64_t>(out.tellp());

        // Seek to where the header stores the chunk index address
        out.seekp(offset_chunk_offsets_ptr, std::ios::beg);
        out.write(reinterpret_cast<char const*>(&chunk_index_offset), sizeof(uint64_t));

        // Now seek back and write the chunk index
        out.seekp(chunk_index_offset, std::ios::beg);

        // Deltafy chunk offsets to convert them to sizes
        for (size_t i = 0; i < chunk_offsets.size()-1; i++) {
            chunk_offsets[i] = chunk_offsets[i+1] - chunk_offsets[i];
        }

        chunk_offsets.back() = chunk_index_offset - chunk_offsets.back();

        BitWriter chunk_index_writer;
        chunk_index_writer.clear();
        gsz_encode(chunk_offsets, header.group_size, chunk_index_writer);

        std::span<uint8_t const> const chunk_index_bytes = chunk_index_writer.asBytes();
        out.write(reinterpret_cast<char const*>(chunk_index_bytes.data()), chunk_index_bytes.size());

        return static_cast<uint64_t>(out.tellp());
    }

    std::vector<std::vector<ProofFragment>> readProofsInRange(Range const& range)
    {
        uint64_t const range_per_chunk = getRangePerChunk();
        uint64_t const chunk_start = range.start / range_per_chunk;
        uint64_t const chunk_end = (range.end - 1) / range_per_chunk;

        std::vector<std::vector<ProofFragment>> plot_proof_fragments(info_.group_size);
        plot_proof_fragments.resize(info_.group_size);

        for (uint64_t c = chunk_start; c <= chunk_end; c++) {
            readChunk(c, plot_proof_fragments, range);
        }

        return plot_proof_fragments;
    }

    void readChunk(const uint64_t chunk_index, std::span<std::vector<ProofFragment>> out_fragments, std::optional<Range> target_range = std::nullopt)
    {
        if (out_fragments.size() < info_.group_size) {
            throw std::runtime_error("Output plot proof fragment span is too small");
        }

        out_fragments = out_fragments.subspan(0, info_.group_size);

        if (chunk_offsets_.empty()) {
            readChunkOffsets();
        }

        if (chunk_index >= chunk_offsets_.size()) {
            throw std::runtime_error("Chunk index is out of range");
        }

        uint64_t const REGION_RANGE = getRangePerChunk();
        uint64_t const ENTRIES_PER_REGION = 1ull << PROOFS_PER_CHUNK_BITS;

        uint64_t const chunk_count  = getChunkCount();
        uint64_t const chunk_offset = chunk_offsets_[chunk_index];

        size_t chunk_size = 0;
        if (chunk_index == chunk_count - 1) {
            chunk_size = size_t(info_.chunk_index_offset - chunk_offset);
        } else {
            chunk_size = size_t(chunk_offsets_[chunk_index+1] - chunk_offset);
        }

        file_.seekg(chunk_offset, std::ifstream::beg);

        std::vector<uint8_t> chunk_buffer{};
        chunk_buffer.resize(chunk_size);

        file_.read(reinterpret_cast<char*>(chunk_buffer.data()), chunk_size);

        std::span<uint8_t> chunk_reader = chunk_buffer;

        // Read the size for the ANS-compressed portion, which is encoded as LEB128
        uint64_t ans_blob_size = 0;
        for (int i = 0; i < 16; i++) {
            uint64_t value = chunk_reader[0];
            chunk_reader = chunk_reader.subspan(1, chunk_reader.size()-1);

            ans_blob_size |= (value & 0x7f) << (i*7);

            if ((value & 0x80) == 0) {
                break;
            }
        }

        if (ans_blob_size >= chunk_reader.size()) {
            throw std::runtime_error("Invalid ANS blob size");
        }

        const uint64_t entries_per_chunk = uint64_t(ENTRIES_PER_REGION) * info_.group_size;

        std::vector<uint8_t> high_bytes{};
        high_bytes.resize(entries_per_chunk + (entries_per_chunk / 3) * 2);

        uint64_t deltas_count = 0;

        // Read ANS blob
        {
            FSE_DTable* dtable = createFSEDTable();

            deltas_count = POS2_FSE_decompress_usingDTable(
                high_bytes.data(), high_bytes.size(), 
                chunk_reader.data(), ans_blob_size, dtable);

            POS2_FSE_freeDTable(dtable); dtable = nullptr;

            chunk_reader = chunk_reader.subspan(ans_blob_size, chunk_reader.size() - ans_blob_size);

            if (POS2_FSE_isError(deltas_count)) {
                std::string error = "FSE_decompress_usingDTable error " + std::to_string(deltas_count) + ": "
                    + POS2_FSE_getErrorName(deltas_count);
                throw std::runtime_error(error);
            }
            if (deltas_count == 0) {
                throw std::runtime_error("No deltas found in ANS data");
            }

            high_bytes.resize(deltas_count);
        }

        /// Decode deltas
        const uint64_t LOW_BITS = uint64_t(info_.k - 8);
        const uint64_t THRESHOLD = uint64_t(178) << LOW_BITS;

        const size_t field_count = (chunk_reader.size() + sizeof(uint64_t) - 1) / sizeof(uint64_t);

        std::vector<uint64_t> compressed_bits(field_count);
        memcpy(compressed_bits.data(), chunk_reader.data(), chunk_reader.size());

        std::vector<uint64_t> proof_deltas(deltas_count);

        size_t deltas_decoded = 0;
        size_t field_index = 0;
        uint64_t field = 0;
        uint64_t field_bits_decoded = 64;

        while (deltas_decoded < deltas_count) {
            uint64_t low_bits = 0;
            uint64_t low_bits_needed = LOW_BITS;

            // Decode fixed-size low bits
            while (low_bits_needed > 0) {
                if (field_bits_decoded == 64) {
                    if (field_index >= compressed_bits.size()) {
                        throw std::runtime_error("Overflowed compressed bits");
                    }

                    field = compressed_bits[field_index];
                    field_index += 1;
                    field_bits_decoded = 0;
                }

                uint64_t const field_bits_available = 64 - field_bits_decoded;
                uint64_t const bits_to_decode = std::min(low_bits_needed, field_bits_available);
                uint64_t const mask = (uint64_t(1) << bits_to_decode) - 1;

                uint64_t const new_bits = (field >> field_bits_decoded) & mask;
                low_bits |= new_bits << (LOW_BITS - low_bits_needed);
                low_bits_needed -= bits_to_decode;
                field_bits_decoded += bits_to_decode;
            }

            // Decode unary bits
            uint64_t quotient = 0;
            while (true) {
                if (field_bits_decoded == 64) {
                    if (field_index >= compressed_bits.size()) {
                        throw std::runtime_error("Overflowed compressed bits");
                    }

                    field = compressed_bits[field_index];
                    field_index += 1;
                    field_bits_decoded = 0;
                }

                uint64_t const unary_field_bits = field >> field_bits_decoded;
                uint64_t const field_bits_available = 64 - field_bits_decoded;
                uint64_t const ones = Bits::count_trailing_ones(unary_field_bits, field_bits_available);

                quotient += ones;
                field_bits_decoded += ones;

                if (ones < field_bits_available) {
                    field_bits_decoded += 1;    // Account for zero-bit sentinel
                    break;
                }
            }

            if (quotient > 64) {
                throw std::runtime_error(
                    "Invalid quotient at delta " + std::to_string(deltas_decoded) + ": "
                    + std::to_string(quotient));
            }

            uint64_t const remainder = (uint64_t(high_bytes[deltas_decoded]) << LOW_BITS) | low_bits;
            uint64_t const delta = quotient * THRESHOLD + remainder;

            proof_deltas[deltas_decoded++] = delta;
        }


        /// De-deltafy
        uint64_t region_start = REGION_RANGE * chunk_index;
        uint64_t region_end   = region_start + REGION_RANGE;
        uint64_t virtual_region = 0;


        uint64_t prev_value = region_start;

        int plot_index = 0;
        std::vector<uint64_t>* current_plot_fragments = &out_fragments[0];
        current_plot_fragments->reserve(current_plot_fragments->size() + ENTRIES_PER_REGION+16);

        Range range = target_range.value_or(Range{ 0, std::numeric_limits<uint64_t>::max() });

        for (size_t i = 0; i < deltas_count; i++) {
            uint64_t delta = proof_deltas[i];
            uint64_t value = delta + prev_value;

            prev_value = value;

            if (value >= region_end) {
                // Out of bounds: This means we start the next plot's region

                if (current_plot_fragments->size() < 1) {
                    throw std::runtime_error("Plot at index " + std::to_string(plot_index) + " had no proof fragments");
                }

                // Begin next plot's proof fragment
                plot_index ++;
                if (plot_index >= info_.group_size) {
                    throw std::runtime_error("Malformed plot group");
                }

                current_plot_fragments = &out_fragments[plot_index];
                current_plot_fragments->reserve(current_plot_fragments->size() + ENTRIES_PER_REGION+16);

                virtual_region += REGION_RANGE;
                region_end += REGION_RANGE;
            }

            value -= virtual_region;

            if (range.isInRange(value)) {
                current_plot_fragments->push_back(value);
            }
        }
    }

    PlotGroupParams getGroupProofParams() const
    {
        return PlotGroupParams(info_.group_id, info_.k, info_.strength, info_.meta_group);
    }

    PlotProofParams getProofParamsForPlotIndex(uint16_t plot_index) const
    {
        return getGroupProofParams().get_plot_params_for_index(plot_index);
    }

    Info const& getInfo() const
    {
        return info_;
    }

    static inline uint64_t getChunkCountForK(uint8_t k)
    {
        return (1ull << (k*2)) / getRangePerChunkForK(k);
    }

    inline uint64_t getChunkCount() const
    {
        return getChunkCountForK(info_.k);
    }

    inline void clearChunkOffsets()
    {
        chunk_offsets_.resize(0);
        chunk_offsets_.shrink_to_fit();
    }

private:
    PlotGroupFile(std::ifstream&& file, Info&& info) 
        : file_(std::move(file))
        , info_(info)
    {}

    static inline uint64_t getRangePerChunkForK(uint8_t k)
    {
        return (1ull << (k + PROOFS_PER_CHUNK_BITS));
    }

    inline uint64_t getRangePerChunk() const
    {
        return getRangePerChunkForK(info_.k);
    }

    void readChunkOffsets() 
    try {
        uint64_t const chunk_count = getChunkCount();
        if (chunk_offsets_.size() == chunk_count) {
            return;
        }

        file_.seekg(info_.chunk_index_offset, std::ifstream::beg);

        // Must be uint64s as we will read as a bitfield stored in 64-bit fields
        std::vector<uint64_t> read_buffer(cdiv(info_.chunk_index_compressed_size, 8));

        file_.read(reinterpret_cast<char*>(read_buffer.data()), info_.chunk_index_compressed_size);

        BitReader reader(read_buffer, (size_t)info_.chunk_index_compressed_size * 8);
        
        chunk_offsets_.resize(chunk_count);
        gsz_decode(chunk_offsets_, info_.group_size, reader);

        // De-deltafy to convert to offsets
        uint64_t prev_offset = info_.chunks_pos;
        for (size_t i = 0; i < chunk_offsets_.size(); i++) {
            uint64_t next_offset = prev_offset + chunk_offsets_[i];
            chunk_offsets_[i] = prev_offset;
            prev_offset = next_offset;
        }
    }
    catch (std::exception const&) {
        chunk_offsets_.clear();
        throw;
    }

    static FSE_DTable* createFSEDTable()
    {
        std::array<short, 256> norm{};
        auto [max_sym, table_log] = createFSENormCounts(norm);

        FSE_DTable* dt = POS2_FSE_createDTable(table_log);
        if (dt == nullptr) {
            throw std::runtime_error("FSE_createDTable failed");
        }

        size_t const r = POS2_FSE_buildDTable(dt, norm.data(), max_sym, table_log);
        if (POS2_FSE_isError(r)) {
            POS2_FSE_freeDTable(dt);
            throw std::runtime_error(
                "FSE_buildDTable failed: " + std::string(POS2_FSE_getErrorName(r)));
        }

        return dt;
    }

    static FSE_DTable* createFSECTable()
    {
        std::array<short, 256> norm{};
        auto [max_sym, table_log] = createFSENormCounts(norm);

        FSE_CTable* ct = POS2_FSE_createCTable(max_sym, table_log);
        if (ct == nullptr) {
            throw std::runtime_error("FSE_createCTable failed");
        }

        size_t const r = POS2_FSE_buildCTable(ct, norm.data(), max_sym, table_log);
        if (POS2_FSE_isError(r)) {
            POS2_FSE_freeCTable(ct);
            throw std::runtime_error(
                "FSE_buildCTable failed: " + std::string(POS2_FSE_getErrorName(r)));
        }

        return ct;
    }

    static std::tuple<unsigned, unsigned> createFSENormCounts(std::span<short, 256> norm)
    {
        static constexpr int MAX_HIGH = 177;
        static constexpr unsigned max_sym = MAX_HIGH;
        static constexpr unsigned table_log = 11;
        static constexpr int table_size = 1 << table_log;

        // short norm[256] = {};
        double weights[MAX_HIGH + 1] = {};

        double total_w = 0.0;
        for (int k = 0; k <= MAX_HIGH; ++k) {
            weights[k] = std::exp(-static_cast<double>(k) / 256.0);
            total_w += weights[k];
        }

        int assigned = 0;
        for (int k = 0; k <= MAX_HIGH; ++k) {
            norm[k] = static_cast<short>(weights[k] / total_w * table_size + 0.5);
            if (norm[k] < 1) {
                norm[k] = 1;
            }

            assigned += static_cast<int>(norm[k]);
        }

        norm[0] += static_cast<short>(table_size - assigned);

        return { max_sym, table_log };
    }

private:
    std::ifstream file_;
    Info info_;
    std::vector<uint64_t> chunk_offsets_;
};
