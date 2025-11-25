#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "PlotIO.hpp"

#define DEBUG_PLOT_FILE true

enum class PlotLayoutKind {
    Flat,        // global t3, ranges, per-partition t4/t5
    Partitioned  // per-partition t3, t4, t5
};


// -----------------------------------------------------------------------------
// Layout utilities (used in Partitioned layout).
// -----------------------------------------------------------------------------

inline size_t map_t4_to_t3_lateral_partition(size_t t4_partition,
                                             size_t num_partitions)
{
    return (t4_partition < num_partitions)
           ? (t4_partition * 2)
           : ((t4_partition - num_partitions) * 2 + 1);
}

inline size_t map_t3_lateral_partition_to_t4(size_t t3_lateral_partition,
                                             size_t num_partitions)
{
    return (t3_lateral_partition % 2 == 0)
           ? (t3_lateral_partition / 2)
           : (num_partitions + (t3_lateral_partition - 1) / 2);
}

// -----------------------------------------------------------------------------
// Layout policies
// -----------------------------------------------------------------------------

struct FlatLayout
{
    using Data = PlotData;

    // The policy writes *body* data and collects per-partition offsets.
    static void writeBody(std::ofstream& out,
                          Data const& data,
                          ProofParams const& params,
                          std::vector<uint64_t>& outOffsets)
    {
        // Write non-partitioned data: global t3 + lateral ranges.
        writeVector(out, data.t3_proof_fragments);
        writeRanges(out, data.t4_to_t3_lateral_ranges);

        const uint64_t outer = static_cast<uint64_t>(
            data.t4_to_t3_back_pointers.size()
        );
        outOffsets.clear();
        outOffsets.reserve(outer);

        // Now write each partition's t4 then t5 vectors; record offsets.
        for (uint64_t i = 0; i < outer; ++i) {
            uint64_t offset = static_cast<uint64_t>(out.tellp());
            outOffsets.push_back(offset);
            writeVector(out, data.t4_to_t3_back_pointers[static_cast<size_t>(i)]);
            writeVector(out, data.t5_to_t4_back_pointers[static_cast<size_t>(i)]);
        }

    #ifdef RETAIN_X_VALUES_TO_T3
        writeVector(out, data.xs_correlating_to_proof_fragments);
    #endif
    }

    // Read the non-partitioned body (global t3 + ranges + optional xs).
    // Called with stream positioned immediately after partition_offsets.
    static void readNonPartitionBody(std::ifstream& in,
                                     Data& data,
                                     ProofParams const& params,
                                     std::vector<uint64_t> const& partition_offsets)
    {
        data = PlotData{};

        data.t3_proof_fragments = readVector<uint64_t>(in);
        data.t4_to_t3_lateral_ranges = readRanges(in);

        const size_t outer = static_cast<size_t>(partition_offsets.size());
        data.t4_to_t3_back_pointers.assign(outer, {});
        data.t5_to_t4_back_pointers.assign(outer, {});

    #ifdef RETAIN_X_VALUES_TO_T3
        data.xs_correlating_to_proof_fragments =
            readVector<std::array<uint32_t, 8>>(in);
    #endif
    }

    static void ensurePartitionLoaded(Data& data,
                                      std::ifstream& in,
                                      size_t partition_index,
                                      std::vector<uint64_t> const& offsets)
    {
        in.seekg(static_cast<std::streamoff>(offsets[partition_index]),
                 std::ios::beg);
        data.t4_to_t3_back_pointers[partition_index] =
            readVector<T4PlotBackPointers>(in);
        data.t5_to_t4_back_pointers[partition_index] =
            readVector<T5PlotBackPointers>(in);
    }

    static bool isPartitionLoaded(Data const& data, size_t idx)
    {
        return !data.t4_to_t3_back_pointers[idx].empty()
            || !data.t5_to_t4_back_pointers[idx].empty();
    }

    static uint64_t computeOuter(Data const& data,
                                 ProofParams const& params)
    {
        // For flat layout, outer is size of t4_to_t3_back_pointers.
        return static_cast<uint64_t>(data.t4_to_t3_back_pointers.size());
    }
};

struct PartitionedLayout
{
    using Data = PartitionedPlotData;

    static void writeBody(std::ofstream& out,
                          Data const& data,
                          ProofParams const& params,
                          std::vector<uint64_t>& outOffsets)
    {
        const uint64_t outer =
            static_cast<uint64_t>(data.t4_to_t3_back_pointers.size());
        outOffsets.clear();
        outOffsets.reserve(outer);

        for (uint64_t i = 0; i < outer; ++i) {
            uint64_t offset = static_cast<uint64_t>(out.tellp());
            outOffsets.push_back(offset);

            writeVector(out, data.t3_proof_fragments[static_cast<size_t>(i)]);
            writeVector(out, data.t4_to_t3_back_pointers[static_cast<size_t>(i)]);
            writeVector(out, data.t5_to_t4_back_pointers[static_cast<size_t>(i)]);
        }

    #ifdef RETAIN_X_VALUES_TO_T3
        // Not supported in your current partitioned format.
        throw std::runtime_error("RETAIN_X_VALUES_TO_T3 is not supported "
                                 "for PartitionedLayout");
    #endif
    }

    static void readNonPartitionBody(std::ifstream& in,
                                     Data& data,
                                     ProofParams const& params,
                                     std::vector<uint64_t> const& partition_offsets)
    {
        // For partitioned layout, there is no non-partition global t3/ranges.
        const size_t outer = static_cast<size_t>(partition_offsets.size());
        data.t3_proof_fragments.assign(outer, {});
        data.t4_to_t3_back_pointers.assign(outer, {});
        data.t5_to_t4_back_pointers.assign(outer, {});

        // Stream is already positioned at first partition; actual reads
        // are deferred to ensurePartitionLoaded().
    }

    static void ensureT3PartitionLoaded(Data& data,
                                      std::ifstream& in,
                                      size_t partition_index,
                                      std::vector<uint64_t> const& offsets)
    {
        if (PartitionedLayout::isT3PartitionLoaded(data, partition_index)) {
            return;
        }
        in.seekg(static_cast<std::streamoff>(offsets[partition_index]),
                 std::ios::beg);
        data.t3_proof_fragments[partition_index] =
            readVector<ProofFragment>(in);
    }

    static void ensurePartitionLoaded(Data& data,
                                      std::ifstream& in,
                                      size_t partition_index,
                                      std::vector<uint64_t> const& offsets)
    {
        if (PartitionedLayout::isPartitionLoaded(data, partition_index)) {
            return;
        }
        in.seekg(static_cast<std::streamoff>(offsets[partition_index]),
                 std::ios::beg);
        data.t3_proof_fragments[partition_index] =
            readVector<ProofFragment>(in);
        data.t4_to_t3_back_pointers[partition_index] =
            readVector<PartitionedBackPointer>(in);
        data.t5_to_t4_back_pointers[partition_index] =
            readVector<T5PlotBackPointers>(in);
    }

    static bool isT3PartitionLoaded(Data const& data, size_t idx)
    {
        return !data.t3_proof_fragments[idx].empty();
    }

    static bool isPartitionLoaded(Data const& data, size_t idx)
    {
        return !data.t3_proof_fragments[idx].empty()
            || !data.t4_to_t3_back_pointers[idx].empty()
            || !data.t5_to_t4_back_pointers[idx].empty();
    }

    static uint64_t computeOuter(Data const& data,
                                 ProofParams const& params)
    {
        // For partitioned layout, outer is t4_to_t3_back_pointers.size().
        return static_cast<uint64_t>(data.t4_to_t3_back_pointers.size());
    }
};

// -----------------------------------------------------------------------------
// Unified PlotFileT
// -----------------------------------------------------------------------------

template <typename LayoutPolicy>
class PlotFileT
{
public:
    using Data = typename LayoutPolicy::Data;

#ifdef RETAIN_X_VALUES_TO_T3
    static constexpr uint8_t FORMAT_VERSION = 3;
#else
    static constexpr uint8_t FORMAT_VERSION = 1;
#endif

    struct Contents {
        Data        data;
        ProofParams params;
        // Offsets to each partition's data on disk.
        std::vector<uint64_t> partition_offsets;

        static inline constexpr std::array<uint8_t, 32> ZERO_PLOT_ID{};
        Contents()
            : data()
            , params(ZERO_PLOT_ID.data(), 28, 2)
            , partition_offsets()
        {}
    };

    // Construct from in-memory data
    PlotFileT(const ProofParams& params,
              std::span<uint8_t const, 32 + 48 + 32> memo,
              const Data& data)
        : filename_()
    {
        contents_.params = params;
        contents_.data   = data;
        std::memcpy(memo_.data(), memo.data(), memo.size());
    }

    // Load only headers and partition offsets from file (lazy body).
    explicit PlotFileT(const std::string& filename)
        : filename_(filename)
    {
        memo_.fill(0);
        readHeadersFromFile();
    }

    // Write out using current internal state.
    void writeToFile(const std::string& filename) const
    {
        std::ofstream out(filename, std::ios::binary);
        if (!out)
            throw std::runtime_error("Failed to open " + filename);

        // Header
        out.write("pos2", 4);
        out.write(reinterpret_cast<char const*>(&FORMAT_VERSION), 1);

        out.write(reinterpret_cast<char const*>(
                      contents_.params.get_plot_id_bytes()),
                  32);

        const uint8_t k =
            numeric_cast<uint8_t>(contents_.params.get_k());
        const uint8_t match_key_bits =
            numeric_cast<uint8_t>(contents_.params.get_match_key_bits());
        out.write(reinterpret_cast<char const*>(&k), 1);
        out.write(reinterpret_cast<char const*>(&match_key_bits), 1);

        out.write(reinterpret_cast<char const*>(memo_.data()),
                  memo_.size());

        // outer = number of partitions for this layout
        // TODO: replace with params count.
        const uint64_t outer =
            LayoutPolicy::computeOuter(contents_.data, contents_.params);
        out.write(reinterpret_cast<char const*>(&outer), sizeof(outer));

        // Reserve space for offsets (all zeros for now)
        const std::streampos offsets_pos = out.tellp();
        uint64_t zero = 0;
        for (uint64_t i = 0; i < outer; ++i) {
            out.write(reinterpret_cast<char const*>(&zero), sizeof(zero));
        }

        // Body write (non-partition + per-partition data)
        std::vector<uint64_t> offsets;
        LayoutPolicy::writeBody(out, contents_.data, contents_.params, offsets);

        if (offsets.size() != outer) {
            throw std::runtime_error("LayoutPolicy::writeBody produced "
                                     "offset count mismatch");
        }

        // Backfill offsets
        if (outer) {
            out.seekp(offsets_pos);
            for (auto off : offsets) {
                out.write(reinterpret_cast<char const*>(&off), sizeof(off));
            }
            out.seekp(0, std::ios::end);
        }

        if (!out)
            throw std::runtime_error("Failed to write " + filename);
    }

    // Lazy-load a specific partition from disk.
    void ensurePartitionLoaded(size_t partition_index)
    {
        if (partition_index >= contents_.partition_offsets.size())
            throw std::out_of_range("Partition index out of range");

        if (LayoutPolicy::isPartitionLoaded(contents_.data, partition_index))
            return;

        if (filename_.empty())
            throw std::runtime_error("No filename associated with PlotFileT");

        std::ifstream in(filename_, std::ios::binary);
        if (!in)
            throw std::runtime_error("Failed to open " + filename_);

        // We already know offsets; no need to re-read header.
        LayoutPolicy::ensurePartitionLoaded(
            contents_.data,
            in,
            partition_index,
            contents_.partition_offsets
        );

        if (!in)
            throw std::runtime_error("Failed to read partition "
                                     + std::to_string(partition_index)
                                     + " from " + filename_);
    }

    // Accessors
    const Contents&    getContents() const { return contents_; }
    // If you need non-const access, uncomment below:
    // Contents&          getContents()       { return contents_; }
    const ProofParams& getProofParams()  const  { return contents_.params; }

    void setMemo(std::span<uint8_t const, 32 + 48 + 32> memo)
    {
        std::memcpy(memo_.data(), memo.data(), memo.size());
    }
    const auto& getMemo() const { return memo_; }

    const std::string& getFilename() const { return filename_; }

private:
    std::string filename_;
    Contents    contents_;
    std::array<uint8_t, 32 + 48 + 32> memo_{};

    void readHeadersFromFile()
    {
        std::ifstream in(filename_, std::ios::binary);
        if (!in)
            throw std::runtime_error("Failed to open plot file '" + filename_ + "'");
        readHeadersFromStream(in);

        loadNonPartitionBody();
        // Just headers + partition offsets here; body is loaded via
        // loadNonPartitionBody() / ensurePartitionLoaded().
    }

    // Optionally read non-partition body (global t3 / ranges / xs etc).
    // For PartitionedLayout this will just size the vectors.
    void loadNonPartitionBody()
    {
        if (filename_.empty()) return;

        std::ifstream in(filename_, std::ios::binary);
        if (!in)
            throw std::runtime_error("Failed to open " + filename_);

        // Re-read header to position stream correctly.
        readHeadersFromStream(in);

        LayoutPolicy::readNonPartitionBody(
            in,
            contents_.data,
            contents_.params,
            contents_.partition_offsets
        );

        if (!in)
            throw std::runtime_error("Failed to read non-partition body from "
                                     + filename_);
    }

    void readHeadersFromStream(std::ifstream& in)
    {
        std::cout << "PlotFile:: readHeadersFromStream " << filename_ << std::endl;
        char magic[4] = {};
        in.read(magic, sizeof(magic));
        if (std::memcmp(magic, "pos2", 4) != 0) {
            throw std::runtime_error("Plot file invalid magic bytes, not a plot file");
        }

        uint8_t version = 0;
        in.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (version != FORMAT_VERSION) {
            throw std::runtime_error(
                "Plot file format version "
                + std::to_string(version)
                + " is not supported (expected "
                + std::to_string(FORMAT_VERSION) + ")"
            );
        }

        uint8_t plot_id_bytes[32];
        in.read(reinterpret_cast<char*>(plot_id_bytes), 32);

        uint8_t k = 0;
        in.read(reinterpret_cast<char*>(&k), sizeof(k));

        uint8_t strength = 0;
        in.read(reinterpret_cast<char*>(&strength), sizeof(strength));

        contents_.params = ProofParams(plot_id_bytes, k, strength);

        in.read(reinterpret_cast<char*>(memo_.data()), memo_.size());

        uint64_t outer = 0;
        in.read(reinterpret_cast<char*>(&outer), sizeof(outer));
        contents_.partition_offsets.assign(static_cast<size_t>(outer), 0);

        for (uint64_t i = 0; i < outer; ++i) {
            in.read(reinterpret_cast<char*>(&contents_.partition_offsets[i]),
                    sizeof(contents_.partition_offsets[i]));
        }

        if (!in)
            throw std::runtime_error("Failed to read plot file headers");
    }
};

// Convenient aliases for your two formats:

using FlatPlotFile        = PlotFileT<FlatLayout>;
using PartitionedPlotFile = PlotFileT<PartitionedLayout>;
