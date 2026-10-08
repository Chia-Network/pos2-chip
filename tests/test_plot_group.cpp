#include "common/Utils.hpp"
#include "pos/ProofParams.hpp"
#include "pos/ProofValidator.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include "prove/Prover.hpp"
#include "solve/Solver.hpp"
#include "pos/sha/sha256.hpp"
#include "test_util.h"

#include <filesystem>
#include <set>

TEST_SUITE_BEGIN("plot-group");

TEST_CASE("plot-parameter-strength-limit")
{
    CHECK_NOTHROW(PlotGroupParams(PlotGroupId {}, 18, 15, 0));
    CHECK_NOTHROW(PlotProofParams::create_raw(PlotId {}, 18, 15));
    CHECK_THROWS_AS(PlotGroupParams(PlotGroupId {}, 18, 16, 0), std::invalid_argument);
    CHECK_THROWS_AS(PlotProofParams::create_raw(PlotId {}, 18, 16), std::invalid_argument);
    CHECK_NOTHROW(PlotGroupParams(PlotGroupId {}, 20, 17, 0));
}

TEST_CASE("plot-group-full")
{
    constexpr const char* CHALLENGE_HEX = "3e91b7d4c82a506f14fd63a9b075ec219a46d8f3527b1c0ee6a934850dcf7200";
    constexpr const char* PLOT_GROUP_ID_HEX = "c6b84729c23dc6d60c92f22c17083f47845c1179227c5509f07a5d2804a7b835";
    constexpr int k = 18;
    constexpr int strength = 2;

    PlotGroupId plot_group_id(PLOT_GROUP_ID_HEX);

    PlotGroupParams group_params(plot_group_id, k, strength, 0);
    PlotProofParams params = group_params.get_plot_params_for_index(0);
    Plotter plotter(params);
    PlotData plot = plotter.run();

    // Create a plot and serialize it as a plot group
    std::filesystem::create_directories(".test_plots");
    std::string file_name = (std::string(".test_plots/test-plot-") + "k") +
                             std::to_string(k) + "_" + PLOT_GROUP_ID_HEX +
                             ".test_plot.bin";

    PlotGroupFile::writeData(
        file_name, plot, group_params, PlotGroupFile::PROOFS_PER_CHUNK_BITS, {});

    GroupProver prover(file_name);

    std::array<uint8_t, 32> challenge = Utils::hexToBytes(CHALLENGE_HEX);
    std::vector<PlotQualityChains> quality_chains;
    bool found_quality = false;

    for (uint16_t challenge_index = 0; challenge_index < 256; challenge_index++) {
        challenge.back() = uint8_t(challenge_index);
        quality_chains = prover.prove(challenge);

        for (auto const& pqc : quality_chains) {
            if (!pqc.quality_chains.empty()) {
                found_quality = true;
                break;
            }
        }

        if (found_quality) {
            break;
        }
    }

    ENSURE(found_quality);

    for (auto& pqc : quality_chains) {
        ProofValidator proof_validator(group_params, 0);

        for (auto& qc: pqc.quality_chains) {
            std::vector<uint32_t> x_bits_list;
            ProofFragmentCodec fragment_codec(params);

            for (auto const& fragment: qc.chain_links) {
                std::array<uint32_t, 4> x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);

                for (auto const& x_bit: x_bits) {
                    x_bits_list.push_back(x_bit);
                }
            }

            Solver solver(params);
            auto proofs = solver.solve(Solver::XBitsList(x_bits_list));

            ENSURE(!proofs.empty());

            for (auto const& proof: proofs) {
                std::optional<QualityChainLinks> validated_chain
                    = proof_validator.validate_full_proof(proof, challenge);

                ENSURE(validated_chain.has_value());
            }
        }
    }
}

TEST_CASE("test_no_duplicate_qualities_for_known_challenge")
{
    uint8_t k = 18;
    uint8_t strength = 2;
    uint16_t index = 0;
    uint8_t meta_group = 0;
    PlotGroupId plot_group_id("1212121212121212121212121212121212121212121212121212121212121212");
    std::array<uint8_t, 112> memo = {};

    std::filesystem::create_directories(".test_plots");
    std::string plot_path = ".test_plots/pos2_dup_qualities_k18.gplot";

    if (!std::filesystem::exists(plot_path)) {
        PlotGroupParams group_params(plot_group_id, k, strength, meta_group);
        PlotProofParams params = group_params.get_plot_params_for_index(index);

        Plotter plotter(params);
        PlotData plot = plotter.run();

        PlotGroupFile::writeData(
            plot_path, plot, group_params, PlotGroupFile::PROOFS_PER_CHUNK_BITS, memo
        );
    }

    GroupProver prover(plot_path);

    auto const& info = prover.getPlotGroup().getInfo();
    ENSURE(info.k == k);
    ENSURE(info.strength == strength);

    // Deterministic challenge that currently yields duplicate quality chains.
    // Without fragment deduplication, this challenge returns seven chains instead of five.
    constexpr int32_t CHALLENGE_IDX = 7206;

    std::array<uint8_t, 32> challenge = {};
    *reinterpret_cast<int32_t*>(&challenge) = CHALLENGE_IDX;

    auto qualities = prover.prove(challenge);

    ENSURE(!qualities.empty());

    std::set<QualityChainLinks> uniq;

    for (auto& q : qualities) {
        for (auto qc : q.quality_chains) {
            ENSURE(uniq.insert(qc.chain_links).second);
        }
    }
}

TEST_CASE("plot-group-ans-size-bounds")
{
    // Check that the plot group reader rejects truncated or overflowing LEB128 sizes,
    // invalid ANS blob lengths, and non-ANS data too short to contain a delta.
    std::filesystem::create_directories(".test_plots");
    std::string const path = ".test_plots/test-ans-size-bounds.gplot";
    Guard cleanup([&] {
        std::error_code error;
        std::filesystem::remove(path, error);
    });

    auto check_size = [&](std::span<uint8_t const> bytes, char const* expected_error, uint8_t k = 18) {
        size_t const chunk_count = PlotGroupFile::getChunkCountForK(k);
        std::vector<uint64_t> sizes(chunk_count, 1);
        sizes[0] = bytes.size();
        BitWriter index;
        gsz_encode(sizes, 1, index);

        PlotGroupFile::Header header {};
        header.magic = PlotGroupFile::MAGIC;
        header.version = PlotGroupFile::FORMAT_VERSION;
        header.k = k;
        header.strength = 2;
        header.group_size = 1;
        header.chunk_index_offset = sizeof(header) + bytes.size() + chunk_count - 1;

        {
            std::ofstream out(path, std::ios::binary);
            out.exceptions(std::ios::badbit | std::ios::failbit);
            out.write(reinterpret_cast<char const*>(&header), sizeof(header));
            out.write(reinterpret_cast<char const*>(bytes.data()), bytes.size());
            std::vector<uint8_t> remaining_chunks(chunk_count - 1, 0);
            out.write(reinterpret_cast<char const*>(remaining_chunks.data()), remaining_chunks.size());
            auto const index_bytes = index.asBytes();
            out.write(reinterpret_cast<char const*>(index_bytes.data()), index_bytes.size());
        }

        auto plot = PlotGroupFile::open(path);
        std::vector<std::vector<ProofFragment>> fragments(1);
        CHECK_THROWS_WITH_AS(plot.readChunk(0, fragments), expected_error, std::runtime_error);
    };

    for (size_t length = 1; length < 10; ++length) {
        CAPTURE(length);
        std::vector<uint8_t> bytes(length, 0x80);
        check_size(bytes, "Truncated ANS blob size");
    }

    std::array<uint8_t, 10> bytes;
    bytes.fill(0xff);
    for (unsigned last = 0; last <= 255; ++last) {
        CAPTURE(last);
        bytes.back() = static_cast<uint8_t>(last);
        // Valid sizes reach the blob length check because the chunk has no payload.
        check_size(bytes, last <= 1 ? "Invalid ANS blob size" : "ANS blob size exceeds 64 bits");
    }

    // A terminator after the tenth byte must not make an oversized encoding valid.
    std::array<uint8_t, 11> overlong;
    overlong.fill(0x80);
    overlong.back() = 0;
    check_size(overlong, "ANS blob size exceeds 64 bits");

    // The ANS blob must be nonempty and leave room for the non-ANS data.
    for (uint8_t const ans_size : std::array<uint8_t, 3>{0, 2, 3}) {
        CAPTURE(ans_size);
        std::array<uint8_t, 3> const invalid_size = {ans_size, 1, 0};
        check_size(invalid_size, "Invalid ANS blob size");
    }

    // One byte cannot hold a delta at k18. At k24, even two bytes are insufficient.
    for (uint8_t const k : std::array<uint8_t, 2>{18, 24}) {
        CAPTURE(k);
        for (size_t non_ans_size = 1; non_ans_size * 8 < size_t(k - 7); ++non_ans_size) {
            CAPTURE(non_ans_size);
            std::vector<uint8_t> chunk(2 + non_ans_size, 0);
            chunk[0] = 1;
            // This ANS end marker lets FSE reach the write that previously crashed.
            chunk[1] = 1;
            check_size(chunk, "Non-ANS data is too short to contain a delta", k);
        }
    }
}

TEST_CASE("plot-group-dense-chunk")
{
    /// Regression test for the updated upper-bound capacity estimation for chunk deltas.
    std::filesystem::create_directories(".test_plots");
    std::string const path = ".test_plots/test-dense-chunk.gplot";
    Guard cleanup([&] {
        std::error_code error;
        std::filesystem::remove(path, error);
    });

    for (uint8_t const k : std::array<uint8_t, 2>{18, 20}) {
        CAPTURE(k);

        PlotGroupParams params(PlotGroupId {}, k, 2, 0);

        ChunkedProofFragments data;
        data.proof_fragments_chunks.resize(PlotGroupFile::getChunkCountForK(k));

        uint64_t const range_per_chunk = 1ull << (k + PlotGroupFile::PROOFS_PER_CHUNK_BITS);

        for (size_t chunk = 0; chunk < data.proof_fragments_chunks.size(); ++chunk) {
            size_t count = 64;

            if (chunk == 0) {
                // The previous method calculated a capacity of 106 deltas for a chunk in a single-plot group.
                count = 108;
            }
            for (size_t entry = 0; entry < count; ++entry) {
                // Unit deltas have zero quotients and use exactly k-7 non-ANS bits.
                // This will excercise the minimum bits per delta.
                data.proof_fragments_chunks[chunk].push_back(chunk * range_per_chunk + entry + 1);
            }
        }

        PlotGroupFile::writeData(path, data, params, PlotGroupFile::PROOFS_PER_CHUNK_BITS, {});
        auto plot = PlotGroupFile::open(path);
        std::vector<std::vector<ProofFragment>> fragments(1);
        plot.readChunk(0, fragments);
        CHECK(fragments[0] == data.proof_fragments_chunks[0]);
    }
}

TEST_SUITE_END();
