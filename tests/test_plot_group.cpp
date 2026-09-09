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

// TEST_CASE("plot-group-full")
// {
//     constexpr const char* CHALLENGE_HEX = "3e91b7d4c82a506f14fd63a9b075ec219a46d8f3527b1c0ee6a934850dcf7200";
//     constexpr const char* PLOT_GROUP_ID_HEX = "c6b84729c23dc6d60c92f22c17083f47845c1179227c5509f07a5d2804a7b835";
//     constexpr int k = 18;
//     constexpr int strength = 2;

//     PlotGroupId plot_group_id(PLOT_GROUP_ID_HEX);

//     PlotGroupParams group_params(plot_group_id, k, strength, 0);
//     PlotProofParams params = group_params.get_plot_params_for_index(0);
//     Plotter plotter(params);
//     PlotData plot = plotter.run();

//     // Create a plot and serialize it as a plot group
//     std::string file_name = (std::string("test-plot-") + "k") +
//                              std::to_string(k) + "_" + PLOT_GROUP_ID_HEX +
//                              ".test_plot.bin";

//     PlotGroupFile::writeData(
//         file_name, plot, group_params, PlotGroupFile::PROOFS_PER_CHUNK_BITS, {});

//     GroupProver prover(file_name);

//     std::array<uint8_t, 32> challenge = Utils::hexToBytes(CHALLENGE_HEX);
//     std::vector<PlotQualityChains> quality_chains;
//     bool found_quality = false;

//     for (uint16_t challenge_index = 0; challenge_index < 256; challenge_index++) {
//         challenge.back() = uint8_t(challenge_index);
//         quality_chains = prover.prove(challenge);

//         for (auto const& pqc : quality_chains) {
//             if (!pqc.quality_chains.empty()) {
//                 found_quality = true;
//                 break;
//             }
//         }

//         if (found_quality) {
//             break;
//         }
//     }

//     ENSURE(found_quality);

//     for (auto& pqc : quality_chains) {
//         ProofValidator proof_validator(group_params, 0);

//         for (auto& qc: pqc.quality_chains) {
//             std::vector<uint32_t> x_bits_list;
//             ProofFragmentCodec fragment_codec(params);

//             for (auto const& fragment: qc.chain_links) {
//                 std::array<uint32_t, 4> x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);

//                 for (auto const& x_bit: x_bits) {
//                     x_bits_list.push_back(x_bit);
//                 }
//             }

//             Solver solver(params);
//             auto proofs = solver.solve(Solver::XBitsList(x_bits_list));

//             ENSURE(!proofs.empty());

//             for (auto const& proof: proofs) {
//                 std::optional<QualityChainLinks> validated_chain
//                     = proof_validator.validate_full_proof(proof, challenge);

//                 ENSURE(validated_chain.has_value());
//             }
//         }
//     }
// }

TEST_CASE("test_no_duplicate_qualities_for_known_challenge")
{
    uint8_t k = 18;
    uint8_t strength = 2;
    uint16_t index = 0;
    uint8_t meta_group = 0;
    PlotGroupId plot_group_id("1212121212121212121212121212121212121212121212121212121212121212");
    std::array<uint8_t, 112> memo = {};

    // Test thingy
    // FeistelCipher cipher(plot_group_id.bytes(), 28);

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
    constexpr int32_t CHALLENGE_IDX = 15849;

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

TEST_SUITE_END();
