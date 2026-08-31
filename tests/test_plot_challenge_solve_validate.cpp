#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include "pos/Chainer.hpp"
#include "prove/Prover.hpp"
#include "solve/Solver.hpp"
#include "pos/sha/sha256.hpp"
#include "test_util.h"

TEST_SUITE_BEGIN("plot-challenge-solve-verify");

TEST_CASE("plot-k18-strength2-4-5")
{
    #ifdef NDEBUG
        const size_t N_TRIALS = 4; // strength 2, 4, 5 -- then strength 2
        size_t const MAX_CHAINS_PER_CHALLENGE_TO_TEST = 1; // 3; // check up to 3 chains from challenge
    #else
        const size_t N_TRIALS = 1; // strength 2 only
        size_t const MAX_CHAINS_PER_CHALLENGE_TO_TEST = 1; // only check one chain from challenge
    #endif

    constexpr uint8_t k = 18;
    std::string plot_group_id_hex = "da9a6a4efcadaf1e3115e79a2b7b2d17890185359f19bfaa02a2f2505a8160b5";

    // for this test plot was generated with a prover scan to find
    // a challenge returning one or more quality chains
    for (size_t trial = 0; trial < N_TRIALS; trial++) {
        uint8_t plot_strength;
        std::string challenge_hex;
        // challenges for trials are found by running "prover check" on a plot of the given strength
        // and proof fragment scan filter
        switch (trial) {
        case 0:
            plot_strength = 2;
            challenge_hex = "368d14ca70224ac4acc37f591b28ff43d05a2533d34b3a9e8baf4837aebcc783";
            break;
        case 1:
            plot_strength = 4;
            challenge_hex = "26d4fa7f3b0bd2d3cc6dc0cf569a97d649cdb543abf4be03f2bc54f15f67784c";
            break;
        case 2:
            plot_strength = 5;
            challenge_hex = "be66452a2cc16867f0598fce61781e805776dd4913f3727d01ba939383b491f0";
            break;
        case 3:
            plot_strength = 2;
            challenge_hex = "7ea596522b9c9b226f5c2bf8d3b09736f0f286b123076a5e78dc295ccf2a891c";
            break;
        default:
            // return error
            std::cerr << "Error: invalid trial number." << std::endl;
            ENSURE(false);
            return;
        }
        // run the actual test

        printfln("Creating a k%d strength:%d plot: %s index: 0", k, (int)plot_strength, plot_group_id_hex.c_str());

        Timer timer {};
        timer.debugOut = true;
        timer.start("Plot Creation");

        PlotGroupParams group_params(PlotGroupId(plot_group_id_hex), k, plot_strength, 0);
        PlotProofParams plot_proof_params = group_params.get_plot_params_for_index(0);

        Plotter plotter(plot_proof_params);
        PlotData plot = plotter.run();
        timer.stop();

        std::string plot_file_name = (std::string("plot_") + "k") + std::to_string(k) + "_"
            + std::to_string(plot_strength) + "_" + plot_group_id_hex + "_0_.bin";

        timer.start("Writing plot file: " + plot_file_name);
        PlotFile::writeData(plot_file_name,
            plot,
            group_params,
            0,
            std::array<uint8_t, 32 + 48 + 32>({}));
        timer.stop();

        std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);

        Prover prover(plot_file_name);
        std::vector<QualityChain> quality_chains = prover.prove(challenge);
        printfln("Prover found %d quality chains.", (int)quality_chains.size());

        ENSURE(!quality_chains.empty());
        if (quality_chains.empty()) {
            std::cerr << "Error: no quality chains found." << std::endl;
            return;
        }

        // only check limited set of chains.
        size_t numTestChains = std::min(MAX_CHAINS_PER_CHALLENGE_TO_TEST, quality_chains.size());

        for (size_t nChain = 0; nChain < numTestChains; nChain++) {

            std::vector<uint32_t> check_proof_xs;

            // at this point should have at least one quality chain,
            // so get the proof fragments for the first one
            QualityChainLinks proof_fragments = quality_chains[nChain].chain_links;
            std::cout << "Proof fragments: " << proof_fragments.size() << std::endl;

            // get x bits list from proof fragments
            std::vector<uint32_t> x_bits_list;
            ProofFragmentCodec fragment_codec(plot_proof_params);
            for (auto const& fragment: proof_fragments) {
                std::array<uint32_t, 4> x_bits
                    = fragment_codec.get_x_bits_from_proof_fragment(fragment);
                for (auto const& x_bit: x_bits) {
                    x_bits_list.push_back(x_bit);
                }
            }

            #ifdef RETAIN_X_VALUES_TO_T3
                // find all indexes of proof fragments
                std::cout << "check proof x values: "; // << std::hex;
                for (int i = 0; i < proof_fragments.size(); i++) {
                    // scan plot file contents for matching proof fragment
                    auto it = std::find(plot.t3_proof_fragments.begin(),
                        plot.t3_proof_fragments.end(),
                        proof_fragments[i]);
                    ENSURE(it != plot.t3_proof_fragments.end());
                    size_t index = std::distance(plot.t3_proof_fragments.begin(), it);
                    // printfln("Proof fragment %d found at index %d", i, (int)index);

                    std::array<uint32_t, 8> x_values = plot.xs_correlating_to_proof_fragments[index];

                    for (int xi = 0; xi < 8; xi++) {
                        std::cout << x_values[xi] << ",";
                        check_proof_xs.push_back(x_values[xi]);
                    }
                    std::cout << std::dec << std::endl;
                }
            #endif

            // now solve using the x bits list
            Solver solver(plot_proof_params);
            Solver::SolveResult all_proofs = solver.solve(Solver::XBitsList(x_bits_list));

            solver.timings().printSummary();

            ENSURE(!all_proofs.empty());
            ENSURE(all_proofs.size() >= 1); // extrememly rare case could be multiple proofs
            if (all_proofs.size() == 0) {
                std::cerr << "Error: no proofs found." << std::endl;
                return;
            }
            else if (all_proofs.size() > 1) {
                std::cout << "RARE event - multiple proofs found (" << all_proofs.size() << ")."
                          << std::endl;
            }

            std::cout << "nChain: " << nChain << " found " << all_proofs.size() << " proofs."
                      << std::endl;
            for (size_t i = 0; i < all_proofs.size(); i++) {
                std::cout << "Proof " << i << " x-values (" << all_proofs[i].size() << "): ";
                for (size_t j = 0; j < all_proofs[i].size(); j++) {
                    std::cout << all_proofs[i][j] << ", ";
                }
                std::cout << std::endl;

                std::array<uint32_t, TOTAL_XS_IN_PROOF> const& proof = all_proofs[i];
                std::cout << "Proof size: " << proof.size() << std::endl;

                ENSURE(proof.size() == NUM_CHAIN_LINKS * 8); // should always have 8 x values per link

                #ifdef RETAIN_X_VALUES_TO_T3
                    ENSURE(proof.size() == check_proof_xs.size());
                    for (size_t i = 0; i < proof.size(); i++) {
                        ENSURE(proof[i] == check_proof_xs[i]);
                    }
                #endif

                // now verify the proof
                ProofValidator proof_validator(group_params, 0);

                std::optional<QualityChainLinks> res =
                    proof_validator.validate_full_proof(proof, challenge);
                ENSURE(res.has_value());

                QualityChainLinks const& quality_links = res.value();
                bool links_match = quality_links == proof_fragments;

                ENSURE(links_match);
            }

            // if we have more than one proof, make sure they aren't duplicates
            if (all_proofs.size() > 1) {
                for (size_t i = 0; i < all_proofs.size(); i++) {
                    for (size_t j = i + 1; j < all_proofs.size(); j++) {
                        ENSURE(!(all_proofs[i] == all_proofs[j]));
                    }
                }
            }
        }
    }
}

TEST_SUITE_END();
