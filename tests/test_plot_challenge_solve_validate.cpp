#include "test_util.h"
#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"
#include "prove/Prover.hpp"
#include "common/Utils.hpp"
#include "solve/Solver.hpp"

TEST_SUITE_BEGIN("plot-challenge-solve-verify");

TEST_CASE("plot-k18-strength2-4-5")
{
    // for this test plot was generated with a prover scan to fine a challenge returning one or more quality chains
    for (int trial = 0; trial < 3; trial++)
    {
        int plot_strength;
        std::string challenge_hex;
        // challenges for trials are found by running "prover check" on a plot of the given strength and proof fragment scan filter
        switch (trial)
        {
        case 0:
            plot_strength = 2;
            challenge_hex = "5c00000000000000000000000000000000000000000000000000000000000000";
            break;
        case 1:
            plot_strength = 4;
            challenge_hex = "6000000000000000000000000000000000000000000000000000000000000000";
            break;
        case 2:
            plot_strength = 5;
            challenge_hex = "62000000000000000000000000000000000000000000000000000000000000";
            break;
        default:
            // return error
            std::cerr << "Error: invalid trial number." << std::endl;
            ENSURE(false);
            return;
        }
        // run the actual test
        constexpr int k = 18;
        std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        printfln("Creating a k%d strength:%d plot: %s", k, (int)plot_strength, plot_id_hex.c_str());

        Timer timer{};
        timer.debugOut = true;
        timer.start("Plot Creation");

        Plotter plotter(Utils::hexToBytes(plot_id_hex), k, plot_strength);
        PlotData plot = plotter.run();
        timer.stop();

        std::string plot_file_name = (std::string("plot_") + "k") + std::to_string(k) + "_" + std::to_string(plot_strength) + "_" + plot_id_hex + ".bin";

        timer.start("Writing plot file: " + plot_file_name);
        PlotFile::writeData(plot_file_name, plot, plotter.getProofParams());
        timer.stop();

        // timer.start("Reading plot file: " + plot_file_name);
        // PlotFile::PlotFileContents read_plot = PlotFile::readData(plot_file_name);
        // timer.stop();

        // ENSURE(plot == read_plot.data);
        // ENSURE(plotter.getProofParams() == read_plot.params);

        std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
        Prover prover(challenge, plot_file_name);
        prover.readPlotFileIfNeeded();
        ENSURE(prover.getProofParams() == plotter.getProofParams());

        // once prover had read file let's cleanup
        std::remove(plot_file_name.c_str());

        int proof_fragment_filter_bits = 1; // 1 bit means 50% of fragments are filtered out

        std::vector<QualityChain> quality_chains = prover.prove(proof_fragment_filter_bits);
        printfln("Found %d quality chains.", (int)quality_chains.size());
        ENSURE(!quality_chains.empty());
        if (quality_chains.empty())
        {
            std::cerr << "Error: no quality chains found." << std::endl;
            return;
        }
        for (size_t nChain = 0; nChain < quality_chains.size(); nChain++)
        {

            std::vector<uint32_t> check_proof_xs;

            // at this point should have at least one quality chain, so get the proof fragments for the first one
            std::vector<ProofFragment> proof_fragments = prover.getAllProofFragmentsForProof(quality_chains[nChain]);
            // std::cout << "Proof fragments: " << proof_fragments.size() << std::endl;

            // get x bits list from proof fragments
            std::vector<uint32_t> x_bits_list;
            ProofFragmentCodec fragment_codec(prover.getProofParams());
            for (const auto &fragment : proof_fragments)
            {
                std::array<uint32_t, 4> x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);
                for (const auto &x_bit : x_bits)
                {
                    x_bits_list.push_back(x_bit);
                }
            }

#ifdef RETAIN_X_VALUES_TO_T3
            // find all indexes of proof fragments
            std::cout << "check proof x values: "; // << std::hex;
            for (int i = 0; i < proof_fragments.size(); i++)
            {
                // scan plot file contents for matching proof fragment
                auto it = std::find(plot.t3_proof_fragments.begin(), plot.t3_proof_fragments.end(), proof_fragments[i]);
                ENSURE(it != plot.t3_proof_fragments.end());
                size_t index = std::distance(plot.t3_proof_fragments.begin(), it);
                // printfln("Proof fragment %d found at index %d", i, (int)index);

                std::array<uint32_t, 8> x_values = plot.xs_correlating_to_proof_fragments[index];

                for (int xi = 0; xi < 8; xi++)
                {
                    std::cout << x_values[xi] << ",";
                    check_proof_xs.push_back(x_values[xi]);
                }
                std::cout << std::dec << std::endl;
            }
#endif

            // now solve using the x bits list
            Solver solver(prover.getProofParams());
            std::vector<std::vector<uint32_t>> all_proofs = solver.solve(x_bits_list);

            ENSURE(!all_proofs.empty());
            ENSURE(all_proofs.size() == 1); // not sure how to handle multiple proofs for now, should be extremely rare.
            if (all_proofs.size() == 0)
            {
                std::cerr << "Error: no proofs found." << std::endl;
                return;
            }
            else if (all_proofs.size() > 1)
            {
                std::cerr << "Warning: RARE event - multiple proofs found (" << all_proofs.size() << "). Update test to validate and find correct proof." << std::endl;
                return;
            }

            std::cout << "Found " << all_proofs.size() << " proofs." << std::endl;
            for (size_t i = 0; i < all_proofs.size(); i++)
            {
                std::cout << "Proof " << i << " x-values (" << all_proofs[i].size() << "): ";
                for (size_t j = 0; j < all_proofs[i].size(); j++)
                {
                    std::cout << all_proofs[i][j] << ", ";
                }
                std::cout << std::endl;
            }

            // at this point should have exactly one proof.

            std::cout << "nChain: " << nChain << " found " << all_proofs.size() << " proofs." << std::endl;
            std::vector<uint32_t> &proof = all_proofs[0];
            std::cout << "Proof size: " << proof.size() << std::endl;

            ENSURE(proof.size() == NUM_CHAIN_LINKS * 32); // should always have 32 x values per link
#ifdef RETAIN_X_VALUES_TO_T3
            ENSURE(proof.size() == check_proof_xs.size());
            for (size_t i = 0; i < proof.size(); i++)
            {
                ENSURE(proof[i] == check_proof_xs[i]);
            }
#endif

            // std::cout << "Proof: ";
            // for (size_t i = 0; i < proof.size(); i++)
            //{
            //     std::cout << proof[i] << " ";
            // }
            // std::cout << std::endl;

            // now verify the proof
            ProofValidator proof_validator(prover.getProofParams());
            std::optional<QualityChainLinks> res = proof_validator.validate_full_proof(proof, challenge, proof_fragment_filter_bits);
            ENSURE(res.has_value());

            QualityChainLinks quality_links = res.value();
            bool links_match = true;
            // run through quality links and ensure they match the original quality chain's links
            for (int i = 0; i < NUM_CHAIN_LINKS; i++)
            {
                auto &check_fragments = quality_links[i].fragments;
                auto &original_fragments = quality_chains[nChain].chain_links[i].fragments;
                // ensure fragments match
                if (!std::equal(std::begin(check_fragments), std::end(check_fragments), std::begin(original_fragments), std::end(original_fragments)))
                {
                    links_match = false;
                    std::cerr << "Error: quality link " << i << " fragments does not match original." << std::endl;
                }
            }
            ENSURE(links_match);

        }
    }
}

TEST_SUITE_END();
