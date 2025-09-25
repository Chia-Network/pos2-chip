#include "test_util.h"
#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"
#include "prove/Prover.hpp"
#include "common/Utils.hpp"
#include "solve/Solver.hpp"

TEST_SUITE_BEGIN("plot-challenge-solve-verify");

TEST_CASE("plot-k18-strength2")
{
    // for this test plot was generated with a prover scan to fine a challenge returning one or more quality chains
    constexpr int k = 18;
    constexpr int plot_strength = 2;
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::string challenge_hex = "5700000000000000000000000000000000000000000000000000000000000000";

    printfln("Creating a %d plot: %s", k, plot_id_hex.c_str());

    Timer timer{};
    timer.start("");

    Plotter plotter(Utils::hexToBytes(plot_id_hex), k);
    PlotData plot = plotter.run();
    timer.stop();

    printfln("Plot completed, writing to file...");

#define tostr std::to_string
    std::string plot_file_name = (std::string("plot_") + "k") + tostr(k) + "_" + plot_id_hex + ".bin";

    timer.start("Writing plot file: " + plot_file_name);
    PlotFile::writeData(plot_file_name, plot, plotter.getProofParams());
    timer.stop();

    timer.start("Reading plot file: " + plot_file_name);
    PlotFile::PlotFileContents read_plot = PlotFile::readData(plot_file_name);
    timer.stop();

    ENSURE(plot == read_plot.data);
    ENSURE(plotter.getProofParams() == read_plot.params);

    std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
    Prover prover(challenge, plot_file_name);
    int proof_fragment_filter_bits = 1; // 1 bit means 50% of fragments are filtered out

    std::vector<QualityChain> quality_chains = prover.prove(proof_fragment_filter_bits);
    printfln("Found %d quality chains.", (int)quality_chains.size());
    ENSURE(!quality_chains.empty());
    if (quality_chains.empty())
    {
        std::cerr << "Error: no quality chains found." << std::endl;
        return;
    }

    std::vector<uint32_t> check_proof_xs;

    // at this point should have at least one quality chain, so get the proof fragments for the first one
    std::vector<ProofFragment> proof_fragments = prover.getAllProofFragmentsForProof(quality_chains[0]);
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

    // at this point should have exactly one proof.

    // std::cout << "Found " << all_proofs.size() << " proofs." << std::endl;
    std::vector<uint32_t> &proof = all_proofs[0];
    // std::cout << "Proof size: " << proof.size() << std::endl;

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
    bool valid = proof_validator.validate_full_proof(proof, challenge, proof_fragment_filter_bits);
    ENSURE(valid);
}

TEST_CASE("plot-k18-strength4")
{
    // for this test plot was generated with a prover scan to fine a challenge returning one or more quality chains
    constexpr int k = 18;
    const int plot_strength = 4;
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::string challenge_hex = "6000000000000000000000000000000000000000000000000000000000000000";

    printfln("Creating a %d plot: %s", k, plot_id_hex.c_str());

    Timer timer{};
    timer.start("");

    Plotter plotter(Utils::hexToBytes(plot_id_hex), k, plot_strength);
    PlotData plot = plotter.run();
    timer.stop();

    printfln("Plot completed, writing to file...");

#define tostr std::to_string
    std::string plot_file_name = (std::string("plot_") + "k") + tostr(k) + "_" + plot_id_hex + "_" + tostr(plot_strength) + ".bin";

    timer.start("Writing plot file: " + plot_file_name);
    PlotFile::writeData(plot_file_name, plot, plotter.getProofParams());
    timer.stop();

    timer.start("Reading plot file: " + plot_file_name);
    PlotFile::PlotFileContents read_plot = PlotFile::readData(plot_file_name);
    timer.stop();

    ENSURE(plot == read_plot.data);
    ENSURE(plotter.getProofParams() == read_plot.params);

    std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
    Prover prover(challenge, plot_file_name);
    int proof_fragment_filter_bits = 1; // 1 bit means 50% of fragments are filtered out

    std::vector<QualityChain> quality_chains = prover.prove(proof_fragment_filter_bits);
    printfln("Found %d quality chains.", (int)quality_chains.size());
    ENSURE(!quality_chains.empty());
    if (quality_chains.empty())
    {
        std::cerr << "Error: no quality chains found." << std::endl;
        return;
    }

    std::vector<uint32_t> check_proof_xs;

    // at this point should have at least one quality chain, so get the proof fragments for the first one
    std::vector<ProofFragment> proof_fragments = prover.getAllProofFragmentsForProof(quality_chains[0]);
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

    // at this point should have exactly one proof.

    // std::cout << "Found " << all_proofs.size() << " proofs." << std::endl;
    std::vector<uint32_t> &proof = all_proofs[0];
    // std::cout << "Proof size: " << proof.size() << std::endl;

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
    bool valid = proof_validator.validate_full_proof(proof, challenge, proof_fragment_filter_bits);
    ENSURE(valid);
}

TEST_SUITE_END();
