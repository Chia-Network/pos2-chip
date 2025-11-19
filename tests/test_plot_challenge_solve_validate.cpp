#include "test_util.h"
#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"
#include "plot/PlotFileT.hpp"
#include "plot/PlotFormat.hpp"
#include "prove/Prover.hpp"
#include "common/Utils.hpp"
#include "solve/Solver.hpp"

TEST_SUITE_BEGIN("plot-challenge-solve-verify");

TEST_CASE("plot-k18-strength2-4-5")
{
    #ifdef NDEBUG
    const size_t N_TRIALS = 3; // strength 2, 4, 5
    const size_t MAX_CHAINS_PER_CHALLENGE_TO_TEST = 3; // check up to 3 chains from challenge
    #else
    const size_t N_TRIALS = 1; // strength 2 only
    const size_t MAX_CHAINS_PER_CHALLENGE_TO_TEST = 1; // only check one chain from challenge
    #endif

    // regression proof for strength 2 first proof.
    std::array<uint32_t, 512> expected_proof = {
        65379, 31592, 56632, 42762, 156890, 73048, 71408, 55022, 147446, 218807, 175492, 223046, 246138, 40167, 109777, 184648, 112299, 164826, 56434, 173683, 218269, 137497, 258846, 104360, 223280, 243902, 213944, 177674, 30395, 17175, 215377, 228462, 207281, 257784, 194796, 53466, 187179, 69064, 93794, 50419, 25352, 247610, 150760, 191996, 45294, 670, 40996, 176330, 232259, 23500, 26455, 42187, 205070, 90945, 126587, 247928, 181155, 98627, 23265, 124318, 155238, 78389, 51366, 4971, 127110, 47500, 137776, 31742, 184674, 1525, 98488, 140828, 176618, 182434, 202972, 47075, 44665, 261453, 65167, 211344, 146707, 189019, 13548, 254878, 53099, 15892, 223152, 188006, 187018, 156351, 173884, 162019, 195553, 188383, 176463, 36281, 154021, 256931, 120750, 205972, 54098, 120464, 243590, 16886, 227246, 117483, 250104, 166953, 153814, 157436, 258122, 92751, 10550, 85557, 131708, 71537, 33641, 20544, 167147, 215172, 148994, 226271, 21102, 74888, 77735, 230188, 260479, 130557, 216245, 78841, 168813, 137509, 30886, 206318, 50679, 226748, 26477, 145149, 56016, 235687, 230343, 47560, 173743, 199029, 27610, 182774, 157645, 179083, 21389, 226236, 81034, 16059, 198044, 211610, 24782, 214209, 19808, 124053, 59513, 150467, 154157, 186563, 129471, 119545, 139548, 173116, 120840, 114177, 242875, 75894, 228131, 20380, 105946, 114360, 193340, 128396, 132023, 98917, 130344, 7038, 109446, 134453, 112665, 208679, 125877, 139545, 222689, 46646, 108799, 108159, 258425, 247276, 64728, 36151, 253628, 45474, 76942, 196280, 40246, 75657, 107454, 191329, 188764, 203535, 74698, 175551, 185739, 61471, 85656, 165242, 143381, 244338, 115339, 2863, 143856, 199375, 154664, 95656, 96049, 236659, 41806, 48063, 197874, 105485, 75435, 77207, 54190, 163396, 201714, 202705, 225221, 246930, 62997, 154939, 208625, 94518, 256354, 135834, 202859, 255625, 168019, 68216, 201210, 60918, 50189, 99238, 63204, 29203, 211249, 19844, 184870, 190065, 227414, 93928, 14487, 249370, 122402, 170388, 177855, 226483, 74932, 226693, 166022, 207526, 165794, 172722, 91283, 54703, 191735, 250570, 197282, 197509, 254104, 39448, 29812, 64642, 240244, 175530, 177625, 149651, 233819, 175597, 26504, 170202, 122546, 8295, 90965, 186271, 214888, 94826, 173341, 258025, 25308, 47037, 68526, 122282, 191231, 102830, 216395, 39515, 68344, 167745, 20505, 232654, 241117, 242997, 70196, 165842, 76161, 197845, 106278, 3762, 84510, 172813, 86594, 22024, 171828, 202560, 153419, 114619, 41482, 182103, 256587, 5513, 65525, 84137, 85155, 197138, 109330, 192669, 19233, 23475, 119387, 260254, 120190, 2330, 258800, 66997, 237873, 36205, 64851, 152891, 3415, 175079, 157115, 13155, 141986, 35856, 194735, 48005, 43941, 97434, 2657, 137186, 199129, 185655, 81716, 190953, 116252, 211884, 150247, 144612, 5674, 68742, 75555, 78178, 6236, 160218, 213205, 193201, 135758, 216435, 175281, 69883, 113338, 189091, 212243, 78134, 114128, 221341, 161778, 102057, 41289, 99677, 150034, 38346, 215296, 239881, 177898, 66092, 202491, 165366, 86028, 44488, 46996, 12322, 206918, 218215, 150578, 43561, 32397, 39158, 36623, 56875, 183599, 59924, 220956, 45613, 17305, 166337, 235024, 203271, 75194, 41532, 127021, 135117, 36754, 87098, 32092, 35390, 184715, 222071, 178360, 192286, 36779, 46343, 4593, 110485, 181197, 47321, 61731, 98828, 5099, 142109, 145226, 113772, 33702, 135241, 168606, 127736, 23356, 26, 106806, 89429, 148428, 76589, 233616, 242984, 225641, 38434, 75458, 163197, 67065, 243273, 56100, 134996, 91650, 27670, 226564, 119020, 133577, 12621, 198968, 257835, 146374, 92556, 150236, 186338, 230601, 105161, 143388, 62755, 57881, 36592, 164578, 135304, 24788, 193895, 54986, 259878, 192731, 11597, 140625, 122136, 193155, 223640, 164820, 55635, 63499, 201329, 141268, 228874, 63662, 55670, 140178, 131545, 99010, 162303, 16899, 128218, 25906, 116716, 233752, 11242, 207153, 246006, 190813, 76392, 121099, 119962, 167311, 118644
    };
    // for this test plot was generated with a prover scan to fine a challenge returning one or more quality chains
    for (size_t trial = 0; trial < N_TRIALS; trial++)
    {
        uint8_t plot_strength;
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
        constexpr uint8_t k = 18;
        std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        printfln("Creating a k%d strength:%d plot: %s", k, (int)plot_strength, plot_id_hex.c_str());

        Timer timer{};
        timer.debugOut = true;
        timer.start("Plot Creation");

        Plotter plotter(Utils::hexToBytes(plot_id_hex), k, plot_strength);
        PlotData plot = plotter.run();
        plotter.getProofParams().show();
        timer.stop();

        std::string plot_file_name = (std::string("plot_") + "k") + std::to_string(k) + "_" + std::to_string(plot_strength) + "_" + plot_id_hex + ".bin";

        timer.start("Writing plot file: " + plot_file_name);
        {
            std::array<uint8_t, 32 + 48 + 32> memo{};
            FlatPlotFile pf(plotter.getProofParams(), memo, plot);
            pf.writeToFile(plot_file_name);
        }
        timer.stop();

        // convert to PlotFormat
        PartitionedPlotData partitioned_data = PlotFormat::convertFromPlotData(plot, plotter.getProofParams());
        std::string plot_format_file_name = (std::string("plot_format_") + "k") + std::to_string(k) + "_" + std::to_string(plot_strength) + "_" + plot_id_hex + ".pf";
        timer.start("Writing plot format file: " + plot_format_file_name);
        {
            std::array<uint8_t, 32 + 48 + 32> memo{};
            PlotFormat::writeData(plot_format_file_name, partitioned_data, plotter.getProofParams(), memo);
        }

        // timer.start("Reading plot file: " + plot_file_name);
        // PlotFile::PlotFileContents read_plot = PlotFile::readData(plot_file_name);
        // timer.stop();

        // ENSURE(plot == read_plot.data);
        // ENSURE(plotter.getProofParams() == read_plot.params);

        std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
        
        // TODO: should be able to give prover headers so doesn't have to read headers each time.
        Prover prover(challenge, plot_file_name);
        prover.readHeadersFromFile();
        
        ProofParams proof_params_prover = prover.getProofParams();
        ENSURE(prover.getProofParams() == plotter.getProofParams());

        int proof_fragment_filter_bits = 1; // 1 bit means 50% of fragments are filtered out

        std::vector<QualityChain> quality_chains = prover.prove(proof_fragment_filter_bits);
        printfln("Found %d quality chains.", (int)quality_chains.size());
        ENSURE(!quality_chains.empty());
        if (quality_chains.empty())
        {
            std::cerr << "Error: no quality chains found." << std::endl;
            return;
        }
        size_t numTestChains = std::min(MAX_CHAINS_PER_CHALLENGE_TO_TEST, quality_chains.size()); // only check limited set of chains.
        std::cout << "Testing " << numTestChains << " quality chains for challenge." << std::endl;
        for (size_t nChain = 0; nChain < numTestChains; nChain++)
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
            std::vector<std::array<uint32_t, 512>> all_proofs = solver.solve(std::span<uint32_t const, 256>(x_bits_list));

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
            std::array<uint32_t, 512> const& proof = all_proofs[0];
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

            QualityChainLinks const& quality_links = res.value();
            bool links_match = true;
            // run through quality links and ensure they match the original quality chain's links
            for (int i = 0; i < NUM_CHAIN_LINKS; i++)
            {
                auto const& check_fragments = quality_links[i].fragments;
                auto const& original_fragments = quality_chains[nChain].chain_links[i].fragments;
                // ensure fragments match
                if (!(check_fragments == original_fragments))
                {
                    links_match = false;
                    std::cerr << "Error: quality link " << i << " fragments does not match original." << std::endl;
                }
            }
            ENSURE(links_match);

            if ((trial == 0) && (nChain == 0)) { // only check first proof of strength 2
                std::cout << "Verifying proof matches expected proof for strength 2 trial: " << trial << " nChain: " << nChain << std::endl;
                ENSURE(proof.size() == expected_proof.size());
                // should match our expected proof for strength 2 first proof
                for (size_t i = 0; i < expected_proof.size(); i++)
                {
                    ENSURE(proof[i] == expected_proof[i]);
                }
            }
        
        }
        
        // once prover had read file let's cleanup
        std::remove(plot_file_name.c_str());
    }
}

TEST_SUITE_END();
