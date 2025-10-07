#include <iostream>
#include <string>
#include <cstdlib>
#include "plot/PlotFile.hpp"
#include "pos/ProofFragment.hpp"
#include "solve/Solver.hpp"
#include "pos/ProofValidator.hpp"
#include "common/Utils.hpp"

int exhaustive_test(PlotFile::PlotFileContents &plot)
{
    // This function not currently used but can be useful for debugging / exhaustive testing with RETAIN_X_VALUES_TO_T3
    ProofFragmentCodec fragment_codec(plot.params);

#ifdef RETAIN_X_VALUES_TO_T3
    for (int partition = 0; partition < plot.data.t5_to_t4_back_pointers.size(); partition++)
        // int partition = 0;
        for (int test_slot = 0; test_slot < plot.data.t5_to_t4_back_pointers[partition].size(); test_slot++)
        {
            // wait for key press, show current test number
            // std::cout << "Press enter to continue to test " << test_slot << " in partition " << partition << std::endl;
            // std::cin.get();

            T5Pairing t5_pairing = plot.data.t5_to_t4_back_pointers[partition][test_slot]; // now get t4 L and R pairings
            T4BackPointers t4_to_t3_L = plot.data.t4_to_t3_back_pointers[partition][t5_pairing.t4_index_l];
            T4BackPointers t4_to_t3_R = plot.data.t4_to_t3_back_pointers[partition][t5_pairing.t4_index_r];
            ProofFragment fragment_LL = plot.data.t3_proof_fragments[t4_to_t3_L.fragment_index_l];
            ProofFragment fragment_LR = plot.data.t3_proof_fragments[t4_to_t3_L.fragment_index_r];
            ProofFragment fragment_RL = plot.data.t3_proof_fragments[t4_to_t3_R.fragment_index_l];
            ProofFragment fragment_RR = plot.data.t3_proof_fragments[t4_to_t3_R.fragment_index_r];
            std::cout << "Fragments LL: " << fragment_LL << std::endl;
            // decode it to get x-bits

            uint64_t decrypted_xs_LL = fragment_codec.decode(fragment_LL);
            uint64_t decrypted_xs_LR = fragment_codec.decode(fragment_LR);
            uint64_t decrypted_xs_RL = fragment_codec.decode(fragment_RL);
            uint64_t decrypted_xs_RR = fragment_codec.decode(fragment_RR);

            if (fragment_codec.validate_proof_fragment(fragment_LL, plot.data.xs_correlating_to_proof_fragments[t4_to_t3_L.fragment_index_l].data()))
            {
                std::cout << "Fragments LL match x-bits." << std::endl;
            }
            else
            {
                std::cerr << "Fragments LL do not match x-bits." << std::endl;
                return 1;
            }
            if (fragment_codec.validate_proof_fragment(fragment_LR, plot.data.xs_correlating_to_proof_fragments[t4_to_t3_L.fragment_index_r].data()))
            {
                std::cout << "Fragments LR match x-bits." << std::endl;
            }
            else
            {
                std::cerr << "Fragments LR do not match x-bits." << std::endl;
                return 1;
            }
            if (fragment_codec.validate_proof_fragment(fragment_RL, plot.data.xs_correlating_to_proof_fragments[t4_to_t3_R.fragment_index_l].data()))
            {
                std::cout << "Fragments RL match x-bits." << std::endl;
            }
            else
            {
                std::cerr << "Fragments RL do not match x-bits." << std::endl;
                return 1;
            }
            if (fragment_codec.validate_proof_fragment(fragment_RR, plot.data.xs_correlating_to_proof_fragments[t4_to_t3_R.fragment_index_r].data()))
            {
                std::cout << "Fragments RR match x-bits." << std::endl;
            }
            else
            {
                std::cerr << "Fragments RR do not match x-bits." << std::endl;
                return 1;
            }
            std::cout << "All fragments match x-bits." << std::endl;

            // output full x's solution
            std::cout << "Xs solution: ";
            std::vector<uint32_t> xs_solution;
            std::vector<uint32_t> x_bits_list;
            int bit_drop = plot.params.get_k() / 2;
            for (int i = 0; i < 8; i++)
            {
                std::cout << plot.data.xs_correlating_to_proof_fragments[t4_to_t3_L.fragment_index_l][i] << " ";
                xs_solution.push_back(plot.data.xs_correlating_to_proof_fragments[t4_to_t3_L.fragment_index_l][i]);
                if (i % 2 == 0)
                {
                    x_bits_list.push_back(plot.data.xs_correlating_to_proof_fragments[t4_to_t3_L.fragment_index_l][i] >> bit_drop);
                }
            }
            for (int i = 0; i < 8; i++)
            {
                std::cout << plot.data.xs_correlating_to_proof_fragments[t4_to_t3_L.fragment_index_r][i] << " ";
                xs_solution.push_back(plot.data.xs_correlating_to_proof_fragments[t4_to_t3_L.fragment_index_r][i]);
                if (i % 2 == 0)
                {
                    x_bits_list.push_back(plot.data.xs_correlating_to_proof_fragments[t4_to_t3_L.fragment_index_r][i] >> bit_drop);
                }
            }
            for (int i = 0; i < 8; i++)
            {
                std::cout << plot.data.xs_correlating_to_proof_fragments[t4_to_t3_R.fragment_index_l][i] << " ";
                xs_solution.push_back(plot.data.xs_correlating_to_proof_fragments[t4_to_t3_R.fragment_index_l][i]);
                if (i % 2 == 0)
                {
                    x_bits_list.push_back(plot.data.xs_correlating_to_proof_fragments[t4_to_t3_R.fragment_index_l][i] >> bit_drop);
                }
            }
            for (int i = 0; i < 8; i++)
            {
                std::cout << plot.data.xs_correlating_to_proof_fragments[t4_to_t3_R.fragment_index_r][i] << " ";
                xs_solution.push_back(plot.data.xs_correlating_to_proof_fragments[t4_to_t3_R.fragment_index_r][i]);
                if (i % 2 == 0)
                {
                    x_bits_list.push_back(plot.data.xs_correlating_to_proof_fragments[t4_to_t3_R.fragment_index_r][i] >> bit_drop);
                }
            }
            std::cout << std::endl;

            // let's verify xs_solution is correct before we solve

            ProofValidator proof_validator(plot.params);
            if (proof_validator.validate_table_5_pairs(xs_solution.data()))
            {
                std::cout << "Xs solution is valid." << std::endl;
            }
            else
            {
                std::cerr << "Xs solution is invalid." << std::endl;
                return 1;
            }

            Solver solver(plot.params);
            std::vector<std::vector<uint32_t>> all_proofs = solver.solve(x_bits_list, xs_solution);

            std::cout << "Found " << all_proofs.size() << " proofs." << std::endl;
            for (size_t i = 0; i < all_proofs.size(); i++)
            {
                std::cout << "Proof " << i << ": ";
                for (size_t j = 0; j < all_proofs[i].size(); j++)
                {
                    std::cout << all_proofs[i][j] << " ";
                }
                std::cout << std::endl;
            }
            if (all_proofs.size() == 0)
            {
                std::cerr << "ERROR: No proofs found." << std::endl;
                return 1;
            }
            if (all_proofs.size() > 1)
            {
                std::cout << "Multiple proofs found! Chaining will resolve which is correct." << std::endl;
            }
        }
    std::cout << "Done." << std::endl;
#else
    std::cerr << "RETAIN_X_VALUES_TO_T3 is not defined. Cannot run exhaustive test." << std::endl;
#endif
    return 0;
}

int benchmark(uint8_t k, uint8_t plot_strength)
{
    const std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    // hex to bytes
    std::array<uint8_t, 32> plot_id = Utils::hexToBytes(plot_id_hex);
    // const uint8_t *plot_id = Utils::hexToBytes(plot_id_hex);
#ifdef NON_BIPARTITE_BEFORE_T3
    uint32_t x_bits_list[256] = {9739, 13461, 10770, 14445, 7339, 6712, 1506, 1453, 4934, 6847, 4101, 9824, 9196, 12120, 6524, 15576, 4026, 12101, 6865, 9189, 4937, 5899, 4342, 13097, 14130, 14922, 10068, 1542, 11971, 9511, 788, 6083, 4026, 12101, 6865, 9189, 4937, 5899, 4342, 13097, 1469, 8090, 10717, 15242, 1356, 619, 7947, 242, 2674, 8416, 15671, 4803, 15002, 15085, 14034, 5366, 5675, 8698, 2355, 3726, 8241, 413, 6578, 7566, 2674, 8416, 15671, 4803, 1404, 9548, 3429, 8580, 2860, 1151, 10345, 1090, 4246, 4, 11413, 12208, 667, 15859, 5872, 10114, 6856, 15823, 6015, 8627, 5987, 4459, 12826, 4445, 9445, 8679, 1566, 12328, 667, 15859, 5872, 10114, 6856, 15823, 6015, 8627, 8192, 8131, 10476, 2966, 3466, 8135, 11290, 8167, 4835, 15248, 12971, 13523, 7356, 16330, 2508, 3642, 12260, 10009, 13650, 10749, 5676, 3509, 14751, 8352, 16070, 12828, 11246, 3880, 1529, 5667, 6331, 7225, 11704, 192, 13773, 8651, 4920, 7466, 15481, 6182, 16070, 12828, 11246, 3880, 1529, 5667, 6331, 7225, 6641, 11842, 3053, 12148, 13731, 10861, 15945, 1189, 16070, 12828, 11246, 3880, 9592, 336, 14284, 13532, 3435, 2250, 8778, 9343, 13788, 14094, 10633, 13773, 16070, 12828, 11246, 3880, 9592, 336, 14284, 13532, 8272, 10913, 5634, 5626, 2824, 7585, 9693, 1610, 16070, 12828, 11246, 3880, 9592, 336, 14284, 13532, 515, 5459, 8248, 9808, 4104, 6409, 15355, 7086, 13734, 11363, 823, 11502, 535, 328, 3902, 15550, 6622, 11639, 1600, 5864, 4765, 7538, 7133, 7887, 13734, 11363, 823, 11502, 535, 328, 3902, 15550, 14566, 11918, 1863, 11614, 9744, 1781, 13911, 15195, 13734, 11363, 823, 11502, 535, 328, 3902, 15550, 5429, 6783, 9648, 140, 11195, 3294, 10334, 14373};
#else
    uint32_t x_bits_list[256] = {5698, 1105, 3557, 6679, 16058, 5983, 9317, 8599, 14352, 1427, 9546, 11208, 6908, 6955, 15821, 6398, 5698, 1105, 3557, 6679, 16058, 5983, 9317, 8599, 4200, 15111, 3710, 11345, 6180, 9108, 8532, 2950, 5698, 1105, 3557, 6679, 16058, 5983, 9317, 8599, 9672, 16268, 7425, 3148, 6192, 10267, 4835, 6671, 13276, 2908, 7300, 11715, 12689, 14131, 4077, 1658, 7831, 5071, 9035, 12728, 6452, 285, 13294, 12809, 13276, 2908, 7300, 11715, 12689, 14131, 4077, 1658, 5226, 10950, 2837, 4284, 11588, 13945, 14451, 8226, 13276, 2908, 7300, 11715, 12689, 14131, 4077, 1658, 4995, 15954, 11003, 4495, 1706, 7869, 13911, 10423, 13276, 2908, 7300, 11715, 12689, 14131, 4077, 1658, 8051, 15527, 9535, 12672, 1174, 6788, 1254, 54, 13276, 2908, 7300, 11715, 12689, 14131, 4077, 1658, 4408, 15692, 6959, 6780, 2347, 9517, 417, 1740, 13994, 10202, 11892, 4997, 8070, 16002, 1230, 11028, 9730, 3114, 4877, 10093, 5178, 2548, 11057, 10285, 13842, 12690, 2078, 12022, 3579, 4573, 15185, 4046, 7558, 12635, 9514, 7133, 1047, 6796, 2426, 16203, 13842, 12690, 2078, 12022, 3579, 4573, 15185, 4046, 5807, 15638, 11307, 14090, 831, 15722, 12025, 7333, 13842, 12690, 2078, 12022, 3579, 4573, 15185, 4046, 1485, 8400, 5844, 5583, 14922, 8871, 16297, 12094, 13842, 12690, 2078, 12022, 3579, 4573, 15185, 4046, 7108, 13167, 11297, 10006, 8136, 14080, 9854, 10958, 9608, 8516, 14988, 1800, 3415, 1227, 9709, 6798, 14375, 3615, 5315, 2355, 1544, 437, 2573, 6534, 9608, 8516, 14988, 1800, 3415, 1227, 9709, 6798, 5207, 5201, 13859, 5317, 11916, 15259, 11966, 2323, 13533, 7713, 10735, 2482, 4527, 15370, 9704, 9599, 4836, 4791, 12169, 11689, 8903, 10716, 12033, 15071};
#endif

    std::cout << "Running benchmark for:" << std::endl;
#ifdef NON_BIPARTITE_BEFORE_T3
    std::cout << "NON_BIPARTITE_BEFORE_T3" << std::endl;
#else
    std::cout << "BIPARTITE" << std::endl;
#endif

    ProofParams params(plot_id.data(), k, plot_strength);
    params.show();

    Solver solver(params);
    solver.setBitmaskShift(0); // with large chaining of 16 bitmask shift doesn't help much (if at all).
#ifdef NON_BIPARTITE_BEFORE_T3
    solver.setUsePrefetching(true);
    // std::cout << "Not using prefetching." << std::endl;
    std::cout << "Using prefetching." << std::endl;
#else
    solver.setUsePrefetching(false);
    // std::cout << "Using prefetching." << std::endl;
    std::cout << "Not using prefetching." << std::endl;
#endif

    std::vector<uint32_t> x_bits_list_vector;
    for (int i = 0; i < 256; i++)
    {
        x_bits_list_vector.push_back(x_bits_list[i]);
    }
    const std::vector<uint32_t> x_solution;
    std::vector<std::array<uint32_t, 512>> all_proofs = solver.solve(std::span<uint32_t const, 256>(x_bits_list_vector), x_solution);

    /*std::cout << "Found " << all_proofs.size() << " proofs." << std::endl;
    for (size_t i = 0; i < all_proofs.size(); i++)
    {
        std::cout << "Proof " << i << ": ";
        for (size_t j = 0; j < all_proofs[i].size(); j++)
        {
            std::cout << all_proofs[i][j] << " ";
        }
        std::cout << std::endl;
    }*/

    return 0;
}

int do_exhaustive_test(const std::string &plot_file)
{
    // read plot file
    PlotFile::PlotFileContents plot = PlotFile::readData(plot_file);
    if (plot.data == PlotData())
    {
        std::cerr << "Error: plot file is empty or invalid." << std::endl;
        return 1;
    }

    std::cout << "Plot file read successfully: " << plot_file << std::endl;
    plot.params.debugPrint();

    // for exhaustive testing, requires plot and compilation with RETAIN_X_VALUES_TO_T3
#ifdef RETAIN_X_VALUES_TO_T3
    exhaustive_test(plot);
#endif

    return 0;
}

int xbits(const std::string &plot_id_hex, const std::vector<uint32_t> &x_bits_list, uint8_t k, uint8_t strength)
{
    // convert plot_id_hex to bytes
    std::array<uint8_t, 32> plot_id = Utils::hexToBytes(plot_id_hex);
    ProofParams params(plot_id.data(), k, strength);

    params.show();

    Solver solver(params);
    solver.setBitmaskShift(0); // with large chaining of 16 bitmask shift doesn't help much (if at all).
#ifdef NON_BIPARTITE_BEFORE_T3
    solver.setUsePrefetching(true);
    std::cout << "Using prefetching." << std::endl;
#else
    solver.setUsePrefetching(false);
    std::cout << "Not using prefetching." << std::endl;
#endif

    const std::vector<uint32_t> x_solution;
    std::vector<std::array<uint32_t, 512>> all_proofs = solver.solve(std::span<uint32_t const, 256>(x_bits_list), x_solution);

    std::cout << "Found " << all_proofs.size() << " proofs." << std::endl;
    for (size_t i = 0; i < all_proofs.size(); i++)
    {
        std::cout << "Proof " << i << " x-values (" << all_proofs[i].size() << "): ";
        for (size_t j = 0; j < all_proofs[i].size(); j++)
        {
            std::cout << all_proofs[i][j] << ", ";
        }
        std::cout << std::endl;
        std::cout << "Proof hex: " << Utils::kValuesToCompressedHex(params.get_k(), all_proofs[i]) << std::endl;
    }

    return 0;
}

int main(int argc, char *argv[])
try
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <mode> <arg>\n"
                  << "Modes:\n"
                  << "  benchmark <k-size> [strength (default 2)]   Run benchmark with the given k-size integer and optional plot strength\n"
                  << "  prove     <plot file>  Run proof on the given plot file.\n";
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "benchmark")
    {
        int k = 0;
        int plot_strength = argv[3] ? std::stoi(argv[3]) : 2; // default strength is 2
        try
        {
            k = std::stoi(argv[2]);
            // k must be 18...32 even
            if (k < 18 || k > 32 || (k % 2) != 0)
            {
                std::cerr << "Error: k-size must be an even integer between 18 and 32." << std::endl;
                return 1;
            }
        }
        catch (const std::invalid_argument &)
        {
            std::cerr << "Error: k-size must be an integer." << std::endl;
            return 1;
        }
        catch (const std::out_of_range &)
        {
            std::cerr << "Error: k-size out of range." << std::endl;
            return 1;
        }

        std::cout << "Running benchmark with k-size = " << k << " and plot strength = " << plot_strength << std::endl;
        return benchmark(numeric_cast<uint8_t>(k), numeric_cast<uint8_t>(plot_strength));
    }
    else if (mode == "xbits")
    {
        // must have 5 args: xbits <k-size> <plot_id_hex> <xbits_hex> <strength>
        if (argc != 5)
        {
            std::cerr << "Usage: " << argv[0] << " xbits <plot_id_hex> <xbits_hex> [strength]\n"
                      << "  plot_id_hex: 64-hex-character string\n"
                      << "  xbits_hex: string for 256 k/2-bit x-values\n"
                      << "  strength: optional integer (default 2)\n";
            return 1;
        }
        /*int k = 0;
        try
        {
            k = std::stoi(argv[2]);
            // k must be 18...32 even
            if (k < 18 || k > 32 || (k % 2) != 0)
            {
                std::cerr << "Error: k-size must be an even integer between 18 and 32." << std::endl;
                return 1;
            }
        }
        catch (const std::invalid_argument &e)
        {
            std::cerr << "Error: k-size must be an integer." << std::endl;
            return 1;
        }
        catch (const std::out_of_range &e)
        {
            std::cerr << "Error: k-size out of range." << std::endl;
            return 1;
        }*/

        // then get plot id hex string
        std::string plot_id_hex = argv[2];
        if (plot_id_hex.length() != 64)
        {
            std::cerr << "Error: plot_id must be a 64-hex-character string." << std::endl;
            return 1;
        }

        // then get string of 256 hex characters for xbits
        std::string xbits_hex = argv[3];
        size_t xbits_hex_len = xbits_hex.length();
        std::vector<uint32_t> x_bits_list;
        size_t calculated_k = xbits_hex_len / 32; // each uint32_t is 4 hex characters
        std::cout << "xbits_hex length: " << xbits_hex_len << ", calculated k: " << calculated_k << std::endl;
        if (calculated_k < 18 || calculated_k > 32 || (calculated_k % 2) != 0)
        {
            std::cerr << "Error: k-size must be an even integer between 18 and 32." << std::endl;
            return 1;
        }
        // decompress each x value from k/2 bits.
        x_bits_list = Utils::compressedHexToKValues(numeric_cast<int>(calculated_k / 2), xbits_hex);
        if (x_bits_list.size() != 256)
        {
            std::cerr << "Error: xbits_hex does not decode to 256 uint32_t values. Has " << x_bits_list.size() << " instead." << std::endl;
            return 1;
        }

        int plot_strength = argv[4] ? std::stoi(argv[4]) : 2; // default strength is 2
        std::cout << "Running xbits with k-size = " << calculated_k << " plot id: " << plot_id_hex << " xbits = " << xbits_hex << " plot strength = " << plot_strength << std::endl;
        // convert xbits_hex to uint32_t array

        return xbits(plot_id_hex, x_bits_list, numeric_cast<uint8_t>(calculated_k), numeric_cast<uint8_t>(plot_strength));
    }
    else
    {
        std::cerr << "Unknown mode: " << mode << "\n"
                  << "Use 'benchmark' or 'xbits'" << std::endl;
        return 1;
    }
}
catch (const std::exception &e)
{
    std::cerr << "Failed with exception: " << e.what() << std::endl;
}
