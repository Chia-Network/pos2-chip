#include <iostream>
#include <string>
#include <cstdlib>
#include "plot/PlotFile.hpp"
#include "pos/ProofFragment.hpp"
#include "solve/Solver.hpp"
#include "pos/ProofValidator.hpp"
#include "common/Utils.hpp"

int benchmark(uint8_t k, uint8_t plot_strength)
{
    const std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    // hex to bytes
    std::array<uint8_t, 32> plot_id = Utils::hexToBytes(plot_id_hex);

    // benchmark with sequential x-bits, so we see performance in full set of groups.
    uint32_t x_bits_list[TOTAL_T1_PAIRS_IN_PROOF];
    for (int i=0; i < TOTAL_T1_PAIRS_IN_PROOF; i++) {
        x_bits_list[i] = i;
    }

    std::cout << "Running benchmark for:" << std::endl;

    ProofParams params(plot_id.data(), k, plot_strength);
    params.show();

    Solver solver(params);
    solver.setBitmaskShift(0); // with large chaining of 16 bitmask shift doesn't help much (if at all).

    solver.setUsePrefetching(true);
    // std::cout << "Not using prefetching." << std::endl;
    std::cout << "Using prefetching." << std::endl;

    std::vector<uint32_t> x_bits_list_vector;
    for (int i = 0; i < TOTAL_T1_PAIRS_IN_PROOF; i++)
    {
        x_bits_list_vector.push_back(x_bits_list[i]);
    }
    const std::vector<uint32_t> x_solution;
    std::vector<std::array<uint32_t, TOTAL_XS_IN_PROOF>> all_proofs = solver.solve(std::span<uint32_t const, TOTAL_T1_PAIRS_IN_PROOF>(x_bits_list_vector), x_solution);

    solver.timings().printSummary();

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

    solver.setUsePrefetching(true);
    std::cout << "Using prefetching." << std::endl;

    const std::vector<uint32_t> x_solution;
    std::vector<std::array<uint32_t, TOTAL_XS_IN_PROOF>> all_proofs = solver.solve(std::span<uint32_t const, TOTAL_XS_IN_PROOF/2>(x_bits_list), x_solution);

    solver.timings().printSummary();

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
                  << "  xbits <plot_id_hex> <xbits_hex> <strength>   Solve for proofs given plot ID, partial x-bits, and plot strength\n";
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
        size_t calculated_k = xbits_hex_len / (TOTAL_XS_IN_PROOF / 16); // each uint32_t is 4 hex characters
        std::cout << "xbits_hex length: " << xbits_hex_len << ", calculated k: " << calculated_k << std::endl;
        if (calculated_k < 18 || calculated_k > 32 || (calculated_k % 2) != 0)
        {
            std::cerr << "Error: k-size must be an even integer between 18 and 32." << std::endl;
            return 1;
        }
        // decompress each x value from k/2 bits.
        x_bits_list = Utils::compressedHexToKValues(numeric_cast<int>(calculated_k / 2), xbits_hex);
        if (x_bits_list.size() != (TOTAL_XS_IN_PROOF / 2))
        {
            std::cerr << "Error: xbits_hex does not decode to " << (TOTAL_XS_IN_PROOF / 2) << " uint32_t values. Has " << x_bits_list.size() << " instead." << std::endl;
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
