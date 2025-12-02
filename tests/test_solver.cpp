#include "test_util.h"
#include "plot/PlotFile.hpp"
#include "pos/ProofFragment.hpp"
#include "solve/Solver.hpp"
#include "pos/ProofValidator.hpp"
#include "common/Utils.hpp"

TEST_SUITE_BEGIN("solve");

TEST_CASE("solve-partial")
{
    // TODO: add solve tests for k28,k30, and k32.
    int k = 18;
    int plot_strength = 2;

    // xs were created by running a k 18 plot with RETAIN_X_VALUES on, and scanning challenges to find an example proof with full x values.
    std::vector<uint32_t> k18_xs_in_proof = {
        4960, 108156, 226388, 39755, 176399, 187432, 127500, 204445, 85656, 165242, 143381, 244338, 115339, 2863, 143856, 199375, 230475, 207908, 239761, 142756, 226306, 78954, 122310, 156040, 227610, 5483, 174031, 65872, 205805, 237222, 238948, 124533, 35988, 89159, 125295, 256652, 60463, 176475, 60392, 8043, 73616, 41982, 189320, 174858, 116886, 203904, 219063, 10054, 247307, 181187, 180192, 158092, 214139, 38805, 18608, 25709, 150493, 193455, 205089, 26060, 166793, 136953, 56562, 209030, 199810, 111074, 68957, 227682, 226908, 121681, 197173, 196395, 194175, 4449, 139331, 248454, 124322, 172353, 157265, 56136, 189435, 230048, 224946, 188330, 87966, 96049, 36231, 209158, 244101, 240590, 110603, 144289, 212555, 207391, 162876, 31519, 199810, 111074, 68957, 227682, 226908, 121681, 197173, 196395, 28044, 142273, 35840, 87549, 164412, 120543, 142751, 6142, 242261, 11356, 968, 160185, 65070, 29968, 102847, 96368, 29914, 189505, 207097, 78006, 223249, 109524, 20145, 164662 };
    std::vector<uint32_t> x_bits_list;
    size_t num_x_bit_quadruples = k18_xs_in_proof.size() / 8;
    for (size_t i = 0; i < num_x_bit_quadruples; i++)
    {
        uint32_t x0 = k18_xs_in_proof[i * 8 + 0];
        uint32_t x2 = k18_xs_in_proof[i * 8 + 2];
        uint32_t x4 = k18_xs_in_proof[i * 8 + 4];
        uint32_t x6 = k18_xs_in_proof[i * 8 + 6];
        int bit_drop = k / 2; // for k=18, drop 9 bits to get top half
        uint32_t x0_bits = x0 >> bit_drop;
        uint32_t x2_bits = x2 >> bit_drop;
        uint32_t x4_bits = x4 >> bit_drop;
        uint32_t x6_bits = x6 >> bit_drop;
        x_bits_list.push_back(x0_bits);
        x_bits_list.push_back(x2_bits);
        x_bits_list.push_back(x4_bits);
        x_bits_list.push_back(x6_bits);
    }

    std::string plot_id_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    std::array<uint8_t, 32> plot_id = Utils::hexToBytes(plot_id_hex);

    ProofParams params(plot_id.data(), numeric_cast<uint8_t>(k), numeric_cast<uint8_t>(plot_strength));
    ProofCore proof_core(params);
    ProofFragmentCodec fragment_codec(params);

    Solver solver(params);
    solver.setUsePrefetching(true);

    const std::vector<uint32_t> x_solution;
    assert(x_bits_list.size() == TOTAL_T1_PAIRS_IN_PROOF);
    std::vector<std::array<uint32_t, TOTAL_XS_IN_PROOF>> all_proofs = solver.solve(std::span<uint32_t, TOTAL_T1_PAIRS_IN_PROOF>(x_bits_list), k18_xs_in_proof);

    solver.timings().printSummary();

    ENSURE(!all_proofs.empty());
    /*if (all_proofs.size() == 0)
    {
        std::cerr << "Error: no proofs found." << std::endl;
    }
    else
    {
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
    }*/

    // check all proofs matches k18_xs_in_proof
    for (const auto &proof : all_proofs)
    {
        ENSURE(proof.size() == k18_xs_in_proof.size());
        for (size_t i = 0; i < proof.size(); i++)
        {
            ENSURE(proof[i] == k18_xs_in_proof[i]);
        }
    }
}
