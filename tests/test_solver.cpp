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
        107610, 53093, 19221, 31922, 161725, 87649, 72927, 83879, 135474, 134230, 155804, 2075, 104426, 64569, 250776, 160949, 255333, 106922, 101189, 234847, 234826, 98733, 220557, 252683, 217150, 137541, 195472, 126466, 47179, 190459, 224470, 230608, 93580, 43759, 94421, 262098, 173592, 133500, 141151, 125, 74625, 51283, 250759, 68190, 10174, 74084, 35126, 63645, 136706, 380, 50553, 76985, 1917, 43409, 174473, 244303, 163122, 94672, 226226, 202321, 126544, 99599, 161610, 169232, 246845, 64061, 221972, 253529, 116988, 261460, 200153, 241459, 109019, 31825, 147639, 40594, 155724, 20173, 177686, 54060, 170031, 24901, 206819, 108904, 241329, 206982, 201788, 108470, 51982, 130268, 184267, 188235, 173990, 203372, 147669, 53211, 96405, 187529, 8471, 178644, 221124, 189499, 125560, 44185, 138786, 98435, 162947, 41258, 184261, 106237, 36808, 31729, 61737, 202609, 46766, 205613, 204671, 96638, 190191, 188177, 88352, 82032, 192763, 84099, 139579, 119187, 91171, 27097 
    };
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
