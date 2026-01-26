#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "pos/ProofFragment.hpp"
#include "pos/ProofValidator.hpp"
#include "solve/Solver.hpp"
#include "test_util.h"

TEST_SUITE_BEGIN("solve");

TEST_CASE("solve-partial")
{
    // TODO: add solve tests for k28,k30, and k32.
    int k = 18;
    int plot_strength = 2;

    // xs were created by running a k 18 plot with RETAIN_X_VALUES on, and scanning challenges to
    // find an example proof with full x values.
    std::vector<uint32_t> k18_xs_in_proof = { 67829,
        225328,
        71782,
        191211,
        86028,
        16517,
        113972,
        59711,
        148021,
        124620,
        220476,
        219515,
        213127,
        136911,
        30307,
        81615,
        113967,
        38634,
        76057,
        100536,
        65619,
        211556,
        32222,
        40170,
        203271,
        182704,
        110847,
        76328,
        148174,
        201795,
        8495,
        67902,
        171857,
        210386,
        48012,
        91434,
        87691,
        46220,
        189088,
        156118,
        165845,
        121679,
        213228,
        140459,
        216907,
        175293,
        29607,
        230490,
        186182,
        238699,
        229533,
        224807,
        222923,
        247127,
        109496,
        238077,
        38469,
        178510,
        104599,
        253540,
        113897,
        142377,
        169660,
        147132,
        53832,
        66835,
        138285,
        193768,
        204077,
        123519,
        137154,
        85905,
        39793,
        12347,
        209443,
        14364,
        252004,
        5889,
        95435,
        200208,
        174504,
        237208,
        199757,
        146729,
        167381,
        110531,
        57978,
        55261,
        32730,
        121818,
        232533,
        73157,
        229061,
        205705,
        234299,
        153856,
        204317,
        146942,
        224128,
        120823,
        111912,
        129036,
        216366,
        182462,
        234413,
        115700,
        128969,
        114307,
        108035,
        12907,
        10387,
        32380,
        47844,
        69711,
        154287,
        41589,
        14542,
        139372,
        257684,
        78243,
        237349,
        72476,
        249237,
        32673,
        97814,
        122095,
        260170,
        257538 };
    std::vector<uint32_t> x_bits_list;
    size_t num_x_bit_quadruples = k18_xs_in_proof.size() / 8;
    for (size_t i = 0; i < num_x_bit_quadruples; i++) {
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

    ProofParams params(
        plot_id.data(), numeric_cast<uint8_t>(k), numeric_cast<uint8_t>(plot_strength));
    ProofCore proof_core(params);
    ProofFragmentCodec fragment_codec(params);

    Solver solver(params);
    solver.setUsePrefetching(true);

    std::vector<uint32_t> const x_solution;
    assert(x_bits_list.size() == TOTAL_T1_PAIRS_IN_PROOF);
    std::vector<std::array<uint32_t, TOTAL_XS_IN_PROOF>> all_proofs
        = solver.solve(std::span<uint32_t, TOTAL_T1_PAIRS_IN_PROOF>(x_bits_list), k18_xs_in_proof);

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
    for (auto const& proof: all_proofs) {
        ENSURE(proof.size() == k18_xs_in_proof.size());
        for (size_t i = 0; i < proof.size(); i++) {
            ENSURE(proof[i] == k18_xs_in_proof[i]);
        }
    }
}
