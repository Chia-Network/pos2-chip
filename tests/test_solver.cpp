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
    std::vector<uint32_t> k18_xs_in_proof = { 210179,
        125456,
        54009,
        174161,
        107915,
        207525,
        257854,
        94354,
        204370,
        43561,
        113844,
        133344,
        84123,
        206690,
        3958,
        167991,
        167889,
        194637,
        204784,
        256666,
        64999,
        175571,
        58819,
        94460,
        258854,
        187002,
        35748,
        165093,
        77420,
        116597,
        122657,
        139621,
        176152,
        174204,
        252608,
        177685,
        77618,
        77212,
        116981,
        170702,
        161952,
        168933,
        84405,
        261915,
        179059,
        138893,
        176814,
        236440,
        207185,
        177108,
        83548,
        237012,
        161869,
        153361,
        117687,
        229453,
        158768,
        91395,
        257843,
        182560,
        67270,
        136174,
        142334,
        32081,
        35922,
        155881,
        203805,
        39878,
        124398,
        84207,
        77923,
        150296,
        140128,
        98685,
        113773,
        134640,
        59203,
        26679,
        25613,
        134593,
        95990,
        133416,
        222634,
        126503,
        17239,
        134920,
        198693,
        60523,
        147716,
        73964,
        198423,
        162248,
        60960,
        253578,
        212962,
        8083,
        27380,
        69995,
        89652,
        243364,
        36023,
        89192,
        77695,
        168502,
        241788,
        23338,
        154364,
        59401,
        108138,
        177920,
        193847,
        14265,
        186599,
        169894,
        114449,
        172789,
        74523,
        197278,
        114921,
        189630,
        194617,
        200096,
        211451,
        57502,
        1812,
        246099,
        85089,
        61601 };
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
