#include "common/Utils.hpp"
#include "pos/ProofFragment.hpp"
#include "pos/ProofValidator.hpp"
#include "pos/sha/sha256.hpp"
#include "solve/Solver.hpp"
#include "test_util.h"

#include <algorithm>
#include <array>

TEST_SUITE_BEGIN("solve");

TEST_CASE("solve-partial")
{
    constexpr uint8_t k = 18;
    constexpr uint8_t strength = 2;
    constexpr uint16_t plot_index = 0;
    constexpr char plot_group_id_hex[] = "da9a6a4efcadaf1e3115e79a2b7b2d17890185359f19bfaa02a2f2505a8160b5";
    constexpr char challenge_hex[] = "368d14ca70224ac4acc37f591b28ff43d05a2533d34b3a9e8baf4837aebcc783";

    // These X values come from the first quality chain in the retained k18 plot.
    std::array<uint32_t, TOTAL_XS_IN_PROOF> const expected_xs = {
        75731, 203321, 177312, 111766, 239933, 96237, 86882, 95037,
        234290, 71079, 41831, 40953, 82786, 7607, 69383, 175869,
        11172, 235766, 73210, 187048, 22816, 230484, 196488, 208309,
        238248, 20048, 18010, 240549, 94217, 215968, 237249, 69591,
        23080, 12440, 232094, 213417, 83810, 111667, 234491, 35540,
        97825, 148843, 114321, 66156, 42079, 49170, 130176, 13727,
        157724, 131746, 71057, 239778, 240095, 21592, 204365, 227408,
        109036, 117979, 189985, 159439, 217440, 24677, 62028, 32791,
        167321, 65974, 69116, 144616, 108416, 195492, 258765, 221038,
        167463, 7400, 64292, 93580, 195451, 38466, 196458, 119928,
        28666, 9217, 240720, 51344, 261496, 80990, 162210, 120118,
        61752, 36962, 121705, 214395, 253179, 101928, 192367, 125268,
        228233, 136880, 160446, 38994, 216953, 115794, 124646, 78996,
        1668, 77712, 223511, 187152, 58798, 202015, 58458, 112268,
        165265, 246059, 222175, 3231, 108909, 107449, 85827, 105706,
        106634, 47323, 229529, 199527, 45459, 73153, 39434, 170969
    };

    PlotGroupParams group_params(PlotGroupId(plot_group_id_hex), k, strength, 0);
    PlotProofParams params = group_params.get_plot_params_for_index(plot_index);
    ProofFragmentCodec fragment_codec(params);

    std::array<uint32_t, TOTAL_T1_PAIRS_IN_PROOF> x_bits_list {};
    for (size_t link = 0; link < NUM_CHAIN_LINKS; ++link) {
        ProofFragment fragment = fragment_codec.encode(expected_xs.data() + link * 8);
        auto x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);
        std::copy(x_bits.begin(), x_bits.end(), x_bits_list.begin() + link * 4);
    }

    auto challenge = Utils::hexToBytes(challenge_hex);
    ProofValidator validator(group_params, plot_index);
    REQUIRE(validator.validate_full_proof(expected_xs, challenge).has_value());

    Solver solver(params);
    solver.setUsePrefetching(true);
    auto all_proofs = solver.solve(x_bits_list, expected_xs);

    REQUIRE(!all_proofs.empty());
    CHECK(std::find(all_proofs.begin(), all_proofs.end(), expected_xs) != all_proofs.end());
}

TEST_CASE("x2-candidate-capacity")
{
    // The fully occupied bitmask must fit, including the existing spare-entry rule.
    CHECK(Solver::x2CandidateCapacity(1.0, 8192) > 8192);
    CHECK(Solver::x2CandidateCapacity(4.0, 8192) > 8192);
    CHECK(Solver::x2CandidateCapacity(0.0, 8192) > 0);

    // Sparse candidates still need enough space for uneven worker counts.
    size_t const sparse_capacity = Solver::x2CandidateCapacity(1.0 / 128.0, 1024);
    CHECK(sparse_capacity >= 256);
    CHECK(sparse_capacity % 16 == 0);

    // A final worker can receive a much larger chunk after alignment.
    uint64_t const num_xs = uint64_t(1) << 18;
    uint64_t const chunk = (num_xs / 192) & ~uint64_t(15);
    uint64_t const last_chunk = num_xs - 191 * chunk;
    double const hit_probability = 32768.0 / double(num_xs);
    CHECK(Solver::x2CandidateCapacity(hit_probability, last_chunk)
        > Solver::x2CandidateCapacity(hit_probability, chunk));
}

TEST_CASE("solve-partial-k28-headroom")
{
    constexpr char plot_group_id_hex[] = "44529d30816b84eb7a0c2300b00397492fff1eca7e06b380816f25dd8efa1533";
    PlotGroupParams group_params(PlotGroupId(plot_group_id_hex), 28, 2, 0);

    struct TestCase {
        uint16_t plot_index;
        char const* challenge_hex;
        char const* partial_proof_hex;
    };

    // These quality chains exceeded the old per-worker estimate on a 32-thread CPU.
    TestCase const cases[] = {
        {
            3,
            "6876d117bbac14ba46f127c040b9b828e219b600597f9835ed6d1b2aec9f6b66",
            "8ff1633c62431c0d6e52f6cf20f3f6428035e164888ff064db6ee03a"
            "b740219936d17482553ddb743ed8eb5e46e518268b8ff064db6ee03a"
            "5efd00c5dfab1ab262fc68e53ea77a31182e9288bdf6faaf6543285e"
            "31dc1f9dafb17f959388177eb0d8ce96d0d6b824b5e140aaeffa8f73",
        },
        {
            4,
            "5db04f68b21f26a76662003aaac99054f62aa7b825e3bb0ffa9a5460afafca09",
            "4ac3aad1c715cc43f15b62319944503ee9856738120f5f614d1d5b9e"
            "878bfb4e38759bde2a7710e8a3b41387d6592180c03fe88e5e6614b5"
            "182674d0bd04a8faa2ddabe3916b8c31d2265c67cc279d80849aa7c6"
            "1dafec8236de91f3a9e78edd5410ac36ef87e7cf787342ee905766c3",
        },
        {
            7,
            "58bfd39db26210d6d793c5444d908a2fd312f2f61ae87ff58539b5934135623c",
            "3650199aec40e14efa835517bd9100261608853c3fd369dfe15613c4"
            "a24f214e64a69588d56e19a8a20cb7a3c1995a17208241690fae6379"
            "602a5daa360b6948adfacfaccec303ae05ea1f9435971ad8c3ff073d"
            "7d627ad54b3696717e3daa2b650d03ae05ea1f9435971ad8c3ff073d",
        },
    };

    for (auto const& test: cases) {
        CAPTURE(test.plot_index);
        auto x_bits = Utils::compressedHexToKValues(14, test.partial_proof_hex);
        REQUIRE(x_bits.size() == TOTAL_T1_PAIRS_IN_PROOF);

        Solver solver(group_params.get_plot_params_for_index(test.plot_index));
        auto proofs = solver.solve(Solver::XBitsList(x_bits));
        REQUIRE(!proofs.empty());

        auto challenge = Utils::hexToBytes(test.challenge_hex);
        ProofValidator validator(group_params, test.plot_index);
        for (auto const& proof: proofs) {
            CHECK(validator.validate_full_proof(proof, challenge).has_value());
        }
    }
}

TEST_SUITE_END();
