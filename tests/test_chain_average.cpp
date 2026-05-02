#include "common/Timer.hpp"
#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include "pos/Chainer.hpp"
#include "pos/ProofConstants.hpp"
#include "prove/Prover.hpp"
#include "test_util.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>

TEST_SUITE_BEGIN("chain-average");

namespace {

// Stirling number of the second kind, S(n, k).
double stirling2(int n, int k)
{
    if (k == 0)
        return n == 0 ? 1.0 : 0.0;
    if (k > n)
        return 0.0;
    if (k == n || k == 1)
        return 1.0;
    return k * stirling2(n - 1, k) + stirling2(n - 1, k - 1);
}

// Raw moment E[X^m] for X ~ Poisson(lambda):
//   E[X^m] = sum_{j=0..m} S(m, j) * lambda^j
double poisson_raw_moment(double lambda, int m)
{
    double sum = 0.0;
    double lambda_pow = 1.0;
    for (int j = 0; j <= m; ++j) {
        sum += stirling2(m, j) * lambda_pow;
        lambda_pow *= lambda;
    }
    return sum;
}

// Predicted E[chains/challenge] under independent Poisson(2^chain_set_bits) set sizes.
//   E[chains] = E[|S|^(L/N)]^N * 2^-total_filter_bits
double jensen_expected_chains(
    int chain_set_bits, int num_chain_links, int num_challenge_sets, int total_filter_bits)
{
    int const reuse_per_set = num_chain_links / num_challenge_sets;
    double const lambda = std::ldexp(1.0, chain_set_bits);
    double const moment = poisson_raw_moment(lambda, reuse_per_set);
    double e_set_pow_n = 1.0;
    for (int i = 0; i < num_challenge_sets; ++i)
        e_set_pow_n *= moment;
    return e_set_pow_n * std::ldexp(1.0, -total_filter_bits);
}

} // namespace

// Runs many challenges against a real plot, prints the empirical mean of
// chains-per-challenge along with the Jensen-inequality theoretical mean
// under independent Poisson set sizes, and asserts the empirical mean is
// close to the design target of 1.0 chains/challenge.
//
// With NUM_CHALLENGE_SETS = 4 (each set used L/N = 4 times in a chain), the
// convexity of E[X^4] under Poisson would push the raw mean to ~1.44.
// `POS2_RECALIBRATE_LAST_LINK_FILTER` (defined in Chainer.hpp) tightens the
// last-link filter by exactly that factor so the empirical mean lands at
// ~1.0. If that macro is set to 0, the assertions below will fail.
TEST_CASE("chain-average-real-plot")
{
#ifdef NDEBUG
    constexpr size_t N_CHALLENGES = 1000;
#else
    constexpr size_t N_CHALLENGES = 100;
#endif

    constexpr uint8_t k = 18;
    constexpr uint8_t plot_strength = 2;
    constexpr uint8_t testnet = 0;

    std::string const plot_id_hex
        = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    printfln("Creating k=%d strength=%d plot", (int)k, (int)plot_strength);
    Timer timer {};
    timer.debugOut = true;
    timer.start("Plot Creation");
    ProofParams proof_params(Utils::hexToBytes(plot_id_hex).data(), k, plot_strength, testnet);
    Plotter plotter(proof_params);
    PlotData plot = plotter.run();
    timer.stop();

    std::string const plot_file_name = std::string("plot_chain_avg_k") + std::to_string(k) + "_s"
        + std::to_string(plot_strength) + "_" + plot_id_hex + ".bin";
    timer.start("Writing plot file: " + plot_file_name);
    PlotFile::writeData(plot_file_name,
        plot,
        plotter.getProofParams(),
        0,
        0,
        std::array<uint8_t, 32 + 48 + 32>({}));
    timer.stop();

    Prover prover(plot_file_name);

    std::vector<int> per_challenge_counts;
    per_challenge_counts.reserve(N_CHALLENGES);
    size_t total_chains = 0;

    timer.start("Running " + std::to_string(N_CHALLENGES) + " challenges");
    for (size_t i = 0; i < N_CHALLENGES; ++i) {
        std::array<uint8_t, 32> challenge {};
        challenge[0] = static_cast<uint8_t>(i & 0xFF);
        challenge[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
        challenge[2] = static_cast<uint8_t>((i >> 16) & 0xFF);
        challenge[3] = static_cast<uint8_t>((i >> 24) & 0xFF);
        std::vector<QualityChain> chains = prover.prove(challenge);
        per_challenge_counts.push_back(static_cast<int>(chains.size()));
        total_chains += chains.size();
    }
    double const elapsed_ms = timer.stop();

    double const mean = static_cast<double>(total_chains) / static_cast<double>(N_CHALLENGES);
    double variance = 0.0;
    int min_count = std::numeric_limits<int>::max();
    int max_count = 0;
    for (int c: per_challenge_counts) {
        variance += (c - mean) * (c - mean);
        min_count = std::min(min_count, c);
        max_count = std::max(max_count, c);
    }
    variance /= static_cast<double>(N_CHALLENGES);
    double const stddev = std::sqrt(variance);
    double const sem = stddev / std::sqrt(static_cast<double>(N_CHALLENGES));

    std::map<int, int> histogram;
    for (int c: per_challenge_counts)
        histogram[c]++;

    int const total_filter_bits = NUM_CHAIN_LINKS * CHAIN_SET_BITS;
    double const jensen_expected = jensen_expected_chains(
        CHAIN_SET_BITS, NUM_CHAIN_LINKS, NUM_CHALLENGE_SETS, total_filter_bits);

    std::cout << "\n--- Chain proof rate over " << N_CHALLENGES << " challenges ---\n";
    std::cout << "Plot:                     k=" << (int)k << ", strength=" << (int)plot_strength
              << "\n";
    std::cout << "Total chains found:       " << total_chains << "\n";
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "Empirical mean:           " << mean << " chains/challenge\n";
    std::cout << "Stddev (per challenge):   " << stddev << "\n";
    std::cout << "Std error of the mean:    " << sem << "\n";
    std::cout << std::defaultfloat;
    std::cout << "Min/Max per challenge:    " << min_count << " / " << max_count << "\n";
    std::cout << "Elapsed:                  " << elapsed_ms << " ms ("
              << (elapsed_ms / static_cast<double>(N_CHALLENGES)) << " ms/challenge)\n";

    std::cout << "Histogram (chains -> #challenges):\n";
    for (auto const& [count, n]: histogram) {
        std::cout << "  " << std::setw(3) << count << " : " << n << "\n";
    }

    std::cout << "\n--- Theoretical Jensen expectation ---\n";
    std::cout << "Assuming |set| ~ Poisson(" << (1 << CHAIN_SET_BITS) << ")\n";
    std::cout << "  NUM_CHAIN_LINKS:        " << NUM_CHAIN_LINKS << "\n";
    std::cout << "  NUM_CHALLENGE_SETS:     " << NUM_CHALLENGE_SETS << "\n";
    std::cout << "  reuse per set (L/N):    " << (NUM_CHAIN_LINKS / NUM_CHALLENGE_SETS) << "\n";
    std::cout << "  total filter bits:      " << total_filter_bits << "\n";
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "  Jensen expected mean:   " << jensen_expected << " chains/challenge\n";

    std::cout << "\n--- Target ---\n";
    std::cout << "Designed target:          1.0000 chains/challenge\n";
    std::cout << "Empirical / target:       " << mean << "\n";
    std::cout << "Empirical / Jensen:       " << (mean / jensen_expected) << "\n";
    std::cout << std::defaultfloat;

    // Assert the empirical mean is close to the design target of 1.0.
    // The last-link recalibration (POS2_RECALIBRATE_LAST_LINK_FILTER in
    // Chainer.hpp) divides by the Jensen bonus so this lands near 1. Toggle
    // that macro to 0 and these assertions will fail with mean ~1.44.
    constexpr double TARGET = 1.0;
    constexpr double TOL = 0.10; // tolerate +/- 10%
    CHECK_MESSAGE(mean >= TARGET * (1.0 - TOL),
        "empirical mean " << mean << " is more than " << (TOL * 100.0) << "% below design target "
                          << TARGET);
    CHECK_MESSAGE(mean <= TARGET * (1.0 + TOL),
        "empirical mean " << mean << " is more than " << (TOL * 100.0) << "% above design target "
                          << TARGET);
}

TEST_SUITE_END();
