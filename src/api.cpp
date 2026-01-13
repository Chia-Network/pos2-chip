#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofFragment.hpp"
#include "pos/ProofParams.hpp"
#include "prove/Prover.hpp"
#include "solve/Solver.hpp"

extern "C" {

// plot_id must point to 32 bytes
// challenge must point to 32 bytes
// proof must point to 512 uint32_t
bool validate_proof(uint8_t const* plot_id,
    uint8_t const k_size,
    uint8_t const strength,
    uint8_t const* challenge,
    uint32_t const* proof,
    QualityChain* quality)
try {
    if ((k_size & 1) == 1)
        throw std::invalid_argument("k must be even");
    ProofParams const params(plot_id, k_size, strength);
    ProofValidator validator(params);
    std::optional<QualityChainLinks> quality_links = validator.validate_full_proof(
        std::span<uint32_t const, TOTAL_XS_IN_PROOF>(proof, proof + TOTAL_XS_IN_PROOF),
        std::span<uint8_t const, 32>(challenge, challenge + 32));
    if (!quality_links) {
        return false;
    }
    quality->chain_links = quality_links.value();
    return true;
}
catch (std::exception const& e) {
    std::cerr << e.what() << std::endl;
    return false;
}

// find quality proofs for a challenge.
// challenge must point to 32 bytes
// plot_file must be a null-terminated string
// output must point to "num_outputs" objects
uint32_t qualities_for_challenge(char const* plot_file,
    uint8_t const* challenge,
    QualityChain* output,
    uint32_t const num_outputs)
try {
    Prover p(plot_file);

    std::span<uint8_t const, 32> const challenge_arr(challenge, challenge + 32);
    std::vector<QualityChain> ret = p.prove(challenge_arr);
    uint32_t const num_results = std::min(static_cast<uint32_t>(ret.size()), num_outputs);
    std::copy(ret.begin(), ret.begin() + num_results, output);
    return num_results;
}
catch (std::exception const& e) {
    std::cerr << e.what() << std::endl;
    return 0;
}

// proof must point to exactly TOTAL_PROOF_FRAGMENTS_IN_PROOF (16) proof fragments (each a uint64_t)
// plot ID must point to exactly 32 bytes
// output must point to exactly TOTAL_XS_IN_PROOF (128) 32-bit integers
bool solve_partial_proof(QualityChain const* quality,
    uint8_t const* plot_id,
    uint8_t const k,
    uint8_t const strength,
    uint32_t* output)
try {
    if ((k & 1) == 1)
        throw std::invalid_argument("k must be even");
    ProofParams params(plot_id, k, strength);
    ProofFragmentCodec c(params);

    std::array<uint32_t, TOTAL_T1_PAIRS_IN_PROOF> x_bits;
    size_t idx = 0;
    for (int i = 0; i < TOTAL_PROOF_FRAGMENTS_IN_PROOF; ++i) {
        for (uint32_t const x: c.get_x_bits_from_proof_fragment(quality->chain_links[i])) {
            x_bits[idx] = x;
            ++idx;
        }
    }
    assert(idx == TOTAL_T1_PAIRS_IN_PROOF);

    Solver solver(params);
    std::vector<std::array<uint32_t, TOTAL_XS_IN_PROOF>> full_proofs = solver.solve(x_bits);
    if (full_proofs.empty())
        return false;
    // TODO: support returning multiple proofs
    std::copy(full_proofs[0].begin(), full_proofs[0].end(), output);
    return true;
}
catch (std::exception const& e) {
    std::cerr << e.what() << std::endl;
    return false;
}

// filename is the full path, null terminated
// plot_id must point to 32 bytes of plot ID
// memo must point to memo_length bytes, containing the:
// * pool contract puzzle hash or pool public key
// * farmer public key
// * plot secret key
// returns true on success
bool create_plot(char const* filename,
    uint8_t const k,
    uint8_t const strength,
    uint8_t const* plot_id,
    uint8_t const index,
    uint16_t const meta_group,
    uint8_t const* memo,
    uint8_t const memo_length)
try {

    if ((k & 1) == 1)
        throw std::invalid_argument("k must be even");
    ProofParams params(plot_id, int(k), int(strength));
    Plotter plotter(params);
    PlotData plot = plotter.run();
    PlotFile::writeData(filename,
        plot,
        plotter.getProofParams(),
        index,
        meta_group,
        std::span<uint8_t const>(memo, memo + memo_length));
    return true;
}
catch (std::exception const& e) {
    std::cerr << e.what() << std::endl;
    return false;
}
}
