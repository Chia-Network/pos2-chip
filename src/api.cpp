#include "prove/Prover.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofParams.hpp"
#include "pos/ProofFragment.hpp"
#include "solve/Solver.hpp"

extern "C" {

// plot_id must point to 32 bytes
// challenge must point to 32 bytes
// proof must point to 512 uint32_t
bool validate_proof(
    uint8_t const* plot_id,
    uint8_t const k_size,
    uint8_t const strength,
    uint8_t const* challenge,
    uint8_t const proof_fragment_scan_filter,
    uint32_t const* proof,
    QualityChain* quality) try
{
    if ((k_size & 1) == 1)
        throw std::invalid_argument("k must be even");
    ProofParams const params(plot_id, k_size, strength);
    ProofValidator validator(params);
    std::optional<QualityChainLinks> quality_links = validator.validate_full_proof(
        std::span<uint32_t const, 512>(proof, proof + 512),
        std::span<uint8_t const, 32>(challenge, challenge + 32),
        proof_fragment_scan_filter
        );
    if (!quality_links) {
        return false;
    }
    quality->chain_links = quality_links.value();
    quality->strength = strength;
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
uint32_t qualities_for_challenge(
    char const* plot_file,
    uint8_t const* challenge,
    uint8_t const proof_fragment_scan_filter,
    QualityChain* output,
    uint32_t const num_outputs) try
{
    std::array<uint8_t, 32> c;
    memcpy(c.data(), challenge, 32);
    Prover p(c, plot_file);

    std::vector<QualityChain> ret = p.prove(proof_fragment_scan_filter);
    uint32_t const num_results = std::min(static_cast<uint32_t>(ret.size()), num_outputs);
    std::copy(ret.begin(), ret.begin() + num_results, output);
    return num_results;
}
catch (std::exception const& e) {
    std::cerr << e.what() << std::endl;
    return 0;
}

// turn a quality proof into a partial proof, which can then be solved into a full proof.
// output must point to exactly 64 uint64 objects. They will all be initialized as the partial proof
// returns true on success, false on failure
bool get_partial_proof(
    char const* plot_file,
    QualityChain const* input,
    uint64_t* output) try
{
    // We don't need the challenge to turn QualityChain into a partial proof, so just pass in a dummy
    std::array<uint8_t, 32> c{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                               0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
    Prover p(c, plot_file);

    std::vector<uint64_t> ret = p.getAllProofFragmentsForProof(*input);
    if (ret.empty()) return false;

    assert(ret.size() == 64);
    std::copy(ret.begin(), ret.end(), output);
    return true;
}
catch (std::exception const& e) {
    std::cerr << e.what() << std::endl;
    return false;
}

// proof must point to exactly 64 proof fragments (each a uint64_t)
// plot ID must point to exactly 32 bytes
// output must point to exactly 512 32-bit integers
bool solve_partial_proof(
    uint64_t const* fragments,
    uint8_t const* plot_id,
    uint8_t const k,
    uint8_t const strength,
    uint32_t* output) try
{
    if ((k & 1) == 1)
        throw std::invalid_argument("k must be even");
    ProofParams params(plot_id, k, strength);
    ProofFragmentCodec c(params);

    std::array<uint32_t, 256> x_bits;
    size_t idx = 0;
    for (int i = 0; i < 64; ++i, ++fragments) {
        for (const uint32_t x: c.get_x_bits_from_proof_fragment(*fragments)) {
            x_bits[idx] = x;
            ++idx;
        }
    }
    assert(idx == 256);

    Solver solver(params);
    std::vector<std::array<uint32_t, 512>> full_proofs = solver.solve(x_bits);
    if (full_proofs.empty()) return false;
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
// memo must point to 32 + 48 + 32 bytes, containing the:
// * pool contract puzzle hash
// * farmer public key
// * plot secret key
// returns true on success
bool create_plot(char const* filename, uint8_t const k, uint8_t const strength, uint8_t const* plot_id, uint8_t const* memo) try {

    if ((k & 1) == 1)
        throw std::invalid_argument("k must be even");
    Plotter plotter(std::span<uint8_t const, 32>(plot_id, plot_id + 32), int(k), int(strength));
    PlotData plot = plotter.run();
    PlotFile::writeData(filename, plot, plotter.getProofParams(), std::span<uint8_t const, 32 + 48 + 32>(memo, memo + 32 + 48 + 32));
    return true;
}
catch (std::exception const& e) {
    std::cerr << e.what() << std::endl;
    return false;
}

}
