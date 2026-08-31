#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofFragment.hpp"
#include "pos/ProofParams.hpp"
#include "prove/Prover.hpp"
#include "solve/Solver.hpp"
#include "pos/sha/sha256.hpp"

extern "C" {

// plot_group_id must point to 32 bytes
// challenge must point to 32 bytes
// proof must point to 512 uint32_t
bool validate_proof(uint8_t const* plot_group_id,
    uint16_t const plot_index,
    uint8_t const k_size,
    uint8_t const strength,
    uint8_t const meta_group,
    uint8_t const* challenge,
    uint32_t const* proof,
    QualityChain* quality)
try {
    if ((k_size & 1) != 0 || k_size < 18 || k_size > 32)
        return false;
    if (strength < 2)
        return false;
    if (plot_group_id == nullptr || challenge == nullptr || proof == nullptr || quality == nullptr)
        return false;

    PlotGroupParams params(PlotGroupId(plot_group_id), k_size, strength, meta_group);

    ProofValidator validator(params, plot_index);
    std::optional<QualityChainLinks> quality_links = validator.validate_full_proof(
        std::span<uint32_t const, TOTAL_XS_IN_PROOF>(proof, proof + TOTAL_XS_IN_PROOF),
        std::span<uint8_t const, 32>(challenge, challenge + 32));
    if (!quality_links) {
        return false;
    }
    quality->chain_links = quality_links.value();
    return true;
}
catch (std::exception const&) {
    return false;
}

struct PlotQualityChain {
    QualityChain quality;
    uint16_t plot_index;
};

// Find quality proofs for a challenge.
// @param challenge must point to 32 bytes
// @param plot_file must be a null-terminated string
// @param output must point to at least "*in_out_output_count" objects
// @param in_out_output_count should point to a value that is > 0.
// @param in_out_output_count will be set to the number of outputs on success.
//      If the number of outputs is greater than the capacity, it will be set to
//      to the actual number of outputs. The caller must cap its own
//      output buffer length to its capacity, if in_out_output_count is greater.
// @param plot_index_base: Unless testing a single-plot group (group_size=1),
//          plot_index_base should always be 0.
bool qualities_for_challenge(char const* plot_group_file,
    uint8_t const* challenge,
    PlotQualityChain* output,
    uint32_t* in_out_output_count,
    uint16_t plot_index_base)
try {
    if (plot_group_file == nullptr || challenge == nullptr) {
        return false;
    }
    if (output == nullptr || in_out_output_count == nullptr) {
        return false;
    }

    uint32_t const output_capacity = *in_out_output_count;

    GroupProver p(plot_group_file);

    std::span<uint8_t const, 32> const challenge_arr(challenge, challenge + 32);

    std::vector<PlotQualityChains> chains_per_plot;
    chains_per_plot = p.prove(challenge_arr, plot_index_base);

    uint32_t result_count = 0;
    std::span<PlotQualityChain> results(output, output + output_capacity);

    for (auto& pc : chains_per_plot) {
        for (auto& c : pc.quality_chains) {
            if (result_count < output_capacity) {
                results[result_count] = PlotQualityChain {
                    .quality = c,
                    .plot_index = pc.plot_index,
                };
            }
            result_count++;
        }
    }

    *in_out_output_count = result_count;
    return true;
}
catch (std::exception const&) {
    return false;
}


// Converts full proof bytes to quality string (does not validate the proof).
// plot_id must point to 32 bytes
// proof must point to 128 uint32_t values
// quality must point to a 16 ProofFragments
bool proof_to_quality_string(uint8_t const* plot_id,
    uint8_t const k,
    uint8_t const strength,
    uint32_t const* proof,
    QualityChain* quality)
try {
    if ((k & 1) != 0 || k < 18 || k > 32)
        return false;
    if (strength < 2)
        return false;
    if (plot_id == nullptr || proof == nullptr || quality == nullptr)
        return false;

    ProofFragmentCodec codec(PlotId(plot_id), k);
    quality->chain_links = codec.fullProofXValuesToQualityString(
        std::span<uint32_t const, TOTAL_XS_IN_PROOF>(proof, proof + TOTAL_XS_IN_PROOF));
    return true;
}
catch (std::exception const&) {
    return false;
}

// plot ID must point to exactly 32 bytes
// output must point to exactly TOTAL_XS_IN_PROOF (128) 32-bit integers
bool solve_partial_proof(QualityChain const* quality,
    uint8_t const* plot_id,
    uint8_t const k,
    uint8_t const strength,
    uint32_t* output)
try {
    if ((k & 1) != 0 || k < 18 || k > 32)
        return false;
    if (strength < 2)
        return false;
    if (quality == nullptr || plot_id == nullptr || output == nullptr)
        return false;
    auto params = PlotProofParams::create_raw(PlotId(plot_id), k, strength);
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

    // We only care about the first proof, as we only need a single witness
    // to the quality proof.
    std::copy(full_proofs[0].begin(), full_proofs[0].end(), output);
    return true;
}
catch (std::exception const&) {
    return false;
}

// filename is the full path, null terminated
// plot_group_id must point to 32 bytes of plot ID
// memo must point to memo_length bytes, containing the:
// * pool contract puzzle hash or pool public key
// * farmer public key
// * plot secret key
// returns true on success
bool create_raw_plot(char const* filename,
    uint8_t const k,
    uint8_t const strength,
    uint8_t const* plot_group_id,
    uint16_t const index,
    uint8_t const meta_group,
    uint8_t const* memo,
    uint8_t const memo_length)
try {
    if ((k & 1) != 0 || k < 18 || k > 32)
        return false;
    if (filename == nullptr || plot_group_id == nullptr || memo == nullptr)
        return false;
    if (strength < 2)
        return false;
    if (memo_length == 0)
        return false;

    PlotGroupParams group_params(PlotGroupId(plot_group_id), k, strength, meta_group);

    Plotter plotter(group_params.get_plot_params_for_index(index));
    PlotData plot = plotter.run();

    PlotFile::writeData(
        filename,
        plot,
        group_params,
        index,
        std::span<uint8_t const>(memo, memo + memo_length)
    );

    return true;
}
catch (std::exception const&) {
    return false;
}

// filename is the full path, null terminated
// plot_group_id must point to 32 bytes of plot ID
// memo must point to memo_length bytes, containing the:
// * pool contract puzzle hash or pool public key
// * farmer public key
// * plot secret key
// returns true on success
bool create_single_plot_group(char const* filename,
    uint8_t const k,
    uint8_t const strength,
    uint8_t const* plot_group_id,
    uint16_t const index,
    uint8_t const meta_group,
    uint8_t const* memo,
    uint8_t const memo_length)
try {
    if ((k & 1) != 0 || k < 18 || k > 32)
        return false;
    if (filename == nullptr || plot_group_id == nullptr || memo == nullptr)
        return false;
    if (strength < 2)
        return false;
    if (memo_length == 0)
        return false;

    PlotGroupParams group_params(PlotGroupId(plot_group_id), k, strength, meta_group);

    Plotter plotter(group_params.get_plot_params_for_index(index));
    PlotData plot = plotter.run();

    PlotGroupFile::writeData(filename,
        plot,
        group_params,
        PlotGroupFile::PROOFS_PER_CHUNK_BITS,
        std::span<uint8_t const>(memo, memo + memo_length)
    );

    return true;
}
catch (std::exception const&) {
    return false;
}

// out_plot_id MUST point to a buffer of at least 32 bytes.
// plot_group_id corresponds to a valid plot group id of 32 bytes.
bool derive_plot_id(
    uint8_t* out_plot_id,
    uint8_t const* plot_group_id,
    uint16_t const plot_index,
    uint8_t const meta_group
) {
    if( out_plot_id == nullptr || plot_group_id == nullptr ) {
        return false;
    }

    std::span<uint8_t const, 32> plot_group_id_span{ plot_group_id, 32 };
    std::span<uint8_t, 32> out_plot_id_span{ out_plot_id, 32 };

    posCalculatePlotIdForIndex(plot_group_id_span, out_plot_id_span, plot_index, meta_group);

    return true;
}

bool plot_group_read_info(
    PlotGroupFile::Info* out_info,
    uint8_t* memo_buf,
    uint8_t* memo_buf_size,
    char const* plot_group_path)
try {
    if (out_info == nullptr || memo_buf == nullptr || 
        memo_buf_size == nullptr || plot_group_path == nullptr)
    {
        return false;
    }

    auto plot_group = PlotGroupFile::open(plot_group_path);
    PlotGroupFile::Info const& info = plot_group.getInfo();

    if (*memo_buf_size < info.memo_length) {
        *memo_buf_size = info.memo_length;
        return false;
    }

    std::vector<uint8_t> memo = plot_group.readMemo();
    if (memo.size() != info.memo_length) {
        return false;
    }

    *memo_buf_size = info.memo_length;
    *out_info = info;
    memcpy(memo_buf, memo.data(), info.memo_length);

    return true;
}
catch (std::exception const&) {
    return false;
}

} // End extern "C"