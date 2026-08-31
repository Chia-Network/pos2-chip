#include <random>
#include <memory>
#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "pos/ProofValidator.hpp"
#include "prove/Prover.hpp"
#include "pos/sha/sha256.hpp"

// ./prover verify 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
// 0cd59329e9de64f1061e478da6d98c16cc4f6588e2409587944d1d6a87582fe61b1d32f0604816831764629e6609883877bf23de692645e57494d5f372e74faff8f527cf9129081e824257f0fda0b705cd53b7614a2a241b8b27a132c37343f451394fa368c0c2db65816c7366c6a24998781b12deb28f511560b45bfdea705632fa548fc13f222ae8a3691811cd7982221f58dc2e2d13210f776fd9cd1fc865d4008e11ee5d3fac99a3d134bf41a6dccffd2743de974d9d3a8a6dba150b149252333c58bd1beecfced70524d5e2cb6d69f18571d4ce7a56872c95adc1c08cb3ad5f88083beb6f1859160ec83bea7c7cbe79a691f5dac46da9d5e8bbe57f2a2345e6a2b42a1f718c8e33d9264112b6c8c4c42a6e5592711a2d00f5eb16a6b6343d04900c3b8159becf88cd24fee0d8a6102429ad723758626e341a537be889be474a5dff9bd4560aa13b8b41a6eb7e37db24ba2ab2ca3e03cc14cc9dc8aeebe5816dfc0826a5110bc1c5beab426c394d1662550d7da105a9332f2e7f6a32cf8b3f0910d47fcf194c0d0c09a681d41b8537ef1475820baca7e37e6bdf2e27dbfee57de5726d5168bced6c76decc7e7f0650c035c24779fa197d03dc6d55e962a7d56967882ca2b83dc2231c7460fd91d79cfd335b8dcec96e05ee58e40faa7cdc10d37e31e54a3916539ab351ff9d315f9ef89b379df34dd79877a30279d765736b8896aab3d94c64c40537a5beaa0fc8b8e9751643a97684f40afa318f6c666c142efeaf53b9380b26e71ddbc3b4b79525cdd27b68d02c6f6deb9134985071323ed68616ceac8bf106b3f4edea21e93f7eb39fa8640ff3f34126b5ae07dd986205a3bc9ea6f7a126dbcb659f5b72e2b864a3bdb0fa5206fa58358cdf7292c08f0eaafd1e0178693745a2c39dbaebe5a9455c20eb5bec924ab4b84238f45c88f55e29c5e81f80b2ce85e1a4b9a942fea2bfca89d86f987d6b91d1835f41430d427626dfcdf3a261ebbf7f898fa4d4c769c35b22531757f3b7db3c7369f9ba33fa88f9a1f5959400cde18d881e99407a435238c4fdb4eda0e23ad8c6a8ac81584300578a4941b3e4085d77e3291f6d453b050c2c61714127f91f397da0f656334b151bc9e0f4cbae3a42e7faf4d21af86944d9270d2f4759c90ed4e173f3c1a9672d6811cb9822adbc192850e07624dd3aa2adfaef0d0e5f38ebb62c774e199cc28c2396d4a7f959ac7042d65ec5e9e1d9544b9aa98259d0fae8d06a9934e13f8734b5a57460529da3d1390adf6fc08cfc62d126cbf64c3680e7196be4c3d3888c4a74e9084ff250631419214c56ff1f3ddbac048e9556cbfd3778999052a63b965922f360210c9aa4c1d561ec70fa0198dbb55dee6a1f93750087539a62ef136b058327046b2f8d7b5bfcdbc9de5077508ce3856ddd6776717d01938088d1081be41b219e69860bc0515f0d11d033ce68a043e556dea8eb6846ff8c47e58f6fd7c3932daaea93aba8b26c639d84085084dd4f37936497268f822a1e1d90b0473d6af187cb8415dea9368faec129ae832baae4c960db09857645b42d4520095dc7e5a5d8c72cfd17bbd576e4aca9144b878b91a23cc4c52dcb90276972e54728ef6791daa6e9c7cb36112364de594fa9229cceda8dfa25713ec32454aea9da8c26facb89b2dd44c1909707dbf22c0b3235f789edb73b361b78b7a8e59e782447470ca47c144cf823720e9de2eec3fd5793ad4189c68ac2944c2ca8b9bb7e9c2ee58f8e57f3050e7242871a88318a398b31bfe49c3fdf10371a4a41b95e891be125e4f89d856f8aa16552585534f4d44841b447a6cabf245bd4c2e4e152159d415ece2ebf7a762a772a29d16d3f68646e0099aced94086a6f84a22f33c1c09b83fd01f50de1b3db0918a053ade615c7932b3c8a2bf091ca07485e810df260072264fb01dc42b44d726bfa91a31e66a97a28960610cead7070d14a131ea699da302e91b05792f9008071873a418b0bd51c8521d0fa4a64cdfd105f08aa4194b9bc9ec2be3f3608e9550cf675683f9485f03c3367f84a2b2906db413eb700c052fbe88169d3b5a91b82d1405934fe02586e0d6bd6875d2ea15c0e5c12315f84b1ee9bbb7de7ed876220cf71700762b287f49975f67d8a5e4d5612edafec2936dfc29b
// 6300000000000000000000000000000000000000000000000000000000000000 2 1
static void printQualityChain(std::string const& challenge, std::span<QualityChain> chains, PlotProofParams const& params);

void printUsage()
{
    std::cout << "Usage:\n"
              << "  prover check [-s|--strict] <plot_file> [total_trials (optional. default=1000)]\n"
              << "  prover challenge [--index=<n>] [challenge_hex] <plot_file>\n"
              << "  prover verify <plot_group_id> <plot_index> <proof_hex> <challenge_hex> <plot_strength> [meta_group (default=0)]\n";
}

int main(int argc, char* argv[])
try {
    // std::cout << "ChiaPOS2 Prover" << std::endl;

    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string mode = argv[1];

    std::string challenge_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::string plotfile;

    int total_trials = 1000; // default 1000 trials for check mode
    int challenge_plot_index = -1;  // Used for 'challenge' mode to select a specific plot index.
    bool should_check_std_dev_range = false;    // For 'check', ensure the result converges within a reasonable expected range.

    if (mode == "challenge") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " challenge [--index=<n>] [challenge_hex] <plot_file>\n";
            return 1;
        }

        int params_read = 0;

        std::string index_arg = argv[2];
        if (index_arg.find("--index=") == 0) {
            challenge_plot_index = std::atoi(index_arg.substr(sizeof("--index=")-1).c_str());
            params_read ++;
        }

        if (argc-params_read > 3) {
            challenge_hex = argv[2 + params_read];
            params_read ++;
        }
        plotfile = argv[2 + params_read];
    }
    // support: prover check [plotfile] [n_trials=1000]
    else if (mode == "check") {
        #define check_usage "Usage: " << argv[0] << " check [-s|--strict] <plot_file> [total_trials (optional. default=1000)]\n";
        if (argc < 3) {
            std::cerr << check_usage;
            return 1;
        }

        plotfile = argv[2];

        if(plotfile == "-s" || plotfile == "--strict") {
            if(argc < 4) {
                std::cerr << check_usage;
                return 1;
            }

            should_check_std_dev_range = true;

            argv ++;
            argc --;

            plotfile = argv[2];
        }

        if (argc >= 4) {
            total_trials = std::stoi(argv[3]);
        }
        std::cout << "Check mode: plot file = " << plotfile << ", total_trials = " << total_trials
                  << std::endl;
    }
    else if (mode == "verify") {
        if (argc < 7) {
            std::cerr << "Usage: " << argv[0]
                      << " <plot_group_id> <plot_index> <proof_hex> <challenge_hex> <plot_strength> [meta_group (default=0)]\n";
            return 1;
        }

        argc -= 2;
        argv += 2;

        int plot_index = 0;
        int meta_group = 0;
        int k = 0;

        std::string plot_group_id_hex = argv[0];
        if (plot_group_id_hex.length() != 64) {
            std::cerr << "Error: plot ID must be 64 hex characters." << std::endl;
            return 1;
        }

        plot_index = std::atoi(argv[1]);
        if( plot_index < 0 || plot_index > UINT16_MAX) {
            std::cerr << "Error: plot index is out of range: " << plot_index << std::endl;
            return 1;
        }

        std::string proof_hex = argv[2];
        int proof_hex_len = numeric_cast<int>(proof_hex.length());
        k = proof_hex_len * 4 / TOTAL_XS_IN_PROOF; // each uint32_t is 4 hex characters, and each proof fragment has 8
                                                   // uint32_t = 32 hex characters

        std::cout << "proof length: " << proof_hex_len << std::endl;
        std::cout << "k derived from proof length: " << k << std::endl;
        if (k < 18 || k > 32 || (k % 2) != 0) {
            std::cerr << "Error: derived k from proof length is invalid: " << k << std::endl;
            return 1;
        }

        challenge_hex = argv[3];
        if (challenge_hex.length() != 64) {
            std::cerr << "Error: challenge must be 64 hex characters." << std::endl;
            return 1;
        }

        int plot_strength = std::stoi(argv[4]);
        if ((plot_strength < 2) || (plot_strength > 255)) {
            std::cerr << "Error: plot strength must be between 2 and 255." << std::endl;
            return 1;
        }

        if (argc >= 6) {
            meta_group = std::stoi(argv[5]);
            if (meta_group < 0 || meta_group > 255) {
                std::cerr << "Error: meeta group is out of range: " << meta_group << std::endl;
                return 1;
            }
        }

        std::cout << "Verifying proof for k=" << k << ", plot group ID=" << plot_group_id_hex
                  << ", challenge=" << challenge_hex << ", proof=" << proof_hex
                  << ", plot_strength=" << plot_strength << std::endl;

        PlotGroupId plot_group_id(Utils::hexToBytes(plot_group_id_hex));
        std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);

        PlotGroupParams group_params(plot_group_id,
            numeric_cast<uint8_t>(k),
            numeric_cast<uint8_t>(plot_strength),
            numeric_cast<uint8_t>(meta_group)
        );
        ProofValidator proof_validator(group_params, uint16_t(plot_index));

        std::vector<uint32_t> proof = Utils::compressedHexToKValues(k, proof_hex);
        if (proof.size() != TOTAL_XS_IN_PROOF) {
            std::cerr << "invalid proof" << std::endl;
            return 1;
        }

        std::optional<QualityChainLinks> chain = proof_validator.validate_full_proof(
            std::span<uint32_t, TOTAL_XS_IN_PROOF>(proof), challenge);

        // get all sub-proofs, which are collections of 32 x-values
        if (chain.has_value()) {
            std::cout << "Proof is valid." << std::endl;
            // std::cout << "QualityChain: " << chainLinksToHex(k, chain.value()) << std::endl;
            return 0;
        }
        else {
            std::cerr << "Proof validation failed." << std::endl;
            return 1;
        }
    }
    else {
        std::cerr << "Unknown mode: " << mode << std::endl;
        printUsage();
        return 1;
    }

    // 64‑hex‑character challenge
    if (mode == "challenge") {
        if (challenge_hex.length() != 64) {
            std::cerr << "Error: challenge must be a 64-hex-character string." << std::endl;
            return 1;
        }

        std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);

        if (plotfile.ends_with(".gplot")) {
            GroupProver gp(plotfile);
            PlotGroupFile& pg = gp.getPlotGroup();

            if (challenge_plot_index >= 0 && size_t(challenge_plot_index) >= pg.getInfo().group_size) {
                std::cerr << "Error: Specified plot index is invalid: " 
                          << challenge_plot_index << "/" << pg.getInfo().group_size
                          << std::endl;
                return 1;
            }

            int const plot_index_end = challenge_plot_index >= 0 ? 
                challenge_plot_index + 1 : int(pg.getInfo().group_size);

            size_t total_proofs = 0;
            std::vector<PlotQualityChains> quality_chains_per_plot = gp.prove(challenge);
            for (auto const& pc: quality_chains_per_plot) {

                if (int(pc.plot_index) < challenge_plot_index || int(pc.plot_index) >= plot_index_end) {
                    continue;
                }

                PlotProofParams plot_params = pg.getProofParamsForPlotIndex(pc.plot_index);
                std::cout << "Plot " << (pc.plot_index+1) << ": " + plot_params.get_plot_id().to_string()
                          << " has " << pc.quality_chains.size() << " "
                          << (pc.quality_chains.size() == 1 ? "chain" : "chains") << std::endl;

                if (!pc.quality_chains.empty()) {
                    total_proofs += pc.quality_chains.size();

                    std::vector<QualityChain> quality_chains = pc.quality_chains;
                    printQualityChain(challenge_hex, quality_chains, plot_params);
                    std::cout << std::endl;
                }
            }

            std::cout << total_proofs << " total proofs found" << std::endl;
        }
        else {
            Prover prover(plotfile);

            std::vector<QualityChain> chains = prover.prove(challenge);

            if (chains.size() == 0) {
                std::cout << "No chains found." << std::endl;
            }
            else {
                std::cout << "Found " << chains.size() << " chains." << std::endl;
                printQualityChain(challenge_hex, chains, prover.getPlotProofParams());
            }
        }

        return 0;
    }

    if (mode == "check") {
        std::array<uint8_t, 32> challenge = { 0 };

        std::unique_ptr<Prover> prover;
        std::unique_ptr<GroupProver> group_prover;

        // set random seed
        uint64_t seed = 0;
        {
            std::random_device rd;
            for (size_t i = 0; i < sizeof(8); i++) {
                seed |= static_cast<std::uint64_t>(rd()) << i;
            }
        }

        std::mt19937_64 rng(seed);
        std::uniform_int_distribution<unsigned int> byte_dist(0, 255);

        bool const is_group = plotfile.ends_with(".gplot");
        uint16_t group_size = 1;
        if (is_group) {
            group_prover = std::unique_ptr<GroupProver>(new GroupProver(plotfile));
            group_size = group_prover->getPlotGroup().getInfo().group_size; 
        }
        else {
            prover = std::unique_ptr<Prover>(new Prover(plotfile));
        }

        uint64_t num_chains_found = 0;
        uint64_t sum_chains_found_squared = 0;

        for (int i = 0; i < total_trials; i++) {
            for (auto& b : challenge) {
                b = static_cast<unsigned char>(byte_dist(rng));
            }

            std::vector<PlotQualityChains> chains_per_plot;

            if (is_group) {
                chains_per_plot = group_prover->prove(challenge);
            }
            else {
                chains_per_plot = { PlotQualityChains { 
                    .quality_chains = prover->prove(challenge),
                    .plot_index     = 0,
                } };
            }

            std::cout << "Challenge: " << Utils::bytesToHex(challenge) << std::endl;
            uint64_t chains_per_challenge = 0;

            for (uint16_t plot_index = 0; plot_index < group_size; plot_index++) {
                std::vector<QualityChain> chains = chains_per_plot[plot_index].quality_chains;

                auto const chains_found = (uint64_t)chains.size();
                chains_per_challenge += chains_found;

                if (chains_found > 0) {
                    if (is_group) {
                        std::cout << "[Plot " << plot_index << "] ";
                    }

                    std::cout << "Found " << chains_found << " proofs." << std::endl;

                    num_chains_found += chains_found;

                    PlotProofParams params = is_group ?
                        group_prover->getPlotGroup().getProofParamsForPlotIndex(plot_index)
                        : prover->getPlotProofParams();
    
                    int idx = 0;
                    for (auto const& chain: chains) {
    
                        QualityChainLinks proof_fragments = chain.chain_links;
    

                        // convert proof fragments to xbits hex
                        ProofFragmentCodec fragment_codec(params);
                        // std::string xbits_hex;
                        std::vector<uint32_t> xbits_list;
                        for (auto const& fragment: proof_fragments) {
                            std::array<uint32_t, 4> x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);

                            for (auto const& x_bit: x_bits) {
                                xbits_list.push_back(x_bit);
                            }
                        }
    
                        std::array<uint8_t, 32> plot_id_arr = params.get_plot_id().data();
                        std::string plot_id_hex = Utils::bytesToHex(plot_id_arr);
                        std::string xbits_hex_compressed = Utils::kValuesToCompressedHex(params.get_k() / 2, xbits_list);
    
                        std::cout << "Proof solution " << idx << ": ";
                        std::cout << "solver xbits " << (int)params.get_strength() << " " 
                                    << plot_id_hex << " " << xbits_hex_compressed
                                    << std::endl;
                        ++idx;
                    }
    
                    std::cout << "Total proofs found: " << num_chains_found << " out of " << (i+1)
                                << " challenges %: " << 100.f * ((double)num_chains_found / (double)(i+1)) << std::endl;
                    std::cout << "   Found 1 proof every " << ((double)(i+1) / (double)num_chains_found)
                                << " challenges." 
                                << " (" <<  "1 / " << ((double)num_chains_found / (double)(i+1)) << ")"
                                << std::endl;
                }
            }

            sum_chains_found_squared += chains_per_challenge * chains_per_challenge;
        }

        // double const expected_mean  = (double)group_size;
        double const actual_mean    = (double)num_chains_found / (double)total_trials;
        double const variance       = (double)sum_chains_found_squared / (double)total_trials - actual_mean * actual_mean;
        double const std_dev_per_challenge = std::sqrt(variance);

        // Standard deviation of the cumulative total
        double const std_dev        = std_dev_per_challenge * std::sqrt((double)total_trials);
        double const expected_total = (double)(total_trials * group_size);
        double const diff           = num_chains_found - expected_total;

        double const std_devs_off = diff / std_dev;

        std::cout << "Total proofs found: " << num_chains_found << " out of " << total_trials
                  << "  %:" << 100.f * ((double)num_chains_found / (double)total_trials) << std::endl;
        std::cout << "   Found 1 proof every " << (double)total_trials / (double)num_chains_found
                    << " challenges."
                    << " (" <<  "1 / " << ((double)num_chains_found / (double)(total_trials)) << ")"
                    << std::endl;
        std::cout << "Standard Dev      : " << std_dev << std::endl;
        std::cout << "Deviation         : " << std_devs_off << " standard deviations off expected." << std::endl;

        if (should_check_std_dev_range) {
            constexpr double expected_std_dev_range = 3.0;
            if (std::abs(std_devs_off) >= expected_std_dev_range) {
                std::cerr << "\033[31m"
                    << "The result deviated beyond the expected range: " 
                    << std::abs(std_devs_off) << " / " << expected_std_dev_range
                    << "\033[0m"
                    << std::endl;
                return -1;
            }
        }

        std::cout << "Prover done." << std::endl;
        return 0;
    }
}
catch (std::exception const& ex) {
    std::cerr << "Failed with exception: " << ex.what() << std::endl;
    return 1;
}

void printQualityChain(std::string const& challenge, std::span<QualityChain> chains, PlotProofParams const& params) {
    for (size_t nChain = 0; nChain < chains.size(); nChain++) {
        std::cout << "Chain: " << nChain << std::endl;

        std::cout << "Challenge: " << challenge << std::endl;

        QualityChainLinks proof_fragments = chains[nChain].chain_links;

        ProofFragmentCodec fragment_codec(params);

        // convert proof fragments to xbits hex
        std::string xbits_hex;
        std::vector<uint32_t> xbits_list;

        for (auto const& fragment: proof_fragments) {
            // std::cout << "ProofFragmentCodec: " << std::hex << fragment << std::dec;
            std::array<uint32_t, 4> x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);
            for (auto const& x_bit: x_bits) {
                // at most 16 bits = 4 x 4 bits
                // xbits_hex += Utils::toHex(x_bit, 4);
                xbits_list.push_back(x_bit);
                // std::cout << " " << x_bit;
            }
            // std::cout << std::endl;
        }

        std::string xbits_hex_compressed = Utils::kValuesToCompressedHex(params.get_k() / 2, xbits_list);
        std::cout << "Partial Proof: " << xbits_hex_compressed << std::endl;
        std::cout << "Plot Strength: " << (int)params.get_strength() << std::endl;

        std::string plot_id_hex = params.get_plot_id().to_string();

        // std::cout << "solver xbits " << params.get_k() << " " << plot_id_hex << " " <<
        // xbits_hex << " " << (int)params.get_strength() << std::endl;
        std::cout << "To complete proof run: " << std::endl
                    << " solver xbits " << (int)params.get_strength() << " "
                        << plot_id_hex << " " << xbits_hex_compressed << " " << std::endl;
        std::cout << std::endl;
    }
}
