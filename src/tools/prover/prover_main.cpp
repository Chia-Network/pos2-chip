#include "plot/PlotFile.hpp"
#include "prove/Prover.hpp"
#include "common/Utils.hpp"

void printUsage()
{
    std::cout << "Usage:\n"
              << "  prover check [plotfile]\n"
              << "  prover challenge [challengehex] [plotfile] [scan_filter_bits=4 (optional)]\n";
}

int main(int argc, char *argv[])
try
{
    std::cout << "ChiaPOS2 Prover" << std::endl;

    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    std::string mode = argv[1];

    std::string challenge_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::string plotfile;
    int proof_fragment_scan_filter_bits = 5; // default 5 bits

    int total_trials = 1000; // default 1000 trials

    if (mode == "challenge")
    {
        if ((argc < 4) || (argc > 5))
        {
            std::cerr << "Usage: " << argv[0] << " challenge [challengehex] [plotfile] [proof_fragment_scan_filter_bits=5 (optional)] \n";
            return 1;
        }
        std::cout << "challenge not implemented yet." << std::endl;
        challenge_hex = argv[2];
        plotfile = argv[3];
        if (argc == 5)
        {
            proof_fragment_scan_filter_bits = std::stoi(argv[4]);
        }
    }
    // support: prover check [plotfile] [n_trials=1000]
    else if (mode == "check")
    {
        if (argc != 3 && argc != 4 && argc != 5)
        {
            std::cerr << "Usage: " << argv[0] << " check [plotfile] [proof_fragment_scan_filter_bits=5 (optional)] [total_trials=1000 (optional)]\n";
            return 1;
        }
        plotfile = argv[2];

        if (argc >= 4)
        {
            proof_fragment_scan_filter_bits = std::stoi(argv[3]);
        }
        if (proof_fragment_scan_filter_bits < 1 || proof_fragment_scan_filter_bits > 16)
        {
            std::cerr << "Error: scan_filter_bits must be between 1 and 16." << std::endl;
            return 1;
        }
        if (argc >= 5)
        {
            total_trials = std::stoi(argv[4]);
        }
        std::cout << "Check mode: plot file = " << plotfile << ", proof_fragment_scan_filter_bit = " << proof_fragment_scan_filter_bits << ", total_trials = " << total_trials << std::endl;
    }
    else {
        std::cerr << "Unknown mode: " << mode << std::endl;
        printUsage();
        return 1;
    }

    // 64‑hex‑character challenge
    if (mode == "challenge")
    {
        if (challenge_hex.length() != 64)
        {
            std::cerr << "Error: challenge must be a 64-hex-character string." << std::endl;
            return 1;
        }

        std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);

        Prover prover(challenge, plotfile);

        prover.setChallenge(challenge);
        std::vector<QualityChain> chains = prover.prove(proof_fragment_scan_filter_bits);

        if (chains.size() > 0)
        {
            std::cout << "Found " << chains.size() << " chains." << std::endl;

            std::vector<uint64_t> proof_fragments = prover.getAllProofFragmentsForProof(chains[0]);
            std::cout << "Proof fragments: " << proof_fragments.size() << std::endl;

            ProofParams params = prover.getProofParams();
            ProofFragmentCodec fragment_codec(params);
            // convert proof fragments to xbits hex
            std::string xbits_hex;
            std::vector<uint32_t> xbits_list;
            for (const auto &fragment : proof_fragments)
            {
                //std::cout << "ProofFragmentCodec: " << std::hex << fragment << std::dec;
                std::array<uint32_t, 4> x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);
                for (const auto &x_bit : x_bits)
                {
                    // at most 16 bits = 4 x 4 bits
                    xbits_hex += Utils::toHex(x_bit, 4);
                    xbits_list.push_back(x_bit);
                    std::cout << " " << x_bit;
                }
                std::cout << std::endl;
            }

            std::array<uint8_t, 32> plot_id_arr;
            std::memcpy(plot_id_arr.data(), params.get_plot_id_bytes(), 32);
            std::string plot_id_hex = Utils::bytesToHex(plot_id_arr);

            std::cout << "solver xbits " << params.get_k() << " " << plot_id_hex << " " << xbits_hex << std::endl;

            std::cout << "Challenge: " << Utils::bytesToHex(challenge) << std::endl;
        }
        else
        {
            std::cout << "No chains found." << std::endl;
        }
    }

    if (mode == "check")
    {
        
        std::array<uint8_t, 32> challenge = {0};
        Prover prover(challenge, plotfile);
        // set random seed
        srand(static_cast<unsigned int>(time(nullptr)));
        int num_chains_found = 0;
        for (int i = 0; i < total_trials; i++)
        {
            std::cout << "----------- Trial " << i << "/" << total_trials << " ------ " << std::endl;
            // std::cout << std::hex << (int)challenge[0] << std::dec << std::endl;

            challenge[0] = i & 0xFF;
            challenge[1] = (i >> 8) & 0xFF;
            challenge[2] = (i >> 16) & 0xFF;
            challenge[3] = (i >> 24) & 0xFF;

            // for (int i = 0; i < 32; i++)
            //{
            //     int randseed = rand() % 65536;
            //     challenge[i] = randseed;
            // }

            prover.setChallenge(challenge);
            std::vector<QualityChain> chains = prover.prove(proof_fragment_scan_filter_bits);
            if (chains.size() > 0)
            {
                std::cout << "Found " << chains.size() << " chains." << std::endl;
                num_chains_found += chains.size();

                for (int chain_solution = 0; chain_solution < chains.size(); chain_solution++) {
                    

                std::vector<uint64_t> proof_fragments = prover.getAllProofFragmentsForProof(chains[chain_solution]);
                // std::cout << "Proof fragments: " << proof_fragments.size() << std::endl;

                ProofParams params = prover.getProofParams();
                ProofFragmentCodec fragment_codec(params);
                // convert proof fragments to xbits hex
                std::string xbits_hex;
                std::vector<uint32_t> xbits_list;
                for (const auto &fragment : proof_fragments)
                {
                    //std::cout << "ProofFragmentCodec: " << std::hex << fragment << std::dec;
                    std::array<uint32_t, 4> x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);
                    for (const auto &x_bit : x_bits)
                    {
                        // at most 16 bits = 4 x 4 bits
                        xbits_hex += Utils::toHex(x_bit, 4);
                        xbits_list.push_back(x_bit);
                        //std::cout << " " << x_bit;
                    }
                    //std::cout << std::endl;
                }

                std::array<uint8_t, 32> plot_id_arr;
                std::memcpy(plot_id_arr.data(), params.get_plot_id_bytes(), 32);
                std::string plot_id_hex = Utils::bytesToHex(plot_id_arr);

                std::cout << "Chain solution " << chain_solution << ": ";
                std::cout << "solver xbits " << params.get_k() << " " << plot_id_hex << " " << xbits_hex << std::endl;
            }

                std::cout << "Challenge: " << Utils::bytesToHex(challenge) << std::endl;
                
            }
            else
            {
                std::cout << "No chains found." << std::endl;
            }
            std::cout << "Total chains found: " << num_chains_found << " out of " << i << "  %:" << ((float)num_chains_found / (float)i) << std::endl;
            std::cout << "   Found 1 in " << (float)i / (float)num_chains_found << " trials." << std::endl;
        }
        std::cout << "Total chains found: " << num_chains_found << " out of " << total_trials << "  %:" << ((float)num_chains_found / (float)total_trials) << std::endl;
        std::cout << "   Found 1 in " << (float)total_trials / (float)num_chains_found << " trials." << std::endl;
        std::cout << "Prover done." << std::endl;
        prover.showStats();
        return 0;
    }
}
catch (const std::exception &ex)
{
    std::cerr << "Failed with exception: " << ex.what() << std::endl;
    return 1;
}