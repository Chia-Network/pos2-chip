#include "plot/PlotFile.hpp"
#include "prove/Prover.hpp"
#include "common/Utils.hpp"

int main(int argc, char *argv[])
{
    std::cout << "Prover: given a challenge and plot file, prove the solution." << std::endl;
    if (argc < 2 || argc > 3)
    {
        std::cerr << "Usage: " << argv[0] << " [challenge] [plotfile]\n";
        return 1;
    }

    // 64‑hex‑character challenge
    std::string challenge_hex = argv[1]; //"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);

    if (false) {
        ProofParams params(challenge.data(), 28, 20);
        ProofCore proof_core(params);
        uint64_t chaining_hash_pass_threshold = proof_core.quality_chain_pass_threshold();
        std::cout << "Chaining hash pass threshold: " << std::dec << chaining_hash_pass_threshold << std::endl;
        exit(23);
    }

    Prover prover(challenge, argv[2], 2);

    // set random seed
    srand(static_cast<unsigned int>(time(nullptr)));
    int num_chains_found = 0;
    int total_trials = 1000; // 2^8
    for (int i = 0; i < total_trials; i++)
    {
        std::cout << "----------- Trial " << i << "/" << total_trials << " ------ " << std::endl;
        // std::cout << std::hex << (int)challenge[0] << std::dec << std::endl;

        challenge[0] = i & 0xFF;
        challenge[1] = (i >> 8) & 0xFF;
        challenge[2] = (i >> 16) & 0xFF;
        challenge[3] = (i >> 24) & 0xFF;

        for (int i = 0; i < 32; i++)
        {
            int randseed = 23;//rand() % 65536;
            challenge[i] = randseed;
        }

        prover.setChallenge(challenge);
        std::vector<QualityChain> chains = prover.prove();
        if (chains.size() > 0)
        {
            std::cout << "Found " << chains.size() << " chains." << std::endl;
            num_chains_found += chains.size();

            std::vector<uint64_t> proof_fragments = prover.getAllProofFragmentsForProof(chains[0]);
            std::cout << "Proof fragments: " << proof_fragments.size() << std::endl;

            ProofParams params = prover.getProofParams();
            XsEncryptor xs_encryptor(params);
            // convert proof fragments to xbits hex
            std::string xbits_hex;
            std::vector<uint32_t> xbits_list;
            for (const auto &fragment : proof_fragments)
            {
                std::cout << "ProofFragment: " << fragment << std::endl;
                std::array<uint32_t, 4> x_bits = xs_encryptor.get_x_bits_from_encrypted_xs(fragment);
                for (const auto &x_bit : x_bits)
                {
                    // at most 16 bits = 4 x 4 bits
                    xbits_hex += Utils::toHex(x_bit, 4);
                    xbits_list.push_back(x_bit);
                    std::cout << " " << x_bit;
                }
            }

            std::array<uint8_t, 32> plot_id_arr;
            std::memcpy(plot_id_arr.data(), params.get_plot_id_bytes(), 32);
            std::string plot_id_hex = Utils::bytesToHex(plot_id_arr);

            std::cout << "./solver xbits " << params.get_k() << " " << plot_id_hex << " " << xbits_hex << std::endl;
            for (size_t j = 0; j < xbits_list.size(); j++)
            {
                std::cout << j << ": " << xbits_list[j] << std::endl;
            }

            std::cout << "Challenge: " << Utils::bytesToHex(challenge) << std::endl;
            exit(23);
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
}