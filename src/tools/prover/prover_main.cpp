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

    Prover prover(challenge, argv[2], 2);

    // set random seed
    srand(static_cast<unsigned int>(time(nullptr)));
    int num_chains_found = 0;
    int total_trials = 100; // 2^8
    for (int i = 0; i < total_trials; i++)
    {
        std::cout << "----------- Trial " << i << "/" << total_trials << " ------ " << std::endl;
        //std::cout << std::hex << (int)challenge[0] << std::dec << std::endl;


        challenge[0] = i & 0xFF;
        challenge[1] = (i >> 8) & 0xFF;
        challenge[2] = (i >> 16) & 0xFF;
        challenge[3] = (i >> 24) & 0xFF;

        for (int i = 0; i < 32; i++) {
            int randseed = rand() % 65536;
            challenge[i] = randseed;
        }

        prover.setChallenge(challenge);
        std::vector<QualityChain> chains = prover.prove();
        if (chains.size() > 0)
        {
            std::cout << "Found " << chains.size() << " chains." << std::endl;
            num_chains_found += chains.size();
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