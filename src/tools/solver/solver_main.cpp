#include <iostream>
#include <string>
#include <cstdlib>
#include "plot/PlotFile.hpp"
#include "pos/XsEncryptor.hpp"
#include "solve/Solver.hpp"
#include "pos/ProofValidator.hpp"

int main(int argc, char *argv[])
{
    std::cout << "The solver will take a Quality Link and reconstruct the missing x-bits." << std::endl;

    // plot file string is first argument
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <plot_file>\n";
        return 1;
    }
    std::string plot_file = argv[1];
    std::cout << "Plot file: " << plot_file << std::endl;
    // read plot file
    ProofParams params(nullptr, /*k*/ 0, /*sub_k*/ 0);

    PlotFile::PlotFileContents plot = PlotFile::readData(plot_file);
    if (plot.data == PlotData())
    {
        std::cerr << "Error: plot file is empty or invalid." << std::endl;
        return 1;
    }
    std::cout << "Plot file read successfully." << std::endl;
    plot.params.show();

    // let's get num_chain proofs from t5 pairings
    int num_chains = 12;
    std::cout << "Number of chains: " << num_chains << std::endl;
    std::vector<uint32_t> x_bits_list;
    std::vector<uint32_t> xs_solution;
    XsEncryptor xs_encryptor(plot.params);
    std::vector<uint32_t> xs_full_solution;
    for (int chain = 0; chain < num_chains; chain++)
    {
        std::cout << "Chain: " << chain << std::endl;

        T5Pairing t5_pairing = plot.data.t5_to_t4_back_pointers[0][chain]; // now get t4 L and R pairings
        T4BackPointers t4_to_t3_L = plot.data.t4_to_t3_back_pointers[0][t5_pairing.t4_index_l];
        T4BackPointers t4_to_t3_R = plot.data.t4_to_t3_back_pointers[0][t5_pairing.t4_index_r];
        uint64_t encrypted_xs_LL = plot.data.t3_encrypted_xs[t4_to_t3_L.encx_index_l];
        uint64_t encrypted_xs_LR = plot.data.t3_encrypted_xs[t4_to_t3_L.encx_index_r];
        uint64_t encrypted_xs_RL = plot.data.t3_encrypted_xs[t4_to_t3_R.encx_index_l];
        uint64_t encrypted_xs_RR = plot.data.t3_encrypted_xs[t4_to_t3_R.encx_index_r];
        
        uint64_t decrypted_xs_LL = xs_encryptor.decrypt(encrypted_xs_LL);
        uint64_t decrypted_xs_LR = xs_encryptor.decrypt(encrypted_xs_LR);
        uint64_t decrypted_xs_RL = xs_encryptor.decrypt(encrypted_xs_RL);
        uint64_t decrypted_xs_RR = xs_encryptor.decrypt(encrypted_xs_RR);
        int half_k = plot.params.get_k() / 2;
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_LL >> (half_k * 3)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_LL >> (half_k * 2)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_LL >> (half_k * 1)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>(decrypted_xs_LL & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_LR >> (half_k * 3)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_LR >> (half_k * 2)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_LR >> (half_k * 1)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>(decrypted_xs_LR & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_RL >> (half_k * 3)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_RL >> (half_k * 2)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_RL >> (half_k * 1)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>(decrypted_xs_RL & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_RR >> (half_k * 3)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_RR >> (half_k * 2)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>((decrypted_xs_RR >> (half_k * 1)) & ((uint64_t(1) << half_k) - 1)));
        x_bits_list.push_back(static_cast<uint32_t>(decrypted_xs_RR & ((uint64_t(1) << half_k) - 1)));

        for (int i = 0; i < 8; i++) {
            xs_full_solution.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_l][i]);
        }
        for (int i = 0; i < 8; i++) {
            xs_full_solution.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_r][i]);
        }
        for (int i = 0; i < 8; i++) {
            xs_full_solution.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_l][i]);
        }
        for (int i = 0; i < 8; i++) {
            xs_full_solution.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_r][i]);
        }

    }
    std::cout << "Xs solution: ";
    for (size_t i = 0; i < xs_full_solution.size(); i++)
    {
        std::cout << xs_full_solution[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "X-bits list: ";
    for (size_t i = 0; i < x_bits_list.size(); i++)
    {
        std::cout << x_bits_list[i] << " ";
    }
    std::cout << std::endl;

    Solver solver(plot.params);
    
    std::vector<std::vector<uint32_t>> all_proofs = solver.solve(x_bits_list, xs_full_solution);

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

    return 0;

    

    // let's get a full proof, get from t5 and collect call leaves.
    // get t5 pairing
    // for (int partition = 0; partition < plot.data.t5_to_t4_back_pointers.size(); partition++)
    int partition = 0;
    for (int test_slot = 0; test_slot < 1; /*plot.data.t5_to_t4_back_pointers[partition].size()*/ test_slot++)
    {
        // wait for key press, show current test number
        // std::cout << "Press enter to continue to test " << test_slot << " in partition " << partition << std::endl;
        // std::cin.get();

        T5Pairing t5_pairing = plot.data.t5_to_t4_back_pointers[partition][test_slot]; // now get t4 L and R pairings
        T4BackPointers t4_to_t3_L = plot.data.t4_to_t3_back_pointers[partition][t5_pairing.t4_index_l];
        T4BackPointers t4_to_t3_R = plot.data.t4_to_t3_back_pointers[partition][t5_pairing.t4_index_r];
        uint64_t encrypted_xs_LL = plot.data.t3_encrypted_xs[t4_to_t3_L.encx_index_l];
        uint64_t encrypted_xs_LR = plot.data.t3_encrypted_xs[t4_to_t3_L.encx_index_r];
        uint64_t encrypted_xs_RL = plot.data.t3_encrypted_xs[t4_to_t3_R.encx_index_l];
        uint64_t encrypted_xs_RR = plot.data.t3_encrypted_xs[t4_to_t3_R.encx_index_r];
        std::cout << "Encrypted xs LL: " << encrypted_xs_LL << std::endl;
        // decrypt it to get x-bits

        uint64_t decrypted_xs_LL = xs_encryptor.decrypt(encrypted_xs_LL);
        uint64_t decrypted_xs_LR = xs_encryptor.decrypt(encrypted_xs_LR);
        uint64_t decrypted_xs_RL = xs_encryptor.decrypt(encrypted_xs_RL);
        uint64_t decrypted_xs_RR = xs_encryptor.decrypt(encrypted_xs_RR);

#ifdef RETAIN_X_VALUES_TO_T3
        // verify our xs are correct with encrypted xs
        if (xs_encryptor.validate_encrypted_xs(encrypted_xs_LL, plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_l].data()))
        {
            std::cout << "Encrypted xs LL match x-bits." << std::endl;
        }
        else
        {
            std::cerr << "Encrypted xs LL do not match x-bits." << std::endl;
            return 1;
        }
        if (xs_encryptor.validate_encrypted_xs(encrypted_xs_LR, plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_r].data()))
        {
            std::cout << "Encrypted xs LR match x-bits." << std::endl;
        }
        else
        {
            std::cerr << "Encrypted xs LR do not match x-bits." << std::endl;
            return 1;
        }
        if (xs_encryptor.validate_encrypted_xs(encrypted_xs_RL, plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_l].data()))
        {
            std::cout << "Encrypted xs RL match x-bits." << std::endl;
        }
        else
        {
            std::cerr << "Encrypted xs RL do not match x-bits." << std::endl;
            return 1;
        }
        if (xs_encryptor.validate_encrypted_xs(encrypted_xs_RR, plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_r].data()))
        {
            std::cout << "Encrypted xs RR match x-bits." << std::endl;
        }
        else
        {
            std::cerr << "Encrypted xs RR do not match x-bits." << std::endl;
            return 1;
        }
        std::cout << "All encrypted xs match x-bits." << std::endl;
#endif

        // output full x's solution
        std::cout << "Xs solution: ";
        std::vector<uint32_t> xs_solution;
        std::vector<uint32_t> x_bits_list;
        int bit_drop = plot.params.get_k() / 2;
        for (int i = 0; i < 8; i++)
        {
            std::cout << plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_l][i] << " ";
            xs_solution.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_l][i]);
            if (i % 2 == 0)
            {
                x_bits_list.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_l][i] >> bit_drop);
            }
        }
        for (int i = 0; i < 8; i++)
        {
            std::cout << plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_r][i] << " ";
            xs_solution.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_r][i]);
            if (i % 2 == 0)
            {
                x_bits_list.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_L.encx_index_r][i] >> bit_drop);
            }
        }
        for (int i = 0; i < 8; i++)
        {
            std::cout << plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_l][i] << " ";
            xs_solution.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_l][i]);
            if (i % 2 == 0)
            {
                x_bits_list.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_l][i] >> bit_drop);
            }
        }
        for (int i = 0; i < 8; i++)
        {
            std::cout << plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_r][i] << " ";
            xs_solution.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_r][i]);
            if (i % 2 == 0)
            {
                x_bits_list.push_back(plot.data.xs_correlating_to_encrypted_xs[t4_to_t3_R.encx_index_r][i] >> bit_drop);
            }
        }
        std::cout << std::endl;

// let's verify xs_solution is correct before we solve
#ifdef RETAIN_X_VALUES_TO_T3
        ProofValidator proof_validator(plot.params);
        if (proof_validator.validate_table_5_pairs(xs_solution.data()))
        {
            std::cout << "Xs solution is valid." << std::endl;
        }
        else
        {
            std::cerr << "Xs solution is invalid." << std::endl;
            return 1;
        }
#endif

        Solver solver(plot.params);
        std::vector<std::vector<uint32_t>> all_proofs = solver.solve(x_bits_list, xs_solution);

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
        if (all_proofs.size() == 0)
        {
            std::cerr << "No proofs found." << std::endl;
            return 1;
        }
        if (all_proofs.size() > 1)
        {
            std::cout << "Multiple proofs found! Chaining will resolve which is correct." << std::endl;
        }
    }
    std::cout << "Done." << std::endl;
    return 0;
}