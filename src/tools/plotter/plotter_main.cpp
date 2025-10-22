#include <iostream>
#include <string>
#include <cstdlib>
#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"
#include "common/Utils.hpp"

static void print_usage(const char* prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " test <k> <plot_id_hex> [strength]\n"
              << "    <k>            : even integer between 18 and 32\n"
              << "    <plot_id_hex>  : 64 hex characters\n"
              << "    [strength]     : optional, defaults to 2\n";
}

// example usage: ./plotter test 18 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 2
int main(int argc, char *argv[]) try
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd != "test") {
        print_usage(argv[0]);
        return 1;
    }

    // Expect: prog test <k> <plot_id_hex> [strength=2 (default)]
    if (argc < 4 || argc > 5) {
        print_usage(argv[0]);
        return 1;
    }

    int k = std::atoi(argv[2]);
    std::string plot_id_hex = argv[3];
    int strength = 2;
    if (argc == 5) {
        strength = std::atoi(argv[4]);
    }

    if ((k < 18) || (k > 32) || (k % 2 != 0)) {
        std::cerr << "Error: k must be an even integer between 18 and 32.\n";
        return 1;
    }

    if (plot_id_hex.size() != 64) {
        std::cerr << "Error: plot_id_hex must be 64 hex characters.\n";
        return 1;
    }

    if (strength < 2 || strength > 255) {
        std::cerr << "Error: strength must be at least 2 and less than 256\n";
        return 1;
    }

    Timer timer;
    timer.start("Plotting");
    Plotter plotter(Utils::hexToBytes(plot_id_hex), numeric_cast<uint8_t>(k), numeric_cast<uint8_t>(strength));
    plotter.setValidate(true);
    PlotData plot = plotter.run();
    timer.stop();
    std::cout << "Plotting completed.\n";
    std::cout << "----------------------" << std::endl;

    // show final plot results
    uint64_t t4_to_t3_count = 0;
    uint64_t t5_to_t4_count = 0;
    for (const auto &t4_partition : plot.t4_to_t3_back_pointers)
    {
        t4_to_t3_count += t4_partition.size();
    }
    for (const auto &t5_partition : plot.t5_to_t4_back_pointers)
    {
        t5_to_t4_count += t5_partition.size();
    }
    if (false)
    {
        for (size_t partition_id = 0; partition_id < plot.t4_to_t3_back_pointers.size(); ++partition_id)
        {
            std::cout << "  Partition " << partition_id << ": " << std::endl
                      << "     T4 entries: " << plot.t4_to_t3_back_pointers[partition_id].size() << std::endl
                      << "     T5 entries: " << plot.t5_to_t4_back_pointers[partition_id].size() << std::endl;
        }
    }
    std::cout << "Total T3 entries: " << plot.t3_proof_fragments.size() << "\n";
    std::cout << "Total T4 entries: " << t4_to_t3_count << "\n";
    std::cout << "Total T5 entries: " << t5_to_t4_count << "\n";
    std::cout << "----------------------" << std::endl;

#ifdef RETAIN_X_VALUES
    bool validate = true;
    if (validate)
    {
        ProofParams params = plotter.getProofParams();
        ProofValidator validator(params);

        // first validate all xs in T3
        timer.start("Validating Table 3 - Final");
        for (const auto& xs_array : plot.xs_correlating_to_proof_fragments) {
            auto result = validator.validate_table_3_pairs(xs_array.data());
            if (!result.has_value()) {
                std::cerr << "Validation failed for Table 3 pair: ["
                          << xs_array[0] << ", " << xs_array[1] << ", " << xs_array[2] << ", " << xs_array[3] 
                          << ", " << xs_array[4] << ", " << xs_array[5] << ", " << xs_array[6] << ", " << xs_array[7]
                          << "]\n";
                return {};
            }
        }
        std::cout << "Table 3 pairs validated successfully." << std::endl;
        timer.stop();


        ProofFragmentCodec fragment_codec = plotter.getProofFragment();
        timer.start("Validating Table 5 - Final");
        int total_validated = 0;
        std::cout << "Partition..." << std::flush;
        for (int partition_id = 0; partition_id < plot.t5_to_t4_back_pointers.size(); partition_id++)
        {
            std::cout << partition_id << "..." << std::flush;
            for (size_t i = 0; i < plot.t5_to_t4_back_pointers[partition_id].size(); ++i)
            {
                uint32_t back_pointer_index = plot.t5_to_t4_back_pointers[partition_id][i].l;
                uint64_t back_l = plot.t4_to_t3_back_pointers[partition_id][back_pointer_index].l;
                uint64_t back_r = plot.t4_to_t3_back_pointers[partition_id][back_pointer_index].r;
                uint64_t proof_fragment_l = plot.t3_proof_fragments[back_l];
                uint64_t proof_fragment_r = plot.t3_proof_fragments[back_r];
                auto res = validator.validate_table_5_pairs(plot.t5_to_t4_back_pointers[partition_id][i].xs);
                if (!res)
                {
                    std::cerr << "Validation failed for T5 x-values: [";
                    for (int i = 0; i < 16; i++)
                    {
                        std::cerr << plot.t5_to_t4_back_pointers[partition_id][i].xs[i] << ", ";
                    }
                    exit(23);
                }
                bool valid_l = fragment_codec.validate_proof_fragment(proof_fragment_l, plot.t5_to_t4_back_pointers[partition_id][i].xs);
                bool valid_r = fragment_codec.validate_proof_fragment(proof_fragment_r, plot.t5_to_t4_back_pointers[partition_id][i].xs + 8);
                if (!valid_l || !valid_r)
                {
                    std::cerr << "Fragments do not match x-values " << i << std::endl;
                    for (int i = 0; i < 8; i++)
                    {
                        std::cerr << plot.t5_to_t4_back_pointers[partition_id][i].xs[i] << ", ";
                    }
                    std::cerr << std::endl;
                    exit(23);
                }

                back_pointer_index = plot.t5_to_t4_back_pointers[partition_id][i].r;
                back_l = plot.t4_to_t3_back_pointers[partition_id][back_pointer_index].l;
                back_r = plot.t4_to_t3_back_pointers[partition_id][back_pointer_index].r;
                proof_fragment_l = plot.t3_proof_fragments[back_l];
                proof_fragment_r = plot.t3_proof_fragments[back_r];
                valid_l = fragment_codec.validate_proof_fragment(proof_fragment_l, plot.t5_to_t4_back_pointers[partition_id][i].xs + 16);
                valid_r = fragment_codec.validate_proof_fragment(proof_fragment_r, plot.t5_to_t4_back_pointers[partition_id][i].xs + 24);
                if (!valid_l || !valid_r)
                {
                    std::cerr << "Fragments xs do not match x-values " << i << std::endl;
                    for (int i = 0; i < 8; i++)
                    {
                        std::cerr << plot.t5_to_t4_back_pointers[partition_id][i].xs[i] << ", ";
                    }
                    std::cerr << std::endl;
                    exit(23);
                }
                total_validated++;
            }
        }
        timer.stop();
        std::cout << "Validated " << total_validated << " final entries." << std::endl;
    }
#endif

    bool writeToFile = true;
    if (writeToFile)
    {
        std::string filename = "plot_" + std::to_string(k) + "_" + std::to_string(strength);
        #ifdef RETAIN_X_VALUES_TO_T3
        filename += "_xvalues";
        #endif
        #ifndef NON_BIPARTITE_BEFORE_T3
        filename += "_bipartite";
        #endif
        filename += '_' + plot_id_hex + ".bin";
        timer.start("Writing plot file: " + filename);
        PlotFile::writeData(filename, plot, plotter.getProofParams(), std::array<uint8_t, 32 + 48 + 32>({}));
        timer.stop();

        // test read
        // if we have x values the comparison function won't be valid since plot does not store x values.
        std::cout << "Reading plot file: " << filename << std::endl;
        PlotFile::PlotFileContents read_plot = PlotFile::readData(filename);
       
        if ((read_plot.data == plot) && (read_plot.params == plotter.getProofParams()))
        {
            std::cout << "Plot read/write successful." << std::endl;
        }
        else
        {
            std::cerr << "Read plot does not match original." << std::endl;
        }
    }

    return 0;
}
catch (const std::exception& e) {
    std::cerr << "Failed with exception: " << e.what() << std::endl;
}
