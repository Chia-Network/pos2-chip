#include <iostream>
#include <string>
#include <cstdlib>
#include "Plotter.hpp"
#include <common/PlotFile.hpp>

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 3)
    {
        std::cerr << "Usage: " << argv[0] << " <k> [sub_k]\n";
        return 1;
    }

    int k = std::atoi(argv[1]);
    int sub_k = 16; // default value
    if (argc == 3)
    {
        sub_k = std::atoi(argv[2]);
    }

    if (k <= 0 || sub_k <= 0 || sub_k > k)
    {
        std::cerr << "Error: invalid parameters k=" << k
                  << ", sub_k=" << sub_k
                  << ". Must satisfy 0 < sub_k ≤ k.\n";
        return 1;
    }

    // 64‑hex‑character plot ID
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    Timer timer;
    timer.start("Plotting");
    Plotter plotter(plot_id_hex, k, sub_k);
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
        for (int partition_id = 0; partition_id < plot.t4_to_t3_back_pointers.size(); ++partition_id)
        {
            std::cout << "  Partition " << partition_id << ": " << std::endl
                      << "     T4 entries: " << plot.t4_to_t3_back_pointers[partition_id].size() << std::endl
                      << "     T5 entries: " << plot.t5_to_t4_back_pointers[partition_id].size() << std::endl;
        }
    }
    std::cout << "Total T3 entries: " << plot.t3_encrypted_xs.size() << "\n";
    std::cout << "Total T4 entries: " << t4_to_t3_count << "\n";
    std::cout << "Total T5 entries: " << t5_to_t4_count << "\n";
    std::cout << "----------------------" << std::endl;

#ifdef RETAIN_X_VALUES
    bool validate = true;
    if (validate)
    {
        XsEncryptor xs_encryptor = plotter.getXsEncryptor();
        timer.start("Validating Table 5 - Final");
        int total_validated = 0;
        std::cout << "Partition..." << std::flush;
        for (int partition_id = 0; partition_id < plot.t5_to_t4_back_pointers.size(); partition_id++)
        {
            std::cout << partition_id << "..." << std::flush;
            for (size_t i = 0; i < plot.t5_to_t4_back_pointers[partition_id].size(); ++i)
            {
                uint32_t back_pointer_index = plot.t5_to_t4_back_pointers[partition_id][i].t4_index_l;
                uint64_t back_l = plot.t4_to_t3_back_pointers[partition_id][back_pointer_index].encx_index_l;
                uint64_t back_r = plot.t4_to_t3_back_pointers[partition_id][back_pointer_index].encx_index_r;
                uint64_t encrypted_xs_l = plot.t3_encrypted_xs[back_l];
                uint64_t encrypted_xs_r = plot.t3_encrypted_xs[back_r];
                bool valid_l = xs_encryptor.validate_encrypted_xs(encrypted_xs_l, plot.t5_to_t4_back_pointers[partition_id][i].xs);
                bool valid_r = xs_encryptor.validate_encrypted_xs(encrypted_xs_r, plot.t5_to_t4_back_pointers[partition_id][i].xs + 8);
                if (!valid_l || !valid_r)
                {
                    std::cerr << "Encrypted_xs do not match x-values " << i << std::endl;
                    for (int i = 0; i < 8; i++)
                    {
                        std::cerr << plot.t5_to_t4_back_pointers[partition_id][i].xs[i] << ", ";
                    }
                    std::cerr << std::endl;
                    exit(23);
                }
                back_pointer_index = plot.t5_to_t4_back_pointers[partition_id][i].t4_index_r;
                back_l = plot.t4_to_t3_back_pointers[partition_id][back_pointer_index].encx_index_l;
                back_r = plot.t4_to_t3_back_pointers[partition_id][back_pointer_index].encx_index_r;
                encrypted_xs_l = plot.t3_encrypted_xs[back_l];
                encrypted_xs_r = plot.t3_encrypted_xs[back_r];
                valid_l = xs_encryptor.validate_encrypted_xs(encrypted_xs_l, plot.t5_to_t4_back_pointers[partition_id][i].xs + 16);
                valid_r = xs_encryptor.validate_encrypted_xs(encrypted_xs_r, plot.t5_to_t4_back_pointers[partition_id][i].xs + 24);
                if (!valid_l || !valid_r)
                {
                    std::cerr << "Encrypted_xs do not match x-values " << i << std::endl;
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
        #ifdef RETAIN_X_VALUES
        std::string filename = "plot_" + std::to_string(k) + "_" + std::to_string(sub_k) + "_xvalues_" + plot_id_hex + ".bin";
        #else
        std::string filename = "plot_" + std::to_string(k) + "_" + std::to_string(sub_k) + '_' + plot_id_hex + ".bin";
        #endif
        timer.start("Writing plot file: " + filename);
        PlotFile::writeData(filename, plot);
        timer.stop();

        // test read
        // if we have x values the comparison function won't be valid since plot does not store x values.
        PlotData read_plot = PlotFile::readData(filename);
       
        if (read_plot == plot)
        {
            std::cout << "Plot read/write successful." << std::endl;
        }
        else
        {
            std::cerr << "Read plot does not match original." << std::endl;
            exit(23);
        }
    }

    return 0;
}
