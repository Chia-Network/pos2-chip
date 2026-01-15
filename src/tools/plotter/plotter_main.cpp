#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include <cstdlib>
#include <iostream>
#include <string>

static void print_usage(char const* prog)
{
    std::cerr << "Usage:\n"
              << "  " << prog << " test <k> <plot_id_hex> [strength]\n"
              << "    <k>            : even integer between 18 and 32\n"
              << "    <plot_id_hex>  : 64 hex characters\n"
              << "    [strength]     : optional, defaults to 2\n";
}

// example usage: ./plotter test 18 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
// 2
int main(int argc, char* argv[])
try {
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

    int const k = std::atoi(argv[2]);
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
    ProofParams params(Utils::hexToBytes(plot_id_hex).data(),
        numeric_cast<uint8_t>(k),
        numeric_cast<uint8_t>(strength));
    Plotter plotter(params);
    plotter.setValidate(true);
    PlotData plot = plotter.run();
    timer.stop();
    std::cout << "Plotting completed.\n";
    std::cout << "----------------------" << std::endl;

    std::cout << "Total T3 entries: " << plot.t3_proof_fragments.size() << "\n";
    std::cout << "----------------------" << std::endl;

#ifdef RETAIN_X_VALUES
    bool validate = true;
    if (validate) {
        ProofParams params = plotter.getProofParams();
        ProofValidator validator(params);

        // first validate all xs in T3
        timer.start("Validating Table 3 - Final");
        for (auto const& xs_array: plot.xs_correlating_to_proof_fragments) {
            auto result = validator.validate_table_3_pairs(xs_array.data());
            if (!result.has_value()) {
                std::cerr << "Validation failed for Table 3 pair: [" << xs_array[0] << ", "
                          << xs_array[1] << ", " << xs_array[2] << ", " << xs_array[3] << ", "
                          << xs_array[4] << ", " << xs_array[5] << ", " << xs_array[6] << ", "
                          << xs_array[7] << "]\n";
                return {};
            }
        }
        std::cout << "Table 3 pairs validated successfully." << std::endl;
        timer.stop();
    }
#endif

    bool writeToFile = true;
    if (writeToFile) {
        std::string filename = "plot_" + std::to_string(k) + "_" + std::to_string(strength);
#ifdef RETAIN_X_VALUES_TO_T3
        filename += "_xvalues";
#endif
        filename += '_' + plot_id_hex + ".bin";
        timer.start("Writing plot file: " + filename);
        size_t bytes_written = PlotFile::writeData(
            filename, plot, plotter.getProofParams(), 0, 0, std::array<uint8_t, 32 + 48 + 32>({}));
        timer.stop();

        double bits_per_entry = (static_cast<double>(bytes_written) * 8.0)
            / static_cast<double>(plot.t3_proof_fragments.size());
        std::cout << "Wrote plot file: " << filename << " (" << bytes_written << " bytes) "
                  << "[" << bits_per_entry << " bits/entry]" << std::endl;
    }

    return 0;
}
catch (std::exception const& e) {
    std::cerr << "Failed with exception: " << e.what() << std::endl;
}
