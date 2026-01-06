#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <string>

static void print_usage(char const* prog)
{
    std::cerr
        << "Usage:\n"
        << "  " << prog << " test <k> <plot_id_hex> [strength] [verbose]\n"
        << "    <k>            : even integer between 18 and 32\n"
        << "    <plot_id_hex>  : 64 hex characters\n"
        << "    [strength]     : optional, defaults to 2\n"
        << "    [verbose]      : optional, 0 (default) for progress bar, 1 for verbose output\n";
}

static void render_progress_line(
    AtomicProgressSnapshot s, std::chrono::steady_clock::time_point start)
{
    double frac = s.fraction;
    if (frac < 0.0)
        frac = 0.0;
    if (frac > 1.0)
        frac = 1.0;

    constexpr int width = 28;
    int filled = int(frac * width + 0.5);
    if (filled < 0)
        filled = 0;
    if (filled > width)
        filled = width;

    std::string bar;
    bar.reserve(width + 2);
    bar.push_back('[');
    for (int i = 0; i < width; ++i)
        bar.push_back(i < filled ? '=' : ' ');
    bar.push_back(']');

    int pct = int(frac * 100.0 + 0.5);
    if (pct > 100)
        pct = 100;

    auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    std::cout << "\r" << bar << " " << pct << "% " << plot_state_name(s.state);

    if (s.table_id)
        std::cout << " T" << int(s.table_id);

    std::cout << " " << elapsed << "s"
              << "\x1b[K" << std::flush;
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

    // Expect: prog test <k> <plot_id_hex> [strength=2 (default)] [verbose=0]
    if (argc < 4 || argc > 6) {
        print_usage(argv[0]);
        return 1;
    }

    int k = std::atoi(argv[2]);
    std::string plot_id_hex = argv[3];
    int strength = 2;
    bool verbose = false;

    if (argc >= 5) {
        // If argv[4] is "0" or "1" treat it as verbose; otherwise treat as strength
        std::string a4 = argv[4];
        if (a4 == "0" || a4 == "1") {
            verbose = (std::atoi(a4.c_str()) != 0);
        }
        else {
            strength = std::atoi(a4.c_str());
        }
    }
    if (argc == 6) {
        // argv[5] is explicit verbose flag (0 or 1)
        verbose = (std::atoi(argv[5]) != 0);
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

    Plotter::Options opt;
    opt.validate = false;
    opt.verbose = verbose;

    ProofParams params(Utils::hexToBytes(plot_id_hex).data(),
        numeric_cast<uint8_t>(k),
        numeric_cast<uint8_t>(strength));
    Plotter plotter(params);

    PlotData plot;

    if (verbose) {
        VerboseConsoleSink console_sink;
        opt.sink = &console_sink;
        plot = plotter.run(opt);
        std::cout << "Total T3 entries: " << plot.t3_proof_fragments.size() << "\n";
    }
    else {
        AtomicProgressSink atomic_sink;
        opt.sink = &atomic_sink;

        auto start = std::chrono::steady_clock::now();
        auto fut = std::async(std::launch::async, [&]() { return plotter.run(opt); });

        while (fut.wait_for(std::chrono::milliseconds(500)) != std::future_status::ready) {
            render_progress_line(atomic_sink.snapshot(), start);
        }
        render_progress_line(atomic_sink.snapshot(), start);
        std::cout << "\n";

        plot = fut.get();
    }

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
        Timer writeTimer;
        writeTimer.start();
        std::cout << "Writing plot to " << filename << "...\n";
        size_t bytes_written = PlotFile::writeData(
            filename, plot, plotter.getProofParams(), std::array<uint8_t, 32 + 48 + 32>({}));
        double write_time_ms = writeTimer.stop();
        double bits_per_entry = (static_cast<double>(bytes_written) * 8.0)
            / static_cast<double>(plot.t3_proof_fragments.size());
        if (bytes_written == 0) {
            std::cerr << "Error: No data written to plot file.\n";
            return 1;
        }
        std::cout << "Wrote plot file: " << filename << " (" << bytes_written << " bytes) "
                  << "[" << bits_per_entry << " bits/entry]" << " in " << write_time_ms << " ms\n";
    }

    return 0;
}
catch (std::exception const& e) {
    std::cerr << "Failed with exception: " << e.what() << std::endl;
}
