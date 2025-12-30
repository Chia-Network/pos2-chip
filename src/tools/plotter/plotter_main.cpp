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

class ConsoleSink final : public IProgressSink {
public:
    explicit ConsoleSink(bool verbose) : verbose_(verbose) {}

    bool on_event(ProgressEvent const& e) noexcept override
    {
        switch (e.kind) {
        case EventKind::PlotBegin:
            std::cout << "Plotting started...\n";
            break;
        case EventKind::PlotEnd:
            std::cout << "Plotting ended. Total time: "
                      << std::chrono::duration<double, std::milli>(e.elapsed).count() << " ms\n";
            break;
        case EventKind::AllocationBegin:
            if (verbose_)
                std::cout << "Allocating memory for plotting...\n";
            break;
        case EventKind::AllocationEnd:
            if (verbose_) {
                std::cout << "Memory allocation completed. Time: "
                          << std::chrono::duration<double, std::milli>(e.elapsed).count()
                          << " ms\n";
            }
            break;
        case EventKind::TableBegin:
            if (verbose_)
                std::cout << "Constructing Table " << int(e.table_id) << " from "
                          << int(e.num_items_in) << " items...\n";
            break;
        case EventKind::TableEnd:
            if (verbose_) {
                std::cout << "Table " << int(e.table_id) << " constructed. Time: "
                          << std::chrono::duration<double, std::milli>(e.elapsed).count()
                          << " ms\n";
            }
            break;
        case EventKind::MatchKeyBegin:
            if (verbose_) {
                std::cout << "    T" << int(e.table_id) << " matching key " << e.match_key
                          << " (section " << int(e.section_l) << "-" << int(e.section_r)
                          << ") with " << e.items_l << " left items and " << e.items_r
                          << " right items...\n";
            }
            break;
        case EventKind::MatchKeyEnd:
            if (verbose_) {
                std::cout << "    T" << int(e.table_id) << " matching key " << e.match_key
                          << " completed. Time: "
                          << std::chrono::duration<double, std::milli>(e.elapsed).count()
                          << " ms\n";
            }
            break;
        case EventKind::SectionBegin:
            if (verbose_) {
                std::cout << "  T" << int(e.table_id) << " section " << int(e.section_l) << "-"
                          << int(e.section_r) << " started...\n";
            }
            break;
        case EventKind::SectionEnd:
            if (verbose_) {
                std::cout << "  T" << int(e.table_id) << " section " << int(e.section_l) << "-"
                          << int(e.section_r) << " time: "
                          << std::chrono::duration<double, std::milli>(e.elapsed).count()
                          << " ms\n";
            }
            break;
        case EventKind::PostSortBegin:
            if (verbose_) {
                std::cout << "  T" << int(e.table_id) << " post-sort started for " << e.produced
                          << " entries...\n";
            }
            break;
        case EventKind::PostSortEnd:
            if (verbose_) {
                std::cout << "  T" << int(e.table_id) << " post-sort completed. Time: "
                          << std::chrono::duration<double, std::milli>(e.elapsed).count()
                          << " ms\n";
            }
            break;
        case EventKind::Note:
            if (verbose_) {
                switch (e.note_id) {
                case NoteId::LayoutTotalBytesAllocated:
                    std::cout << "Note: Total bytes allocated for layout: " << e.u64_0
                              << " bytes\n";
                    break;
                case NoteId::TableCapacityUsed:
                    std::cout << "Note: Table " << int(e.table_id)
                              << " capacity used: " << e.f64_0 * 100.0 << "%\n";
                    break;
                default:
                    std::cout << "Note: " << e.msg << "\n";
                    break;
                }
            }
            break;
        case EventKind::Warning:
            std::cerr << "Warning: " << e.msg << "\n";
            break;
        case EventKind::Error:
            std::cerr << "Error: " << e.msg << "\n";
            break;

        default:
            break;
        }
        return true; // continue
    }

private:
    bool verbose_ = false;
};

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

    ConsoleSink sink(/*verbose=*/true);
    Plotter::Options opt;
    opt.validate = false;
    opt.verbose = false;
    opt.sink = &sink;

    ProofParams params(Utils::hexToBytes(plot_id_hex).data(),
        numeric_cast<uint8_t>(k),
        numeric_cast<uint8_t>(strength));
    Plotter plotter(params);
    PlotData plot = plotter.run(opt);
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
            filename, plot, plotter.getProofParams(), std::array<uint8_t, 32 + 48 + 32>({}));
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
