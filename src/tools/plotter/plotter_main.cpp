#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
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
                case NoteId::HasAESHardware:
                    std::cout << "Note: AES hardware acceleration is "
                              << (e.u64_0 ? "available." : "not available.") << "\n";
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

class ProgressBarSink final : public IProgressSink {
public:
    explicit ProgressBarSink(bool show_tables = true) : show_tables_(show_tables) {}

    enum class TablePhase : uint8_t { MatchKeys, PostSort, Done };

    TablePhase phase_ = TablePhase::MatchKeys;
    double phase_progress_ = 0.0; // 0..1 within phase

    static constexpr double kMatchKeysWeight = 0.90;
    static constexpr double kPostSortWeight = 0.10;

    double table_fraction() const
    {
        switch (phase_) {
        case TablePhase::MatchKeys:
            return kMatchKeysWeight * phase_progress_;
        case TablePhase::PostSort:
            return kMatchKeysWeight + kPostSortWeight * phase_progress_;
        case TablePhase::Done:
            return 1.0;
        }
        return 0.0;
    }

    bool on_event(ProgressEvent const& e) noexcept override
    {
        using clock = std::chrono::steady_clock;

        switch (e.kind) {
        case EventKind::PlotBegin:
            start_ = clock::now();
            printed_line_ = false;
            std::cout << "Plotting...\n";
            break;

        case EventKind::TableBegin:
            cur_table_ = e.table_id;
            // Optional: table begin line (milestone)
            if (show_tables_) {
                flush_line_(); // finish any in-place line
                // std::cout << "T" << int(cur_table_) << "...\n";
            }
            break;

        case EventKind::SectionBegin:
            section_l_ = e.section_l;
            section_r_ = e.section_r;
            break;

        case EventKind::MatchKeyBegin:
            // Treat MatchKeyBegin as progress tick; don't print.
            match_key_ = e.match_key;
            match_total_ = (e.match_keys_total ? e.match_keys_total : match_total_);
            // Some events might have counts; keep if present
            if (e.items_l)
                items_l_ = e.items_l;
            if (e.items_r)
                items_r_ = e.items_r;
            maybe_render_();
            break;

        case EventKind::MatchKeyEnd:
            // Also can tick progress here if you prefer end-of-work
            phase_ = TablePhase::MatchKeys;
            if (e.match_keys_total > 0) {
                phase_progress_
                    = std::min(1.0, double(e.match_key + 1) / double(e.match_keys_total));
            }
            maybe_render_();
            break;

        case EventKind::PostSortBegin:
            phase_ = TablePhase::PostSort;
            phase_progress_ = 0.0;
            force_render_(); // show “post-sort…” immediately
            break;

        case EventKind::PostSortEnd:
            phase_ = TablePhase::PostSort;
            phase_progress_ = 1.0;
            force_render_(); // now bar can hit 100%
            break;

        case EventKind::TableEnd:
            phase_ = TablePhase::Done;
            phase_progress_ = 1.0;
            force_render_();
            flush_line_();
            if (show_tables_) {
                double ms = std::chrono::duration<double, std::milli>(e.elapsed).count();
                std::cout << "T" << int(e.table_id) << " done in " << ms << " ms";
                if (e.produced)
                    std::cout << "  produced=" << e.produced;
                std::cout << "\n";
            }
            break;

        case EventKind::Note:
            if (e.note_id == NoteId::LayoutTotalBytesAllocated) {
                total_bytes_alloc_ = e.u64_0;
            }
            else if (e.note_id == NoteId::TableCapacityUsed) {
                table_cap_used_[e.table_id] = e.f64_0; // store fraction 0..1
            }
            else if (e.note_id == NoteId::HasAESHardware) {
                if (e.u64_0) {
                    std::cout << "✅ AES hardware acceleration available for hashing.\n";
                }
                else {
                    std::cout
                        << "❌ AES hardware acceleration not available; using software hashing.\n";
                }
            }
            break;

        case EventKind::PlotEnd: {
            flush_line_();
            double ms = std::chrono::duration<double, std::milli>(e.elapsed).count();
            std::cout << "Done in " << ms << " ms";
            if (total_bytes_alloc_) {
                std::cout << "  total mem=" << format_bytes_(total_bytes_alloc_);
            }
            std::cout << "\n";
            break;
        }

        case EventKind::Warning:
            flush_line_();
            std::cerr << "Warning: " << e.msg << "\n";
            break;

        case EventKind::Error:
            flush_line_();
            std::cerr << "Error: " << e.msg << "\n";
            break;

        default:
            break;
        }

        return true;
    }

private:
    void maybe_render_() noexcept
    {
        using clock = std::chrono::steady_clock;
        auto now = clock::now();
        if (now - last_render_ < min_period_)
            return;
        last_render_ = now;
        render_line_();
    }

    void force_render_() noexcept
    {
        render_line_();
        last_render_ = std::chrono::steady_clock::now();
    }

    void render_line_() noexcept
    {
        // Compute fraction from match keys if we can
        double frac = 0.0;
        if (match_total_ > 0) {
            // If match_key_ is a "completed count", clamp is fine.
            // If match_key_ is an index, you probably want (match_key_ + 1) / total on End events.
            frac = std::clamp(double(match_key_) / double(match_total_), 0.0, 1.0);
        }

        // Force 100% when done (and optionally during post-sort you might not want to show 100%)
        if (phase_ == TablePhase::Done) {
            frac = 1.0;
        }

        constexpr int width = 28;
        int filled = int(frac * width + 0.5);
        if (filled > width)
            filled = width;

        auto elapsed
            = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_).count();

        std::string bar;
        bar.reserve(width + 2);
        bar.push_back('[');
        for (int i = 0; i < width; ++i)
            bar.push_back(i < filled ? '=' : ' ');
        bar.push_back(']');

        int pct = int(frac * 100.0 + 0.5);
        if (pct > 100)
            pct = 100;
        if (phase_ == TablePhase::Done)
            pct = 100;

        // One-line, overwrite-in-place
        std::cout << "\r" << bar << "  T" << int(cur_table_) << " ";

        // Status field: print a fixed-width token to avoid leftover chars
        // (Assumes section indices are single-digit; widen/pad if needed.)
        if (phase_ == TablePhase::PostSort) {
            std::cout << "srt  "; // 5 chars
        }
        else if (phase_ == TablePhase::MatchKeys) {
            // e.g. "3-0  " fixed-ish width
            std::cout << int(section_l_) << "-" << int(section_r_) << "  ";
        }
        else { // Done
            std::cout << "done "; // 5 chars
        }

        // Percentage fixed width: "  7%", " 42%", "100%"
        std::cout << " ";
        if (pct < 10)
            std::cout << "  ";
        else if (pct < 100)
            std::cout << " ";
        std::cout << pct << "%  ";

        std::cout << elapsed << "s";

        // Clear to end-of-line so shorter updates don't leave garbage behind
        // (If you want to avoid ANSI when redirected, gate this on isatty().)
        std::cout << "\x1b[K" << std::flush;

        printed_line_ = true;
    }

    void flush_line_() noexcept
    {
        if (!printed_line_)
            return;
        std::cout << "\n";
        printed_line_ = false;
    }

    static std::string format_bytes_(uint64_t b)
    {
        static constexpr char const* suf[] = { "B", "KiB", "MiB", "GiB", "TiB" };
        double v = double(b);
        int i = 0;
        while (v >= 1024.0 && i < 4) {
            v /= 1024.0;
            ++i;
        }
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.2f %s", v, suf[i]);
        return std::string(buf);
    }

private:
    bool show_tables_ = true;

    std::chrono::steady_clock::time_point start_ {};
    std::chrono::steady_clock::time_point last_render_ {};
    std::chrono::milliseconds min_period_ { 150 };

    bool printed_line_ = false;

    uint8_t cur_table_ = 0;
    uint8_t section_l_ = 0, section_r_ = 0;
    uint32_t match_key_ = 0, match_total_ = 0;
    uint64_t items_l_ = 0, items_r_ = 0;

    uint64_t total_bytes_alloc_ = 0;
    double table_cap_used_[8] = {}; // small fixed array; index by table_id
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

    ConsoleSink console_sink(verbose);
    ProgressBarSink progress_sink(/*show_tables=*/true);
    IProgressSink* chosen_sink = verbose ? static_cast<IProgressSink*>(&console_sink)
                                         : static_cast<IProgressSink*>(&progress_sink);

    Plotter::Options opt;
    opt.validate = false;
    opt.verbose = verbose;
    opt.sink = chosen_sink;

    ProofParams params(Utils::hexToBytes(plot_id_hex).data(),
        numeric_cast<uint8_t>(k),
        numeric_cast<uint8_t>(strength));
    Plotter plotter(params);
    PlotData plot = plotter.run(opt);
    std::cout << "----------------------\n";
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
        Timer timer;
        timer.start("Writing plot file: " + filename);
        size_t bytes_written = PlotFile::writeData(
            filename, plot, plotter.getProofParams(), std::array<uint8_t, 32 + 48 + 32>({}));
        double write_time_ms = timer.stop();

        double bits_per_entry = (static_cast<double>(bytes_written) * 8.0)
            / static_cast<double>(plot.t3_proof_fragments.size());
        std::cout << "Wrote plot file: " << filename << " (" << bytes_written << " bytes) "
                  << "[" << bits_per_entry << " bits/entry]" << " in " << write_time_ms << " ms\n";
    }

    return 0;
}
catch (std::exception const& e) {
    std::cerr << "Failed with exception: " << e.what() << std::endl;
}
