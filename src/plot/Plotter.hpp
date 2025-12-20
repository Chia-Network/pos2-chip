#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <memory_resource>
#include <optional>
#include <string>
#include <vector>

#include "PlotData.hpp"
#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"

#include "TableConstructorGeneric.hpp"

#include "ResettableArenaResource.hpp"

#if defined(__APPLE__)
#include <mach/mach.h>
#elif defined(__linux__)
#include <fstream>
#include <sstream>
#include <unistd.h>
#elif defined(_WIN32)
#define NOMINMAX
#include <psapi.h>
#include <windows.h>
#endif

namespace {
// Best-effort RSS (resident set size) in bytes. Returns nullopt if unavailable.
inline std::optional<uint64_t> current_rss_bytes()
{
#if defined(__APPLE__)
    mach_task_basic_info info {};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(
            mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count)
        != KERN_SUCCESS) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(info.resident_size);
#elif defined(__linux__)
    // /proc/self/statm: size resident shared text lib data dt (in pages)
    std::ifstream f("/proc/self/statm");
    if (!f.is_open())
        return std::nullopt;

    uint64_t size_pages = 0, resident_pages = 0;
    f >> size_pages >> resident_pages;
    if (!f)
        return std::nullopt;

    long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        return std::nullopt;

    return resident_pages * static_cast<uint64_t>(page_size);
#elif defined(_WIN32)
    PROCESS_MEMORY_COUNTERS_EX pmc {};
    if (!GetProcessMemoryInfo(
            GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(pmc.WorkingSetSize);
#else
    return std::nullopt;
#endif
}

inline void print_rss(char const* label)
{
    auto rss = current_rss_bytes();
    if (!rss.has_value()) {
        std::cout << label << " RSS: (unavailable)\n";
        return;
    }
    double mib = static_cast<double>(*rss) / (1024.0 * 1024.0);
    std::cout << label << " RSS: " << mib << " MiB\n";
}
} // namespace

class Plotter {
public:
    // Construct with a hexadecimal plot ID, k parameter, and sub-k parameter
    Plotter(ProofParams const& proof_params)
        : proof_params_(proof_params)
        , fragment_codec_(proof_params)
        , validator_(proof_params)
    {
    }

    // Execute the plotting pipeline
    PlotData run()
    {
        Timer totalPlotTimer;
        totalPlotTimer.start();
        std::cout << "Starting plotter..." << std::endl;
        proof_params_.debugPrint();

#if HAVE_AES
        std::cout << "Using AES hardware acceleration for hashing." << std::endl;
#else
        std::cout << "AES hardware acceleration not available. Using software hashing."
                  << std::endl;
#endif

        Timer allocationTimer;
        allocationTimer.debugOut = true;
        size_t max_bytes_needed = sizeof(T2Pairing) * (1ull << proof_params_.get_k());
        allocationTimer.start(
            "Allocating Arena Buffers: 2 x " + std::to_string(max_bytes_needed) + " bytes");
        auto mem = TwoResources::allocate_vm(max_bytes_needed, /*prefault=*/true);

        mem.a.reset();
        mem.b.reset();
        allocationTimer.stop();

        // 1) Construct Xs candidates
        XsConstructor xs_gen_ctor(proof_params_);
        auto xs_candidates = xs_gen_ctor.construct(&mem.a, &mem.b);
        xs_gen_ctor.timings.show();
        std::cout << "Constructed " << xs_candidates.view.size() << " Xs candidates." << std::endl;

        print_rss("[After Xs Generation]");

        // 2) Table1 generic
        Table1Constructor t1_ctor(proof_params_);
        auto t1_pairs = t1_ctor.construct(xs_candidates.view);
        t1_ctor.timings.show("Table 1 Timings:");
        std::cout << "Constructed " << t1_pairs.size() << " Table 1 pairs." << std::endl;

        // output current ram used
        print_rss("[After Table1]");

#ifdef RETAIN_X_VALUES
        if (validate_) {
            for (auto const& pair: t1_pairs) {
                uint32_t xs[2] = { static_cast<uint32_t>(pair.meta >> proof_params_.get_k()),
                    static_cast<uint32_t>(pair.meta & ((1 << proof_params_.get_k()) - 1)) };
                auto result = validator_.validate_table_1_pair(xs);
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 1 pair: [" << xs[0] << ", " << xs[1]
                              << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 1 pairs validated successfully." << std::endl;
        }
#endif

        // 3) Table2 generic
        Table2Constructor t2_ctor(proof_params_);
        auto t2_pairs = t2_ctor.construct(t1_pairs);
        t2_ctor.timings.show("Table 2 Timings:");
        std::cout << "Constructed " << t2_pairs.size() << " Table 2 pairs." << std::endl;

        print_rss("[After Table2]");

#ifdef RETAIN_X_VALUES
        if (validate_) {
            for (auto const& pair: t2_pairs) {
                auto result = validator_.validate_table_2_pairs(pair.xs);
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 2 pair: [" << pair.xs[0] << ", "
                              << pair.xs[1] << ", " << pair.xs[2] << ", " << pair.xs[3] << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 2 pairs validated successfully." << std::endl;
        }
#endif

        // 4) Table3 generic
        Table3Constructor t3_ctor(proof_params_);
        std::vector<T3Pairing> t3_results = t3_ctor.construct(t2_pairs);
        t3_ctor.timings.show("Table 3 Timings:");
        std::cout << "Constructed " << t3_results.size() << " Table 3 entries." << std::endl;

        print_rss("[After Table3]");

        decltype(t1_ctor)::Timings total_timings;
        total_timings.hash_time_ms = xs_gen_ctor.timings.hash_time_ms + t1_ctor.timings.hash_time_ms
            + t2_ctor.timings.hash_time_ms + t3_ctor.timings.hash_time_ms;
        total_timings.setup_time_ms = xs_gen_ctor.timings.setup_time_ms
            + t1_ctor.timings.setup_time_ms + t2_ctor.timings.setup_time_ms
            + t3_ctor.timings.setup_time_ms;
        total_timings.sort_time_ms = xs_gen_ctor.timings.sort_time_ms + t1_ctor.timings.sort_time_ms
            + t2_ctor.timings.sort_time_ms + t3_ctor.timings.sort_time_ms;
        total_timings.find_pairs_time_ms = t1_ctor.timings.find_pairs_time_ms
            + t2_ctor.timings.find_pairs_time_ms + t3_ctor.timings.find_pairs_time_ms;
        total_timings.post_sort_time_ms = t1_ctor.timings.post_sort_time_ms
            + t2_ctor.timings.post_sort_time_ms + t3_ctor.timings.post_sort_time_ms;
        total_timings.misc_time_ms = t1_ctor.timings.misc_time_ms + t2_ctor.timings.misc_time_ms
            + t3_ctor.timings.misc_time_ms;
        total_timings.show("Total Plotting Timings:");

        std::cout << "Total plotting time: " << totalPlotTimer.stop() << " ms." << std::endl;

#if AES_COUNT_HASHES
        showHashCounts();
#endif

#ifdef RETAIN_X_VALUES
        if (validate_) {
            for (auto const& t3_pair: t3_results) {
                auto const& xs_array = t3_pair.xs;
                auto result = validator_.validate_table_3_pairs(xs_array.data());
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 3 pair: [" << xs_array[0] << ", "
                              << xs_array[1] << ", " << xs_array[2] << ", " << xs_array[3] << ", "
                              << xs_array[4] << ", " << xs_array[5] << ", " << xs_array[6] << ", "
                              << xs_array[7] << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 3 pairs validated successfully." << std::endl;
        }
#endif

        // Return a default-constructed PlotData to avoid relying on specific member names here.
        auto dummy_data = PlotData {};
        std::vector<ProofFragment> t3_proof_fragments;
        t3_proof_fragments.reserve(t3_results.size());
        for (auto const& t3_pair: t3_results) {
            t3_proof_fragments.push_back(t3_pair.proof_fragment);
        }
        dummy_data.t3_proof_fragments = t3_proof_fragments;
        return dummy_data;
    }

    ProofParams getProofParams() const { return proof_params_; }

    void setValidate(bool validate) { validate_ = validate; }

private:
    ProofParams proof_params_;
    ProofFragmentCodec fragment_codec_;

    // Timing utility
    Timer timer_;

    // Debugging: validate as we go
    bool validate_ = true;
    ProofValidator validator_;
};

// Helper: convert hex string to 32-byte array
inline std::array<uint8_t, 32> hexToBytes(std::string const& hex)
{
    std::array<uint8_t, 32> bytes {};
    for (size_t i = 0; i < bytes.size(); ++i) {
        auto byte_str = hex.substr(2 * i, 2);
        bytes[i] = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
    }
    return bytes;
}
