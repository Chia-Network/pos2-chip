#pragma once
#include "common/Timer.hpp"
#include <iostream>
#include <iomanip>
#include <string>

struct ProofSolverTimings
{
    double allocating                = 0;
    double hashing_x1s               = 0;
    double sorting_x1s               = 0;
    double bitmaskfillzero           = 0;
    double bitmasksetx1s             = 0;
    double chachafilterx2sbybitmask  = 0;
    double sorting_filtered_x2s      = 0;
    double match_x1_x2_sorted_lists  = 0;
    double t2_matches                = 0;
    double t2_gen_L_list          = 0;
    double t2_sort_short_list        = 0;
    double t2_scan_for_matches       = 0;
    double misc                      = 0;

    void printSummary()
    {
        constexpr int LABEL_W = 25;
        constexpr int VALUE_W =  8;
        const std::string sep(LABEL_W + VALUE_W + 5, '-');

        auto& os = std::cout;
        // reset fill-char to space, set fixed + two decimals
        os << std::setfill(' ')
           << std::fixed
           << std::setprecision(2);

        os << sep << "\n";
        os << std::left  << std::setw(LABEL_W) << "Allocating"             << ": "
           << std::right << std::setw(VALUE_W) << allocating          << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "Hashing x1's"          << ": "
           << std::right << std::setw(VALUE_W) << hashing_x1s         << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "Sorting x1's"          << ": "
           << std::right << std::setw(VALUE_W) << sorting_x1s         << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "Bitmask fill zero"     << ": "
           << std::right << std::setw(VALUE_W) << bitmaskfillzero     << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "Bitmask set x1's"      << ": "
           << std::right << std::setw(VALUE_W) << bitmasksetx1s       << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "Chacha filter x2's"    << ": "
           << std::right << std::setw(VALUE_W) << chachafilterx2sbybitmask << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "Sorting filtered x2's" << ": "
           << std::right << std::setw(VALUE_W) << sorting_filtered_x2s << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "Match x1 x2 sorted"    << ": "
           << std::right << std::setw(VALUE_W) << match_x1_x2_sorted_lists << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "T2 matches"            << ": "
           << std::right << std::setw(VALUE_W) << t2_matches          << " ms\n";
        os << std::left  << std::setw(LABEL_W) << " - T2 gen L list"      << ": "
           << std::right << std::setw(VALUE_W) << t2_gen_L_list      << " ms\n";
        os << std::left  << std::setw(LABEL_W) << " - T2 sort short list"    << ": "
           << std::right << std::setw(VALUE_W) << t2_sort_short_list  << " ms\n";
        os << std::left  << std::setw(LABEL_W) << " - T2 scan for matches"   << ": "
           << std::right << std::setw(VALUE_W) << t2_scan_for_matches << " ms\n";
        os << std::left  << std::setw(LABEL_W) << "Misc"                  << ": "
           << std::right << std::setw(VALUE_W) << misc                << " ms\n";

        double nonAllocTotal =
            hashing_x1s + sorting_x1s + bitmaskfillzero + bitmasksetx1s +
            chachafilterx2sbybitmask + sorting_filtered_x2s +
            match_x1_x2_sorted_lists + t2_matches + misc;

        os << sep << "\n";
        os << std::left  << std::setw(LABEL_W) << "Non-allocating total"  << ": "
           << std::right << std::setw(VALUE_W) << nonAllocTotal       << " ms\n";
        os << sep << "\n";
    }
};
