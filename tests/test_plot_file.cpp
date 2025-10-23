#include "test_util.h"
#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"
#include "common/Utils.hpp"


TEST_SUITE_BEGIN("plot-file");

TEST_CASE("plot-read-write")
{
    #define PLOT_ID_HEX "c6b84729c23dc6d60c92f22c17083f47845c1179227c5509f07a5d2804a7b835"
    constexpr int         K           = 18;
    constexpr int         strength    = 2;

    printfln("Creating a %d plot: %s", K, PLOT_ID_HEX);

    Timer timer{};
    timer.start("");

    Plotter  plotter(Utils::hexToBytes(PLOT_ID_HEX), K, strength);
    PlotData plot = plotter.run();
    timer.stop();

    printfln("Plot completed, writing to file..."); 

    #define tostr std::to_string
    std::string file_name = (std::string("plot_") + "k") + tostr(K) + "_" PLOT_ID_HEX + ".bin";
    
    timer.start("Writing plot file: " + file_name);
    PlotFile::writeData(file_name, plot, plotter.getProofParams(), std::array<uint8_t, 32 + 48 + 32>({}));
    timer.stop();

    timer.start("Reading plot file: " + file_name);
    PlotFile::PlotFileContents read_plot = PlotFile::readData(file_name);
    // read all partitions
    for (size_t partition_id = 0; partition_id < read_plot.data.t4_to_t3_back_pointers.size(); ++partition_id)
    {
        PlotFile::readPartitionT4T5BackPointers(file_name, read_plot, partition_id);
    }
    timer.stop();

    ENSURE(plot == read_plot.data);
    ENSURE(plotter.getProofParams() == read_plot.params);
}

TEST_SUITE_END();
