#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"


TEST_SUITE_BEGIN("plot-file");

TEST_CASE("plot-read-write")
{
    #define PLOT_ID_HEX "c6b84729c23dc6d60c92f22c17083f47845c1179227c5509f07a5d2804a7b835"
    constexpr int         K           = 18;
    constexpr int         SUB_K       = 16;

    printfln("Creating a %d/%d plot: %s", K, SUB_K, PLOT_ID_HEX);

    Timer timer{};
    timer.start("");

    Plotter  plotter(PLOT_ID_HEX, K, SUB_K);
    PlotData plot = plotter.run();
    timer.stop();

    printfln("Plot completed, writing to file..."); 

    #define tostr std::to_string
    std::string file_name = (std::string("plot_") + "k") + tostr(K) + "_" + tostr(SUB_K) + "_" PLOT_ID_HEX + ".bin";
    
    timer.start("Writing plot file: " + file_name);
    PlotFile::writeData(file_name, plot, plotter.getProofParams());
    timer.stop();

    timer.start("Reading plot file: " + file_name);
    PlotFile::PlotFileContents read_plot = PlotFile::readData(file_name);
    timer.stop();

    ENSURE(plot == read_plot.data);
    ENSURE(plotter.getProofParams() == read_plot.params);
}

TEST_SUITE_END();
