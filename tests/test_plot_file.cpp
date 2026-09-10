#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include "test_util.h"
#include "pos/sha/sha256.hpp"

TEST_SUITE_BEGIN("plot-file");

TEST_CASE("plot-read-write")
{
    #define PLOT_GROUP_ID_HEX "c6b84729c23dc6d60c92f22c17083f47845c1179227c5509f07a5d2804a7b835"

    constexpr int k = 18;
    constexpr int strength = 2;
    constexpr int index = 0;

    PlotGroupParams group_params(PlotGroupId(PLOT_GROUP_ID_HEX), k, strength, 0);
    PlotProofParams params = group_params.get_plot_params_for_index(uint16_t(index));

    PlotId plot_id = params.get_plot_id();
    std::string plot_id_hex = plot_id.to_string();

    printfln("Creating a %d plot (index %d): %s -> %s",  k, index, PLOT_GROUP_ID_HEX, plot_id_hex.c_str());

    Timer timer {};
    timer.start("");

    Plotter plotter(params);
    PlotData plot = plotter.run();
    timer.stop();

    int CHUNK_SPAN_SCAN_RANGE_BITS = 16; // 65k entries per chunk
    uint64_t chunk_span = (1ULL << (plotter.getProofParams().get_k() + CHUNK_SPAN_SCAN_RANGE_BITS));
    ChunkedProofFragments partitioned_data
        = ChunkedProofFragments::convertToChunkedProofFragments(plot, chunk_span);
    std::cout << "partitioned data has " << partitioned_data.proof_fragments_chunks.size()
              << " spans." << std::endl;
    // show all spans
    std::cout << "Span sizes (" << partitioned_data.proof_fragments_chunks.size() << "): ";
    for (size_t i = 0; i < partitioned_data.proof_fragments_chunks.size(); i++) {
        std::cout << "," << partitioned_data.proof_fragments_chunks[i].size();
        // std::cout << " span #" << i << " has " <<
        // partitioned_data.t3_proof_fragments_chunks[i].size() << " fragments." << std::endl;
    }
    std::cout << std::endl;

    printfln("Plot completed, writing to file...");

    #define tostr std::to_string
    std::string file_name = (std::string("plot_") + "k") + tostr(k) + ("_" PLOT_GROUP_ID_HEX "_") + tostr(index) + ".bin";

    timer.start("Writing plot file: " + file_name);
    PlotFile::writeData(
        file_name, 
        plot,
        group_params,
        uint16_t(index),
        std::array<uint8_t, 32 + 48 + 32>({}));
    timer.stop();

    timer.start("Reading plot file: " + file_name);
    PlotFile::PlotFileContents read_plot = PlotFile::readAllChunkedData(file_name);
    timer.stop();

    PlotData converted = ChunkedProofFragments::convertToPlotData(partitioned_data);
    ENSURE(plot == converted);
    ENSURE(group_params == read_plot.params);
}
TEST_SUITE_END();
