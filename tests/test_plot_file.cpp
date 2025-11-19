#include "test_util.h"
#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"
#include "plot/PlotFormat.hpp"
#include "common/Utils.hpp"

TEST_SUITE_BEGIN("plot-file");

TEST_CASE("plot-format-partition-mappings")
{
    size_t num_partitions = 8;
    std::vector<size_t> t4_partitions = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::vector<size_t> expected_t3_partition_mappings = {0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15 };

    for (size_t i = 0; i < t4_partitions.size(); ++i)
    {
        size_t t4_partition = t4_partitions[i];
        size_t expected_t3_partition = expected_t3_partition_mappings[i];

        size_t test_t3_partition = PlotFormat::map_t4_to_t3_lateral_partition(t4_partition, num_partitions);
        std::cout << "T4 partition " << t4_partition << " maps to T3 partition " << test_t3_partition << std::endl;
        REQUIRE(test_t3_partition == expected_t3_partition);

        size_t back_mapped_t4_partition = PlotFormat::map_t3_lateral_partition_to_t4(test_t3_partition, num_partitions);
        std::cout << "  back mapped T4 partition: " << back_mapped_t4_partition << std::endl;
        REQUIRE(back_mapped_t4_partition == t4_partition);
    }
}

TEST_CASE("plot-read-write")
{
#define PLOT_ID_HEX "c6b84729c23dc6d60c92f22c17083f47845c1179227c5509f07a5d2804a7b835"
    constexpr int K = 18;
    constexpr int strength = 2;

    printfln("Creating a %d plot: %s", K, PLOT_ID_HEX);

    Timer timer{};
    timer.start("");

    Plotter plotter(Utils::hexToBytes(PLOT_ID_HEX), K, strength);
    PlotData plot = plotter.run();
    timer.stop();

    printfln("Plot completed, writing to file...");
   
#define tostr std::to_string
    std::string file_name = (std::string("plot_") + "k") + tostr(K) + "_" PLOT_ID_HEX + ".bin";

    timer.start("Writing plot file: " + file_name);
    {
        std::array<uint8_t, 32 + 48 + 32> memo{};
        PlotFile pf(plotter.getProofParams(), memo, plot);
        pf.writeToFile(file_name);
    }
    timer.stop();

    timer.start("Reading plot file: " + file_name);
    // load plot file via instance
    PlotFile pf_loaded(file_name);
    pf_loaded.readEntireT3FromFile(file_name);
    PlotFile::PlotFileContents read_plot = pf_loaded.getContents();

    // move all t3 proof fragments into partitioned structure.
    // map by going over ranges, and mapping into t4 partitions
    PartitionedPlotData partitioned_data;
    partitioned_data.t3_proof_fragments.resize(read_plot.params.get_num_partitions() * 2);
    partitioned_data.t4_to_t3_back_pointers.resize(read_plot.params.get_num_partitions() * 2);
    partitioned_data.t5_to_t4_back_pointers.resize(read_plot.params.get_num_partitions() * 2);

    for (size_t t4_partition_id = 0; t4_partition_id < read_plot.data.t4_to_t3_lateral_ranges.size(); ++t4_partition_id)
    {
        Range const &range = read_plot.data.t4_to_t3_lateral_ranges[t4_partition_id];
        std::cout << "Moving T3 proof fragments for T4 partition " << t4_partition_id
                  << " to T3 index " << t4_partition_id
                  << " for range " << range.start << " - " << range.end << std::endl;
        for (uint32_t t3_index = range.start; t3_index <= range.end; ++t3_index)
        {
            // record index-in-partition after push_back
            partitioned_data.t3_proof_fragments[t4_partition_id].push_back(read_plot.data.t3_proof_fragments[t3_index]);
        }
    }


    // use the memo from the loaded PlotFile and fully qualify the type to avoid ambiguity
    PlotFormat plot_format(read_plot.params, pf_loaded.getMemo(), partitioned_data);

    // read all partitions
    for (size_t partition_id = 0; partition_id < read_plot.data.t4_to_t3_back_pointers.size(); ++partition_id)
    {
        // ensure partition data is loaded into the PlotFile instance
        pf_loaded.ensurePartitionT4T5BackPointersLoaded(file_name, partition_id);
        // refresh the local copy if tests expect a separate PlotFileContents
        read_plot = pf_loaded.getContents();

        // test T4 partition l pointers are in expected T3 partition.
        // 0 -> 0
        // 1 -> 2
        // 2 -> 4
        // num_partitions - 1 -> num_partitions * 2
        // num_partitions -> 1
        // num_partitions + 1 -> 3
        // etc.
        size_t expected_t3_l_partition = plot_format.map_t4_to_t3_lateral_partition(partition_id, read_plot.params.get_num_partitions());
        std::cout << "T4 partition " << partition_id << " expected T3 partition " << expected_t3_l_partition << std::endl;
        
        // check that all t4tot3 back pointers are in the t3 partition range
        Range t3_partition_range = read_plot.data.t4_to_t3_lateral_ranges[partition_id];
        std::cout << "T4 to T3 lateral range: " << t3_partition_range.start << " - " << t3_partition_range.end << std::endl;

        uint64_t t3_range_per_partition = (static_cast<uint64_t>(1) << (2 * K)) / (2 * read_plot.params.get_num_partitions());
        uint64_t t3_partition_start_value = t3_range_per_partition * (static_cast<uint64_t>(expected_t3_l_partition));
        uint64_t t3_partition_end_value = t3_partition_start_value + t3_range_per_partition - 1;
        std::cout << "T3 partition " << expected_t3_l_partition << " value range: "
                  << t3_partition_start_value << " - " << t3_partition_end_value << std::endl;

        size_t count = 0;
        uint32_t max_l_index = 0;
        uint32_t max_r_index = 0;
        for (const auto &t4_entry : read_plot.data.t4_to_t3_back_pointers[partition_id])
        {
            ProofFragment t3_l = read_plot.data.t3_proof_fragments[t4_entry.l];
            ProofFragment t3_r = read_plot.data.t3_proof_fragments[t4_entry.r];
            
            if ((count < 5) || (count > read_plot.data.t4_to_t3_back_pointers[partition_id].size() - 5))
            {
                std::cout << "  T4 entry l: " << t4_entry.l << " r: " << t4_entry.r << std::endl;
                std::cout << "    T3 proof fragment at l: " << t3_l << std::endl;
                std::cout << "    T3 proof fragment at r: " << t3_r << std::endl;
            }
            ENSURE(t3_partition_range.isInRange(t4_entry.l));
            ENSURE(t3_l >= t3_partition_start_value);
            ENSURE(t3_l <= t3_partition_end_value);

            // find t3_r partition by scanning ranges
            uint32_t t3_r_partition = 0;
            uint32_t t3_r_partition_start_value = 0;

            size_t mapped_r_partition = 0;

            for (size_t range_index = 0; range_index < read_plot.data.t4_to_t3_lateral_ranges.size(); ++range_index)
            {
                const auto &range = read_plot.data.t4_to_t3_lateral_ranges[range_index];
                if (range.isInRange(t4_entry.r))
                {
                    //t3_r_partition = (range_index < read_plot.data.t4_to_t3_back_pointers.size() / 2) ? (range_index * 2) : ((range_index - read_plot.data.t4_to_t3_back_pointers.size() / 2) * 2 + 1);
                    t3_r_partition = PlotFormat::map_t4_to_t3_lateral_partition(range_index, read_plot.params.get_num_partitions());
                    mapped_r_partition = range_index;
                    t3_r_partition_start_value = range.start;
                    break;
                }
            }

            ENSURE(t3_r >= (t3_range_per_partition * t3_r_partition));
            ENSURE(t3_r <= (t3_range_per_partition * (t3_r_partition + 1) - 1));

            PartitionedBackPointer partitioned_back_pointer;
            PartitionedBackPointer::Input input;
            input.l_absolute_t3_index = t4_entry.l;
            input.r_absolute_t3_index = t4_entry.r;
            input.t3_l_partition_range_start = t3_partition_range.start;
            input.t3_r_partition = mapped_r_partition;//t3_r_partition;
            input.t3_r_partition_range_start = t3_r_partition_start_value;
            input.num_partition_bits = read_plot.params.get_num_partition_bits();
            partitioned_back_pointer.setPointer(input);

            // now add to partitioned data set
            partitioned_data.t4_to_t3_back_pointers[partition_id].push_back(partitioned_back_pointer);

            PartitionedBackPointer::Result t4_to_t3_partitioned_back_pointer = partitioned_back_pointer.getPointer(
                partition_id,
                read_plot.params.get_num_partition_bits());
            

            ProofFragment test_t3_proof_fragment_l = partitioned_data.t3_proof_fragments[partition_id][t4_to_t3_partitioned_back_pointer.l_in_partition];
            ProofFragment test_t3_proof_fragment_r = partitioned_data.t3_proof_fragments[t4_to_t3_partitioned_back_pointer.r_t3_partition][t4_to_t3_partitioned_back_pointer.r_in_partition];
            
            if ((count < 5) || (count > read_plot.data.t4_to_t3_back_pointers[partition_id].size() - 5))
            {
                std::cout << "DEBUG: want to find r in partition " << mapped_r_partition << " at index " << t4_to_t3_partitioned_back_pointer.r_in_partition << std::endl;
                //ProofFragment test_t3_proof_fragment_r = t3_lateral_partitioned[mapped_r_partition][t4_to_t3_partitioned_back_pointer.r_in_partition];
                std::cout << "    T3 proof fragment at r: " << t3_r << " in partition " << t3_r_partition << std::endl;
                std::cout << "    t4_to_t3_partitioned_back_pointer.l_in_partition: " << t4_to_t3_partitioned_back_pointer.l_in_partition << std::endl
                          << "    t4_to_t3_partitioned_back_pointer.r_in_partition: " << t4_to_t3_partitioned_back_pointer.r_in_partition << std::endl
                          << "    t4_to_t3_partitioned_back_pointer.r_t3_partition: " << t4_to_t3_partitioned_back_pointer.r_t3_partition << std::endl
                          << "    test_t3_proof_fragment_l: " << test_t3_proof_fragment_l << std::endl
                          << "    test_t3_proof_fragment_r: " << test_t3_proof_fragment_r << std::endl
                          << std::endl;
                // TODO: instead of r_in_partition, get rth_partition value of t3 entries that map to this partition.
                // TODO: instead of l_in_partition, get lth_partition value? Does it make sense?
            }

            REQUIRE(t4_to_t3_partitioned_back_pointer.r_t3_partition == mapped_r_partition);
            REQUIRE(test_t3_proof_fragment_l == t3_l);
            REQUIRE(test_t3_proof_fragment_r == t3_r);
            count++;

            if (max_l_index < t4_to_t3_partitioned_back_pointer.l_in_partition) {
                max_l_index = t4_to_t3_partitioned_back_pointer.l_in_partition;
            }
            if (max_r_index < t4_to_t3_partitioned_back_pointer.r_in_partition) {
                max_r_index = t4_to_t3_partitioned_back_pointer.r_in_partition;
            }
        }
        std::cout << "  Checked " << count << " T4 to T3 back pointers. Max l_in_partition: " << max_l_index << " Max r_in_partition: " << max_r_index << std::endl;
    
        // now let's look at t5 data in this partition
        uint32_t max_l = 0;
        uint32_t min_r = UINT32_MAX;
        for (const auto &t5_entry : read_plot.data.t5_to_t4_back_pointers[partition_id])
        {
            if (t5_entry.l % 100 == 0) {
                std::cout << " T5 entry l/r: " << t5_entry.l << " / " << t5_entry.r << std::endl;
            }
            if (max_l < t5_entry.l) {
                max_l = t5_entry.l;
            }
            if (min_r > t5_entry.r) {
                min_r = t5_entry.r;
            }
        }
        std::cout << "  T5 to T4 back pointers: max l: " << max_l << " min r: " << min_r << std::endl;
    
    }
    timer.stop();

    // now write PlotFormat to disk
    timer.debugOut = true;
    std::string plot_format_file_name = file_name + ".plot_format";
    timer.start("Writing plot format file: " + plot_format_file_name);
    {    
        plot_format.writeData(plot_format_file_name, partitioned_data, read_plot.params, pf_loaded.getMemo());
    }
    timer.stop();

    // read PlotFormat back from disk, load up all partitions, and verify data matches
    timer.start("Reading plot format file: " + plot_format_file_name);
    PlotFormat read_plot_format(plot_format_file_name); 
    //PlotFormat::PlotFormatContents read_plot_format = plot_format.readHeaderData(plot_format_file_name);
    for (size_t partition_id = 0; partition_id < read_plot_format.getParams().get_num_partitions() * 2; ++partition_id)
    {  
        std::cout << "Reading partition " << partition_id << std::endl;
        read_plot_format.ensurePartitionT4T5BackPointersLoaded(partition_id);
    }
    timer.stop();

    PlotFormat::PlotFormatContents read_plot_format_contents = read_plot_format.getContents();
    // check that read_plot_format matches partitioned_data
    ENSURE(read_plot_format_contents.data.t3_proof_fragments == partitioned_data.t3_proof_fragments);
    ENSURE(read_plot_format_contents.data.t4_to_t3_back_pointers == partitioned_data.t4_to_t3_back_pointers);
    ENSURE(read_plot_format_contents.data.t5_to_t4_back_pointers == partitioned_data.t5_to_t4_back_pointers);
    ENSURE(plot == read_plot.data);
    ENSURE(plotter.getProofParams() == read_plot.params);
}

TEST_SUITE_END();
