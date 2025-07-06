#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <queue>

#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"
#include "MemoryGrid.hpp"
#include "PlotData.hpp"

#include "TableConstructorGeneric.hpp"
#include "TablePruner.hpp"
// #include "TableCompressor.hpp"

class Plotter
{
private:
    MemoryGrid *memory_grid_;
    DiskGrid *disk_grid_;
    StripeIO *stripe_io_;
    std::vector<std::vector<size_t>> sectionGridCounts_;

public:
    // Construct with a hexadecimal plot ID, k parameter, and sub-k parameter
    Plotter(const std::array<uint8_t, 32> plot_id, int k, int sub_k)
        : plot_id_(plot_id), k_(k), sub_k_(sub_k),
          proof_params_(plot_id_.data(), k_, sub_k_), fragment_codec_(proof_params_), validator_(proof_params_)
    {

        size_t N_stripes = proof_params_.get_num_sections();

        size_t ramBlockBytesTotalNeeded = 4000ULL * 1024ULL * 1024ULL; // 4000 MB total
        size_t diskBlockBytesTotalNeeded = 0;
        memory_grid_ = new MemoryGrid(N_stripes, ramBlockBytesTotalNeeded);
        disk_grid_ = new DiskGrid(N_stripes, diskBlockBytesTotalNeeded, "stripes.bin");
        stripe_io_ = new StripeIO(*memory_grid_, *disk_grid_);

        sectionGridCounts_.resize(N_stripes, std::vector<size_t>(N_stripes, 0ULL));
    }

    void transposeT1PairsToGrid(Table1Constructor::StripeResult &result, size_t stripe)
    {
        size_t N_stripes = proof_params_.get_num_sections();
        std::vector<size_t> stripeBytes(N_stripes);
        for (size_t i = 0; i < N_stripes; ++i)
        {
            stripeBytes[i] = result.section_counts[i] * sizeof(Xs_Candidate);
            sectionGridCounts_[stripe][i] = result.section_counts[i];
        }
        // write into stripe
        stripe_io_->pushStripe(StripeIO::Direction::VERTICAL, stripe,
                               result.candidates.data(),
                               stripeBytes.data(),
                               /*offsetInBlock=*/0);
    }

    void transposeXsCandidatesToGrid(XsConstructor::StripeResult &result, size_t stripe)
    {
        size_t N_stripes = proof_params_.get_num_sections();
        std::vector<size_t> stripeBytes(N_stripes);
        for (size_t i = 0; i < N_stripes; ++i)
        {
            stripeBytes[i] = result.section_counts[i] * sizeof(Xs_Candidate);
            sectionGridCounts_[i][stripe] = result.section_counts[i];
        }
        // write into stripe
        stripe_io_->pushStripe(StripeIO::Direction::HORIZONTAL, stripe,
                               result.candidates.data(),
                               stripeBytes.data(),
                               /*offsetInBlock=*/0);
    }

    std::span<T1Pairing> transposeT1PairsFromGrid(size_t stripe, WorkingBuffer &working_buffer)
    {
        size_t N_stripes = proof_params_.get_num_sections();
        std::pmr::vector<size_t> numEntriesPerBlock(N_stripes, working_buffer.resource());
        std::pmr::vector<size_t> stripeBytes(N_stripes, working_buffer.resource());

        // fill the numEntriesPerBlock with counts from sectionGridCounts_
        // this is the number of entries per block in the stripe
        size_t totalEntries = 0;
        for (size_t i = 0; i < N_stripes; ++i)
        {
            numEntriesPerBlock[i] = sectionGridCounts_[i][stripe];
            stripeBytes[i] = numEntriesPerBlock[i] * sizeof(T1Pairing);
            totalEntries += numEntriesPerBlock[i];
        }

        // allocate span in working buffer for entries expected in this stripe
        std::pmr::vector<T1Pairing> sorted_pairs(totalEntries, working_buffer.resource());
        std::pmr::vector<T1Pairing> pairs(totalEntries, working_buffer.resource());

        // pull the stripe data into pairs
        stripe_io_->pullStripe(StripeIO::Direction::HORIZONTAL, stripe, pairs.data(), stripeBytes.data(), /*offsetInBlock=*/0);

        // will do a k-way merge of the pairs from each section

        // Create indices and pointers for each section
        std::vector<size_t> indices(N_stripes, 0);
        std::vector<size_t> offsets(N_stripes + 1, 0);

        // Calculate section offsets
        for (size_t i = 0; i < N_stripes; ++i)
        {
            offsets[i + 1] = offsets[i] + numEntriesPerBlock[i];
        }

        // Use a min-heap for efficient merging
        struct HeapEntry
        {
            T1Pairing pairing;
            size_t section_idx;

            bool operator>(const HeapEntry &other) const
            {
                return pairing.match_info > other.pairing.match_info;
            }
        };

        // Create a min-heap using std::priority_queue
        std::priority_queue<HeapEntry, std::vector<HeapEntry>, std::greater<HeapEntry>> min_heap;

        // Initialize the heap with the first element from each section
        for (size_t i = 0; i < N_stripes; ++i)
        {
            if (numEntriesPerBlock[i] > 0)
            {
                min_heap.push({pairs[offsets[i]], i});
                indices[i]++;
            }
        }
        // Merge the sections
        size_t out_idx = 0;
        while (!min_heap.empty())
        {
            HeapEntry top = min_heap.top();
            min_heap.pop();

            sorted_pairs[out_idx++] = top.pairing;

            size_t section = top.section_idx;
            if (indices[section] < numEntriesPerBlock[section])
            {
                min_heap.push({pairs[offsets[section] + indices[section]], section});
                indices[section]++;
            }
        }
        assert(out_idx == totalEntries);
        return std::span<T1Pairing>(sorted_pairs.data(), sorted_pairs.size());
    }

    

    std::span<Xs_Candidate> transposeXsCandidatesFromGrid(size_t stripe, WorkingBuffer &working_buffer)
    {
        size_t N_stripes = proof_params_.get_num_sections();
        std::pmr::vector<size_t> numEntriesPerBlock(N_stripes, working_buffer.resource());
        std::pmr::vector<size_t> stripeBytes(N_stripes, working_buffer.resource());

        // fill the numEntriesPerBlock with counts from sectionGridCounts_
        // this is the number of entries per block in the stripe
        size_t totalEntries = 0;
        for (size_t i = 0; i < N_stripes; ++i)
        {
            numEntriesPerBlock[i] = sectionGridCounts_[stripe][i];
            stripeBytes[i] = numEntriesPerBlock[i] * sizeof(Xs_Candidate);
            totalEntries += numEntriesPerBlock[i];
        }

        // allocate span in working buffer for entries expected in this stripe
        std::pmr::vector<Xs_Candidate> sorted_candidates(totalEntries, working_buffer.resource());
        std::pmr::vector<Xs_Candidate> candidates(totalEntries, working_buffer.resource());

        // pull the stripe data into candidates
        stripe_io_->pullStripe(StripeIO::Direction::VERTICAL, stripe, candidates.data(), stripeBytes.data(), /*offsetInBlock=*/0);

        // will do a k-way merge of the candidates from each section

        // Create indices and pointers for each section
        std::vector<size_t> indices(N_stripes, 0);
        std::vector<size_t> offsets(N_stripes + 1, 0);

        // Calculate section offsets
        for (size_t i = 0; i < N_stripes; ++i)
        {
            offsets[i + 1] = offsets[i] + numEntriesPerBlock[i];
        }

        // Use a min-heap for efficient merging
        struct HeapEntry
        {
            Xs_Candidate candidate;
            size_t section_idx;

            bool operator>(const HeapEntry &other) const
            {
                return candidate.match_info > other.candidate.match_info;
            }
        };

        // Create a min-heap using std::priority_queue
        std::priority_queue<HeapEntry, std::vector<HeapEntry>, std::greater<HeapEntry>> min_heap;

        // Initialize the heap with the first element from each section
        for (size_t i = 0; i < N_stripes; ++i)
        {
            if (numEntriesPerBlock[i] > 0)
            {
                min_heap.push({candidates[offsets[i]], i});
                indices[i]++;
            }
        }

        // Merge the sections
        size_t out_idx = 0;
        while (!min_heap.empty())
        {
            HeapEntry top = min_heap.top();
            min_heap.pop();

            sorted_candidates[out_idx++] = top.candidate;

            size_t section = top.section_idx;
            if (indices[section] < numEntriesPerBlock[section])
            {
                min_heap.push({candidates[offsets[section] + indices[section]], section});
                indices[section]++;
            }
        }

        assert(out_idx == totalEntries);

        return std::span<Xs_Candidate>(sorted_candidates.data(), sorted_candidates.size());
    }

    // Execute the plotting pipeline
    PlotData run()
    {
        std::cout << "Starting plotter..." << std::endl;

        // initialize working buffer
        WorkingBuffer working_buffer(4 * 1024 * 1024 * 1024UL); // 4GB buffer

        // 1) Construct Xs candidates
        XsConstructor xs_gen_ctor(proof_params_, working_buffer);

        // prepare a 1-D “stripe” grid of size N×N blocks; we’ll only ever use col==0
        size_t N_stripes = proof_params_.get_num_sections();

        // record how many bytes each stripe actually took
        std::vector<size_t> stripeBytes(N_stripes);
        std::vector<std::vector<size_t>> sectionGridCounts(N_stripes, std::vector<size_t>(N_stripes, 0ULL));

        // 1) for each stripe: build, push to stripeIO, then free the arena
        for (size_t stripe = 0; stripe < N_stripes; ++stripe)
        {
            working_buffer.reset();
            auto result = xs_gen_ctor.constructStripe(stripe);
            transposeXsCandidatesToGrid(result, stripe);
            std::cout << "Bytes used in working buffer for stripe " << stripe
                      << ": " << working_buffer.bytesUsed() << std::endl;
        }

        auto xs_candidates = xs_gen_ctor.construct();
        timer_.stop();
        std::cout << "Constructed " << xs_candidates.size() << " Xs candidates." << std::endl;

        // 2) Table1 generic
        Table1Constructor t1_ctor(proof_params_, working_buffer);
        timer_.start("Constructing Table 1");
        auto t1_pairs = t1_ctor.construct(xs_candidates);
        timer_.stop();
        std::cout << "Constructed " << t1_pairs.size() << " Table 1 pairs." << std::endl;

        // now try stripe version of plotter: let's pull section data for each stripe
        uint32_t section_l = 0;
        uint32_t section_r = proof_core_.matching_section(section_l);
        std::span<Xs_Candidate> original_l_candidates_in_section = transposeXsCandidatesFromGrid(section_l, working_buffer);
        auto wb_section_0_checkpoint = working_buffer.checkpoint();
        while (true)
        {
            // we retain original section_l candidates from stripe 0 in working buffer,
            // since this get's overwritten.
            working_buffer.release(wb_section_0_checkpoint);

            section_r = proof_core_.matching_section(section_l);

            // pull the stripe data
            // TODO: can be more efficient by caching previous pulled sections
            std::span<Xs_Candidate> l_candidates_in_section;
            std::span<Xs_Candidate> r_candidates_in_section;
            if (section_l == 0)
            {
                l_candidates_in_section = original_l_candidates_in_section;
            }
            else
            {
                l_candidates_in_section = transposeXsCandidatesFromGrid(section_l, working_buffer);
            }
            if (section_r == 0)
            {
                r_candidates_in_section = original_l_candidates_in_section;
            }
            else
            {
                r_candidates_in_section = transposeXsCandidatesFromGrid(section_r, working_buffer);
            }
            std::cout << "section_l: " << section_l
                      << ", section_r: " << section_r
                      << ", l_candidates_in_section.size(): " << l_candidates_in_section.size()
                      << ", r_candidates_in_section.size(): " << r_candidates_in_section.size() << std::endl;

            auto t1_results = t1_ctor.constructFromSections(l_candidates_in_section, r_candidates_in_section);
            std::cout << "Constructed " << t1_results.candidates.size() << " Table 1 pairs from section " << section_l << "." << std::endl;
            // show section counts
            for (size_t i = 0; i < N_stripes; ++i)
            {
                std::cout << "Section " << i << " count: " << t1_results.section_counts[i] << std::endl;
            }

#ifdef RETAIN_X_VALUES
            if (validate_)
            {
                for (const auto &pair : t1_results.candidates)
                {
                    uint32_t xs[2] = {
                        static_cast<uint32_t>(pair.meta >> proof_params_.get_k()),
                        static_cast<uint32_t>(pair.meta & ((1 << proof_params_.get_k()) - 1))};
                    auto result = validator_.validate_table_1_pair(xs);
                    if (!result.has_value())
                    {
                        std::cerr << "Validation failed for Table 1 pair: ["
                                  << xs[0] << ", " << xs[1] << "]\n";
                        exit(23);
                    }
                }
                std::cout << "Table 1 pairs validated successfully." << std::endl;
            }
#endif

            // transpose the pairs to grid
            std::cout << "Transposing Table 1 pairs to grid stripe " << section_l << std::endl;
            transposeT1PairsToGrid(t1_results, section_l);

            // move to next section
            section_l = section_r;

            // break loop if finished doing section r as 0
            if (section_r == 0)
                break;
        }

#ifdef RETAIN_X_VALUES
        if (validate_)
        {
            for (const auto &pair : t1_pairs)
            {
                uint32_t xs[2] = {
                    static_cast<uint32_t>(pair.meta >> proof_params_.get_k()),
                    static_cast<uint32_t>(pair.meta & ((1 << proof_params_.get_k()) - 1))};
                auto result = validator_.validate_table_1_pair(xs);
                if (!result.has_value())
                {
                    std::cerr << "Validation failed for Table 1 pair: ["
                              << xs[0] << ", " << xs[1] << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 1 pairs validated successfully." << std::endl;
        }
#endif
        /*
                // 3) Table2 generic
                Table2Constructor t2_ctor(proof_params_, working_buffer);
                timer_.start("Constructing Table 2");
                auto t2_pairs = t2_ctor.construct(t1_pairs);
                timer_.stop();
                std::cout << "Constructed " << t2_pairs.size() << " Table 2 pairs." << std::endl;

                #ifdef RETAIN_X_VALUES
                if (validate_) {
                    for (const auto& pair : t2_pairs) {
                        auto result = validator_.validate_table_2_pairs(pair.xs);
                        if (!result.has_value()) {
                            std::cerr << "Validation failed for Table 2 pair: ["
                                      << pair.xs[0] << ", " << pair.xs[1] << ", " << pair.xs[2] << ", " << pair.xs[3] << "]\n";
                            exit(23);
                        }
                    }
                    std::cout << "Table 2 pairs validated successfully." << std::endl;
                }
                #endif

                // 4) Table3 generic
                Table3Constructor t3_ctor(proof_params_, working_buffer);
                timer_.start("Constructing Table 3");
                T3_Partitions_Results t3_results = t3_ctor.construct(t2_pairs);
                timer_.stop();
                std::cout << "Constructed " << t3_results.proof_fragments.size() << " Table 3 entries." << std::endl;

                #ifdef RETAIN_X_VALUES
                if (validate_) {
                    for (const auto& xs_array : t3_results.xs_correlating_to_proof_fragments) {
                        auto result = validator_.validate_table_3_pairs(xs_array.data());
                        if (!result.has_value()) {
                            std::cerr << "Validation failed for Table 3 pair: ["
                                      << xs_array[0] << ", " << xs_array[1] << ", " << xs_array[2] << ", " << xs_array[3]
                                      << ", " << xs_array[4] << ", " << xs_array[5] << ", " << xs_array[6] << ", " << xs_array[7]
                                      << "]\n";
                            exit(23);
                        }
                    }
                    std::cout << "Table 3 pairs validated successfully." << std::endl;
                }
                #endif

                // 5) Prepare pruner

                #ifdef RETAIN_X_VALUES_TO_T3
                TablePruner pruner(proof_params_, t3_results.proof_fragments, t3_results.xs_correlating_to_proof_fragments);
                #else
                TablePruner pruner(proof_params_, t3_results.proof_fragments);
                #endif

                // 6) Partitioned Table4 + Table5
                std::vector<std::vector<T4BackPointers>> all_t4;
                std::vector<std::vector<T5Pairing>> all_t5;
                ProofParams sub_params(plot_id_.data(), sub_k_);

                for (size_t pid = 0; pid < t3_results.partitioned_pairs.size(); ++pid) {
                    const auto& partition = t3_results.partitioned_pairs[pid];

                    timer_.start("Building t3/4 partition " + std::to_string(pid));

                    Table4PartitionConstructor t4_ctor(sub_params, proof_params_.get_k(), working_buffer);
                    T4_Partition_Result t4_res = t4_ctor.construct(partition);

                    #ifdef RETAIN_X_VALUES
                    if (validate_) {
                        for (const auto& pair : t4_res.pairs) {
                            std::vector<T4Pairing> res = validator_.validate_table_4_pairs(pair.xs);
                            if (res.size() == 0) {
                                std::cerr << "Validation failed for Table 4 pair" << std::endl;
                                exit(23);
                            }
                        }
                        std::cout << "Table 4 pairs validated successfully." << std::endl;
                    }
                    #endif

                    Table5GenericConstructor t5_ctor(sub_params, working_buffer);
                    std::vector<T5Pairing> t5_pairs = t5_ctor.construct(t4_res.pairs);

                    #ifdef RETAIN_X_VALUES
                    if (validate_) {
                        for (const auto& pair : t5_pairs) {
                            if (!validator_.validate_table_5_pairs(pair.xs)) {
                                std::cerr << "Validation failed for Table 5 pair" << std::endl;
                                exit(23);
                            }
                        }
                        std::cout << "Table 5 pairs validated successfully." << std::endl;
                    }
                    #endif

                    TablePruner::PrunedStats stats = pruner.prune_t4_and_update_t5(t4_res.t4_to_t3_back_pointers, t5_pairs);

                    all_t4.push_back(std::move(t4_res.t4_to_t3_back_pointers));
                    all_t5.push_back(std::move(t5_pairs));

                    timer_.stop();
                    std::cout << "Processed partition " << pid << ": " << std::endl
                              << "  T4 size: " << all_t4.back().size() << " (before pruning: " << stats.original_count << ")" << std::endl
                              << "  T5 size: " << all_t5.back().size()
                              << std::endl;
                }

                // 7) Finalize pruning
                timer_.start("Finalizing Table 3");
                T4ToT3LateralPartitionRanges t4_to_t3_lateral_partition_ranges = pruner.finalize_t3_and_prepare_mappings_for_t4();
                timer_.stop();

                timer_.start("Finalizing Table 4");
                for (auto& t4bp : all_t4) pruner.finalize_t4_partition(t4bp);
                timer_.stop();

                return {
                    .t3_proof_fragments = t3_results.proof_fragments,
                    .t4_to_t3_lateral_ranges = t4_to_t3_lateral_partition_ranges,
                    .t4_to_t3_back_pointers = all_t4,
                    .t5_to_t4_back_pointers = all_t5,
                    #ifdef RETAIN_X_VALUES_TO_T3
                    .xs_correlating_to_proof_fragments = t3_results.xs_correlating_to_proof_fragments,
                    #endif
                };*/
    }

    ProofParams
    getProofParams() const
    {
        return proof_params_;
    }

    ProofFragmentCodec getProofFragment() const
    {
        return fragment_codec_;
    }

    void setValidate(bool validate)
    {
        validate_ = validate;
    }

    // Helper: convert hex string to 32-byte array
    std::array<uint8_t, 32> hexToBytes(const std::string &hex)
    {
        std::array<uint8_t, 32> bytes{};
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            auto byte_str = hex.substr(2 * i, 2);
            bytes[i] = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
        }
        return bytes;
    }

private:
    // Plot identifiers and parameters
    std::array<uint8_t, 32> plot_id_;
    int k_;
    int sub_k_;

    // Core PoSpace objects
    ProofParams proof_params_;
    ProofCore proof_core_{proof_params_};
    ProofFragmentCodec fragment_codec_;

    // Timing utility
    Timer timer_;

    // Debugging: validate as we go
    bool validate_ = true;
    ProofValidator validator_;
};
