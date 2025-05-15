#pragma once

#include "pos/ProofCore.hpp"
#include "plot/PlotFile.hpp"
#include "common/Utils.hpp"
#include "prove/ProofFragmentScanFilter.hpp"
#include "pos/XsEncryptor.hpp"
#include <bitset>


// these will go into proof core once done testing
struct QualityLink
{
    uint64_t fragments[3]; // our 3 proof fragments that form a chain
};

struct QualityChain
{
    std::array<QualityLink, 16> chain_links; // 16 links in a chain
};



class Prover
{
public:
    Prover(const std::array<uint8_t, 32> &challenge, const std::string &plot_file_name, const int scan_filter)
        : challenge_(challenge), plot_file_name_(plot_file_name), scan_filter_(scan_filter)
    {
    }
    ~Prover() = default;

    std::vector<QualityChain> prove()
    {
        // 1) Read plot file
        if (!plot_.has_value())
        {
            std::cout << "Reading plot file: " << plot_file_name_ << std::endl;
            plot_ = PlotFile::readData(plot_file_name_);
            std::cout << "Plot file read successfully: " << plot_file_name_ << std::endl;
            plot_.value().params.debugPrint();
        }
        else
        {
            std::cout << "Plot file already read." << std::endl;
        }
        
        PlotFile::PlotFileContents plot = plot_.value();

        ProofFragmentScanFilter scan_filter(plot.params, challenge_, scan_filter_);
        std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments = scan_filter.scan(plot.data.t3_encrypted_xs);

        XsEncryptor xs_encryptor(plot.params);

        if (filtered_fragments.size() > 0)
        {
            std::cout << "Found fragments passing filter: " << filtered_fragments.size() << std::endl;
            for (size_t i = 0; i < filtered_fragments.size(); i++)
            {
                uint64_t fragment = filtered_fragments[i].fragment;
                std::cout << "  Fragment: " << std::hex << fragment << std::dec << std::endl;
                // extract R pointer
                uint32_t l_partition = xs_encryptor.get_lateral_to_t4_partition(fragment);
                uint32_t r_partition = xs_encryptor.get_r_t4_partition(fragment);
                std::cout << "          Total partitions: " << plot.params.get_num_partitions() << std::endl;
                std::cout << "          Partition A(L): " << l_partition << std::endl;
                std::cout << "          Partition R(R): " << r_partition << std::endl;

                std::vector<QualityLink> links = getQualityLinks(l_partition, r_partition);
                std::cout << " # Link: " << links.size() << std::endl;
                
            }
        }
        else
        {
            std::cout << "No filtered fragments found." << std::endl;
        }
        
        
        std::vector<QualityChain> all_chains;
        if (filtered_fragments.size() > 0)
        {
            // 2) Create chains
            for (size_t i = 0; i < filtered_fragments.size(); i ++)
            {
                QualityChain chain;
                
                for (int j = 0; j < 16; ++j)
                {
                    QualityLink link;
                    chain.chain_links[j] = link;
                }

                all_chains.push_back(chain);
            }
            
        }
        return all_chains;
    }

    std::vector<QualityLink> getQualityLinks(uint32_t partition_A, uint32_t partition_B) {
        std::vector<QualityLink> links;

        // 1. get t4 partition A, and scan R side links that link to partition_B
        std::vector<T4BackPointers> t4_b_to_t3_a = plot_.value().data.t4_to_t3_back_pointers[partition_A];
        Range t4_b_to_t3_a_lateral_ranges = plot_.value().data.t4_to_t3_lateral_ranges[partition_A];

        std::cout << "Partition A: " << partition_A << std::endl;
        std::cout << "t4_b_to_t3_a_lateral_ranges: " << t4_b_to_t3_a_lateral_ranges.start << " - " << t4_b_to_t3_a_lateral_ranges.end << std::endl;
        
        std::vector<uint64_t> t4_b_to_t3_a_indexes = findT4IndexesWithRInRange(t4_b_to_t3_a_lateral_ranges, t4_b_to_t3_a);
        std::cout << "t4_b_to_t3_a_indexes num results: " << t4_b_to_t3_a_indexes.size() << std::endl;

        return links;
    }

    std::vector<uint64_t> findT4IndexesWithRInRange(Range range, std::vector<T4BackPointers> &t4_entries) {
        std::vector<uint64_t> indexes;
        for (size_t i = range.start; i < range.end; ++i)
        {
            T4BackPointers entry = t4_entries[i];
            uint32_t r = entry.encx_index_r;
            if (range.isInRange(r))
            {
                indexes.push_back(i);
            }
        }
        return indexes;
    }

    void setChallenge(const std::array<uint8_t, 32> &challenge)
    {
        challenge_ = challenge;
    }

private:
    std::optional<PlotFile::PlotFileContents> plot_;  
    int scan_filter_;
    std::array<uint8_t, 32> challenge_;
    std::string plot_file_name_;
};