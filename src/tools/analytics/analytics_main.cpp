#include "plot/PlotFile.hpp"
#include "prove/Prover.hpp"
#include "pos/ProofValidator.hpp"
#include "common/Utils.hpp"
#include "DiskBench.hpp"

void printUsage()
{
    std::cout << "Usage:\n"
              << "  analytics diskbench [plotIdFilter=256] [pfScanFilter=64][diskTB=20] [diskSeekMs=10] [diskReadMBs=70]\n";
}

int main(int argc, char *argv[])
try
{
    std::cout << "ChiaPOS2 Analytics" << std::endl;

    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "diskbench")
    {
        size_t plotIdFilter = 8;
        size_t diskTB = 20;
        double diskSeekMs = 10.0;
        double diskReadMBs = 70.0;
        if (argc < 2 || argc > 7)
        {
            std::cerr << "Usage: " << argv[0] << " diskbench [plotIdFilterBits=8] [diskTB=20] [diskSeekMs=10] [diskReadMBs=70]\n";
            return 1;
        }
        if (argc >= 3) {
            plotIdFilter = std::stoul(argv[2]);
        }
        if (argc >= 4) {
            diskTB = std::stoul(argv[4]);
        }
        if (argc >= 5) {
            diskSeekMs = std::stod(argv[5]);
        }
        if (argc >= 6) {
            diskReadMBs = std::stod(argv[6]);
        }
        std::cout << "Disk benchmark simulation: Plot ID filter bits: " << plotIdFilter
                  << ", " << diskTB << " TB, Seek time: " << diskSeekMs << " ms, Read speed: " << diskReadMBs << " MB/s\n";
        
        ProofParams proof_params(Utils::hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").data(), 28, 2);
        DiskBench diskbench(proof_params);
        diskbench.simulateChallengeDiskReads(plotIdFilter, diskTB, diskSeekMs, diskReadMBs);

        return 0;
    }
    else
    {
        std::cerr << "Unknown mode: " << mode << std::endl;
        printUsage();
        return 1;
    }
}
catch (const std::exception &ex)
{
    std::cerr << "Failed with exception: " << ex.what() << std::endl;
    return 1;
}
