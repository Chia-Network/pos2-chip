// ─────────────────────────────────── memory_grid.hpp ───────────────────────────
#pragma once
#include <cstddef>
#include <cstdint>
#include <cassert>
#include <new>
#include <memory>
#include <vector>
#include <memory_resource>
#include <string>
#include <fstream>
#include <cstring>

//==============================================================================
// 1.  MemoryGrid : one contiguous arena holding N×N equally-sized blocks
//==============================================================================
class MemoryGrid
{
public:
    MemoryGrid(size_t N,
               size_t blockBytes,
               size_t align = alignof(std::max_align_t))
        : N_(N),
          blockSize_(roundUp(blockBytes, align)),
          align_(align),
          totalBytes_(N_ * N_ * blockSize_),
          stripeBytes_(N_ * blockSize_)
    {
        pool_ = static_cast<std::byte*>(
            ::operator new (totalBytes_, std::align_val_t(align_)));
        std::cout << "MemoryGrid created with N=" << N_ 
                  << ", blockSize=" << blockSize_ 
                  << ", totalBytes=" << totalBytes_ 
                  << ", align=" << align_ << std::endl;
    }

    ~MemoryGrid() { ::operator delete(pool_, std::align_val_t(align_)); }

    MemoryGrid(const MemoryGrid&)            = delete;
    MemoryGrid& operator=(const MemoryGrid&) = delete;
    MemoryGrid(MemoryGrid&&)                 = default;
    MemoryGrid& operator=(MemoryGrid&&)      = default;

    [[nodiscard]] std::byte* blockPtr(size_t row, size_t col) noexcept
    {
        assert(row < N_ && col < N_);
        return pool_ + blockSize_ * (row * N_ + col);
    }
    [[nodiscard]] const std::byte* blockPtr(size_t r, size_t c) const noexcept
    { return const_cast<MemoryGrid*>(this)->blockPtr(r, c); }

    void writeBlock(size_t row,
                    size_t col,
                    const void* src,
                    size_t srcBytes,
                    size_t atPosBytes = 0)
    {
        assert(row < N_ && col < N_);
        assert(atPosBytes + srcBytes <= blockSize_);
        auto dst = blockPtr(row, col) + atPosBytes;

        std::memcpy(dst, src, srcBytes);
    }

    void readBlock(size_t row,
                   size_t col,
                   void* dst,
                   size_t bytes,
                   size_t fromPosBytes = 0) const
    {
        assert(row < N_ && col < N_);
        assert(bytes + fromPosBytes <= blockSize_);
        auto src = blockPtr(row, col) + fromPosBytes;
        std::memcpy(dst, src, bytes);
    }

    [[nodiscard]] std::byte* pool() noexcept { return pool_; }
    [[nodiscard]] const std::byte* pool() const noexcept { return pool_; }

    [[nodiscard]] size_t blockSize()  const noexcept { return blockSize_;  }
    [[nodiscard]] size_t stripeSize() const noexcept { return stripeBytes_; }
    [[nodiscard]] size_t totalBytes() const noexcept { return totalBytes_; }
    [[nodiscard]] size_t N()          const noexcept { return N_;          }

private:
    static size_t roundUp(size_t n, size_t a) noexcept
    { return (n + a - 1) & ~(a - 1); }

    size_t N_;
    size_t blockSize_;
    size_t align_;
    size_t totalBytes_;
    size_t stripeBytes_;
    std::byte*  pool_{nullptr};
};


// ─────────────────────────────────── disk_grid.hpp ───────────────────────────
class DiskGrid
{
public:
    DiskGrid(size_t N,
             size_t blockBytes,
             const std::string& filename)
        : N_(N),
          blockSize_(roundUp(blockBytes, alignof(std::max_align_t))),
          totalBytes_(N_ * N_ * blockSize_),
          filename_(filename)
    {
        if (blockSize_ == 0) {
            return; // no file to create.
        }
        file_.open(filename_, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
        file_.seekp(totalBytes_ - 1);
        file_.write("", 1);
        file_.flush();
    }

    ~DiskGrid() { file_.close(); }

    DiskGrid(const DiskGrid&)            = delete;
    DiskGrid& operator=(const DiskGrid&) = delete;
    DiskGrid(DiskGrid&&)                 = default;
    DiskGrid& operator=(DiskGrid&&)      = default;

    void writeBlock(size_t row,
                    size_t col,
                    const void* src,
                    size_t srcBytes,
                    size_t atPosBytes = 0)
    {
        assert(row < N_ && col < N_);
        assert(atPosBytes + srcBytes <= blockSize_);
        assert(blockSize_ > 0);
        if (srcBytes == 0) {
            return; // nothing to write
        }
        if (atPosBytes + srcBytes > blockSize_) {
            throw std::out_of_range("writeBlock: atPosBytes + srcBytes exceeds block size");
        }
        file_.seekp(blockOffset(row, col)+ atPosBytes);
        file_.write(reinterpret_cast<const char*>(src), srcBytes);
        file_.flush();
    }

    void readBlock(size_t row,
                   size_t col,
                   void* dst,
                   size_t bytes,
                   size_t fromPosBytes = 0) const
    {
        assert(row < N_ && col < N_);
        assert(bytes + fromPosBytes <= blockSize_);
        if (bytes == 0) {
            return; // nothing to read
        }
        if (fromPosBytes + bytes > blockSize_) {
            throw std::out_of_range("readBlock: fromPosBytes + bytes exceeds block size");
        }
        file_.seekg(blockOffset(row, col) + fromPosBytes);
        file_.read(reinterpret_cast<char*>(dst), bytes);
    }

    [[nodiscard]] size_t blockSize()  const noexcept { return blockSize_;  }
    [[nodiscard]] size_t totalBytes() const noexcept { return totalBytes_; }
    [[nodiscard]] size_t N()          const noexcept { return N_;          }

private:
    static size_t roundUp(size_t n, size_t a) noexcept
    { return (n + a - 1) & ~(a - 1); }

    size_t blockOffset(size_t row, size_t col) const noexcept
    { return blockSize_ * (row * N_ + col); }

    size_t N_;
    size_t blockSize_;
    size_t totalBytes_;
    std::string    filename_;
    mutable std::fstream   file_;
};


// ───────────────────────────────── combined_stripe_io.hpp ──────────────────
class StripeIO
{
public:
    enum class Direction {
        HORIZONTAL,  // row fixed, iterate over columns
        VERTICAL     // column fixed, iterate over rows
    };
    StripeIO(MemoryGrid& mg, DiskGrid& dg) 
        : memGrid(mg), diskGrid(dg) {}

    void pushBlock(size_t row, size_t col, const void* src, size_t srcBytes, size_t offsetInBlock) noexcept
    {
       assert(row < memGrid.N() && col < memGrid.N());
       std::cout << "StripeIO::pushBlock (" << row << ", " << col << ") srcBytes: " << srcBytes << std::endl;

        size_t offsetInMemoryBlock, bytesToCopyToMem;
        size_t offsetInDiskBlock, bytesToCopyToDisk;
        if (offsetInBlock >= memGrid.blockSize())
        {
            // offset is beyond the memory block, so write to disk only
            bytesToCopyToMem = 0;
            bytesToCopyToDisk = srcBytes;
            offsetInDiskBlock = offsetInBlock - memGrid.blockSize();
        }
        else
        {
            // offset is within the memory block, so write to both memory and disk
            offsetInMemoryBlock = offsetInBlock;
            bytesToCopyToMem = std::min(memGrid.blockSize() - offsetInBlock, srcBytes);
            offsetInDiskBlock = 0;
            bytesToCopyToDisk = srcBytes - bytesToCopyToMem;
        }

        if (bytesToCopyToMem > 0)
        {
            float perc_used = static_cast<float>(bytesToCopyToMem) / memGrid.blockSize();
            std::cout << "Writing to memory block (" << row << ", " << col << ") at offset " << offsetInMemoryBlock
                      << ", bytes: " << bytesToCopyToMem << ", percent used: " << perc_used * 100 << "%" << std::endl;
            memGrid.writeBlock(row, col, src, bytesToCopyToMem, offsetInMemoryBlock);
        }
        if (bytesToCopyToDisk > 0)
        {
            auto dstDisk = static_cast<const std::byte*>(src) + bytesToCopyToMem;
            diskGrid.writeBlock(row, col, dstDisk, bytesToCopyToDisk, offsetInDiskBlock);
        }
    }

    void pullBlock(size_t row, size_t col, void* dst, size_t bytes, size_t fromPosBytes = 0) const noexcept
    {
        assert(row < memGrid.N() && col < memGrid.N());
        assert(fromPosBytes + bytes <= memGrid.blockSize());

        std::cout << "StripeIO::pullBlock (" << row << ", " << col << ") bytes: " << bytes << ", fromPosBytes: " << fromPosBytes << std::endl;

        // Read from memory first
        if (fromPosBytes < memGrid.blockSize())
        {
            size_t bytesFromMem = std::min(bytes, memGrid.blockSize() - fromPosBytes);
            memGrid.readBlock(row, col, dst, bytesFromMem, fromPosBytes);
            bytes -= bytesFromMem;
            if (bytes == 0) return; // all data read from memory
            dst = static_cast<std::byte*>(dst) + bytesFromMem;
        }
        else {
            fromPosBytes -= memGrid.blockSize();
        }

        // Read remaining data from disk
        if (bytes > 0)
        {
            diskGrid.readBlock(row, col, dst, bytes, fromPosBytes);
        }
    }

    // pushStripe: write from src into mem+disk along a stripe
    // startBytes/endBytes are arrays of size N: [0..start)→mem, [start..end)→disk
    void pushStripe(Direction dir,
                    size_t idx,
                    const void* src,
                    const size_t* srcBytes,
                    size_t offsetInBlock = 0) noexcept
    {
        const auto* in = static_cast<const std::byte*>(src);
        size_t srcOffset = 0;
        for (size_t j = 0, N = memGrid.N(); j < N; ++j)
        {
            pushBlock(
                dir == Direction::HORIZONTAL ? idx : j,
                dir == Direction::HORIZONTAL ? j : idx,
                in + srcOffset,
                srcBytes[j],
                offsetInBlock);
            srcOffset += srcBytes[j];
        }
    }

    // pullStripe: read from mem+disk into dst
    void pullStripe(Direction dir,
                    size_t idx,
                    void* dst,
                    const size_t* dstBytes,
                    size_t offsetInBlock = 0) const noexcept
    {
        auto* out = static_cast<std::byte*>(dst);
        size_t dstOffset = 0;
        for (size_t j = 0, N = memGrid.N(); j < N; ++j)
        {
            pullBlock(
                dir == Direction::HORIZONTAL ? idx : j,
                dir == Direction::HORIZONTAL ? j : idx,
                out + dstOffset,
                dstBytes[j],
                offsetInBlock);
            dstOffset += dstBytes[j];
        }
    }

private:
    MemoryGrid& memGrid;
    DiskGrid&   diskGrid;
};
