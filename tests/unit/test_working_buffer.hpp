// filepath: tests/unit/test_working_buffer.hpp
#include "plot/WorkingBuffer.hpp"
#include <vector>
#include <memory_resource>
#include <cstddef>

TEST_SUITE_BEGIN("working-buffer");

TEST_CASE("initial capacity and bytesUsed")
{
    const std::size_t size = 1024;
    WorkingBuffer wb(size);
    CHECK(wb.capacity() == size);
    CHECK(wb.bytesUsed() == 0);
}

TEST_CASE("allocateRaw increases bytesUsed")
{
    const std::size_t size = 1024;
    WorkingBuffer wb(size);
    void *ptr1 = wb.allocateRaw(128);
    CHECK(ptr1 != nullptr);
    CHECK(wb.bytesUsed() >= 128);
    void *ptr2 = wb.allocateRaw(256, alignof(std::max_align_t));
    CHECK(ptr2 != nullptr);
    CHECK(wb.bytesUsed() >= 128 + 256);
}

TEST_CASE("pmr vector allocation uses WorkingBuffer")
{
    const std::size_t size = 1024;
    WorkingBuffer wb(size);
    std::pmr::vector<int> vec(wb.resource());
    for (int i = 0; i < 10; ++i)
    {
        vec.push_back(i);
    }
    CHECK(vec.size() == 10);
    CHECK(wb.bytesUsed() > 0);
    std::cout << "Bytes used after vector allocation: " << wb.bytesUsed() << std::endl;

    {
        WorkingBuffer::CheckpointGuard guard(wb);
        std::pmr::vector<int> vec2(wb.resource());
        vec2.resize(20);
        for (int i = 0; i < 20; ++i)
        {
            vec2[i] = i * 2;
        }
        CHECK(vec2.size() == 20);
        CHECK(wb.bytesUsed() > 0);
        std::cout << "Bytes used after second vector allocation: " << wb.bytesUsed() << std::endl;
    }
    std::pmr::vector<int> vec3(wb.resource());
    vec3.resize(20); // allocate more space
    for (int i = 0; i < 20; ++i)
    {
        vec3[i] = i * 3;
    }
    CHECK(vec3.size() == 20);
    CHECK(wb.bytesUsed() > 0);
    std::cout << "Bytes used after third vector allocation: " << wb.bytesUsed() << std::endl;

    // check vec1 and vec2 contents
    for (int i = 0; i < 10; ++i)
    {
        CHECK(vec[i] == i);
    }
    for (int i = 0; i < 20; ++i)
    {
        CHECK(vec3[i] == i * 3);
    }
}

TEST_CASE("reset clears allocations")
{
    const std::size_t size = 512;
    WorkingBuffer wb(size);
    wb.allocateRaw(100);
    CHECK(wb.bytesUsed() > 0);
    wb.reset();
    CHECK(wb.bytesUsed() == 0);
}

TEST_CASE("checkpoint and release allocations")
{
    const std::size_t size = 512;
    WorkingBuffer wb(size);
    // mark initial point
    auto mark1 = wb.checkpoint();
    wb.allocateRaw(100);
    CHECK(wb.bytesUsed() >= mark1 + 100);
    wb.release(mark1);
    CHECK(wb.bytesUsed() == mark1);

    // mark before pmr vector allocation
    auto mark2 = wb.checkpoint();
    {
        std::pmr::vector<int> v(wb.resource());
        v.resize(20);
        CHECK(wb.bytesUsed() > mark2);
    }
    // after vector destruction bump::do_deallocate is noop, still allocated
    wb.release(mark2);
    CHECK(wb.bytesUsed() == mark2);
}

TEST_CASE("checkpoint guard frees on scope exit")
{
    const std::size_t size = 256;
    WorkingBuffer wb(size);
    wb.allocateRaw(50);
    {
        WorkingBuffer::CheckpointGuard guard(wb);
        wb.allocateRaw(100);
        CHECK(wb.bytesUsed() >= 150);
    }
    // after guard destruction, buffer rewound
    CHECK(wb.bytesUsed() == wb.checkpoint());
}

TEST_SUITE_END();
