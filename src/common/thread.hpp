#pragma once

#include <thread>
#include <utility>

// Use std::jthread when available; falls back to std::thread+join
#if defined(__cpp_lib_jthread)
using thread = std::jthread;
#else
struct thread : std::thread
{
    template <typename F, typename ...Args>
    explicit thread(F&& f, Args&&... args): std::thread(std::forward<F>(f), std::forward<Args>(args)...) {}
    thread(thread const&) = delete;
    thread(thread&&) = default;
    ~thread() { if (joinable()) join(); }
};
#endif
