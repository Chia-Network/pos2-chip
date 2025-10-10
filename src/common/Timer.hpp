#pragma once

#include <chrono>

class Timer
{
public:
    bool debugOut = false;

    Timer() : start_time_point(std::chrono::steady_clock::now()) {}

    std::chrono::steady_clock::time_point now()
    {
        return std::chrono::steady_clock::now();
    }

    void start(std::string msg = "")
    {
        if (debugOut && msg != "")
        {
            this->message = msg;
            std::cout << message << std::endl;
        }
        start_time_point = now();
    }

    double stop()
    {
        std::chrono::steady_clock::time_point end_time_point = now();
        std::chrono::duration<double, std::milli> duration = end_time_point - start_time_point;
        if (debugOut && message != "")
        {
            std::cout << message << " took " << duration.count() << "ms" << std::endl;
            message = "";
        }
        return duration.count();
    }

private:
    std::chrono::steady_clock::time_point start_time_point;
    std::string message;
};
