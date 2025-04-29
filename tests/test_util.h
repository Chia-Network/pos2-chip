#pragma once

// When testing, include as well so that we can intercept panic() calls.
#if CP_TEST_MODE
    #ifndef DOCTEST_LIBRARY_INCLUDED
        #define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
    #endif

    #define DOCTEST_CONFIG_NO_EXCEPTIONS_BUT_WITH_ALL_ASSERTS
    #include "doctest.h"
#else
    #define REQUIRE(x)  // For panic calls
#endif

#include <assert.h>
#include <stdarg.h>
#ifdef _WIN32 
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN 1
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX 1
    #endif
    #include <Windows.h>
#elif defined(__linux__)
    #include <sys/types.h>
    #include <sys/ptrace.h>
    #include <signal.h>
#elif defined(__APPLE__)
    #include <mach/task.h>
    #include <mach/mach_init.h>
    #include <stdbool.h>
    #include <signal.h>
#endif


#ifdef _WIN32 
    #define DEBUG_BREAK() __debugbreak()
#elif defined( __APPLE__ )
    #define DEBUG_BREAK() __builtin_trap()
#elif defined( __linux__ )
    #define DEBUG_BREAK() raise( SIGTRAP )
#else
    #error Unsupported platform
#endif

// CREDIT: https://forum.juce.com/t/detecting-if-a-process-is-being-run-under-a-debugger/2098
//         https://stackoverflow.com/a/23043802/2850659
inline bool 
is_debugger_present()
{
    #ifdef _WIN32 
        return IsDebuggerPresent() == TRUE;
    #elif defined(__linux__)
        if( ptrace(PTRACE_TRACEME, 0, 1, 0) < 0 )
            return true;
        
        ptrace(PTRACE_DETACH, 0, 1, 0);
        return false;
    #elif defined(__APPLE__)
        mach_msg_type_number_t count = 0;
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_port_t ports[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];

        exception_mask_t mask = EXC_MASK_ALL & ~(EXC_MASK_RESOURCE | EXC_MASK_GUARD);
        kern_return_t result = task_get_exception_ports(mach_task_self(), mask, masks, &count, ports, behaviors, flavors);
        if (result == KERN_SUCCESS)
        {
            for (mach_msg_type_number_t portIndex = 0; portIndex < count; portIndex++)
            {
                if (MACH_PORT_VALID(ports[portIndex]))
                {
                    return true;
                }
            }
        }
        return false;
    #endif

    return false;
}

// Helper to break on the assertion failure when debugging a test.
// You can pass an argument to catch to break on asserts, however,
// REQUIRE itself is extremely heavy to call directly.
#define ENSURE( x ) \
    if( !(x) ) { if(is_debugger_present()) { DEBUG_BREAK(); } REQUIRE(x); }


void printfln(const char* fmt, ... ) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    fputc('\n', stdout);
    fflush(stdout);
}
