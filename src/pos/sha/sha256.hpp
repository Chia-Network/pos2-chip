#pragma once

#if defined(_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4244 )
#endif

extern "C" {
    #include "sha256.c"
}

#if defined(_MSC_VER)
    #pragma warning( pop ) 
#endif