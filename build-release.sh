#! /usr/bin/env bash
set -eo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

function get_thread_count
{
    if [[ $OSTYPE == 'darwin'* ]]; then
        sysctl -n hw.logicalcpu
    else
        nproc
    fi
}

cmake -B build -DCMAKE_BUILD_TYPE=Release .
cmake --build build -j$(get_thread_count)
