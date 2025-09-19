#!/usr/bin/env bash
set -eo pipefail

# Move to repository root (this script’s directory)
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

function get_thread_count {
    if [[ $OSTYPE == 'darwin'* ]]; then
        sysctl -n hw.logicalcpu
    else
        nproc
    fi
}

# Configure with tests enabled
cmake -B build \
      -DCP_ENABLE_TESTS=ON \
      -DCMAKE_BUILD_TYPE=Release \
      .

# Build the tests target (and its dependencies)
cmake --build build \
      --config Release \
      -j"$(get_thread_count)" \
      --target tests