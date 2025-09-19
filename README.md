# PoSpace Reference Implementation (CHIP)

This repository provides a **public reference implementation** of the new Proof of Space (“PoSpace”) format, as defined in CHIP-XXXX. It includes:

- **`lib/pos/`** — core Proof of Space header‑only library (`<pos/...>`)
- **`lib/common/`** — header‑only utilities (`<common/...>`)
- **`lib/fse/`** — vendored FSE compression library
- **`tools/src/plotter/`** — example C++ plotter executable using the above
- **`tools/src/solver/`** - solver benchmarking and testing

---

## Features

- Header‑only, C++20 PoSpace core (`ProofCore`, hashing, parameters, validator, etc.)
- Example **plotter** tool demonstrating the plot pipeline and writing a plot (but does not yet compress data)
- **Solver** tool for benchmarking solve times for k28/30/28 sizes on CPUs.

> [!NOTE]
> The reference implementations do not optimize for memory usage, and consume much more memory than the upcoming production versions.

---

## Prerequisites

- A C++20‑capable compiler
- [CMake](https://cmake.org/) ≥ 3.15
- `make` (or your preferred build tool)
- A Unix‑style shell (Linux/macOS) or PowerShell/Bash on Windows

## Building

1. **Clone** the repo:
   ```bash
   git clone https://github.com/your-org/pos2-chip.git
   cd pos2-chip
   ```

### Shortcut with helper script:
2. Build
```bash
   ./build-release.sh
```

### Manually, directly via CMake:
2. Configure with CMake (Release mode enables optimizations):
    ```bash
    cmake -B build -DCMAKE_BUILD_TYPE=Release .
    ```
3. Compile:
    ```bash
    
    # Linux
    cmake --build build -j$(nproc)

    # macOS
    cmake --build build -j$(sysctl -n hw.logicalcpu)
    ```

## Running the Plotter

From the root of your build directory, invoke the plotter executable:

```
./tools/plotter/plotter <k> [sub_k]
```

By default it uses the sample plot ID and parameters defined in tools/plotter/src/main.cpp. To customize, edit that file or supply your own main() implementation.

Currently the PoS 2 is expected to use:
k=28 sub_k=20
k=30 sub_k=21
k=32 sub_k=22

### Examples

```bash
# Use k=18, default sub_k=20
./src/tools/plotter/plotter 18

# Use k=28 and sub_k=16
./src/tools/plotter/plotter 28 16
```

## Running the Solver

Run the solver executable with one of the two modes:

### Benchmark Mode

    ./src/tools/solver/solver benchmark <k-size>

- `<k-size>`: integer value for the solver’s k parameter (e.g. 28).

Example:

    ./src/tools/solver/solver benchmark 32

Outputs timing and performance metrics for reconstructing proofs.

### Prove Mode

Reads the plot, prints its parameters, and runs the a chaining test for getting and solving for a full proof.

> [!NOTE]
> Currently the solver does not accept a challenge to choose a proof from the plot. Coming soon (TM).

    ./src/tools/solver/solver prove <plot-file>

- `<plot-file>`: path to a plot file to test.

Example:

    ./src/tools/solver/solver prove /path/to/plot.bin

> [!NOTE]
> Plot files are changing frequently, so use the plotter to generate a new plot to then test it.
