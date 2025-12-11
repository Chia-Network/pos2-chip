# PoSpace Reference Implementation (CHIP)

This repository provides a **public reference implementation** of the new Proof of Space (“PoSpace”) format, as defined in [CHIP-48](https://github.com/Chia-Network/chips/pull/160). It includes:

- **`lib/pos/`** — core Proof of Space header‑only library (`<pos/...>`)
- **`lib/common/`** — header‑only utilities (`<common/...>`)
- **`lib/fse/`** — vendored FSE compression library
- **`tools/src/plotter/`** — example C++ plotter executable using the above
- **`tools/src/solver/`** - solver benchmarking and testing

---

## Features

- Header‑only, C++20 PoSpace core (`ProofCore`, hashing, parameters, validator, etc.)
- Example **plotter** tool demonstrating the plot pipeline and writing a plot (but does not yet compress data)
- **Solver** tool for benchmarking solve times for k28/30/32 sizes on CPUs.

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
   git clone https://github.com/Chia-Network/pos2-chip.git
   ```
   ```bash
   cd pos2-chip
   ```

2. Build

   **Option A:** Use the helper script
   ```bash
   ./build-release.sh
   ```

   **Option B:** Use CMake

   First, build with `Release` mode to enable optimizations:
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Release .
   ```

   Next, compile:

   Linux:
   ```bash
   cmake --build build -j$(nproc)
   ```

   macOS:
   ```bash
   cmake --build build -j$(sysctl -n hw.logicalcpu)
   ```
---

## Running the Plotter

From the root of your build directory, invoke the plotter executable:

```
./build/src/tools/plotter/plotter <k> [sub_k]
```

By default it uses the sample plot ID and parameters defined in tools/plotter/src/main.cpp. To customize, edit that file or supply your own main() implementation.

### About k

`k` determines the size of the plot. For testing, valid `k`-sizes are even numbers from 18 to 32. For mainnet, only 28, 30, and 32 will be allowed.

For your reference, the current plot size for k=18 is ~6.5 MB. For k=28, it's ~5 GB. The final optimized sizes are expected to be about 75% smaller than the current sizes.

### About sub_k

Each increment of `sub_k` doubles the number of unique Proof Fragments an attacker must solve for. The goal is to achieve bit drop saturation in order to maximize resistance against compression.

The only k/sub_k combinations expected to be valid on mainnet are:
* k=28, sub_k=20
* k=30, sub_k=21
* k=32, sub_k=22

If running code-based or CI tests, then k=18, sub_k=15 is recommended.

For running on a testnet, k=24, sub_k=18 will likely be recommended. The reason for the larger values on testnet is to lower the variance on plot size and output.

### Examples

To use k=18 with the default sub_k:
```bash
./build/src/tools/plotter/plotter 18
```

To use k=28 and sub_k=20
```bash
./build/src/tools/plotter/plotter 28 20
```

## Running the Solver

Run the solver executable with one of the two modes:

Coming soon.

### Benchmark Mode

```bash
./build/src/tools/solver/solver benchmark <k-size>
```

Where `<k-size>` is an integer value for the solver’s k parameter (e.g. 28).

Example:
```bash
./build/src/tools/solver/solver benchmark 32
```

Outputs timing and performance metrics for reconstructing proofs.

### Prove Mode

Reads the plot, prints its parameters, and runs the a chaining test for getting and solving for a full proof.

> [!NOTE]
> Currently the solver does not accept a challenge to choose a proof from the plot. Coming soon (TM).

```bash
./build/src/tools/solver/solver prove <plot-file>
```

Where `<plot-file>` is the path to a plot file to test.

Example:

```bash
./build/src/tools/solver/solver prove /path/to/plot.bin
```

> [!NOTE]
> Plot files are changing frequently, so use the plotter to generate a new plot to then test it.
