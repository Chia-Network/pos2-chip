# PoSpace Reference Implementation (CHIP)

This repository provides a **public reference implementation** of the new Proof of Space (“PoSpace”) format, as defined in [CHIP-48](https://github.com/Chia-Network/chips/pull/160). It includes:

- **`lib/pos/`** — core Proof of Space header‑only library (`<pos/...>`)
- **`lib/common/`** — header‑only utilities (`<common/...>`)
- **`lib/fse/`** — vendored FSE compression library
- **`tools/src/plotter/`** — example C++ plotter executable using the above
- **`tools/src/solver/`** - solver benchmarking and testing
- **`tools/src/prover/`** - finding proofs given challenges

---

## Features

- Header‑only, C++20 PoSpace core (`ProofCore`, hashing, parameters, validator, etc.)
- Example **plotter** tool demonstrating the plot pipeline and writing a plot
- **Solver** tool for benchmarking solve times on CPUs.

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
./build/src/tools/plotter/plotter <k>
```

By default it uses the sample plot ID and parameters defined in tools/plotter/src/main.cpp. To customize, edit that file or supply your own main() implementation.

### About strength

`strength` influences the effective plot filter. Higher strength, means that your plot will be accessed less frequently for responding to challenges.

### Examples

To use k=28:
```bash
./build/src/tools/plotter/plotter test 28 2
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
