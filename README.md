# PoSpace Reference Implementation (CHIP)

This repository provides a **public reference implementation** of the new Proof of Space ("PoSpace") format, as defined in [CHIP-48](https://github.com/Chia-Network/chips/pull/160). It includes:

- **`src/pos/`** — core Proof of Space header‑only library (`<pos/...>`)
- **`src/common/`** — header‑only utilities (`<common/...>`)
- **`src/plot/`, `src/solve/`, `src/prove/`** — plotting, solving and proving headers
- **`lib/fse/`** — vendored FSE compression library
- **`src/tools/plotter/`** — example C++ plotter executable
- **`src/tools/solver/`** — solver benchmarking and partial‑proof solving
- **`src/tools/prover/`** — finding and verifying proofs given challenges
- **`src/tools/analytics/`** — disk‑usage simulations and hash benchmarks

---

## Features

- Header‑only, C++20 PoSpace core (`ProofCore`, hashing, parameters, validator, etc.)
- Example **plotter** tool demonstrating the plot pipeline and writing a plot file
- **Solver** tool for benchmarking CPU solve times and solving from partial proofs
- **Prover** tool that runs challenges against a plot file and verifies full proofs
- **Analytics** tool for disk‑usage simulations and hash micro‑benchmarks

> [!IMPORTANT]
> **`k=28` is the only k size used on mainnet.** All other supported k values (even integers in `18`..`32`) are intended for testing, development, and benchmarking only — plots made with any `k != 28` are **not** valid on mainnet, even without the `--testnet` flag.

---

## Prerequisites

- A C++20‑capable compiler
- [CMake](https://cmake.org/) ≥ 3.15
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

   **Option B:** Use CMake directly

   First, configure with `Release` mode to enable optimizations:
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

All executables are written directly to the `build/` directory:

- `build/plotter`
- `build/solver`
- `build/prover`
- `build/analytics`

By default all four tools are built. You can disable individual targets at configure time with `-DCP_ENABLE_PLOTTER=OFF`, `-DCP_ENABLE_SOLVER=OFF`, `-DCP_ENABLE_PROVER=OFF`, `-DCP_ENABLE_ANALYTICS=OFF`.

---

## Running the Plotter

From the repository root:

```bash
./build/plotter test <k> <plot_id_hex> [strength] [plot_index] [meta_group] [verbose] [--testnet]
```

Arguments:

- `<k>` — even integer between 18 and 32. **Use `k=28` for mainnet plots; any other value is for testing only and will not produce mainnet‑valid plots.**
- `<plot_id_hex>` — exactly 64 hex characters (a 32‑byte plot ID)
- `[strength]` — optional, defaults to `2` (range `2`..`255`)
- `[plot_index]` — optional, defaults to `0` (range `0`..`65535`)
- `[meta_group]` — optional, defaults to `0` (range `0`..`255`)
- `[verbose]` — optional, `0` (default) shows a progress bar, `1` prints per‑stage logs
- `[--testnet]` — optional flag; produces a plot using testnet parameters (not valid on mainnet)

The plotter writes a plot file in the current working directory named like:

```
plot_<k>_<strength>_<plot_index>_<meta_group>[_testnet]_<plot_id_hex>.bin
```

### About strength

`strength` influences the effective plot filter. Higher strength means your plot will be accessed less frequently when responding to challenges.

### Examples

Plot with `k=28`, default strength, default plot index/meta group:

```bash
./build/plotter test 28 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
```

Plot with `k=28` and strength `3`:

```bash
./build/plotter test 28 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 3
```

Verbose output for `k=28`, strength `2`, plot index `1`, meta group `0`:

```bash
./build/plotter test 28 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 2 1 0 1
```

Plot a testnet plot:

```bash
./build/plotter test 28 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 2 0 0 0 --testnet
```

---

## Running the Solver

The solver has two modes:

### Benchmark Mode

Reconstructs proofs from a deterministic sequence of x‑bits and prints timing/throughput numbers — useful for measuring solve performance on a given CPU.

```bash
./build/solver benchmark <k> [strength]
```

- `<k>` — even integer between 18 and 32. Mainnet uses `k=28`; other values are for benchmarking/testing only.
- `[strength]` — optional, defaults to `2`

Example (mainnet k):

```bash
./build/solver benchmark 28
```

Example (test‑only k):

```bash
./build/solver benchmark 32 2
```

### xbits Mode

Given a plot ID and a partial proof (compressed x‑bits hex string, as printed by `prover challenge`), the solver completes the proof and prints the resulting x‑values.

```bash
./build/solver xbits <plot_id_hex> <xbits_hex> [strength]
```

- `<plot_id_hex>` — 64 hex characters
- `<xbits_hex>` — compressed hex string of `k/2`-bit x values for the partial proof (the `prover challenge` command prints exactly this string in its "To complete proof run:" line)
- `[strength]` — optional, defaults to `2`

The easiest way to get a valid `xbits_hex` is to run `prover challenge` against an existing plot (see below) and copy its output.

---

## Running the Prover

The prover loads a plot file and either finds proofs for a challenge or verifies an already‑known proof. It has three modes.

### check mode

Runs many random challenges against a plot and reports how often a proof is found.

```bash
./build/prover check <plotfile> [total_trials]
```

- `<plotfile>` — path to a `.bin` plot produced by the plotter
- `[total_trials]` — optional, defaults to `1000`

Example:

```bash
./build/prover check ./plot_28_2_0_0_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF.bin 5000
```

### challenge mode

Runs a single challenge against a plot, prints any proof fragments found, and prints a ready‑to‑run `solver xbits ...` command for completing the proof.

```bash
./build/prover challenge <challenge_hex> <plotfile>
```

- `<challenge_hex>` — 64 hex characters
- `<plotfile>` — path to a plot file

Example:

```bash
./build/prover challenge 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF \
  ./plot_28_2_0_0_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF.bin
```

### verify mode

Verifies a full proof against a plot ID, challenge, and strength — no plot file required.

```bash
./build/prover verify <plot_id_hex> <proof_hex> <challenge_hex> <plot_strength>
```

- `<plot_id_hex>` — 64 hex characters
- `<proof_hex>` — compressed hex proof (`k` is derived from its length)
- `<challenge_hex>` — 64 hex characters
- `<plot_strength>` — integer in `2`..`255`

> [!NOTE]
> Plot file formats are still evolving. If a stored plot stops working, regenerate it with the current plotter.

---

## Running Analytics

Disk‑usage simulations and hashing micro‑benchmarks.

### simdiskusage

Simulates how often a plot of a given size would be accessed for challenges.

```bash
./build/analytics simdiskusage [plotIdFilterBits] [plotsInGroup] [diskTB] [diskSeekMs] [diskReadMBs]
```

Defaults: `plotIdFilterBits=8`, `plotsInGroup=32`, `diskTB=20`, `diskSeekMs=10`, `diskReadMBs=250`.

Example:

```bash
./build/analytics simdiskusage 8 32 20 10 250
```

### hashbench

Benchmarks the AES (hardware + software), Blake, and ChaCha hash paths used internally.

```bash
./build/analytics hashbench <N> [rounds] [threads]
```

- `<N>` — runs `2^N` hashes per test
- `[rounds]` — AES rounds, defaults to `16`
- `[threads]` — defaults to `max` (hardware concurrency)

Example:

```bash
./build/analytics hashbench 24 16 max
```

### simpreallocateplotgrouping

Reads an existing plot file and estimates the preallocation padding required when grouping plots together.

```bash
./build/analytics simpreallocateplotgrouping <plotfile> [numPlotsInGroup] [numTrials]
```

Defaults: `numPlotsInGroup=64`, `numTrials=10000`.

---

## Tests

To build the tests, set the option `-DCP_BUILD_TESTS=ON` when configuring:

```bash
cmake -B build -DCP_BUILD_TESTS=ON .
cmake --build build -j$(sysctl -n hw.logicalcpu 2>/dev/null || nproc)
ctest --test-dir build --output-on-failure
```

Or you can use the `run-tests.sh` script:

```bash
./run-tests.sh
```

See `run-tests.sh -h` for additional options (filtering by regex/label, build type, parallel jobs, rerun‑failed, etc.).

> [!NOTE]
> Building tests is enabled by default when building from CI.
