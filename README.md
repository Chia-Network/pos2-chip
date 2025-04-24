# PoSpace Reference Implementation (CHIP)

This repository provides a **public reference implementation** of the new Proof of Space (“PoSpace”) format, as defined in CHIP-XXXX. It includes:

- **`lib/pos/`** — core Proof of Space header‑only library (`<pos/...>`)
- **`lib/common/`** — header‑only utilities (`<common/...>`)
- **`lib/fse/`** — vendored FSE compression library
- **`tools/plotter/`** — example C++ plotter executable using the above

---

## Features

- Header‑only, C++20 PoSpace core (`ProofCore`, hashing, parameters, validator, etc.)
- Example **plotter** tool demonstrating the plot pipeline (but does not yet write to disk)

---

## Prerequisites

- A C++20‑capable compiler
- [CMake](https://cmake.org/) ≥ 3.15
- `make` (or your preferred build tool)
- A Unix‑style shell (Linux/macOS) or PowerShell/Bash on Windows

---

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

### Examples

```bash
# Use k=18, default sub_k=16
./tools/plotter/plotter 18

# Use k=28 and sub_k=17
./tools/plotter/plotter 28 17
```