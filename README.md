# Partial SHA-2 Collision with Prefix/Suffix (oneAPI SYCL)

For explaintion on the algorithm (Van Oorschot–Wiener), SHA-2 (Merkle–Damgard Construction) or results, please visit [https://jianxun-p.github.io/sha2-collision-with-oneapi.html](https://jianxun-p.github.io/sha2-collision-with-oneapi.html).

This project searches for a **partial collision** in SHA-2 outputs: two different inputs that share the same first `N` bytes of hash output.

Inputs are constrained to this format:

`input = prefix || variable_middle(N bytes) || suffix`

The implementation uses a Van Oorschot–Wiener (VOW) style collision search with **distinguishable points (DPs)** and runs in parallel with **oneAPI SYCL**.

---

## Features

- Supports SHA-2 family variants:
	- `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA512_224`, `SHA512_256`
- Configurable partial-collision size (`N` bytes)
- Configurable DP condition (`K` bytes, where `K <= N`)
- Prefix/suffix constrained input space
- Parallel stage-1 walk on CPU/GPU SYCL device
- Header-only SHA-2 implementation in [sha2.hpp](sha2.hpp)

---

## Repository Layout

- [main.cpp](main.cpp): VOW search logic, SYCL kernels, collision reporting
- [sha2.hpp](sha2.hpp): Header-only SHA-2 implementations
- [Makefile](Makefile): Build and run targets

---

## How It Works

### Stage 1: Parallel random walks + DP collision search

Each worker thread:
1. Starts from a deterministic seed
2. Repeatedly hashes `prefix || middle || suffix`
3. Treats outputs with first `K` bytes equal to zero as a distinguishable point
4. Stores chains ending at DPs

When two chains hit the same DP key (matching first `N` bytes), stage 1 returns two chain starts (`X`, `Y`) and distances to that DP.

### Stage 2: Backtracking to find the actual partial collision

The two chains are aligned by step count and advanced together until the first point where their first `N` hash bytes match. The corresponding two inputs are reported.

---

## Configuration

Edit constants near the top of [main.cpp](main.cpp):

- `hash_type`: select SHA-2 variant
- `N`: number of leading output bytes that must collide
- `K`: DP prefix length in bytes (`K <= N`)
- `prefix`, `suffix`: fixed bytes around the variable `N`-byte middle
- `THREADS`: number of parallel walkers
- `BATCH_SIZE`: steps per walker before host merge/check
- `DP_ARRAY_LEN`: max DPs stored per thread per batch

### Notes

- Larger `N` increases expected work roughly as $2^{4N}$ for birthday-style partial collisions (in bits: $2^{8N/2}$).
- Larger `K` reduces DP frequency; smaller `K` increases merge overhead.
- Tune `THREADS`, `BATCH_SIZE`, and `DP_ARRAY_LEN` for your device memory and throughput.

---

## Build

Prerequisites:
- Intel oneAPI DPC++/C++ compiler (`icpx`)
- oneAPI/SYCL runtime properly configured in shell environment

### Option 1: Build with Makefile

The project Makefile compiles to `sha2_collision` (or `sha2_collision.exe` on Windows).

### Option 2: Direct compile command

```bash
icpx -fsycl -O3 -std=c++20 -Wall -Wextra -march=native -o sha2_collision main.cpp
```

---

## Run

Run the built binary.

Program output includes:
- selected SYCL device
- stage-1 batch progress and hash counts
- detected DP collision
- stage-2 alignment/backtracking logs
- final partial collision inputs and outputs
- total hashes, duration, and hashing speed

---

## Example Collision Condition

If `N = 8`, success means the first 8 bytes of the two outputs are identical:

`hash(input1)[0..7] == hash(input2)[0..7]`

with `input1 != input2` and both matching the `prefix || middle || suffix` format.

---

## Disclaimer

This project is for educational and research use (parallel hash search, SYCL programming, and collision-search techniques). Do not use it for unauthorized security testing.

