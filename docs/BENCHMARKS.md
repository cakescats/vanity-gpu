# Benchmarks

Measured on 2026-11-19.

| | |
|---|---|
| GPU | NVIDIA GeForce RTX 3090 (24 GB, stock clocks, 350 W limit), driver 595.99 |
| CPU | AMD Ryzen 7 7800X3D (8 cores / 16 threads) |
| OS | Ubuntu 26.04.1, kernel 7.0 |
| build | CUDA 12.4, g++-13, `CMAKE_CUDA_ARCHITECTURES=86`, `VG_NATIVE_CPU=ON` |

The numbers are sustained speeds on a warm card (after several minutes of load), with patterns that are never found. A cold card is 2–4% faster for the first minute. To reproduce: `tests/bench.sh build/vanity-gpu 8`.

## vanity-gpu, every search mode

| mode | command | speed |
|---|---|---|
| EVM prefix | `evm ffffffffffffffff` | 1.81 Gkey/s |
| EVM prefix + CPU | `evm ffffffffffffffff --cpu max` | 1.92 Gkey/s |
| EVM beauty | `evm --beauty` | 1.80 Gkey/s |
| EVM digits only | `evm --only digits` | 1.74 Gkey/s |
| EVM upper case (EIP-55) | `evm --only upper` | 1.77 Gkey/s |
| TRON prefix | `tron TTTTTTTTTTTTTT` | 1.77 Gkey/s |
| TRON prefix + CPU | `tron TTTTTTTTTTTTTT --cpu max` | 1.89 Gkey/s |
| TRON suffix | `tron ..zzzzzzzzzzzz` | 1.07 Gkey/s |
| TRON beauty | `tron --beauty` | 1.11 Gkey/s |
| Bitcoin `bc1q` prefix | `btc bc1qzzzzzzzzzzzzzz` | 3.85 Gkey/s |
| Bitcoin `bc1q` prefix + CPU | `btc bc1qzzzzzzzzzzzzzz --cpu max` | 3.98 Gkey/s |
| Bitcoin `bc1q` suffix | `btc ..zzzzzzzzzzzz` | 2.99 Gkey/s |
| Bitcoin `1…` prefix | `btc 1zzzzzzzzzzzzz` | 3.79 Gkey/s |
| Bitcoin `1…` suffix | `btc-legacy ..zzzzzzzzzzzz` | 1.72 Gkey/s |
| Bitcoin `3…` prefix | `btc 3Mzzzzzzzzzzzz` | 2.11–2.19 Gkey/s |
| Solana prefix | `sol zzzzzzzzzzzz` | 255 Mkey/s |
| Solana suffix | `sol ..zzzzzzzzzzzz` | 252 Mkey/s |
| TON prefix | `ton UQAzzzzzzzzzzzz` | 207 Mkey/s |
| TON suffix | `ton ..zzzzzzzzzzzz` | 200 Mkey/s |

### Several chains in one pass (`multi`), speed per chain

| chains | patterns | `--beauty` | the same chains one after another, `--beauty` |
|---|---|---|---|
| evm,tron | 1.63 Gkey/s | 1.0 Gkey/s | 0.7 Gkey/s |
| evm,tron,btc | 1.16 Gkey/s | 0.81 Gkey/s | 0.56 Gkey/s |
| evm,tron,btc-all (5 address types) | — | 0.46 Gkey/s | 0.3 Gkey/s |
| sol,ton | — | 210 Mkey/s | 114 Mkey/s |

## Other generators on the same card

All tools were built from source on this machine and run back to back with vanity-gpu, warm card, unreachable patterns.

| chain | tool | version | speed | vanity-gpu |
|---|---|---|---|---|
| EVM | [vanity-eth-address](https://github.com/MrSpike63/vanity-eth-address) | main, Nov 2026 | 1.63 Gkey/s | **1.80** |
| EVM | [ProVanity](https://github.com/WooMai/ProVanity) | 1.1.2 (1d45939) | 1.11 Gkey/s | **1.80** |
| EVM | [profanity2](https://github.com/1inch/profanity2) | main, Nov 2026 | 0.84 Gkey/s | **1.80** |
| TRON prefix | ProVanity | 1.1.2 | 0.99 Gkey/s | **1.78** |
| TRON suffix | ProVanity (8 characters at most) | 1.1.2 | 0.75 Gkey/s | **1.07** |
| Bitcoin `1…` | [VanitySearch](https://github.com/JeanLucPons/VanitySearch) | master, Nov 2026 | 3.87 Gkey/s | 3.79 |
| Bitcoin `bc1q…` | VanitySearch | master | 3.87 Gkey/s | 3.85 |
| Bitcoin `3…` | VanitySearch | master | 2.00 Gkey/s | **2.19** |

How they were run:

```bash
# profanity2 (OpenCL); -z is a seed public key, here the generator point G (benchmark only)
make && cd bin && ./profanity2.x64 --benchmark -z 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

# vanity-eth-address (CUDA)
nvcc -O3 -arch=sm_86 -ccbin g++-13 -std=c++17 -o vanity-eth src/main.cu && ./vanity-eth -lz -d 0

# ProVanity (CUDA 13 + Go 1.25+)
NVCC=/usr/local/cuda-13.5/bin/nvcc go run ./cmd/build -arch sm_86 -skip-tests
./provanity bench --duration 60s --json
./provanity generate-tron --pattern prefix:TTTTTTTTTTTTT
./provanity generate-tron --pattern suffix:zzzzzzzz

# VanitySearch (CUDA); old code needs <cstdint> with modern g++
make gpu=1 CCAP=8.6 CUDA=/usr CXXCUDA=g++-13 CXX="g++ -include cstdint" all
./VanitySearch -t 0 -gpu -o /dev/null 1zzzzzzzzzzz      # also bc1qzzzzzzzzzzzz, 3Mzzzzzzzzzzz
```

Not measured:

- **Solana**: [solanity](https://github.com/ChorusOne/solanity) states in its README that it does not use a cryptographically secure RNG and its keys are not safe. The [mcf-rocks fork](https://github.com/mcf-rocks/solanity) uses OS entropy and reports 12 minutes on average for a 5-character prefix on a Tesla V100; vanity-gpu takes ~3 s for that on the RTX 3090 (58^5 / 255 Mkey/s).
- **TON**: no GPU generator of wallet keys was found. [ton-org/vanity](https://github.com/ton-org/vanity) searches a salt for a smart-contract address, a different task (the contract has to be deployed, and a wallet imported from a key lives at another address).

## Ideas that were measured and rejected

- **Keccak rotations on the IMAD pipe** (multiply by 2^r instead of funnel shifts, to offload the ALU pipe): 1–12% slower on the RTX 3090 depending on how many rotations are moved; `mul.hi` runs at half rate on this GPU.
- **A separate template copy of the last ed25519 point addition** (to skip T): made the kernels slower (instruction cache); a runtime flag is used instead.
