# Building vanity-gpu

**English** | [Русский](BUILD.ru.md)

vanity-gpu runs on Linux x86-64 with an NVIDIA GPU. There are two ways to get it:

1. Download a release binary built by GitHub Actions (any NVIDIA GPU from RTX 20xx up).
2. Build it yourself (a few minutes for one GPU type; the binary is tuned for your CPU too).

## 1. Release binary

Download `vanity-gpu-<version>-linux-x86_64.tar.gz` from the Releases page, check it and run the self-test:

```bash
sha256sum -c vanity-gpu-*-linux-x86_64.tar.gz.sha256
tar xzf vanity-gpu-*-linux-x86_64.tar.gz
cd vanity-gpu-*-linux-x86_64
./vanity-gpu selftest
```

The release binary contains code for compute capability 7.5, 8.0, 8.6, 8.9, 9.0 and 12.0 (RTX 20xx, A100, RTX 30xx, RTX 40xx, H100, RTX 50xx). The archive is ~240 MB. The CUDA runtime is linked in statically, so you need only the NVIDIA driver (570 or newer recommended), not the CUDA toolkit. It was built on Ubuntu 24.04 and needs glibc 2.39 or newer (Ubuntu 24.04+, Debian 13+, Fedora 40+). On an older distribution, build from source.

The release binary uses portable CPU code for `--cpu`: on the test machine `--cpu max` adds 2% to EVM instead of 6% with `-march=native`. If you use `--cpu`, build from source.

## 2. Build from source

### Requirements

| | version | notes |
|---|---|---|
| NVIDIA driver | any that supports your CUDA toolkit | `nvidia-smi` shows the highest CUDA version it supports |
| CUDA toolkit | 12.4 or newer (tested: 12.4, 13.5) | only `nvcc` and the runtime are needed |
| C++ compiler | g++ 11–13 for CUDA 12.x; newer for CUDA 13 | CMake picks `g++-13` by itself if it is installed |
| CMake | 3.20 or newer | |
| Python 3 + `cryptography` | optional | only for `tests/crosscheck.py` |

On Ubuntu:

```bash
sudo apt install build-essential g++-13 cmake git
# CUDA: either Ubuntu's package (may be older)...
sudo apt install nvidia-cuda-toolkit
# ...or NVIDIA's repository (pick your Ubuntu version in the URL):
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb && sudo apt update
sudo apt install cuda-toolkit-12-8
```

### Build

```bash
git clone https://github.com/<you>/vanity-gpu.git
cd vanity-gpu
cmake -S . -B build -DCMAKE_CUDA_ARCHITECTURES=86
cmake --build build -j
./build/vanity-gpu selftest
```

Set `CMAKE_CUDA_ARCHITECTURES` to your GPU's compute capability without the dot (the default is 86):

| GPU | value |
|---|---|
| RTX 20xx, GTX 16xx | 75 |
| A100 | 80 |
| RTX 30xx, A10, A40 | 86 |
| RTX 40xx, L4, L40 | 89 |
| H100 | 90 |
| RTX 50xx (needs CUDA 12.8+) | 120 |

`nvidia-smi --query-gpu=compute_cap --format=csv` prints it. Several values (`"86;89"`) build one binary for several GPUs, but each one adds several minutes of compile time.

If `nvcc` is not in `PATH` or you have several toolkits, point CMake at one: `-DCMAKE_CUDA_COMPILER=/usr/local/cuda-12.8/bin/nvcc`. After changing the toolkit or the host compiler, delete `build/` first.

### Options

| option | default | meaning |
|---|---|---|
| `CMAKE_CUDA_ARCHITECTURES` | `86` | GPU types to compile for |
| `VG_NATIVE_CPU` | `ON` | build the `--cpu` workers with `-march=native` (AVX-512 / AVX2 of this CPU). Turn `OFF` for a binary you will copy to other machines |
| `VG_VERSION` | project version | string printed by `--version` |
| `CMAKE_CUDA_HOST_COMPILER` | `g++-13` if found | host compiler for `nvcc` |

### Check the build

```bash
./build/vanity-gpu selftest                        # known vectors, GPU vs CPU, hit rates (~1-2 min)
python3 -I tests/crosscheck.py build/vanity-gpu 40 # independent check with the Python cryptography package
tests/bench.sh build/vanity-gpu 8                  # speed of every search mode
```

`selftest` must end with `all tests passed`. If it does not, do not use the keys from that build.

### Common problems

- **`unsupported GNU version! gcc versions later than 13 are not supported`**: CUDA 12.x with gcc 14/15. Install `g++-13` and delete `build/`, or pass `-DCMAKE_CUDA_HOST_COMPILER=/usr/bin/g++-13`.
- **`no kernel image is available for execution on the device`**: the binary was built for another GPU. Rebuild with your `CMAKE_CUDA_ARCHITECTURES`.
- **`CUDA driver version is insufficient for CUDA runtime version`**: the toolkit is newer than the driver. Update the driver or use an older toolkit.
- **Solana/TON slower than expected**: with less than ~5.5 GB of free video memory the small 50 MB table is used (about 25% slower). Close other GPU programs.

## 3. Build on GitHub (Actions)

The repository contains `.github/workflows/build.yml`. It runs on every push to `main`, on pull requests, by hand (Actions → build → Run workflow), and on tags `v*`.

What it does:

1. Installs `nvcc` and the CUDA runtime 12.8 from NVIDIA's repository on `ubuntu-24.04` (no driver, no GPU).
2. Builds for all architectures from the table above with `VG_NATIVE_CPU=OFF`.
3. Runs `vanity-gpu --version` (GitHub's runners have no GPU, so `selftest` cannot run there).
4. Packs the binary, READMEs, LICENSE, `examples/` and `docs/` into `vanity-gpu-<version>-linux-x86_64.tar.gz` plus a `.sha256` file and attaches them to the run (Actions → the run → Artifacts).
5. On a tag `v*`, also creates a GitHub release with these files.

To publish a release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The build takes about 30 minutes (six GPU architectures; a local 16-core build took 29 minutes), and the binary is ~240 MB because it holds machine code for six GPU generations. Then download the archive on a machine with an NVIDIA GPU and run `./vanity-gpu selftest` before announcing the release.

To change the CUDA version or the GPU list, edit `CUDA_PKG`, `CUDA_HOME` and `CUDA_ARCHS` at the top of the workflow. Compute capability 12.0 (RTX 50xx) needs CUDA 12.8 or newer.
