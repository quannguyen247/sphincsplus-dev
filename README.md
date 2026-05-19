# SPHINCS+ (research fork)

This repository is a fork of the upstream SPHINCS+ implementation ([sphincs/sphincsplus](https://github.com/sphincs/sphincsplus)), customized for post-quantum cryptography (PQC) research and benchmarking. SPHINCS+ is standardized as [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).

It contains:

- `ref/`: portable reference C implementation
- `haraka-aesni/`: x86_64 implementation using Haraka with AES-NI
- `sha2-avx2/`: x86_64 implementation using SHA2 + AVX2 (x8)
- `shake-avx2/`: x86_64 implementation using SHAKE + AVX2 (x4)
- `shake-a64/`: AArch64 implementation using SHAKE (x2)

For a list of changes in this fork, see [CHANGELOG.md](CHANGELOG.md).

## Table of contents

- [Reproducibility quick start](#reproducibility-quick-start)
- [Build](#build)
- [Correctness tests](#correctness-tests)
- [Benchmarking (cycle counts)](#benchmarking-cycle-counts)
- [Deterministic test vectors](#deterministic-test-vectors)
- [NIST KAT generator (optional)](#nist-kat-generator-optional)
- [TCP client/server demo (optional)](#tcp-clientserver-demo-optional)
- [Coverage (optional)](#coverage-optional)
- [License](#license)

## Reproducibility quick start

### Platform notes

- **Linux is recommended** for reproducible benchmarking.
- **macOS** builds the `ref/` implementation fine in most setups; `shake-a64/` is intended for AArch64.
- **Windows**: use **WSL2** for the simplest build/run workflow (some benchmarks/tools use POSIX APIs).

### Dependencies

Ubuntu/Debian:

```sh
sudo apt-get update
sudo apt-get install -y build-essential make pkg-config libssl-dev python3
```

Notes:

- OpenSSL (`libssl-dev`) is required for the deterministic RNG used by the NIST KAT generator and some test/benchmark targets.

## Build

All commands below assume you are at the repository root.

### Instance selection

You can select a SPHINCS+ instance and tweakable-hash variant via Makefile variables:

- `PARAMS`: `sphincs-<hash>-<sec><opt>` where:
	- `<hash>` is `sha2`, `shake`, or `haraka`
	- `<sec>` is `128`, `192`, or `256` (targets NIST security categories 1, 3, 5)
	- `<opt>` is `s` (smaller signatures) or `f` (faster signing)
- `THASH`: `simple` or `robust`

Examples:

```sh
make -C ref clean PARAMS=sphincs-sha2-128f THASH=simple
make -C ref tests PARAMS=sphincs-shake-256s THASH=robust
```

### Reference implementation (`ref/`)

Build everything (KAT generator + tests + benchmark binary):

```sh
make -C ref clean
make -C ref all
```

This produces (among others):

- `ref/PQCgenKAT_sign`
- `ref/test/spx`, `ref/test/fors`
- `ref/test/benchmark`

### Haraka AES-NI implementation (`haraka-aesni/`)

Requires an x86_64 CPU with AES-NI.

```sh
make -C haraka-aesni clean
make -C haraka-aesni all
```

### SHA2 AVX2 implementation (`sha2-avx2/`)

Requires an x86_64 CPU with AVX2.

```sh
make -C sha2-avx2 clean
make -C sha2-avx2 all
```

### SHAKE AVX2 implementation (`shake-avx2/`)

Requires an x86_64 CPU with AVX2.

```sh
make -C shake-avx2 clean
make -C shake-avx2 all
```

### SHAKE AArch64 implementation (`shake-a64/`)

Intended for AArch64.

```sh
make -C shake-a64 clean
make -C shake-a64 all
```

## Correctness tests

Each implementation directory provides a `test` target that builds and runs its basic correctness tests.

Reference:

```sh
make -C ref test
```

Optimized implementations:

```sh
make -C haraka-aesni test
make -C sha2-avx2 test
make -C shake-avx2 test
make -C shake-a64 test
```

This runs the binaries under each directory’s `test/` folder (e.g., `test/spx`, `test/fors`, and the `thashx*` tests where applicable).

This fork also includes an additional harness under `ref/test/test_sphincsplus.c`:

```sh
make -C ref test_sphincsplus
cd ref
./test/test_sphincsplus
```

## Benchmarking (cycle counts)

The `benchmark` target builds and executes `test/benchmark`, which prints cycle counts (via `RDTSC`) and CPU-time in microseconds.

Single instance (reference):

```sh
make -C ref benchmark
```

Sweep all instances across multiple implementations (prints results as it goes):

```sh
python3 benchmark.py
```

Reproducibility tips:

- Pin the exact commit hash: `git rev-parse HEAD`
- Record compiler versions: `gcc --version` / `clang --version`
- Record CPU model and frequency scaling settings (e.g., `lscpu`)

## Deterministic test vectors

This repo includes `vectors.py` and `SHA256SUMS` to validate deterministic NIST KAT response files.

Generate SHA256 sums for all instances (reference implementation):

```sh
python3 vectors.py
```

Check one instance against `SHA256SUMS` using a specific implementation directory:

```sh
python3 vectors.py sphincs-shake-128s-simple shake-avx2
```

## NIST KAT generator (optional)

Build and run the NIST KAT generator (`PQCgenKAT_sign`) for a selected instance:

```sh
make -C ref clean PARAMS=sphincs-sha2-128f THASH=simple
make -C ref PQCgenKAT_sign PARAMS=sphincs-sha2-128f THASH=simple
cd ref
./PQCgenKAT_sign
```

This writes `PQCsignKAT_*.req` / `PQCsignKAT_*.rsp` in the current directory.

## TCP client/server demo (optional)

This fork includes a simple TCP challenge/response demo under `ref/test/`:

- `test_sphincsplus_keygen`: generate a keypair and write `client_sk.bin`, `client_pk.bin`, `server_pk.bin`
- `test_sphincsplus_server`: listen on TCP port `5000`, send a challenge, verify the signature
- `test_sphincsplus_client`: connect to the server, sign the challenge, send the signature
- `test_sphincsplus_stress`: concurrent client load generator (uses `fork()`)

Build + run (localhost, recommended on Linux/WSL):

```sh
make -C ref/test clean
make -C ref/test keygen
make -C ref/test run-server
```

In a second terminal:

```sh
make -C ref/test run-client TARGET_IP=127.0.0.1
```

Stress tool:

```sh
make -C ref/test stress TARGET_IP=127.0.0.1 CONCURRENT_SESSIONS=10
```

Network protocol (framed):

1. server → client: `uint32_be length` + challenge bytes
2. client → server: `uint32_be length` + signature bytes

Logs and files are written in `ref/test/` (e.g., `client.log`, `server.log`, and `*.bin`).

## Coverage (optional)

There is no dedicated coverage script in this fork. If you want coverage, build with coverage flags using `EXTRA_CFLAGS` (supported by the Makefiles), run tests/benchmarks, then use your preferred tooling (e.g., `gcov`/`lcov`).

## License

See [LICENSE](LICENSE) and the licenses under [LICENSES/](LICENSES).

Upstream SPHINCS+ code is placed into public domain and is available under various open source licenses, with the exception of `rng.c`, `rng.h`, and `PQCgenKAT_sign.c` (provided by NIST) and parts of `ref/haraka.c` (MIT).
