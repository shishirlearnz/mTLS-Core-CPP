# mTLS-Core-C++

A minimal, memory-safe TLS 1.3 (RFC 8446) **record-layer engine** written from
scratch in C++20, using OpenSSL 3.x EVP APIs for the AES-256-GCM AEAD.

This is a teaching project built strictly with **TDD**: every architectural
layer is written as a GoogleTest suite first, then the implementation.

## Layout

```
include/mtls_core/   # public headers (constants, cipher state, record layer, ...)
src/                 # implementation (.cpp)
tests/               # GoogleTest suites (one per layer, test-first)
CMakeLists.txt       # target-based build
```

## Requirements

- CMake >= 3.20
- A C++20 compiler (MSVC 19.2x+, GCC 10+, Apple Clang 12+)
- OpenSSL **3.x** (LibreSSL is *not* supported)
- (fetched automatically) GoogleTest

## Building

### macOS / Linux

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

> macOS: the build auto-detects Homebrew OpenSSL. If not, pass
> `-DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3`.

### Windows (MSVC)

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 ^
      -DOPENSSL_ROOT_DIR=C:\OpenSSL-Win64
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

## AddressSanitizer

```sh
# GCC / Clang
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DMTLS_CORE_ENABLE_ASAN=ON -DMTLS_CORE_ENABLE_UBSAN=ON
cmake --build build-asan
ctest --test-dir build-asan --output-on-failure
```

```powershell
# MSVC (ASan only; UBSan is not available)
cmake -S . -B build-asan -G "Visual Studio 17 2022" -A x64 ^
      -DMTLS_CORE_ENABLE_ASAN=ON
```

## Status

- [x] Scaffolding + TLS 1.3 constants (Commit 1)
- [ ] Secure memory primitives
- [ ] Cipher state (nonce generation)
- [ ] Record layer (AES-256-GCM encrypt/decrypt)
