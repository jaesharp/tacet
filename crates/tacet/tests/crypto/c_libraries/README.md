# C/C++ Cryptographic Library Tests

This directory contains timing side-channel tests for C/C++ cryptographic libraries accessed via Rust FFI bindings.

## Libraries Tested

### LibreSSL (via `openssl` crate)
- RSA-2048 PKCS#1 v1.5 decryption (Bleichenbacher, MARVIN vulnerability class)
- RSA-2048 OAEP decryption
- ECDSA P-256 signing and verification (multiple 2024 CVEs in similar implementations)
- AES-256-GCM encryption (software fallback paths)

### Libsodium (via `sodiumoxide` crate)
- Ed25519 signing and verification
- X25519 scalar multiplication
- crypto_box (X25519-XSalsa20-Poly1305 authenticated encryption)
- crypto_secretbox (XSalsa20-Poly1305 symmetric authenticated encryption)

### wolfSSL (via FFI)
- RSA-2048 PKCS#1 v1.5 decryption
- RSA-2048 OAEP decryption
- ECDSA P-256 signing
- AES-256-GCM encryption/decryption

### mbedTLS (via FFI)
- RSA-2048 PKCS#1 v1.5 decryption
- RSA-2048 OAEP decryption
- ECDSA P-256 signing
- AES-256-GCM encryption/decryption

### Botan (via FFI)
- RSA-2048 PKCS#1 v1.5 decryption
- RSA-2048 OAEP decryption
- ECDSA P-256 signing
- AES-256-GCM encryption/decryption
- ChaCha20-Poly1305 encryption/decryption

## BoringSSL (Not Integrated)

**Status**: Code complete but not integrated.

BoringSSL tests are implemented (`boringssl.rs`) but cannot run in the same binary as LibreSSL tests due to symbol conflicts between the `openssl` and `boring` Rust crates. Both crates link to OpenSSL-compatible libraries that export identical symbol names.

See [`BORINGSSL_INVESTIGATION_REPORT.md`](../../../BORINGSSL_INVESTIGATION_REPORT.md) for:
- Full technical analysis
- 8 implemented tests (RSA, ECDSA, AES-GCM)
- Rationale for exclusion
- Possible future integration approaches

**Why this matters**: BoringSSL powers Chrome, Android, and gRPC (billions of users). Testing it would provide massive real-world validation, but tooling limitations prevent integration at this time.

## Setup Requirements

### macOS (with devenv)

1. Enter the devenv shell:
   ```bash
   devenv shell
   ```

2. Find the LibreSSL path:
   ```bash
   LIBRESSL_DIR=$(find /nix/store -maxdepth 1 -name "*libressl-*" -type d | grep -v "\\-nc\\|\\-man" | head -1)
   ```

3. Export the OpenSSL directory:
   ```bash
   export OPENSSL_DIR="$LIBRESSL_DIR"
   ```

4. Run the tests:
   ```bash
   cargo test --test crypto c_libraries
   ```

### Alternative: System OpenSSL/LibreSSL

If you have OpenSSL or LibreSSL installed system-wide (e.g., via Homebrew):

```bash
# Homebrew OpenSSL
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3

# Or Homebrew LibreSSL
export OPENSSL_DIR=/opt/homebrew/opt/libressl

cargo test --test crypto c_libraries
```

### Linux

On Linux, install development packages:

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev libsodium-dev

# Fedora/RHEL
sudo dnf install openssl-devel libsodium-devel

cargo test --test crypto c_libraries
```

## Running with PMU Timers (Recommended)

For best results on Apple Silicon, use PMU timers:

```bash
sudo -E cargo test --test crypto c_libraries
```

The `-E` flag preserves environment variables including `OPENSSL_DIR`.

## Why C Libraries?

Testing C/C++ libraries demonstrates tacet's cross-language validation capabilities:

1. **FFI Harness Verification**: FFI overhead can introduce measurement noise - harness sanity checks are critical
2. **Real-World Validation**: LibreSSL and Libsodium are production libraries with millions of users
3. **CVE Detection**: Historical vulnerabilities (MARVIN, ECDSA timing leaks) validate the methodology
4. **Constant-Time Expectations**: Libsodium is designed for constant-time operation - should PASS all tests
5. **PKCS#1 v1.5 Sensitivity**: LibreSSL RSA PKCS#1 v1.5 tests for Bleichenbacher-class timing leaks

## Expected Results

- **Libsodium**: All tests should PASS (designed for constant-time operation)
- **LibreSSL RSA PKCS#1 v1.5**: Watch for timing leaks (MARVIN-class vulnerabilities)
- **LibreSSL ECDSA P-256**: Should PASS (recent implementations use constant-time techniques)
- **LibreSSL AES-GCM**: Should PASS on hardware with AES-NI; software fallback may show timing

## Troubleshooting

### `openssl-sys` build failure

If you see "OpenSSL include directory does not exist":
- Ensure `OPENSSL_DIR` is set correctly
- Check that the path contains both `include/` and `lib/` directories
- On NixOS/devenv, you may need the `.dev` output: `libressl.dev`

### `sodiumoxide` linking errors

If libsodium is not found:
- Install libsodium-dev (Linux) or ensure it's in your devenv
- Check `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS)

### Tests marked `#[ignore]`

Some tests are computationally expensive (RSA-2048 signing). Run with:
```bash
cargo test --test crypto c_libraries -- --ignored
```
