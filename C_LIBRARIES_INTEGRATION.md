# C/C++ Cryptographic Library Integration

## Summary

Successfully integrated **LibreSSL** and **Libsodium** C/C++ cryptographic libraries into tacet's test suite to demonstrate cross-language validation capabilities.

## Implementation

### File Structure
```
crates/tacet/tests/crypto/
├── c_libraries.rs              # Module declaration
└── c_libraries/
    ├── README.md               # Setup and usage documentation
    ├── libressl.rs             # LibreSSL timing tests
    └── libsodium.rs            # Libsodium timing tests
```

### LibreSSL Tests (`libressl.rs`)

**Operations tested:**
1. **RSA-2048 PKCS#1 v1.5 decryption** - Tests for Bleichenbacher-class timing leaks (MARVIN vulnerability, CVE-2023-50782)
2. **RSA-2048 OAEP decryption** - Validates constant-time properties of OAEP padding
3. **ECDSA P-256 signing** - Tests nonce generation and modular inversion (multiple 2024 CVEs in other implementations)
4. **ECDSA P-256 verification** - Validates public-key operation constant-time properties
5. **AES-256-GCM encryption** - Tests software fallback paths for data-dependent timing
6. **Harness sanity check** - Verifies FFI overhead doesn't introduce spurious timing differences

**Key features:**
- Pool-based pattern to avoid caching artifacts (100+ ciphertexts per class)
- Comprehensive error reporting with CVE context
- Explicit harness verification (critical for FFI tests)
- Uses `AttackerModel::SharedHardware` (~2 cycles) for ECDSA/Ed25519
- Uses `AttackerModel::AdjacentNetwork` (100ns) for RSA/AES-GCM

### Libsodium Tests (`libsodium.rs`)

**Operations tested:**
1. **Ed25519 signing** - Validates constant-time properties of signature generation
2. **Ed25519 verification** - Tests signature verification timing
3. **X25519 scalar multiplication** - Core ECDH operation with zeros vs random scalars
4. **crypto_box encryption** - X25519 + XSalsa20 + Poly1305 authenticated encryption
5. **crypto_box decryption** - MAC verification constant-time properties
6. **crypto_secretbox encryption** - XSalsa20 + Poly1305 symmetric AEAD
7. **crypto_secretbox decryption** - Symmetric MAC verification
8. **Harness sanity check** - FFI overhead verification

**Key features:**
- Libsodium is designed for constant-time operation - all tests should PASS
- Tests validate misuse-resistance claims
- Pool-based patterns for operations with state (100 samples per class)
- Unique nonces for each measurement (AEAD operations)
- Uses `AttackerModel::SharedHardware` for Ed25519/X25519
- Uses `AttackerModel::AdjacentNetwork` for crypto_box/secretbox

## Test Patterns

All tests follow **DudeCT's two-class pattern**:
- **Baseline class**: All zeros or fixed values (triggers slow path or matches secret)
- **Sample class**: Random values (triggers fast path or mismatches)

### RSA Decryption Pattern
```rust
// Pre-generate pools to avoid caching artifacts
let pool_baseline: Vec<Vec<u8>> = (0..POOL_SIZE)
    .map(|_| encrypt_random_message())
    .collect();

let pool_sample: Vec<Vec<u8>> = (0..POOL_SIZE)
    .map(|_| encrypt_random_message())
    .collect();

// Cycle through pools
let inputs = InputPair::new(
    || pool_baseline[next_baseline()].clone(),
    || pool_sample[next_sample()].clone(),
);
```

### ECDSA/Ed25519 Signing Pattern
```rust
// Zeros vs random for messages
let inputs = InputPair::new(
    || [0u8; 32],     // Baseline: all zeros
    rand_bytes_32,    // Sample: random bytes
);
```

### X25519 Scalar Multiplication Pattern
```rust
// Fixed scalar vs random scalars
let fixed_scalar: [u8; 32] = [0x4e, 0x5a, ...];  // Non-zero fixed value
let inputs = InputPair::new(
    || fixed_scalar,
    rand_bytes_32,    // Random scalars
);
```

## Build Configuration

### Environment Setup

The tests require LibreSSL and Libsodium development files. Two approaches:

#### Option 1: Nix/devenv (Recommended)

1. Update `devenv.nix` (already done):
```nix
packages = with pkgs; [
    libressl.dev      # LibreSSL with headers
    libsodium.dev     # Libsodium with headers
    ...
];
```

2. Build with environment variables:
```bash
# Find LibreSSL paths
LIBRESSL_DEV=$(nix-build '<nixpkgs>' -A libressl.dev)
LIBRESSL_LIB=$(nix-build '<nixpkgs>' -A libressl)

# Export paths
export OPENSSL_DIR="$LIBRESSL_DEV"
export OPENSSL_LIB_DIR="$LIBRESSL_LIB/lib"

# Build tests
cargo check --test crypto
```

#### Option 2: System Libraries

Install via Homebrew (macOS) or system package manager:
```bash
# Homebrew
brew install libressl libsodium
export OPENSSL_DIR=/opt/homebrew/opt/libressl

# Debian/Ubuntu
sudo apt-get install libssl-dev libsodium-dev

# Fedora/RHEL
sudo dnf install openssl-devel libsodium-devel
```

### Running Tests

```bash
# Standard run (requires environment variables above)
cargo test --test crypto c_libraries

# With PMU timers (recommended for Apple Silicon)
sudo -E cargo test --test crypto c_libraries

# Run specific library
cargo test --test crypto c_libraries::libressl
cargo test --test crypto c_libraries::libsodium

# Run specific test
cargo test --test crypto libressl_rsa_2048_pkcs1v15_decrypt_constant_time
```

## Expected Results

### Libsodium
**All tests should PASS** - Libsodium is designed for constant-time operation and misuse resistance.

If any Libsodium test FAILS:
- Verify FFI harness with sanity check
- Check for measurement noise (quality gates)
- Report as potential vulnerability (unexpected for Libsodium)

### LibreSSL

**RSA PKCS#1 v1.5 decryption**: Watch for timing leaks
- Historical vulnerabilities: Bleichenbacher (1998), ROBOT (2017), MARVIN (2023)
- Modern LibreSSL should be constant-time, but worth validating
- FAIL indicates potential MARVIN-class vulnerability

**RSA OAEP decryption**: Should PASS
- OAEP is more robust than PKCS#1 v1.5
- FAIL indicates padding oracle timing leak

**ECDSA P-256 signing**: Should PASS
- Modern implementations use constant-time scalar multiplication
- FAIL could indicate nonce generation or modular inversion leak
- Similar to multiple 2024 CVEs in other ECDSA implementations

**ECDSA P-256 verification**: Should PASS
- Public-key operation, but should still be constant-time
- FAIL indicates information leakage through verification timing

**AES-256-GCM encryption**: Should PASS on hardware with AES-NI
- Software fallback may show timing (data-dependent table lookups)
- FAIL on AES-NI hardware indicates cache-timing vulnerability

## Dependencies

Added to `Cargo.toml` dev-dependencies:
```toml
[dev-dependencies]
openssl = "0.10.75"      # LibreSSL/OpenSSL Rust bindings
sodiumoxide = "0.2.7"    # Libsodium Rust bindings
```

Both crates use FFI to call native C libraries.

## FFI Harness Verification

**CRITICAL**: FFI overhead can introduce noise. Each test file includes a sanity check:

```rust
#[test]
fn libressl_harness_sanity_check() {
    // Use identical inputs for both classes
    let inputs = InputPair::new(
        || same_ciphertext.clone(),
        || same_ciphertext.clone(),
    );

    // Should always PASS
    assert!(outcome.passed());
}
```

**If sanity check fails**: FFI harness or measurement environment issue, not a timing leak.

## Known Issues

1. **openssl-sys build requirements**: Needs `OPENSSL_DIR` pointing to LibreSSL with both `include/` and `lib/` directories

2. **NixOS/devenv split outputs**: Standard `libressl` package doesn't include headers. Must use `libressl.dev`.

3. **sodiumoxide API**: Uses module-qualified functions (e.g., `ed25519::gen_keypair()`), not direct imports

4. **Scalar type hashing**: sodiumoxide's `Scalar` doesn't implement `Hash`. Use byte arrays `[u8; 32]` for inputs, construct `Scalar` in measurement closure.

## Future Work

1. **Automated environment setup**: Shell script or Cargo build.rs to find/set OPENSSL_DIR
2. **Additional operations**:
   - LibreSSL: RSA-PSS, ECDH P-384, ChaCha20-Poly1305
   - Libsodium: crypto_sign (detached signatures), crypto_auth (HMAC-SHA512-256)
3. **Cross-platform CI**: Test on Linux and macOS in GitHub Actions
4. **Vulnerability database**: Track known CVEs and expected test outcomes
5. **Comparative analysis**: LibreSSL vs OpenSSL vs BoringSSL on same operations

## References

- **MARVIN vulnerability**: CVE-2023-50782 (RSA PKCS#1 v1.5 timing leak)
- **Bleichenbacher attack**: Original 1998 padding oracle attack on RSA PKCS#1 v1.5
- **ROBOT attack**: 2017 return of Bleichenbacher via timing side channels
- **DudeCT methodology**: "Dude, is my code constant time?" (USENIX Security 2017)
- **Libsodium design**: https://doc.libsodium.org/
- **LibreSSL project**: https://www.libressl.org/

## Deliverables

✅ New test files:
- `crates/tacet/tests/crypto/c_libraries/libressl.rs` (580 lines, 6 tests + harness check)
- `crates/tacet/tests/crypto/c_libraries/libsodium.rs` (680 lines, 8 tests + harness check)
- `crates/tacet/tests/crypto/c_libraries/README.md` (comprehensive setup documentation)

✅ Updated files:
- `devenv.nix`: Added `libressl.dev` and `libsodium.dev` to packages
- `crates/tacet/tests/crypto/c_libraries.rs`: Module structure (already existed)

✅ Documentation:
- Setup requirements for macOS, Linux, and devenv
- FFI harness verification patterns
- Expected results and vulnerability context
- Troubleshooting guide

✅ Compilation: All tests compile successfully with proper environment setup

📋 Testing: Tests are ready to run with `sudo -E cargo test --test crypto c_libraries` (requires OPENSSL_DIR environment variable)

## Validation

To verify the integration works:

```bash
# Set environment (adjust path to your libressl.dev output)
export OPENSSL_DIR=/nix/store/l43j2hra6c8p6wdglprhzbny24rp5mnf-libressl-4.2.1-dev
export OPENSSL_LIB_DIR=/nix/store/v83k0ga15a07k5l1pild1lg3chkbxfpz-libressl-4.2.1/lib

# Verify compilation
cargo check --test crypto

# Run harness sanity checks (fast, no timing measurements)
cargo test --test crypto harness_sanity_check

# Run full suite (requires sudo for PMU timers on macOS)
sudo -E cargo test --test crypto c_libraries
```

Expected output:
- Libsodium tests: All PASS
- LibreSSL tests: Depends on implementation (watch for MARVIN in PKCS#1 v1.5)
- Harness sanity checks: Must PASS (verifies FFI overhead is acceptable)
