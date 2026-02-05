# BoringSSL Timing Side-Channel Investigation Report

**Date**: 2026-02-05
**Platform**: macOS ARM64 (Apple Silicon)
**BoringSSL Version**: 5.0.0-alpha.3 (via `boring` Rust crate)
**tacet Version**: 0.4.2
**Status**: ✅ Code Complete, ❌ Not Integrated (tooling limitation)

## Executive Summary

BoringSSL timing tests were developed but **cannot be integrated** into the main test suite due to a fundamental compatibility issue: the `openssl` and `boring` Rust crates cannot coexist in the same binary. Both crates link to their respective OpenSSL/BoringSSL libraries, which export conflicting symbols.

## Background

### Why BoringSSL?

BoringSSL is Google's fork of OpenSSL, designed to meet Google's specific needs. It powers:

- **Chrome browser** (billions of users)
- **Android OS** (billions of devices)
- **gRPC** (widely used in microservices)
- Other Google infrastructure

Testing BoringSSL is valuable for:
1. **Massive user base validation** - Real-world impact at scale
2. **Paper credibility** - "Tested crypto implementations used by Chrome/Android"
3. **Comparison with OpenSSL/LibreSSL** - Understanding divergence in constant-time implementations

### Implementation Status

**Code location**: `/Users/agucova/repos/tacet/crates/tacet/tests/crypto/c_libraries/boringssl.rs`

**Tests implemented** (8 total):
- ✅ RSA-2048 PKCS#1 v1.5 decryption (Bleichenbacher/MARVIN)
- ✅ RSA-2048 OAEP decryption
- ✅ RSA-2048 PSS signing
- ✅ ECDSA P-256 signing
- ✅ AES-256-GCM encryption
- ✅ AES-256-GCM decryption
- ✅ Harness sanity check
- ❌ ChaCha20-Poly1305 (not available via standard API)

## Technical Limitations

### 1. Crate Compatibility Issue

**Problem**: The `openssl` crate (used for LibreSSL tests) and `boring` crate (BoringSSL bindings) cannot coexist in the same binary.

**Root cause**:
```
error: linking with `cc` failed: exit status: 1
  = note: "_ERR_get_error_all", referenced from:
          openssl::error::Error::get::hce1f4f83a41a1a36 in libopenssl
```

Both crates:
- Link to C libraries (`libssl`, `libcrypto`)
- Export identical symbol names
- Cause linker conflicts when combined

**Upstream reference**: This is a known limitation in the Rust ecosystem. The `boring` crate is explicitly designed as a drop-in replacement for `openssl`, not a complement.

### 2. ChaCha20-Poly1305 API Differences

**Problem**: BoringSSL uses a different API (`EVP_AEAD`) for ChaCha20-Poly1305 instead of the standard `EVP_CIPHER` interface.

**Impact**: The `boring::symm::Cipher` enum does not expose `chacha20_poly1305()` method.

**Workaround**: Would require using BoringSSL's low-level `EVP_AEAD` API directly via FFI, which is not exposed in the `boring` crate's safe interface.

**Reference**:
- [pyca/cryptography #8946](https://github.com/pyca/cryptography/pull/8946) - "Add support for ChaCha20-Poly1305 with BoringSSL"
- [docs.rs/boring](https://docs.rs/boring) - Cipher API documentation

## Possible Solutions

### Option 1: Separate Test Binary (Recommended)

Create a dedicated test binary for BoringSSL:

**Pros**:
- Clean separation
- No conflicts
- Easy to maintain

**Cons**:
- Separate invocation needed
- Cannot run in CI with other tests
- Duplicates test infrastructure

**Implementation**:
```toml
# Cargo.toml
[[test]]
name = "boringssl"
path = "tests/boringssl.rs"
```

Then conditionally exclude `openssl` crate when building BoringSSL tests.

### Option 2: Feature Flags (Complex)

Use mutually exclusive features:

**Pros**:
- Single codebase
- User chooses which to test

**Cons**:
- Complex configuration
- Cannot test both in one CI run
- Error-prone for users

### Option 3: Skip BoringSSL Tests (Current)

Document the limitation and skip BoringSSL testing.

**Pros**:
- Simplest solution
- No maintenance burden

**Cons**:
- Misses validation of Chrome/Android crypto
- Less paper impact

## Operations Tested (Implementation Complete, Not Runnable)

| Operation | Attack Class | Threshold | Status |
|-----------|-------------|-----------|--------|
| RSA PKCS#1 v1.5 decrypt | Bleichenbacher, MARVIN | 100ns | ✅ Implemented |
| RSA OAEP decrypt | Padding oracle | 100ns | ✅ Implemented |
| RSA PSS sign | Private key leak | 100ns | ✅ Implemented |
| ECDSA P-256 sign | Nonce leak, private key | ~2 cycles | ✅ Implemented |
| AES-256-GCM encrypt | Data-dependent timing | 100ns | ✅ Implemented |
| AES-256-GCM decrypt | MAC timing, padding | 100ns | ✅ Implemented |
| ChaCha20-Poly1305 | AEAD timing | 100ns | ❌ API unavailable |

### Test Configuration

All tests use:
- **Time budget**: 30–60 seconds
- **Max samples**: 50,000
- **Attacker models**:
  - `SharedHardware` (~2 cycles @ 5 GHz) for ECDSA
  - `AdjacentNetwork` (100ns) for RSA/AES
- **Pattern**: DudeCT two-class (zeros vs random)
- **PMU timers**: Designed for `sudo` execution with cycle-accurate measurements

### Expected Behaviors

Based on BoringSSL's design principles:

**Should PASS** (constant-time):
- RSA OAEP decryption (constant-time padding checks)
- ECDSA P-256 signing (constant-time scalar multiplication)
- AES-256-GCM (hardware-accelerated or table-free implementation)

**May FAIL** (known issues):
- RSA PKCS#1 v1.5 decryption - Historical leaks (Bleichenbacher, ROBOT, MARVIN)
  - BoringSSL has patches but timing channels persist in some cases
  - Comparison with LibreSSL/OpenSSL would be valuable

## Recommendations

### For Paper/Publication

1. **Document the limitation** in the methodology section
2. **Note attempted coverage** - "BoringSSL tests developed but excluded due to tooling limitations"
3. **Focus on libraries tested** - LibreSSL, wolfSSL, mbedTLS provide sufficient C library coverage
4. **Future work section** - Mention BoringSSL as valuable future validation target

### For Future Implementation

1. **Separate test binary** approach (Option 1) is most practical
2. **CI configuration**:
   ```yaml
   # Run standard tests
   - cargo test --test crypto

   # Run BoringSSL tests separately (if implemented)
   - cargo test --test boringssl --features boring-tests
   ```
3. **Document** how users can manually run BoringSSL tests

### For Immediate Use

**Status**: Tests are code-complete but not integrated.

**To run** (after addressing linking issues):
```bash
# Would require:
# 1. Separate test binary or feature gating
# 2. Exclude openssl crate when using boring
cargo test --test boringssl -- --test-threads=1
sudo cargo test --test boringssl -- --ignored  # For PMU timers
```

## Comparison Value (If Implemented)

Testing BoringSSL alongside LibreSSL/wolfSSL/mbedTLS would reveal:

1. **Divergence in constant-time practices**:
   - Google's MARVIN mitigations vs other implementations
   - ECDSA nonce generation differences
   - AES-GCM timing profiles

2. **Real-world validation**:
   - Crypto used by Chrome = billions of TLS connections
   - Android crypto stack = billions of devices
   - gRPC authentication = enterprise-scale microservices

3. **Security posture**:
   - Does BoringSSL's aggressive constant-time focus show measurably better results?
   - Are there BoringSSL-specific timing channels?

## Conclusion

BoringSSL timing tests are **fully implemented** but **cannot be executed** in the current test infrastructure due to `openssl` ↔ `boring` crate conflicts. The tests remain valuable for:

- **Future separate binary** if project priorities shift
- **Demonstration of methodology** applied to major crypto library
- **Documentation** of tacet's ability to test diverse implementations

For the current scope, the existing C library coverage (LibreSSL, wolfSSL, mbedTLS, libsodium) provides sufficient validation of C-based cryptographic implementations.

---

## References

- [BoringSSL GitHub](https://github.com/google/boringssl)
- [boring crate (Cloudflare)](https://github.com/cloudflare/boring)
- [docs.rs/boring](https://docs.rs/boring)
- [MARVIN vulnerability (CVE-2023-50782)](https://people.redhat.com/~hkario/marvin/)
- BoringSSL test code: `/Users/agucova/repos/tacet/crates/tacet/tests/crypto/c_libraries/boringssl.rs`

## Test Suite Statistics

### C/C++ Library Coverage (Integrated)

| Library | Tests | Lines of Code | Status |
|---------|-------|---------------|--------|
| LibreSSL | 6 | 586 | ✅ Integrated |
| libsodium | 8 | 681 | ✅ Integrated |
| wolfSSL | 6 | 945 | ✅ Integrated |
| mbedTLS | 5 | 741 | ✅ Integrated |
| Botan | 5 | 861 | ✅ Integrated |
| **BoringSSL** | **7** | **659** | ❌ **Not Integrated** |
| **Total** | **37** | **4,473** | **32 integrated, 5 excluded** |

### BoringSSL Tests (Excluded)

**File**: `crates/tacet/tests/crypto/c_libraries/boringssl.rs` (659 lines)

**Tests implemented**:
1. `boringssl_rsa_2048_pkcs1v15_decrypt_constant_time` - Bleichenbacher/MARVIN
2. `boringssl_rsa_2048_oaep_decrypt_constant_time` - Padding oracle resistance
3. `boringssl_rsa_2048_pss_sign_constant_time` - PSS signature timing
4. `boringssl_ecdsa_p256_sign_constant_time` - Private key leak detection
5. `boringssl_aes_256_gcm_encrypt_constant_time` - AEAD encryption timing
6. `boringssl_aes_256_gcm_decrypt_constant_time` - AEAD decryption + MAC verification
7. `boringssl_harness_sanity_check` - FFI harness validation

**Test configuration**:
- All use pool-based generation (100-element pools for RSA/AES)
- Zeros vs random pattern (DudeCT two-class)
- 30–60 second time budgets
- SharedHardware (~2 cycles) for ECDSA, AdjacentNetwork (100ns) for RSA/AES

## Integration Path (If Needed in Future)

### Step 1: Create Separate Test Binary

```toml
# Cargo.toml
[[test]]
name = "boringssl"
path = "tests/boringssl_standalone.rs"
```

### Step 2: Feature Gate Dependencies

```toml
[dev-dependencies]
openssl = { version = "0.10", optional = true }
boring = { version = "5.0", optional = true }

[features]
default = ["test-openssl"]
test-openssl = ["dep:openssl"]
test-boringssl = ["dep:boring"]
```

### Step 3: Conditional Compilation

```rust
// tests/boringssl_standalone.rs
#[cfg(feature = "test-boringssl")]
mod boringssl_tests;

#[cfg(not(feature = "test-boringssl"))]
compile_error!("Run with: cargo test --test boringssl --features test-boringssl");
```

### Step 4: CI Configuration

```yaml
# .github/workflows/tests.yml
- name: Run standard tests
  run: cargo test --features test-openssl

- name: Run BoringSSL tests
  run: cargo test --test boringssl --features test-boringssl --no-default-features
```

## Appendix: Code Snippet

```rust
// Example: BoringSSL RSA PKCS#1 v1.5 test (non-functional due to linking)
use boring::rsa::{Padding, Rsa};
use boring::pkey::PKey;

let rsa = Rsa::generate(2048).unwrap();
let private_key = PKey::from_rsa(rsa.clone()).unwrap();

let outcome = TimingOracle::for_attacker(AttackerModel::AdjacentNetwork)
    .time_budget(Duration::from_secs(60))
    .test(inputs, |ciphertext| {
        let rsa = private_key.rsa().unwrap();
        let mut decrypted = vec![0u8; 256];
        rsa.private_decrypt(ciphertext, &mut decrypted, Padding::PKCS1);
    });
```

This pattern mirrors LibreSSL/wolfSSL tests but uses BoringSSL's implementation.

---

**End of Report**
