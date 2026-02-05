# Botan Timing Side-Channel Investigation Report

**Date**: February 5, 2026
**Platform**: macOS ARM64 (Apple Silicon)
**Botan Version**: 3.10.0 (release, dated 20251106)
**Tacet Version**: 0.4.2 (v7.1)

## Executive Summary

This report documents the addition of timing side-channel tests for **Botan**, a modern C++11/14 cryptographic library that emphasizes constant-time implementations and side-channel resistance. Botan is the **only modern C++ crypto library** in the tacet test suite, making it a valuable data point for comparing modern C++ design against C implementations.

## Why Botan?

1. **Modern C++ Focus**: Unlike other C libraries (LibreSSL, wolfSSL, mbedTLS), Botan is written in modern C++11/14 with explicit attention to constant-time operations
2. **Constant-Time Philosophy**: Botan's design explicitly targets side-channel resistance in core cryptographic primitives
3. **Post-Quantum Ready**: Botan includes post-quantum algorithm support (Kyber, Dilithium), though not all are available via FFI
4. **Academic Validation Target**: Good baseline for measuring whether modern C++ design provides timing advantages over C
5. **Paper Value**: Adds "validated C++ crypto implementations with modern design" to tacet's coverage

## Test Implementation

### Location
- **File**: `/Users/agucova/repos/tacet/crates/tacet/tests/crypto/c_libraries/botan.rs`
- **Module**: Added to `crates/tacet/tests/crypto/c_libraries.rs`
- **Build Configuration**: Updated `crates/tacet/build.rs` with Botan linker paths

### FFI Integration
Botan provides a clean C89 FFI API (`botan/ffi.h`) that:
- Uses opaque pointer types for all objects
- Provides RAII-friendly lifecycle management
- Returns consistent error codes
- Avoids memory ownership transfer across FFI boundary

This made FFI integration straightforward compared to other C libraries.

### Operations Tested

#### 1. RSA-2048 PKCS#1 v1.5 Decryption
- **Test**: `botan_rsa_2048_pkcs1v15_decrypt_constant_time`
- **Attacker Model**: `AdjacentNetwork` (100ns threshold)
- **Time Budget**: 60 seconds
- **Pattern**: Pool-based (100 ciphertexts per class)
- **Historical Context**: Tests for Bleichenbacher-class attacks (1998), ROBOT (2017), MARVIN (2023)
- **Status**: ⏳ Pending execution

#### 2. RSA-2048 OAEP Decryption (SHA-256)
- **Test**: `botan_rsa_2048_oaep_decrypt_constant_time`
- **Attacker Model**: `AdjacentNetwork` (100ns threshold)
- **Time Budget**: 60 seconds
- **Pattern**: Pool-based (100 ciphertexts per class)
- **OAEP Variant**: OAEP(SHA-256) with MGF1
- **Status**: ⏳ Pending execution

#### 3. ECDSA P-256 Signing
- **Test**: `botan_ecdsa_p256_sign_constant_time`
- **Attacker Model**: `SharedHardware` (~2 cycles @ 5 GHz)
- **Time Budget**: 60 seconds
- **Pattern**: Zeros vs random messages
- **Critical**: Nonce generation and modular inversion must be constant-time
- **Status**: ⏳ Pending execution

#### 4. AES-256-GCM Encryption
- **Test**: `botan_aes_256_gcm_encrypt_constant_time`
- **Attacker Model**: `AdjacentNetwork` (100ns threshold)
- **Time Budget**: 30 seconds
- **Pattern**: Zeros vs random plaintext
- **Note**: Tests data-dependent timing in GCM mode
- **Status**: ⏳ Pending execution

#### 5. Harness Sanity Check
- **Test**: `botan_harness_sanity_check`
- **Purpose**: Verify FFI overhead is acceptable
- **Pattern**: Identical ciphertexts for both classes
- **Expected**: Pass (no timing difference)
- **Status**: ⏳ Pending execution

### Post-Quantum Support

Botan 3.10.0 includes Kyber and Dilithium implementations, but:
- **Not available via C FFI**: Post-quantum KEM/signature operations are not exposed in `ffi.h`
- **Future work**: May require direct C++ bindings or waiting for FFI expansion
- **Alternative**: Could test via Botan's command-line tools if needed

## Comparison Framework

### C Library Comparison
Botan results will be compared against:

| Library | Language | Design Philosophy | Version |
|---------|----------|------------------|---------|
| **LibreSSL** | C | Conservative, OpenBSD-derived | 3.x |
| **wolfSSL** | C | Embedded/IoT focus, configurable | 5.8.4 |
| **mbedTLS** | C | ARM/embedded target | 3.6.5 |
| **Botan** | **C++11/14** | **Modern, constant-time focused** | **3.10.0** |

### Key Research Questions
1. **Does modern C++ provide timing advantages?**
   - RAII for resource management
   - Template metaprogramming for compile-time guarantees
   - Stronger type safety

2. **How does Botan's explicit constant-time focus compare to C implementations?**
   - Compare RSA PKCS#1 v1.5 results across all libraries
   - Compare ECDSA P-256 results

3. **FFI noise floor comparison**
   - Does C++ FFI introduce more overhead than C FFI?
   - Compare harness sanity check results

## Expected Challenges

### 1. FFI Noise Floor
- **Issue**: C++ FFI may introduce additional overhead compared to pure C
- **Mitigation**: Pool-based pattern reduces FFI call frequency
- **Validation**: Harness sanity check confirms FFI is acceptable

### 2. Build Configuration
- **macOS**: Uses Homebrew-installed Botan (`/opt/homebrew/lib/libbotan-3.dylib`)
- **Linux**: Not yet tested (would use system package or custom build)
- **Version Warning**: Homebrew Botan built for macOS 26.0, may show linker warnings on older systems

### 3. Opaque Struct Sizes
- **Solution**: Used opaque pointer types (`*mut std::ffi::c_void`) throughout
- **No issues**: Botan FFI doesn't require knowing struct sizes

## Current Status

### ✅ Completed
- [x] Install Botan 3.10.0 via Homebrew
- [x] Update `build.rs` with Botan linker configuration
- [x] Create FFI bindings for required operations
- [x] Implement RAII wrappers for Botan objects
- [x] Write 5 comprehensive tests (4 operations + 1 sanity check)
- [x] Add Botan module to test suite
- [x] Verify Botan FFI linkage (test compiles and links)

### ⏳ Pending
- [ ] Run tests with `sudo` for PMU timer access
- [ ] Execute full test suite
- [ ] Compare results with C implementations
- [ ] Document timing characteristics
- [ ] Analyze constant-time effectiveness
- [ ] Report findings to Botan maintainers if issues found

## Test Execution Plan

### Phase 1: Sanity Check (5-10 minutes)
```bash
sudo cargo test --test crypto botan_harness_sanity_check
```
**Expected**: Pass (identical inputs should show no timing difference)
**If fails**: FFI overhead too high, need to adjust test configuration

### Phase 2: Quick Validation (30-60 minutes)
```bash
sudo cargo test --test crypto botan_aes_256_gcm_encrypt_constant_time
sudo cargo test --test crypto botan_ecdsa_p256_sign_constant_time
```
**Expected**: Pass (both should be constant-time)
**If fails**: Investigate which operation is leaking

### Phase 3: RSA Deep Dive (60-90 minutes)
```bash
sudo cargo test --test crypto botan_rsa_2048_pkcs1v15_decrypt_constant_time
sudo cargo test --test crypto botan_rsa_2048_oaep_decrypt_constant_time
```
**Expected**: Pass (Botan claims constant-time RSA)
**If fails**: Compare with LibreSSL/wolfSSL results, document vulnerability

### Phase 4: Comparative Analysis (2-3 hours)
Run all Botan tests alongside corresponding LibreSSL, wolfSSL, and mbedTLS tests:
```bash
sudo cargo test --test crypto \
  botan_rsa_2048_pkcs1v15_decrypt_constant_time \
  libressl_rsa_2048_pkcs1v15_decrypt_constant_time \
  wolfssl_rsa_2048_pkcs1v15_decrypt_constant_time
```
Compare results for:
- Leak probability
- Effect size (if leak detected)
- Measurement quality
- Sample efficiency

## Analysis Framework

### Metrics to Compare

1. **Pass/Fail/Inconclusive Rate**
   - Does Botan pass more tests than C libraries?

2. **Effect Size (if fails)**
   - How large is the timing leak in nanoseconds?
   - Compare maximum effect across libraries

3. **Measurement Quality**
   - Excellent / Good / Poor / TooNoisy
   - Does C++ FFI reduce measurement quality?

4. **Sample Efficiency**
   - How many samples needed to reach conclusion?
   - Does Botan's constant-time design converge faster?

### Statistical Rigor

All tests use:
- **Bayesian adaptive sampling** (tacet v7.1)
- **W₁ distance metric** (more sensitive than t-test)
- **Quality gates** (5 checks for early stopping)
- **DudeCT two-class pattern** (zeros vs random)

## Known Build Issues

### LibreSSL Compatibility
The test suite currently has LibreSSL/OpenSSL 3.x compatibility issues:
- Missing symbols: `ERR_get_error_all`, `EVP_CIPHER_CTX_get0_cipher`, etc.
- **Impact**: Cannot run full `crypto` test suite until fixed
- **Workaround**: Tests can be run individually once LibreSSL issues resolved

### Botan-Specific Issues
- **None**: Botan FFI linkage verified, no build errors specific to Botan
- **Linker Warning**: "dylib was built for newer macOS version (26.0) than being linked (14.0)"
  - **Impact**: Warning only, does not affect functionality

## Paper Contributions

Including Botan in the tacet paper provides:

1. **Modern C++ Coverage**: Only modern C++ library tested
2. **Design Philosophy Comparison**: Explicit constant-time design vs. traditional C
3. **Language Analysis**: C vs. C++ for side-channel resistance
4. **Academic Credibility**: Botan is well-regarded in cryptographic community
5. **Post-Quantum Context**: Foundation for future PQ algorithm testing

## Recommendations for Botan Maintainers

*Will be updated after test execution*

### If Tests Pass
- Document tacet validation in Botan release notes
- Consider adding tacet to Botan's CI pipeline
- Publish timing guarantees with quantified thresholds

### If Tests Fail
- Provide detailed vulnerability report
- Compare with C library results to isolate root cause
- Suggest constant-time implementation improvements
- Consider whether C++ abstraction overhead contributes to leaks

## Future Work

1. **Post-Quantum FFI Expansion**
   - Work with Botan maintainers to expose Kyber/Dilithium via FFI
   - Test when available

2. **Linux Testing**
   - Verify results on x86_64 with different timer characteristics
   - Test on ARM64 Linux (e.g., AWS Graviton)

3. **Additional Operations**
   - ChaCha20-Poly1305 AEAD
   - X25519 key agreement
   - Ed25519 signatures

4. **Performance Profiling**
   - Compare raw operation speed vs. C libraries
   - Quantify FFI overhead

## References

- **Botan Website**: https://botan.randombit.net/
- **Botan C FFI Documentation**: https://botan.randombit.net/handbook/api_ref/ffi.html
- **Tacet Specification**: `website/src/content/docs/reference/specification.md` (v7.1)
- **Similar C FFI Tests**: `crates/tacet/tests/crypto/c_libraries/libressl.rs`
- **Build Configuration**: `crates/tacet/build.rs`

---

**Report Status**: Initial implementation complete, pending test execution
**Next Action**: Run `sudo cargo test --test crypto botan_harness_sanity_check` to validate FFI harness
