# Go Standard Library Timing Side-Channel Investigation Report

**Date**: 2026-02-05
**Investigator**: Claude Code Agent
**Previous Report**: `/Users/agucova/repos/tacet/GO_STDLIB_CRYPTO_ANALYSIS.md`
**Test Suite**: `/Users/agucova/repos/tacet/crates/tacet-go/stdlib_crypto_test.go`

## Executive Summary

This investigation reviewed timing side-channel findings reported by a previous agent for Go's standard library cryptographic implementations. **Most of the reported findings are either test harness issues, misinterpretations of intended behavior, or apply only to architectures not under test.**

### Critical Assessment

1. **CVE-2025-22866**: **NOT APPLICABLE** to macOS ARM64. Affects only ppc64/ppc64le architectures.
2. **ECDSA P-256 Verification (135ns leak)**: **LIKELY HARNESS ISSUE** - testing verification with wrong inputs.
3. **RSA PKCS#1 v1.5**: **KNOWN LIMITATION** - already documented as unsafe, not a new finding.
4. **Test methodology**: Several tests violate the two-class pattern documented in `/website/src/content/docs/core-concepts/two-class-pattern.mdx`.

---

## Detailed Analysis of Each Finding

### Finding 1: ECDSA P-256 Signing (3.32 ns leak)

**Claim**: 3.32 ns timing leak, related to CVE-2025-22866

**Harness Validation**: ✅ HARNESS_OK (for general timing detection)
The test uses zeros vs random for message digests, which is correct per the two-class pattern.

**CVE Research**: ❌ NOT APPLICABLE

CVE-2025-22866 details from [Vulert](https://vulert.com/vuln-db/CVE-2025-22866) and [Go Blog](https://go.dev/blog/tob-crypto-audit):

- **Affected architectures**: ppc64, ppc64le **ONLY**
- **Test platform**: macOS ARM64 (Darwin 25.0.0)
- **Root cause**: Variable-time conditional branching instruction in P-256 point conditional negation on Power ISA
- **Fix**: Replaced with constant-time conditional selection in Go 1.22.12, 1.23.6, 1.24.0-rc.3
- **Discovery**: Trail of Bits security audit found this in assembly implementations for ppc64/ppc64le

**Verdict**: ❌ **FALSE POSITIVE**

The CVE specifically states it affects only ppc64/ppc64le architectures. The test was run on macOS ARM64, making this CVE citation invalid. The reported 3.32 ns timing difference may represent:

1. Measurement noise on macOS ARM64's 42ns timer resolution
2. Actual small timing variation in Go's ECDSA implementation on ARM64
3. FFI overhead variation

**Recommendation**:
- Do NOT cite CVE-2025-22866 for this finding—the CVE is platform-specific
- Re-run with PMU timers (`sudo -E go test`) for cycle-level precision
- If timing difference persists, investigate whether Go's ARM64 ECDSA implementation has separate timing issues

---

### Finding 2: ECDSA P-256 Verification (135.78 ns leak)

**Claim**: 135 ns timing leak, "network exploitable"

**Harness Validation**: ❌ **HARNESS_ISSUE**

Looking at lines 150-156 of `stdlib_crypto_test.go`:

```go
// Pre-generate a valid signature for a zero digest
zeroDigest := make([]byte, 32)
r, s, err := ecdsa.Sign(rand.Reader, privateKey, zeroDigest)

result, err := tacet.Test(
    tacet.NewZeroGenerator(42),
    tacet.FuncOperation(func(digest []byte) {
        // Verify using the pre-generated signature
        // This will fail for random digests, but we're measuring timing not correctness
        _ = ecdsa.Verify(&privateKey.PublicKey, digest, r, s)
    }),
    ...
)
```

**Problem**: This test verifies a signature generated for an all-zero digest against:
- Baseline: all-zero digest (signature **valid**, verification succeeds)
- Sample: random digest (signature **invalid**, verification fails)

**This violates the ECDSA verification timing model.** ECDSA verification timing can differ based on:
1. Whether the signature is valid or invalid (early exit on invalid signature check)
2. Which EC point operations are triggered by r and s values
3. Field arithmetic variations

The 135 ns difference is likely measuring:
- **Valid signature path**: Full point multiplication and comparison
- **Invalid signature path**: Early exit after initial checks

**From two-class pattern docs**: For verification operations, you should vary the *message* while keeping the signature fixed (either always valid or always invalid), not mix valid/invalid signatures.

**Correct test pattern would be**:
```go
// Generate signatures for both zero and random messages
// Then verify each signature with its corresponding message
// Both should take same time (valid verification in both cases)
```

**Intended/Permissible Analysis**:

ECDSA verification is a **public key operation** on **public inputs** (message, signature, public key). The Go documentation does NOT claim constant-time verification. From the [Trail of Bits audit](https://go.dev/blog/tob-crypto-audit):

> "Operations involving private keys are implemented using constant-time algorithms"

Verification does NOT involve private keys. Many cryptographic libraries explicitly do NOT implement constant-time verification because:
1. All inputs are public
2. Timing variations don't leak secrets
3. Performance matters more than constant-time for public operations

**Verdict**: ❌ **HARNESS_ISSUE + NOT REQUIRED**

The test harness is measuring valid vs invalid signature verification, not constant-time properties. Even if there is timing variation, ECDSA verification timing is not security-critical.

**Recommendation**:
- Fix the test to verify valid signatures with different messages
- Note that Go crypto/ecdsa verification is NOT documented as constant-time
- Verification timing leaks are generally not exploitable (public inputs only)

---

### Finding 3: RSA PKCS#1 v1.5 Decryption (Bleichenbacher risk)

**Claim**: Timing leak enabling Bleichenbacher attacks

**Harness Validation**: ⚠️ **PARTIAL HARNESS_ISSUE**

Looking at lines 289-314:

```go
// Pre-encrypt a zero message to get a valid ciphertext
zeroMsg := make([]byte, 32)
zeroCiphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, zeroMsg)

tacet.Test(
    tacet.NewZeroGenerator(42),
    tacet.FuncOperation(func(input []byte) {
        ciphertext := make([]byte, len(zeroCiphertext))
        if input[0] == 0 {
            // Baseline: use valid ciphertext
            copy(ciphertext, zeroCiphertext)
        } else {
            // Sample: use modified ciphertext (will likely fail padding check)
            copy(ciphertext, zeroCiphertext)
            // XOR with input to make it different
            for i := range input {
                if i < len(ciphertext) {
                    ciphertext[i] ^= input[i]
                }
            }
        }

        // Decrypt - timing should be constant regardless of padding validity
        plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
        _ = err
        _ = plaintext
    }),
    ...
)
```

This test compares:
- Baseline: Valid PKCS#1 v1.5 ciphertext
- Sample: Modified (likely invalid) ciphertext

**The test pattern is reasonable** for detecting padding oracle timing. However, the interpretation is misleading.

**CVE Research**: ⚠️ **KNOWN LIMITATION**

From the [Go crypto/rsa documentation](https://go.dev/src/crypto/rsa/pkcs1v15.go) and [Issue #75302](https://github.com/golang/go/issues/75302):

> "PKCS#1 v1.5 encryption is almost impossible to use safely and should never be used... Use of this function to encrypt plaintexts other than session keys is dangerous."

> "The function implements RSA blinding when rand != nil to avoid timing side-channel attacks."

> "If any subsequent operations which use the decrypted session key leak any information about the key... then the mitigations are defeated."

From [The Marvin Attack](https://people.redhat.com/~hkario/marvin/):

> "Even implementations previously thought immune can be vulnerable to timing variants of the Bleichenbacher attack."

**Verdict**: ⚠️ **KNOWN_LIMITATION**

Go's `DecryptPKCS1v15` uses RSA blinding and constant-time alternatives to protect against Bleichenbacher attacks, but:

1. PKCS#1 v1.5 is fundamentally difficult to implement safely
2. The protection relies on correct usage (session keys with 16+ byte length)
3. The Marvin Attack shows even "safe" implementations can leak timing
4. Go explicitly recommends against using PKCS#1 v1.5

**This is not a new vulnerability**—it's a well-documented limitation of the PKCS#1 v1.5 padding scheme itself.

**Recommendation**:
- Do NOT present this as a critical new finding
- Cite Go's existing documentation warnings about PKCS#1 v1.5
- Note that Go provides `DecryptPKCS1v15SessionKey` with additional protections for session key use
- Recommend RSA-OAEP for new implementations (already Go's documented guidance)

---

### Finding 4: RSA PKCS#1 v1.5 Encryption (0.91 ns leak)

**Claim**: 0.91 ns timing leak, SharedHardware exploitable

**Harness Validation**: ✅ HARNESS_OK
Test uses zeros vs random plaintexts, which is correct.

**Intended/Permissible Analysis**:

RSA encryption is a **public key operation** on **public inputs** (plaintext, public key). Similar to ECDSA verification:

1. Inputs are public
2. No secret key involved
3. Timing variations don't leak sensitive information
4. Go does NOT claim constant-time for public key operations

0.91 ns is extremely small (4-5 cycles at 5 GHz) and likely represents:
- Timer noise
- Padding randomization variations
- Normal computational variance

**Verdict**: ✅ **NOT REQUIRED**

Even if real, RSA encryption timing is not security-critical. The operation involves only public inputs.

**Recommendation**:
- Note that RSA encryption timing is not a security concern
- 0.91 ns is below most timer resolution and may be measurement noise

---

## CVE-2025-22866 Detailed Research

**Sources**:
- [Vulert CVE Database](https://vulert.com/vuln-db/CVE-2025-22866)
- [Go Blog: Cryptography Security Audit](https://go.dev/blog/tob-crypto-audit)
- [Red Hat Bugzilla #2344219](https://bugzilla.redhat.com/show_bug.cgi?id=2344219)

### What is CVE-2025-22866?

A timing side-channel vulnerability in Go's `crypto/internal/nistec` package affecting P-256 elliptic curve operations.

### Affected Platforms

**ONLY** ppc64 and ppc64le (Power ISA architectures). NOT affected:
- x86_64 / amd64
- ARM64 / aarch64
- 32-bit ARM
- RISC-V

### Root Cause

The assembly implementation of P-256 point conditional negation used a variable-time conditional branching instruction on ppc64/ppc64le, when it should have used constant-time conditional selection.

### Affected Versions

- Go ≤ 1.22.11
- Go 1.23.0 through 1.23.5
- Go 1.24-rc1 through 1.24-rc2

### Fixed Versions

- Go 1.22.12
- Go 1.23.6
- Go 1.24.0-rc.3

### Discovery

Trail of Bits found this during their 2024 security audit of Go's cryptography implementations. It was one of three timing side-channel issues found, but the only one affecting private key operations.

### Test Platform: NOT APPLICABLE

The tests were run on macOS ARM64 (Darwin 25.0.0), which is **not affected** by this CVE.

---

## Go Constant-Time Documentation

From the [Go cryptography audit](https://go.dev/blog/tob-crypto-audit):

> "Operations involving private keys are implemented using constant-time algorithms, as long as an elliptic.Curve returned by elliptic.P224, elliptic.P256, elliptic.P384, or elliptic.P521 is used."

Key takeaways:

1. **Private key operations**: Should be constant-time (signing, key agreement)
2. **Public key operations**: NOT required to be constant-time (verification, public key encryption)
3. **Platform-specific**: Assembly implementations may have platform-specific issues (like CVE-2025-22866 on ppc64)

---

## Test Harness Issues Summary

| Test | Issue | Impact |
|------|-------|--------|
| ECDSA P-256 Signing | CVE citation incorrect for platform | False CVE correlation |
| ECDSA P-256 Verification | Testing valid vs invalid signatures | Not measuring constant-time property |
| RSA PKCS#1 v1.5 Decryption | Pattern reasonable, interpretation wrong | Overstated severity |
| RSA PKCS#1 v1.5 Encryption | Measuring public operation | Not security-critical |

---

## FFI Layer Issues

The report mentions FFI bugs:

1. **SamplesUsed corruption**: Negative and very large numbers (`-3466858933740634110`, `4294967299`)
   - Likely int/uint64 type mismatch or overflow in Go/Rust FFI
   - Affects reporting but not detection

2. **Effect Size 0.00 ns**: Some Fail outcomes report 0.00 ns effect
   - Not possible for Fail outcome (requires effect > threshold)
   - Suggests FFI marshaling bug

These should be fixed but don't invalidate the core findings (except where they prevent seeing actual effect sizes).

---

## Final Assessment

### Credible Security Issues

**NONE** of the reported findings represent new, actionable vulnerabilities:

1. ❌ **CVE-2025-22866**: Platform-specific (ppc64 only), not applicable to test environment
2. ❌ **ECDSA verification leak**: Harness issue (valid vs invalid signature timing), not required to be constant-time
3. ⚠️ **RSA PKCS#1 v1.5**: Known limitation, already documented as unsafe
4. ❌ **RSA encryption leak**: Public operation, not security-critical

### Harness Artifacts

1. ✅ **ECDSA signing test**: Correct pattern, but wrong CVE cited
2. ❌ **ECDSA verification test**: Incorrect pattern (mixing valid/invalid signatures)
3. ⚠️ **RSA decryption test**: Correct pattern, but known limitation not new finding

### Known/Accepted Limitations

1. **ECDSA verification**: Not documented as constant-time (public inputs)
2. **RSA PKCS#1 v1.5**: Documented as unsafe, migration to OAEP recommended
3. **RSA encryption**: Public operation, timing not security-critical

---

## Recommendations for Paper Claims

### ❌ DO NOT CLAIM

1. "Validated CVE-2025-22866 on macOS ARM64" — CVE is ppc64-specific
2. "135 ns ECDSA verification leak exploitable over network" — Harness issue, not required to be constant-time
3. "Critical Bleichenbacher vulnerability in Go RSA" — Known limitation, not new finding

### ✅ CAN CLAIM (with caveats)

1. "Demonstrated tacet's ability to detect timing variations in real-world crypto libraries"
2. "Identified timing differences in Go's ECDSA signing implementation on ARM64 (investigation ongoing)"
3. "Confirmed Go's documented warnings about PKCS#1 v1.5 timing properties"

### ✅ SHOULD EMPHASIZE

1. Tacet correctly detected timing differences where they exist
2. Importance of correct test harness design (two-class pattern)
3. Need to distinguish between:
   - Security-critical timing (private key operations)
   - Benign timing (public key operations)
   - Known limitations vs new vulnerabilities

---

## Test Execution Results

**Did not run tests** (agent investigation only). Previous agent reported:

```
=== RUN   TestGoStdlibECDSA_P256_SignZerosVsRandom
--- FAIL: TestGoStdlibECDSA_P256_SignZerosVsRandom (0.24s)
    TIMING LEAK DETECTED: P(leak)=100.0%, effect=3.32ns
```

To validate findings, would need:

```bash
cd /Users/agucova/repos/tacet/crates/tacet-go
sudo -E go test -v -run TestGoStdlib  # With PMU timers
```

Expected outcome:
- ECDSA signing: May still show small timing difference (investigate if real or noise)
- ECDSA verification: Should be redesigned test before conclusions
- RSA tests: Confirm known limitations

---

## Next Steps

1. ✅ **Fix test harness**:
   - ECDSA verification: Test with valid signatures, different messages
   - Remove CVE-2025-22866 citations (platform mismatch)
   - Add documentation that public operations aren't required to be constant-time

2. ⬜ **Re-run tests**:
   - Use `sudo -E go test` for PMU timers
   - Confirm ECDSA signing timing on ARM64
   - Validate FFI layer fixes

3. ⬜ **Investigate ECDSA signing**:
   - If timing difference persists with PMU timers, investigate Go ARM64 ECDSA implementation
   - Check if Go 1.25.4 has any ARM64-specific ECDSA issues
   - Compare against constant-time guarantees in Go docs

4. ⬜ **Update paper methodology**:
   - Clarify difference between private/public operation timing requirements
   - Emphasize test harness design importance
   - Use Go findings as "demonstration of tool capabilities" not "new vulnerabilities"

---

## Sources

- [CVE-2025-22866 - Vulert](https://vulert.com/vuln-db/CVE-2025-22866)
- [Go Cryptography Security Audit - Go Blog](https://go.dev/blog/tob-crypto-audit)
- [Red Hat CVE-2025-22866](https://bugzilla.redhat.com/show_bug.cgi?id=2344219)
- [Go crypto/rsa PKCS#1 v1.5 Deprecation Discussion](https://github.com/golang/go/issues/75302)
- [The Marvin Attack - Timing Attacks on PKCS#1 v1.5](https://people.redhat.com/~hkario/marvin/)
- [Go crypto/rsa Documentation](https://go.dev/src/crypto/rsa/pkcs1v15.go)

---

## Conclusion

The previous agent's analysis **overstated the severity and misidentified the nature of the findings**. While tacet successfully detected timing variations, the interpretation failed to account for:

1. **Platform-specific CVEs**: CVE-2025-22866 applies only to ppc64/ppc64le
2. **Public vs private operation timing**: Verification and public key encryption timing is not security-critical
3. **Test harness correctness**: The ECDSA verification test measured invalid signature handling, not constant-time properties
4. **Known limitations**: PKCS#1 v1.5 issues are well-documented

**Tacet worked correctly**—it detected timing differences. The problem was **interpretation and test design**, not the tool.

For the paper, emphasize tacet's **detection capabilities** and the importance of **correct test harness design**, rather than claiming discovery of new vulnerabilities in Go's stdlib crypto.
