# Noble Crypto Timing Tests

Comprehensive timing tests for noble-crypto JavaScript libraries (@noble/curves, @noble/ciphers) to validate constant-time properties.

## Overview

These tests measure timing behavior of cryptographic operations in JavaScript using tacet's WebAssembly bindings. Results are included in the paper comparing JavaScript vs Rust crypto implementations.

**Key insight:** JavaScript's JIT compilation and garbage collection make true constant-time execution extremely difficult, even for algorithmically constant-time code. These tests measure empirical timing behavior vs theoretical analysis.

## Test Methodology

### DudeCT Two-Class Pattern

All tests follow the DudeCT two-class testing pattern:

- **Baseline class:** Fixed input (all zeros or constant value)
- **Sample class:** Random input (`crypto.getRandomValues()`)

This tests for data-dependent timing rather than specific value comparisons.

### Input Generation

**Critical:** Inputs are generated OUTSIDE the timing measurement region to avoid measuring generator overhead:

```typescript
const result = await TimingOracle.testAsync(
  {
    baseline: () => new Uint8Array(32), // Generate baseline outside
    sample: () => crypto.getRandomValues(new Uint8Array(32)), // Generate sample outside
  },
  async (input) => {
    // Only this operation is timed
    cryptoFunction(input);
  }
);
```

### Attacker Models

Tests use attacker models appropriate to their threat scenario:

| Operation Type | Model | Threshold | Rationale |
|---------------|-------|-----------|-----------|
| Curve signing (ECDSA, EdDSA) | `PostQuantum` | 2ns (~10 cycles @ 5 GHz) | ECC timing leaks historically exploitable at ~20 cycles (e.g., KyberSlash) |
| ECDH | `PostQuantum` | 2ns | Scalar multiplication with secret keys |
| Ciphers (ChaCha, Salsa, AES) | `AdjacentNetwork` | 100ns | Stream ciphers in web APIs, LAN attacker realistic |

**Note:** JavaScript's runtime characteristics make strict constant-time impossible. We document **exploitability levels** rather than enforcing Pass/Fail:

- **Negligible:** Effect < threshold, not exploitable
- **PossibleLAN:** Effect > 100ns, potentially exploitable on LAN
- **LikelyLAN:** Effect > 500ns, likely exploitable on LAN
- **PossibleRemote:** Effect > 50μs, potentially exploitable remotely

## Test Coverage

### Curves (@noble/curves) - 12 tests

**secp256k1 (5 tests):**
- ✅ Sign with random messages (SHOULD be constant-time)
- ✅ ECDH with random private keys (SHOULD be constant-time)
- ℹ️ Sign with different private keys + fixed message (informational)
- ✅ Hamming weight independence (0x00 vs 0xFF messages)
- 📊 Verify operation (baseline measurement, NOT a constant-time requirement)

**ed25519 (5 tests):**
- ✅ Sign with random messages (SHOULD be constant-time)
- ℹ️ Sign with different private keys + fixed message (informational)
- ✅ Hamming weight independence
- ✅ Byte pattern independence (sequential vs reverse)
- 📊 Verify operation (baseline)

**ed448 (2 tests):**
- ✅ Sign with random messages
- 📊 Verify operation (baseline)

### Ciphers (@noble/ciphers) - 8 tests

**ChaCha20 (3 tests):**
- ✅ Encrypt with random plaintext
- ✅ Encrypt with different keys + fixed plaintext
- ✅ Nonce independence test

**Salsa20 (2 tests):**
- ✅ Encrypt with random plaintext
- ✅ Encrypt with different keys

**XSalsa20 (1 test):**
- ✅ Encrypt with random plaintext (extended nonce variant)

**AES-256-CTR (2 tests):**
- ✅ Encrypt with random plaintext
- ⚠️ Encrypt with different keys (SHOULD detect leak - T-table cache timing)

## Running Tests

```bash
# Install dependencies first
cd crates/tacet-wasm
bun install

# Build WASM and TypeScript
bun run build

# Run all noble tests (~10-15 minutes)
bun test tests/noble/

# Run individual suites
bun test tests/noble/curves.test.ts    # ~5-10 minutes (12 tests × 30s avg)
bun test tests/noble/ciphers.test.ts   # ~3-5 minutes (8 tests × 30s avg)
```

### Using justfile commands

```bash
# From repository root
just test noble             # Run all noble tests
just test noble-curves      # Run curves tests only
just test noble-ciphers     # Run ciphers tests only
just test noble-report      # Generate JSON/CSV report for paper
```

## Interpreting Results

### Outcome Types

1. **Pass** - P(leak) < 5%: No timing leak detected at this threshold
2. **Fail** - P(leak) > 95%: Timing leak confirmed
3. **Inconclusive** - Cannot reach decision within time/sample budget
4. **Unmeasurable** - Operation too fast to measure reliably

### JavaScript-Specific Considerations

**JavaScript is NOT constant-time at the platform level:**

1. **JIT compilation:** V8/SpiderMonkey optimize hot code paths differently
2. **Garbage collection:** GC pauses introduce timing noise
3. **Async/await overhead:** Promise resolution adds variable latency
4. **Object allocation:** Variable allocation patterns affect timing

**Noble-crypto targets algorithmic constant-time:**
- Uses constant-time field arithmetic algorithms
- Avoids secret-dependent branches and table lookups
- But cannot control JIT optimization or GC behavior

### Expected Outcomes

Based on methodology and JavaScript limitations:

**Ciphers (ChaCha20, Salsa20, AES-CTR):**
- **ChaCha20/Salsa20**: Expected Pass or low-exploitability Fail (Negligible/PossibleLAN)
  - Stream ciphers have simple, data-independent structure
  - Effects likely 5-50ns (below LAN threshold but detectable)
- **AES-256-CTR with different keys**: Expected Fail with high exploitability
  - **This is documented, expected behavior** - not a bug
  - Noble-ciphers uses T-tables for AES performance (same as OpenSSL, Go stdlib)
  - T-tables leak cache-timing information during key expansion
  - See [noble-ciphers constant-time documentation](https://github.com/paulmillr/noble-ciphers#constant-timeness)
  - Academic references: [Bernstein 2005](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf), [HAL-04652991](https://hal.science/hal-04652991/document)
  - The library explicitly states: "The library uses T-tables for AES, which leak access timings"

**Curves (ECDSA, EdDSA):**
- Expected: Higher-exploitability Fail (PossibleLAN to LikelyLAN)
- Field arithmetic involves complex operations
- JIT optimization creates timing variations in multiply/reduce operations
- Effects likely 20-200ns (potentially exploitable on LAN)

**Verification operations:**
- Expected: Fail (NOT a constant-time requirement)
- Verification is allowed to be variable-time
- Included for baseline comparison

### Comparison with Rust

For the paper, compare noble-crypto (JavaScript) vs RustCrypto (Rust) implementations:

**Expected findings:**
1. **AES T-table timing leak** - Noble-ciphers AES shows confirmed cache-timing leak (P≈96%, exploitability: standardRemote) due to documented use of T-tables for performance. This demonstrates fundamental JavaScript platform limitations even in audited libraries.
2. JavaScript shows 2-5× larger timing effects than Rust for equivalent operations
3. JavaScript exploitability levels trend higher (more PossibleLAN/LikelyLAN outcomes)
4. Rust shows more Pass outcomes due to better platform-level constant-time properties
5. Both may fail for operations that are inherently data-dependent

**Key insight:** The AES result shows that even high-quality, audited JavaScript crypto libraries (noble-ciphers passed Cure53 audit 2024) make explicit performance vs timing-safety trade-offs that would be unacceptable in Rust constant-time implementations.

## Paper Integration

### JSON Output Format

Test runner generates structured results:

```json
{
  "library": "@noble/curves",
  "operation": "secp256k1_sign",
  "version": "1.6.0",
  "timestamp": "2026-02-05T12:34:56.789Z",
  "platform": {
    "runtime": "Bun 1.1.38",
    "os": "darwin",
    "arch": "arm64"
  },
  "tacet": {
    "outcome": "fail",
    "leakProbability": 0.98,
    "effectNs": 45.2,
    "exploitability": "PossibleLAN",
    "samplesUsed": 25000,
    "elapsedSecs": 28.3
  },
  "attackerModel": "PostQuantum"
}
```

### CSV Summary

Aggregated results for paper tables:

```csv
Library,Operation,Outcome,Leak Probability,Effect (ns),Exploitability,Samples,Time (s)
@noble/curves,secp256k1_sign,Fail,0.98,45.2,PossibleLAN,25000,28.3
@noble/ciphers,chacha20_encrypt,Pass,0.02,1.8,Negligible,15000,18.7
```

### Paper Draft Section

```latex
\subsection{JavaScript Cryptography: noble-crypto}

We evaluated the noble-crypto suite using tacet's WebAssembly bindings.
Noble-crypto targets algorithmic constant-time design but acknowledges
JavaScript's inherent limitations (JIT compilation, garbage collection).

\textbf{Results:}
\begin{itemize}
\item Curves: secp256k1/ed25519 signing showed timing variations
      (median effect: [X]ns, exploitability: [level])
\item Ciphers: ChaCha20/Salsa20 showed minimal leaks
      (median effect: [Y]ns, exploitability: Negligible)
\end{itemize}

Despite algorithmic constant-time design, JavaScript runtime characteristics
introduce measurable timing variations. Effects range [X]-[Y]ns, potentially
exploitable in [contexts]. Comparison with Rust implementations shows
JavaScript exhibits [Z]× larger timing effects for equivalent operations.
```

## Environment Requirements

### System Configuration

**To reduce timing noise:**

1. **Disable CPU throttling:**
   ```bash
   # macOS
   sudo systemctl disable cpufreqd  # If available

   # Linux
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   ```

2. **Close background applications:**
   - Close browsers, IDEs, music players
   - Disable system updates, indexing services
   - Run tests on AC power (disable battery throttling)

3. **Use longer time budgets if needed:**
   - Default: 30 seconds (quick validation)
   - Noisy environment: 60 seconds (thorough validation)
   - Modify `TIME_BUDGETS.THOROUGH` in `helpers.ts`

### Runtime Requirements

- **Bun 1.1.38+** or **Node.js 18+**
- **tacet-wasm built:** Run `bun run build` first
- **Dependencies installed:** Run `bun install` first

## Common Issues

### GC Pauses Causing Spurious Failures

**Symptom:** Tests fail with high P(leak) but effects are inconsistent across runs.

**Solution:** Run with `--smol` (reduce heap pressure) or increase time budget:
```bash
bun --smol test tests/noble/curves.test.ts
```

### Operation Too Fast (Unmeasurable)

**Symptom:** Tests return `Unmeasurable` outcome.

**Solution:** Cipher operations on small inputs may be too fast. Increase input size (64 bytes → 1 KB).

### Inconclusive Results

**Symptom:** Tests return `Inconclusive` with reason `NotLearning` or `DataTooNoisy`.

**Solution:**
1. Check CPU governor settings (disable power saving)
2. Close background applications
3. Increase time budget to 60 seconds
4. Run on stable hardware (not VM or container)

## License

Tests use MPL-2.0 license (same as tacet). Noble-crypto uses MIT license.

## References

- Noble-crypto: https://github.com/paulmillr/noble-curves
- DudeCT methodology: https://github.com/oreparaz/dudect
- Timeless Timing Attacks: DiTroia et al., 2021 (LAN-level precision over HTTP/2)
- KyberSlash: Timing attacks on lattice crypto at ~20 cycle granularity
