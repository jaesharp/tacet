# Tacet Evaluation Scripts

This directory contains scripts for measuring and analyzing the false positive rate (FPR) across all crypto library tests.

## Quick Start

```bash
# Run all tests 10 times (default)
./scripts/measure_fpr.sh

# Run all tests 100 times (for tighter confidence intervals)
./scripts/measure_fpr.sh 100

# Specify custom output file
./scripts/measure_fpr.sh 10 results/fpr_$(date +%Y%m%d).csv

# Analyze results
./scripts/analyze_fpr.py fpr_results_*.csv
```

## Scripts

### `measure_fpr.sh`

Runs all crypto library tests N times to measure empirical false positive rate.

**Usage:**
```bash
./measure_fpr.sh [iterations] [output_file]
```

**Parameters:**
- `iterations` - Number of times to run each test (default: 10)
- `output_file` - CSV file for results (default: `fpr_results_TIMESTAMP.csv`)

**What it does:**
1. Runs each crypto test `iterations` times
2. Parses Pass/Fail/Inconclusive outcomes
3. Logs all results to CSV
4. Continues on error (doesn't stop if a test fails)
5. Generates summary report with Wilson confidence intervals

**Requirements:**
- `sudo` access (for PMU timers in Rust tests)
- `cargo` (for Rust tests)
- `bun` (for JavaScript tests)
- `python3` (optional, for confidence intervals in summary)

**Test Coverage:**

The script runs tests across four ecosystems:

- **Rust** (via `cargo test --test crypto`):
  - RustCrypto: AES, SHA3, BLAKE2, ChaCha20-Poly1305, RSA
  - ring: AES-GCM
  - dalek: X25519
  - pqcrypto: Kyber, Dilithium
  - orion: BLAKE2b-MAC, XChaCha20-Poly1305, Argon2i

- **C/C++ via FFI** (via `cargo test --test crypto`):
  - LibreSSL: RSA, ECDSA, AES-GCM
  - Libsodium: Ed25519, X25519
  - wolfSSL: RSA, ECDSA, AES-GCM
  - mbedTLS: AES-GCM, RSA
  - Botan: RSA, ECDSA, AES-GCM

- **JavaScript/WASM** (via `bun test`):
  - node-forge: RSA, ECDSA
  - crypto-js: AES, DES
  - Noble: P-256, secp256k1

- **Go** (SKIPPED - blocked by FFI bug)

**Output Format (CSV):**
```
ecosystem,library,test_name,iteration,outcome,leak_probability,samples,elapsed_sec,timestamp
Rust,RustCrypto,AES-128 Encrypt,1,PASS,0.0,6000,2.3,2026-02-05T12:34:56+00:00
Rust,orion,BLAKE2b-MAC,1,PASS,0.0,6000,1.8,2026-02-05T12:35:01+00:00
...
```

### `analyze_fpr.py`

Analyzes FPR results and generates comprehensive statistics.

**Usage:**
```bash
./analyze_fpr.py results.csv
```

**What it computes:**
- Overall FPR with Wilson score 95% confidence intervals
- Per-ecosystem breakdown (Rust, C/C++, JavaScript)
- Per-library breakdown (RustCrypto, wolfSSL, orion, etc.)
- Test-level reliability (which specific tests had false positives)
- Paper-ready summary statement

**Example Output:**
```
======================================================================
FALSE POSITIVE RATE ANALYSIS
======================================================================

Total test runs: 300
  Pass:            285 ( 95.0%)
  Fail (FP):         0 (  0.0%)
  Inconclusive:     15 (  5.0%)

──────────────────────────────────────────────────────────────────────
FALSE POSITIVE RATE
──────────────────────────────────────────────────────────────────────
Point estimate: 0.0000 (0.00%)
Wilson 95% CI:  [0.00%, 1.22%]

✓ NO FALSE POSITIVES DETECTED
  This validates the calibration property with 95% confidence
  that the true FPR is below 1.22%

──────────────────────────────────────────────────────────────────────
PAPER-READY SUMMARY
──────────────────────────────────────────────────────────────────────

Across 30 unique tests run 300 times
(average 10.0 iterations per test),
tacet returned 0 false positives
(FPR = 0.00%, Wilson 95% CI: [0.00%, 1.22%]).

This validates the calibration property: with 95% confidence,
the true false positive rate is below 1.22%.
```

## Typical Workflow

### Quick Check (10 iterations per test)
```bash
# ~30-60 minutes runtime for all tests
./scripts/measure_fpr.sh 10 fpr_quick.csv
./scripts/analyze_fpr.py fpr_quick.csv
```

Expected CI width with N=10 × 30 tests = 300 runs: ~[0%, 1.2%]

### Standard Evaluation (50 iterations per test)
```bash
# ~3-5 hours runtime
./scripts/measure_fpr.sh 50 fpr_standard.csv
./scripts/analyze_fpr.py fpr_standard.csv
```

Expected CI width with N=50 × 30 tests = 1500 runs: ~[0%, 0.25%]

### Paper-Quality (100 iterations per test)
```bash
# ~6-10 hours runtime
./scripts/measure_fpr.sh 100 fpr_paper.csv
./scripts/analyze_fpr.py fpr_paper.csv
```

Expected CI width with N=100 × 30 tests = 3000 runs: ~[0%, 0.12%]

## Interpreting Results

### False Positive Rate (FPR)

The FPR measures how often tacet incorrectly reports a timing leak when none exists. All tests in this suite are on implementations **without known timing vulnerabilities**, so any `Fail` outcome is a false positive.

**Expected FPR:**
- At α = 0.05 (default `fail_threshold`), we expect ~5% false positives
- However, tacet's Bayesian calibration should keep the actual FPR below this nominal rate
- Zero false positives validates the calibration property

**Wilson Score Confidence Interval:**
- Provides 95% confidence bounds on the true FPR
- With 0 false positives, the upper bound indicates maximum plausible FPR
- Tighter bounds require more iterations

### Outcome Types

- **PASS**: No timing leak detected (`P(leak) < 0.05`)
- **FAIL**: Timing leak detected (`P(leak) > 0.95`) - **FALSE POSITIVE** in this context
- **INCONCLUSIVE**: Could not reach decision (poor conditions, insufficient samples, etc.)
- **SKIP**: Test was skipped (e.g., Go tests due to FFI bug)

### What Good Looks Like

**Ideal results:**
- FPR = 0% with tight confidence interval (e.g., [0%, 0.5%])
- Inconclusive rate 0-10% (indicates good measurement conditions)
- No specific tests showing repeated failures

**Acceptable results:**
- FPR < 5% (at or below nominal α level)
- Inconclusive rate 10-20% (some tests on borderline precision)
- Any false positives are isolated (not systematic)

**Problematic results:**
- FPR > 5% (exceeds nominal rate - calibration issue)
- Specific tests consistently failing (suggests real leak or test bug)
- High inconclusive rate >30% (measurement quality issues)

## Updating for New Tests

When you add new crypto tests, update `measure_fpr.sh`:

1. Find the appropriate ecosystem section (Rust, C/C++, JavaScript)
2. Add a `run_rust_test` or `run_js_test` call:

```bash
# For Rust tests:
run_rust_test "module::test_function_name" "Readable Test Name" "Library Name"

# Example:
run_rust_test "rust_libraries::orion::orion_auth_constant_time" "BLAKE2b-MAC" "orion"

# For JavaScript tests:
run_js_test "test-file-pattern" "Readable Test Name" "Library Name"

# Example:
run_js_test "node-forge" "RSA PKCS1v15 Encrypt" "node-forge"
```

## Troubleshooting

### Tests timing out
- Increase timeout in `run_rust_test` or `run_js_test` functions
- For JavaScript: Adjust `--timeout 300000` parameter

### Parsing errors
- Check if test output format has changed
- Update `parse_rust_outcome()` regex patterns if needed

### Sudo permission denied
- Ensure you have sudo access for PMU timers
- Alternative: Run without sudo but note reduced precision

### CSV format issues
- Ensure no commas in test names or library names
- Check timestamp format compatibility

## Files Generated

- `fpr_results_TIMESTAMP.csv` - Raw test results
- Analysis output goes to stdout (redirect to file if needed)

**Suggested workflow:**
```bash
# Run tests
./scripts/measure_fpr.sh 50 results/fpr_$(date +%Y%m%d).csv

# Analyze and save
./scripts/analyze_fpr.py results/fpr_$(date +%Y%m%d).csv | tee results/analysis_$(date +%Y%m%d).txt
```

## References

- Wilson Score Interval: https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval
- Calibration property: See paper Section 3.3
- Test methodology: See paper Section 5.1
