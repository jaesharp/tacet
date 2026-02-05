#!/usr/bin/env bash
# Measure False Positive Rate (FPR) across all crypto library tests
#
# Usage: ./measure_fpr.sh [iterations] [output_file]
#
# This script runs all crypto library tests N times and collects outcomes
# to calculate the empirical false positive rate. All tests are on implementations
# WITHOUT known timing vulnerabilities, so any Fail outcome is a false positive.

set -euo pipefail

ITERATIONS="${1:-10}"  # Default: 10 iterations
OUTPUT_FILE="${2:-fpr_results_$(date +%Y%m%d_%H%M%S).csv}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $*"
}

log_error() {
    echo -e "${RED}[$(date +%H:%M:%S)]${NC} $*"
}

# Initialize CSV file
init_csv() {
    echo "ecosystem,library,test_name,iteration,outcome,leak_probability,samples,elapsed_sec,timestamp" > "$OUTPUT_FILE"
    log "Initialized output file: $OUTPUT_FILE"
}

# Parse Rust test output
parse_rust_outcome() {
    local output="$1"
    local outcome="UNKNOWN"
    local leak_prob="0.0"
    local samples="0"

    if echo "$output" | grep -q "test result: ok"; then
        outcome="PASS"
    elif echo "$output" | grep -q "FAIL.*timing leak"; then
        outcome="FAIL"
        # Try to extract leak probability
        leak_prob=$(echo "$output" | grep -oP "P\(leak\)=\K[0-9.]+%" | head -1 | sed 's/%//' || echo "100.0")
    elif echo "$output" | grep -q "inconclusive\|Inconclusive"; then
        outcome="INCONCLUSIVE"
        leak_prob=$(echo "$output" | grep -oP "P\(leak\)=\K[0-9.]+%" | head -1 | sed 's/%//' || echo "0.0")
    elif echo "$output" | grep -q "SKIPPED\|skipped"; then
        outcome="SKIP"
    fi

    # Extract samples if available
    samples=$(echo "$output" | grep -oP "samples[_:= ]+\K[0-9]+" | head -1 || echo "0")

    echo "$outcome,$leak_prob,$samples"
}

# Run a Rust test N times
run_rust_test() {
    local test_pattern="$1"
    local test_name="$2"
    local library="$3"

    log "Running Rust test: $library / $test_name"

    for ((i=1; i<=ITERATIONS; i++)); do
        log "  Iteration $i/$ITERATIONS..."

        local start_time=$(date +%s)
        local output
        local exit_code=0

        # Run test and capture output
        output=$(cd "$REPO_ROOT" && sudo -E cargo test --test crypto "$test_pattern" --no-fail-fast -- --nocapture --test-threads=1 2>&1) || exit_code=$?

        local elapsed=$(($(date +%s) - start_time))
        local timestamp=$(date -Iseconds)

        # Parse outcome
        local parsed
        parsed=$(parse_rust_outcome "$output")
        local outcome=$(echo "$parsed" | cut -d, -f1)
        local leak_prob=$(echo "$parsed" | cut -d, -f2)
        local samples=$(echo "$parsed" | cut -d, -f3)

        # Log result
        if [[ "$outcome" == "FAIL" ]]; then
            log_error "    → FAIL (P=$leak_prob%)"
        elif [[ "$outcome" == "PASS" ]]; then
            log_success "    → PASS"
        else
            log_warn "    → $outcome"
        fi

        # Write to CSV
        echo "Rust,$library,$test_name,$i,$outcome,$leak_prob,$samples,$elapsed,$timestamp" >> "$OUTPUT_FILE"
    done
}

# Run JavaScript/WASM test N times
run_js_test() {
    local test_pattern="$1"
    local test_name="$2"
    local library="$3"

    log "Running JS test: $library / $test_name"

    for ((i=1; i<=ITERATIONS; i++)); do
        log "  Iteration $i/$ITERATIONS..."

        local start_time=$(date +%s)
        local output
        local exit_code=0

        # Run test and capture output
        output=$(cd "$REPO_ROOT/crates/tacet-wasm" && bun test --timeout 300000 "$test_pattern" 2>&1) || exit_code=$?

        local elapsed=$(($(date +%s) - start_time))
        local timestamp=$(date -Iseconds)

        # Parse outcome (similar to Rust)
        local parsed
        parsed=$(parse_rust_outcome "$output")
        local outcome=$(echo "$parsed" | cut -d, -f1)
        local leak_prob=$(echo "$parsed" | cut -d, -f2)
        local samples=$(echo "$parsed" | cut -d, -f3)

        # Log result
        if [[ "$outcome" == "FAIL" ]]; then
            log_error "    → FAIL (P=$leak_prob%)"
        elif [[ "$outcome" == "PASS" ]]; then
            log_success "    → PASS"
        else
            log_warn "    → $outcome"
        fi

        # Write to CSV
        echo "JavaScript,$library,$test_name,$i,$outcome,$leak_prob,$samples,$elapsed,$timestamp" >> "$OUTPUT_FILE"
    done
}

# Generate summary report
generate_report() {
    log ""
    log "=========================================="
    log "False Positive Rate Report"
    log "=========================================="
    log "Iterations per test: $ITERATIONS"
    log "Output file: $OUTPUT_FILE"
    log ""

    # Count outcomes by ecosystem
    local total_runs=$(grep -v "^ecosystem," "$OUTPUT_FILE" | wc -l)
    local pass_count=$(grep -c ",PASS," "$OUTPUT_FILE" || echo 0)
    local fail_count=$(grep -c ",FAIL," "$OUTPUT_FILE" || echo 0)
    local inconclusive_count=$(grep -c ",INCONCLUSIVE," "$OUTPUT_FILE" || echo 0)
    local skip_count=$(grep -c ",SKIP," "$OUTPUT_FILE" || echo 0)
    local unknown_count=$(grep -c ",UNKNOWN," "$OUTPUT_FILE" || echo 0)

    log "Overall Results:"
    log "  Total runs:        $total_runs"
    log "  Pass:              $pass_count ($(awk "BEGIN {printf \"%.1f\", 100*$pass_count/$total_runs}")%)"
    log "  Fail (FP):         $fail_count ($(awk "BEGIN {printf \"%.1f\", 100*$fail_count/$total_runs}")%)"
    log "  Inconclusive:      $inconclusive_count ($(awk "BEGIN {printf \"%.1f\", 100*$inconclusive_count/$total_runs}")%)"
    log "  Skipped:           $skip_count"
    log "  Unknown:           $unknown_count"
    log ""

    # Calculate FPR with Wilson confidence interval
    if [[ $total_runs -gt 0 ]]; then
        local fpr=$(awk "BEGIN {printf \"%.4f\", $fail_count/$total_runs}")
        log "False Positive Rate: $fpr ($(awk "BEGIN {printf \"%.2f\", 100*$fpr}")%)"

        # Wilson score interval (95% CI)
        python3 -c "
import math
n = $total_runs
x = $fail_count
z = 1.96  # 95% CI

if n == 0:
    print('Wilson 95% CI: N/A (no data)')
else:
    p = x / n
    denominator = 1 + z**2 / n
    center = (p + z**2 / (2*n)) / denominator
    margin = z * math.sqrt((p * (1 - p) / n + z**2 / (4 * n**2))) / denominator

    lower = max(0, center - margin)
    upper = min(1, center + margin)

    print(f'Wilson 95% CI: [{lower*100:.2f}%, {upper*100:.2f}%]')
" 2>/dev/null || log_warn "  (Install Python 3 for confidence intervals)"
    fi

    log ""
    log "=========================================="
    log "Per-Ecosystem Breakdown"
    log "=========================================="

    # Breakdown by ecosystem
    for ecosystem in Rust JavaScript "C/C++"; do
        local eco_total=$(grep "^$ecosystem," "$OUTPUT_FILE" | wc -l)
        if [[ $eco_total -gt 0 ]]; then
            local eco_pass=$(grep "^$ecosystem," "$OUTPUT_FILE" | grep -c ",PASS," || echo 0)
            local eco_fail=$(grep "^$ecosystem," "$OUTPUT_FILE" | grep -c ",FAIL," || echo 0)
            local eco_inc=$(grep "^$ecosystem," "$OUTPUT_FILE" | grep -c ",INCONCLUSIVE," || echo 0)

            log "$ecosystem:"
            log "  Runs:   $eco_total"
            log "  Pass:   $eco_pass ($(awk "BEGIN {printf \"%.1f\", 100*$eco_pass/$eco_total}")%)"
            log "  Fail:   $eco_fail ($(awk "BEGIN {printf \"%.1f\", 100*$eco_fail/$eco_total}")%)"
            log "  Inconcl: $eco_inc ($(awk "BEGIN {printf \"%.1f\", 100*$eco_inc/$eco_total}")%)"
            log ""
        fi
    done

    # List any failures
    if [[ $fail_count -gt 0 ]]; then
        log_error "=========================================="
        log_error "FALSE POSITIVES DETECTED:"
        log_error "=========================================="
        grep ",FAIL," "$OUTPUT_FILE" | while IFS=, read -r eco lib test iter out prob samp elapsed ts; do
            log_error "  $eco / $lib / $test (iter $iter): P=$prob%"
        done
    else
        log_success "=========================================="
        log_success "NO FALSE POSITIVES DETECTED!"
        log_success "=========================================="
    fi
}

# Main execution
main() {
    log "=========================================="
    log "Crypto Library FPR Measurement"
    log "=========================================="
    log "Iterations: $ITERATIONS"
    log "Output: $OUTPUT_FILE"
    log ""

    init_csv

    # =========================================================================
    # RUST TESTS
    # =========================================================================
    log ""
    log "========================================"
    log "RUST ECOSYSTEM"
    log "========================================"

    # RustCrypto tests
    run_rust_test "rustcrypto::aes_128_encrypt_constant_time" "AES-128 Encrypt" "RustCrypto"
    run_rust_test "rustcrypto::sha3_256_hash_constant_time" "SHA3-256 Hash" "RustCrypto"
    run_rust_test "rustcrypto::blake2b_512_hash_constant_time" "BLAKE2b Hash" "RustCrypto"
    run_rust_test "rustcrypto::chacha20poly1305_encrypt_constant_time" "ChaCha20-Poly1305" "RustCrypto"
    run_rust_test "rustcrypto::rsa_2048_sign_constant_time" "RSA-2048 Sign" "RustCrypto"

    # ring tests
    run_rust_test "ring::aes_256_gcm_encrypt_constant_time" "AES-256-GCM Encrypt" "ring"
    run_rust_test "ring::aes_256_gcm_decrypt_constant_time" "AES-256-GCM Decrypt" "ring"

    # dalek tests
    run_rust_test "dalek::x25519_scalar_mult_constant_time" "X25519 ScalarMult" "dalek"

    # pqcrypto tests (sample)
    run_rust_test "pqcrypto::kyber768_encapsulate_constant_time" "Kyber-768 Encap" "pqcrypto"
    run_rust_test "pqcrypto::dilithium3_sign_constant_time" "Dilithium3 Sign" "pqcrypto"

    # orion tests (NEW)
    run_rust_test "rust_libraries::orion::orion_auth_constant_time" "BLAKE2b-MAC" "orion"
    run_rust_test "rust_libraries::orion::orion_hash_constant_time" "BLAKE2b Hash" "orion"
    run_rust_test "rust_libraries::orion::orion_aead_encrypt_constant_time" "XChaCha20-Poly1305 Encrypt" "orion"
    run_rust_test "rust_libraries::orion::orion_aead_decrypt_constant_time" "XChaCha20-Poly1305 Decrypt" "orion"
    run_rust_test "rust_libraries::orion::orion_pwhash_constant_time" "Argon2i" "orion"

    # =========================================================================
    # C/C++ TESTS (via FFI)
    # =========================================================================
    log ""
    log "========================================"
    log "C/C++ ECOSYSTEM (via FFI)"
    log "========================================"

    # LibreSSL tests
    run_rust_test "c_libraries::libressl::libressl_rsa_2048_pkcs1v15_decrypt_constant_time" "RSA-2048 PKCS1v15" "LibreSSL"
    run_rust_test "c_libraries::libressl::libressl_ecdsa_p256_sign_constant_time" "ECDSA P-256 Sign" "LibreSSL"
    run_rust_test "c_libraries::libressl::libressl_aes_256_gcm_encrypt_constant_time" "AES-256-GCM" "LibreSSL"

    # Libsodium tests
    run_rust_test "c_libraries::libsodium::libsodium_ed25519_sign_constant_time" "Ed25519 Sign" "Libsodium"
    run_rust_test "c_libraries::libsodium::libsodium_x25519_scalar_mult_constant_time" "X25519 ScalarMult" "Libsodium"

    # wolfSSL tests (NEW)
    run_rust_test "c_libraries::wolfssl::wolfssl_rsa_2048_pkcs1v15_decrypt_constant_time" "RSA-2048 PKCS1v15" "wolfSSL"
    run_rust_test "c_libraries::wolfssl::wolfssl_rsa_2048_oaep_decrypt_constant_time" "RSA-2048 OAEP" "wolfSSL"
    run_rust_test "c_libraries::wolfssl::wolfssl_ecdsa_p256_sign_constant_time" "ECDSA P-256 Sign" "wolfSSL"
    run_rust_test "c_libraries::wolfssl::wolfssl_aes_256_gcm_encrypt_constant_time" "AES-256-GCM Encrypt" "wolfSSL"
    run_rust_test "c_libraries::wolfssl::wolfssl_aes_256_gcm_decrypt_constant_time" "AES-256-GCM Decrypt" "wolfSSL"

    # mbedTLS tests (NEW)
    run_rust_test "c_libraries::mbedtls::mbedtls_aes_256_gcm_encrypt_constant_time" "AES-256-GCM Encrypt" "mbedTLS"
    run_rust_test "c_libraries::mbedtls::mbedtls_rsa_2048_pkcs1v15_decrypt_constant_time" "RSA-2048 PKCS1v15" "mbedTLS"
    run_rust_test "c_libraries::mbedtls::mbedtls_rsa_2048_oaep_decrypt_constant_time" "RSA-2048 OAEP" "mbedTLS"

    # Botan tests (NEW)
    run_rust_test "c_libraries::botan::botan_rsa_2048_pkcs1v15_decrypt_constant_time" "RSA-2048 PKCS1v15" "Botan"
    run_rust_test "c_libraries::botan::botan_rsa_2048_oaep_decrypt_constant_time" "RSA-2048 OAEP" "Botan"
    run_rust_test "c_libraries::botan::botan_ecdsa_p256_sign_constant_time" "ECDSA P-256 Sign" "Botan"
    run_rust_test "c_libraries::botan::botan_aes_256_gcm_encrypt_constant_time" "AES-256-GCM" "Botan"

    # =========================================================================
    # JAVASCRIPT TESTS
    # =========================================================================
    log ""
    log "========================================"
    log "JAVASCRIPT ECOSYSTEM (WASM)"
    log "========================================"

    # node-forge tests
    run_js_test "node-forge" "RSA PKCS1v15 Encrypt" "node-forge"
    run_js_test "node-forge" "ECDSA P-256 Sign" "node-forge"

    # crypto-js tests
    run_js_test "crypto-js" "AES-128 Encrypt" "crypto-js"
    run_js_test "crypto-js" "DES Encrypt" "crypto-js"

    # Noble tests
    run_js_test "noble/curves" "P-256 Sign" "Noble"
    run_js_test "noble/curves" "secp256k1 Sign" "Noble"

    # =========================================================================
    # GO TESTS (SKIP - blocked by FFI bug)
    # =========================================================================
    log ""
    log_warn "========================================"
    log_warn "GO ECOSYSTEM - SKIPPED"
    log_warn "========================================"
    log_warn "All Go tests blocked by tacet-go FFI bug"
    log_warn "See: crates/tacet-go/README.md"

    # =========================================================================
    # GENERATE REPORT
    # =========================================================================
    log ""
    generate_report
}

# Run main function
main
