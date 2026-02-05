#!/usr/bin/env bash
# Measure False Positive Rate (FPR) across all Rust crypto library tests
#
# Usage: ./scripts/measure_fpr.sh [iterations] [output_file]
#
# Dynamically discovers all tests in the crypto binary, filters out
# sanity checks, and runs each test N times to compute empirical FPR.
# All included tests are on constant-time implementations, so any
# Fail outcome is a false positive.
#
# Requires: cargo build --release -p tacet --test crypto

set -euo pipefail

ITERATIONS="${1:-10}"
OUTPUT_FILE="${2:-fpr_results_$(date +%Y%m%d_%H%M%S).csv}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()         { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
log_success() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $*"; }
log_error()   { echo -e "${RED}[$(date +%H:%M:%S)]${NC} $*"; }

# Find the release crypto test binary dynamically
find_test_binary() {
    local bin
    bin=$(find "$REPO_ROOT/target/release/deps" -name 'crypto-*' -type f -executable -not -name '*.d' 2>/dev/null | head -1)
    if [[ -z "$bin" ]]; then
        log_error "No crypto test binary found in target/release/deps/"
        log_error "Build first: cargo build --release -p tacet --test crypto"
        exit 1
    fi
    echo "$bin"
}

# Discover all tests, filtering out sanity checks
discover_tests() {
    local binary="$1"
    "$binary" --list 2>/dev/null \
        | grep ': test$' \
        | sed 's/: test$//' \
        | grep -v 'sanity_check'
}

# Extract library name from test path (e.g., "rustcrypto::aes::foo" → "RustCrypto")
extract_library() {
    local test_name="$1"
    local prefix
    prefix=$(echo "$test_name" | cut -d: -f1)
    case "$prefix" in
        rustcrypto)       echo "RustCrypto" ;;
        ring)             echo "ring" ;;
        dalek)            echo "dalek" ;;
        pqcrypto)         echo "pqcrypto" ;;
        rust_libraries)   echo "$(echo "$test_name" | cut -d: -f3)" ;;  # e.g., orion
        c_libraries)      echo "$(echo "$test_name" | cut -d: -f3)" ;;  # e.g., libressl
        *)                echo "$prefix" ;;
    esac
}

# Extract ecosystem from test path
extract_ecosystem() {
    local test_name="$1"
    local prefix
    prefix=$(echo "$test_name" | cut -d: -f1)
    case "$prefix" in
        c_libraries)  echo "C/C++" ;;
        *)            echo "Rust" ;;
    esac
}

# Parse outcome from test output (portable, no PCRE)
parse_outcome() {
    local output="$1"
    local exit_code="$2"
    local outcome="UNKNOWN"
    local leak_prob="0.0"
    local samples="0"

    # Check for each outcome in priority order
    if echo "$output" | grep -q "Test passed:"; then
        outcome="PASS"
    elif echo "$output" | grep -q "test result:.*FAILED\|FAILED\|panicked"; then
        outcome="FAIL"
    elif echo "$output" | grep -q "Inconclusive:"; then
        outcome="INCONCLUSIVE"
    elif echo "$output" | grep -q "Skipping:\|Unmeasurable:"; then
        outcome="SKIP"
    elif [[ "$exit_code" -ne 0 ]]; then
        outcome="FAIL"
    fi

    # Extract P(leak) — portable alternative to grep -oP
    leak_prob=$(echo "$output" | grep -o 'P(leak)=[0-9.]*%' | head -1 | sed 's/P(leak)=//;s/%//' || echo "0.0")
    if [[ -z "$leak_prob" ]]; then
        leak_prob="0.0"
    fi

    # Extract samples
    samples=$(echo "$output" | grep -o 'Samples: [0-9]*' | head -1 | sed 's/Samples: //' || echo "0")
    if [[ -z "$samples" ]]; then
        samples="0"
    fi

    echo "$outcome,$leak_prob,$samples"
}

# Initialize CSV
init_csv() {
    echo "ecosystem,library,test_name,iteration,outcome,leak_probability,samples,elapsed_sec,timestamp" > "$OUTPUT_FILE"
    log "Initialized output file: $OUTPUT_FILE"
}

# Generate summary report with Wilson CIs
generate_report() {
    log ""
    log "=========================================="
    log "False Positive Rate Report"
    log "=========================================="
    log "Iterations per test: $ITERATIONS"
    log "Output file: $OUTPUT_FILE"
    log ""

    local total_runs pass_count fail_count inconclusive_count skip_count unknown_count
    total_runs=$(tail -n +2 "$OUTPUT_FILE" | wc -l | tr -d ' ')
    pass_count=$(grep -c ",PASS," "$OUTPUT_FILE" || echo 0)
    fail_count=$(grep -c ",FAIL," "$OUTPUT_FILE" || echo 0)
    inconclusive_count=$(grep -c ",INCONCLUSIVE," "$OUTPUT_FILE" || echo 0)
    skip_count=$(grep -c ",SKIP," "$OUTPUT_FILE" || echo 0)
    unknown_count=$(grep -c ",UNKNOWN," "$OUTPUT_FILE" || echo 0)

    log "Overall Results:"
    log "  Total runs:        $total_runs"
    log "  Pass:              $pass_count ($(awk "BEGIN {if ($total_runs>0) printf \"%.1f\", 100*$pass_count/$total_runs; else print \"0.0\"}")%)"
    log "  Fail (FP):         $fail_count ($(awk "BEGIN {if ($total_runs>0) printf \"%.1f\", 100*$fail_count/$total_runs; else print \"0.0\"}")%)"
    log "  Inconclusive:      $inconclusive_count ($(awk "BEGIN {if ($total_runs>0) printf \"%.1f\", 100*$inconclusive_count/$total_runs; else print \"0.0\"}")%)"
    log "  Skipped:           $skip_count"
    log "  Unknown:           $unknown_count"
    log ""

    # Wilson CI via Python (already available in devenv)
    if [[ $total_runs -gt 0 ]]; then
        python3 -c "
import math
n = $total_runs
x = $fail_count
z = 1.96
p = x / n
denom = 1 + z**2 / n
center = (p + z**2 / (2*n)) / denom
margin = z * math.sqrt((p*(1-p)/n + z**2/(4*n**2))) / denom
lo = max(0, center - margin)
hi = min(1, center + margin)
print(f'False Positive Rate: {p:.4f} ({100*p:.2f}%)')
print(f'Wilson 95% CI: [{100*lo:.2f}%, {100*hi:.2f}%]')
" 2>/dev/null || log_warn "  (Python 3 not available for CI calculation)"
    fi

    log ""
    log "=========================================="
    log "Per-Ecosystem Breakdown"
    log "=========================================="

    for ecosystem in Rust "C/C++"; do
        local eco_total eco_pass eco_fail eco_inc
        eco_total=$(grep "^$ecosystem," "$OUTPUT_FILE" | wc -l | tr -d ' ')
        if [[ $eco_total -gt 0 ]]; then
            eco_pass=$(grep "^$ecosystem," "$OUTPUT_FILE" | grep -c ",PASS," || echo 0)
            eco_fail=$(grep "^$ecosystem," "$OUTPUT_FILE" | grep -c ",FAIL," || echo 0)
            eco_inc=$(grep "^$ecosystem," "$OUTPUT_FILE" | grep -c ",INCONCLUSIVE," || echo 0)
            log "$ecosystem:"
            log "  Runs:    $eco_total"
            log "  Pass:    $eco_pass ($(awk "BEGIN {printf \"%.1f\", 100*$eco_pass/$eco_total}")%)"
            log "  Fail:    $eco_fail ($(awk "BEGIN {printf \"%.1f\", 100*$eco_fail/$eco_total}")%)"
            log "  Inconcl: $eco_inc ($(awk "BEGIN {printf \"%.1f\", 100*$eco_inc/$eco_total}")%)"
            log ""
        fi
    done

    # List failures
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

# Main
main() {
    log "=========================================="
    log "Crypto Library FPR Measurement (Rust)"
    log "=========================================="
    log "Iterations: $ITERATIONS"
    log "Output: $OUTPUT_FILE"
    log ""

    # Find binary
    local test_binary
    test_binary=$(find_test_binary)
    log "Test binary: $test_binary"

    # Discover tests
    local tests
    tests=$(discover_tests "$test_binary")
    local test_count
    test_count=$(echo "$tests" | wc -l | tr -d ' ')
    log "Discovered $test_count FPR-relevant tests (sanity checks excluded)"
    log ""

    # Sudo credential keeper
    (while true; do sleep 50; sudo -n true 2>/dev/null || exit; done) &
    SUDO_KEEPER_PID=$!
    trap "kill $SUDO_KEEPER_PID 2>/dev/null" EXIT

    init_csv

    local completed=0
    local total=$((test_count * ITERATIONS))

    while IFS= read -r test_name; do
        local library ecosystem
        library=$(extract_library "$test_name")
        ecosystem=$(extract_ecosystem "$test_name")

        log "[$((completed / ITERATIONS + 1))/$test_count] $ecosystem / $library / $test_name"

        for ((i=1; i<=ITERATIONS; i++)); do
            completed=$((completed + 1))
            log "  Iteration $i/$ITERATIONS ($completed/$total total)..."

            local start_time exit_code output
            start_time=$(date +%s)
            exit_code=0
            output=$(sudo -E "$test_binary" "$test_name" --nocapture --test-threads=1 2>&1) || exit_code=$?

            local elapsed timestamp parsed outcome leak_prob samples
            elapsed=$(($(date +%s) - start_time))
            timestamp=$(date -Iseconds)

            parsed=$(parse_outcome "$output" "$exit_code")
            outcome=$(echo "$parsed" | cut -d, -f1)
            leak_prob=$(echo "$parsed" | cut -d, -f2)
            samples=$(echo "$parsed" | cut -d, -f3)

            case "$outcome" in
                FAIL)          log_error   "    → FAIL (P=${leak_prob}%)" ;;
                PASS)          log_success "    → PASS (P=${leak_prob}%, ${elapsed}s)" ;;
                INCONCLUSIVE)  log_warn    "    → INCONCLUSIVE (P=${leak_prob}%)" ;;
                SKIP)          log_warn    "    → SKIP" ;;
                *)             log_warn    "    → $outcome" ;;
            esac

            echo "$ecosystem,$library,$test_name,$i,$outcome,$leak_prob,$samples,$elapsed,$timestamp" >> "$OUTPUT_FILE"
        done
    done <<< "$tests"

    generate_report
}

main
