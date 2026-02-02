#!/usr/bin/env bash
# Quick harness validation (~5-10 min)
# Purpose: Catch any harness/tool issues before longer runs

set -euo pipefail

OUTPUT_DIR=~/bench-results/quick
mkdir -p "$OUTPUT_DIR/logs"

echo "=== Quick Harness Validation ==="
echo "Output: $OUTPUT_DIR"
echo "Architecture: $(uname -m)"
echo ""

cargo run --release -p tacet-bench --bin benchmark -- \
    --preset quick --tools all \
    --output "$OUTPUT_DIR" -q \
    2>&1 | tee "$OUTPUT_DIR/logs/run.log"

echo ""
echo "=== Verification ==="
echo ""
echo "Tools ran:"
cut -d, -f1 "$OUTPUT_DIR/benchmark_results.csv" 2>/dev/null | sort | uniq -c | tail -n +2 || echo "  (no results yet)"

echo ""
echo "Errors (if any):"
grep -i error "$OUTPUT_DIR/benchmark_results.csv" 2>/dev/null | head -5 || echo "  None found"

echo ""
echo "=== Quick validation complete ==="
echo "Results in: $OUTPUT_DIR"
