#!/usr/bin/env bash
# Medium first-pass (~30-45 min each mode)
# Usage: ./aws-bench-medium.sh [synth|real]

set -euo pipefail

MODE="${1:-synth}"

case "$MODE" in
    synth|synthetic)
        OUTPUT_DIR=~/bench-results/medium-synth
        EXTRA_ARGS=""
        ;;
    real|realistic)
        OUTPUT_DIR=~/bench-results/medium-real
        EXTRA_ARGS="--realistic --realistic-base-ns 1000"
        ;;
    *)
        echo "Usage: $0 [synth|real]"
        echo "  synth - Synthetic timing mode (default)"
        echo "  real  - Realistic timing mode (requires sudo)"
        exit 1
        ;;
esac

mkdir -p "$OUTPUT_DIR/logs"

echo "=== Medium Benchmark: $MODE ==="
echo "Output: $OUTPUT_DIR"
echo "Architecture: $(uname -m)"
echo "Expected: ~9,000 datasets × 9 tools = 81,000 tool runs"
echo ""

if [[ "$MODE" == "real" || "$MODE" == "realistic" ]]; then
    echo "Running with sudo for realistic mode..."
    sudo -E cargo run --release -p tacet-bench --bin benchmark -- \
        --preset medium --tools all $EXTRA_ARGS \
        --output "$OUTPUT_DIR" -q \
        2>&1 | tee "$OUTPUT_DIR/logs/run.log"
else
    cargo run --release -p tacet-bench --bin benchmark -- \
        --preset medium --tools all $EXTRA_ARGS \
        --output "$OUTPUT_DIR" -q \
        2>&1 | tee "$OUTPUT_DIR/logs/run.log"
fi

echo ""
echo "=== Verification ==="
echo ""
echo "Tools ran:"
cut -d, -f1 "$OUTPUT_DIR/benchmark_results.csv" 2>/dev/null | sort | uniq -c | tail -n +2 || echo "  (no results yet)"

echo ""
echo "Row count:"
wc -l < "$OUTPUT_DIR/benchmark_results.csv" 2>/dev/null || echo "0"

echo ""
echo "=== Medium $MODE complete ==="
echo "Results in: $OUTPUT_DIR"
