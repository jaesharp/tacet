#!/usr/bin/env bash
# Thorough overnight benchmark (~3-5 hours each mode)
# Usage: ./aws-bench-thorough.sh [synth|real] [--foreground]
#
# By default runs in background with nohup. Use --foreground to run interactively.

set -euo pipefail

MODE="${1:-synth}"
FOREGROUND=false

for arg in "$@"; do
    case "$arg" in
        --foreground|-f)
            FOREGROUND=true
            ;;
    esac
done

case "$MODE" in
    synth|synthetic)
        OUTPUT_DIR=~/bench-results/thorough-synth
        EXTRA_ARGS=""
        NEEDS_SUDO=false
        ;;
    real|realistic)
        OUTPUT_DIR=~/bench-results/thorough-real
        EXTRA_ARGS="--realistic --realistic-base-ns 1000"
        NEEDS_SUDO=true
        ;;
    *)
        echo "Usage: $0 [synth|real] [--foreground]"
        echo "  synth - Synthetic timing mode (default)"
        echo "  real  - Realistic timing mode (requires sudo)"
        echo "  --foreground - Run in foreground (default: background with nohup)"
        exit 1
        ;;
esac

mkdir -p "$OUTPUT_DIR/logs"

echo "=== Thorough Benchmark: $MODE ==="
echo "Output: $OUTPUT_DIR"
echo "Architecture: $(uname -m)"
echo "Expected: ~102,600 datasets × 9 tools = 923,400 tool runs"
echo "Estimated time: 3-5 hours"
echo ""

if [[ "$FOREGROUND" == "true" ]]; then
    echo "Running in foreground..."
    if [[ "$NEEDS_SUDO" == "true" ]]; then
        sudo -E cargo run --release -p tacet-bench --bin benchmark -- \
            --preset thorough --tools all $EXTRA_ARGS \
            --output "$OUTPUT_DIR" -q \
            2>&1 | tee "$OUTPUT_DIR/logs/run.log"
    else
        cargo run --release -p tacet-bench --bin benchmark -- \
            --preset thorough --tools all $EXTRA_ARGS \
            --output "$OUTPUT_DIR" -q \
            2>&1 | tee "$OUTPUT_DIR/logs/run.log"
    fi
else
    echo "Running in background with nohup..."
    if [[ "$NEEDS_SUDO" == "true" ]]; then
        nohup sudo -E cargo run --release -p tacet-bench --bin benchmark -- \
            --preset thorough --tools all $EXTRA_ARGS \
            --output "$OUTPUT_DIR" -q \
            > "$OUTPUT_DIR/logs/run.log" 2>&1 &
    else
        nohup cargo run --release -p tacet-bench --bin benchmark -- \
            --preset thorough --tools all $EXTRA_ARGS \
            --output "$OUTPUT_DIR" -q \
            > "$OUTPUT_DIR/logs/run.log" 2>&1 &
    fi
    PID=$!
    echo "$PID" > "$OUTPUT_DIR/pid"
    echo ""
    echo "Started background process: PID $PID"
    echo "PID saved to: $OUTPUT_DIR/pid"
    echo ""
    echo "Monitor with:"
    echo "  tail -f $OUTPUT_DIR/logs/run.log"
    echo ""
    echo "Check progress:"
    echo "  ROWS=\$(wc -l < $OUTPUT_DIR/benchmark_results.csv); echo \"\$((ROWS * 100 / 923400))% complete\""
    echo ""
    echo "Kill if needed:"
    echo "  kill \$(cat $OUTPUT_DIR/pid)"
fi

echo ""
echo "=== Thorough $MODE started ==="
