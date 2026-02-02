#!/usr/bin/env bash
# Collect and archive benchmark results

set -euo pipefail

ARCH=$(uname -m)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ARCHIVE="bench-results-${ARCH}-${TIMESTAMP}.tar.gz"

echo "=== Collecting Benchmark Results ==="
echo "Architecture: $ARCH"
echo "Archive: $ARCHIVE"
echo ""

# Check what exists
echo "Available results:"
for dir in ~/bench-results/*/; do
    if [[ -d "$dir" ]]; then
        name=$(basename "$dir")
        csv="$dir/benchmark_results.csv"
        if [[ -f "$csv" ]]; then
            rows=$(wc -l < "$csv" | tr -d ' ')
            echo "  $name: $rows rows"
        else
            echo "  $name: (no CSV)"
        fi
    fi
done

echo ""
echo "Creating archive..."
tar -czvf "$ARCHIVE" -C ~ bench-results/

echo ""
echo "Archive created: $(pwd)/$ARCHIVE"
echo "Size: $(du -h "$ARCHIVE" | cut -f1)"
echo ""
echo "To download (run on your local machine):"
echo "  scp $(hostname -I 2>/dev/null | awk '{print $1}' || echo 'SERVER_IP'):$(pwd)/$ARCHIVE ./results/"
