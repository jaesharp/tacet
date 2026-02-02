#!/usr/bin/env bash
# Check status of all benchmark runs

set -euo pipefail

echo "=== Benchmark Status: $(uname -m) ==="
echo ""

check_run() {
    local name="$1"
    local dir="$2"
    local expected="${3:-0}"

    echo "--- $name ---"

    if [[ ! -d "$dir" ]]; then
        echo "  Not started"
        return
    fi

    local csv="$dir/benchmark_results.csv"
    local pid_file="$dir/pid"
    local log="$dir/logs/run.log"

    # Check if running
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo "  Status: RUNNING (PID $pid)"
        else
            echo "  Status: FINISHED (or crashed)"
        fi
    else
        echo "  Status: Not running in background"
    fi

    # Check row count
    if [[ -f "$csv" ]]; then
        local rows=$(wc -l < "$csv" | tr -d ' ')
        rows=$((rows - 1))  # Subtract header
        if [[ "$expected" -gt 0 ]]; then
            local pct=$((rows * 100 / expected))
            echo "  Progress: $rows rows ($pct%)"
        else
            echo "  Progress: $rows rows"
        fi

        # Tool breakdown
        echo "  Tools:"
        cut -d, -f1 "$csv" 2>/dev/null | sort | uniq -c | tail -n +2 | while read count tool; do
            echo "    $tool: $count"
        done
    else
        echo "  No results yet"
    fi

    # Recent log
    if [[ -f "$log" ]]; then
        echo "  Last log line:"
        echo "    $(tail -1 "$log" 2>/dev/null | cut -c1-80)"
    fi

    echo ""
}

# Quick: 6 effects × 2 patterns × 3 noise × 20 datasets × 9 tools = 6,480
check_run "Quick" ~/bench-results/quick 6480

# Medium: ~81,000 tool runs
check_run "Medium Synthetic" ~/bench-results/medium-synth 81000
check_run "Medium Realistic" ~/bench-results/medium-real 81000

# Thorough: ~923,400 tool runs
check_run "Thorough Synthetic" ~/bench-results/thorough-synth 923400
check_run "Thorough Realistic" ~/bench-results/thorough-real 923400

echo "=== End Status ==="
