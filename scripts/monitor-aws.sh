#!/usr/bin/env bash
# Monitor both AWS servers from local machine

set -euo pipefail

X86="98.84.17.7"
ARM="13.223.200.77"

echo "=== AWS Benchmark Server Monitor ==="
echo "Time: $(date)"
echo ""

check_server() {
    local ip="$1"
    local arch="$2"

    echo "--- $arch ($ip) ---"

    # Check if reachable
    if ! ssh -o ConnectTimeout=3 "$ip" 'true' 2>/dev/null; then
        echo "  UNREACHABLE"
        return
    fi

    # Check devenv build
    local devenv_log=$(ssh "$ip" 'tail -3 ~/devenv-build.log 2>/dev/null' 2>/dev/null || echo "No log")
    if [[ "$devenv_log" == "No log" ]]; then
        echo "  Devenv: Not started"
    else
        local devenv_procs=$(ssh "$ip" 'ps aux | grep -E "devenv|cargo" | grep -v grep | wc -l' 2>/dev/null || echo "0")
        if [[ "$devenv_procs" -gt 0 ]]; then
            echo "  Devenv: Building ($devenv_procs processes)"
            echo "  Last log:"
            echo "$devenv_log" | sed 's/^/    /'
        else
            # Check if binary exists
            local binary=$(ssh "$ip" 'ls ~/tacet/target/release/benchmark 2>/dev/null && echo "exists"' 2>/dev/null || echo "")
            if [[ "$binary" == "exists" ]]; then
                echo "  Devenv: Build complete"
            else
                echo "  Devenv: Build finished or failed (check log)"
            fi
        fi
    fi

    # Check benchmark runs
    for preset in quick medium-synth medium-real thorough-synth thorough-real; do
        local csv="~/bench-results/$preset/benchmark_results.csv"
        local rows=$(ssh "$ip" "wc -l < $csv 2>/dev/null || echo 0" 2>/dev/null)
        if [[ "$rows" -gt 1 ]]; then
            rows=$((rows - 1))  # Subtract header
            echo "  $preset: $rows rows"
        fi
    done

    echo ""
}

check_server "$X86" "x86_64"
check_server "$ARM" "ARM64"

echo "=== End Monitor ==="
