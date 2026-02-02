#!/usr/bin/env bash
# AWS Benchmark Server Setup Script
# Run this on both servers to prepare for validation runs

set -euo pipefail

echo "=== tacet AWS Benchmark Setup ==="
echo "Architecture: $(uname -m)"
echo "Hostname: $(hostname)"
echo ""

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]] || ! grep -q 'name = "tacet"' Cargo.toml 2>/dev/null; then
    echo "ERROR: Run this script from the tacet repository root"
    echo "  git clone https://github.com/agucova/tacet.git && cd tacet"
    exit 1
fi

# Check if devenv is available
if ! command -v devenv &> /dev/null; then
    echo "ERROR: devenv not found. Enter devenv shell first:"
    echo "  nix-shell -p devenv --command 'devenv shell'"
    exit 1
fi

echo "=== Step 1: Verifying tools ==="

echo -n "  cargo: "
cargo --version | head -1

echo -n "  rtlf: "
if command -v rtlf &> /dev/null; then
    rtlf --help 2>&1 | head -1 || echo "(available)"
else
    echo "NOT FOUND - check devenv"
fi

echo -n "  silent: "
if command -v silent &> /dev/null; then
    silent --help 2>&1 | head -1 || echo "(available)"
else
    echo "NOT FOUND - check devenv"
fi

echo -n "  tlsfuzzer: "
if command -v tlsfuzzer &> /dev/null; then
    echo "(available)"
else
    echo "NOT FOUND (OK if in devenv virtualenv)"
fi

echo ""
echo "=== Step 2: Building benchmark binary ==="
cargo build --release -p tacet-bench
echo "  Done!"

echo ""
echo "=== Step 3: Creating output directories ==="
mkdir -p ~/bench-results/{quick,medium-synth,medium-real,thorough-synth,thorough-real}/logs
echo "  Created ~/bench-results/{quick,medium-synth,medium-real,thorough-synth,thorough-real}/logs"

echo ""
echo "=== Step 4: Configuring PMU access ==="
if [[ "$(uname)" == "Linux" ]]; then
    current=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "unknown")
    echo "  Current perf_event_paranoid: $current"
    if [[ "$current" != "1" ]] && [[ "$current" != "0" ]] && [[ "$current" != "-1" ]]; then
        echo "  Setting perf_event_paranoid=1..."
        sudo sysctl -w kernel.perf_event_paranoid=1
    else
        echo "  Already configured for PMU access"
    fi
else
    echo "  Not Linux, skipping PMU configuration"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Run quick validation:    ./scripts/aws-bench-quick.sh"
echo "  2. Run medium synthetic:    ./scripts/aws-bench-medium.sh synth"
echo "  3. Run medium realistic:    ./scripts/aws-bench-medium.sh real"
echo "  4. Run thorough overnight:  ./scripts/aws-bench-thorough.sh synth"
echo "  5. Run thorough realistic:  ./scripts/aws-bench-thorough.sh real"
echo ""
