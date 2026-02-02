# tacet-bench AWS Validation Run Plan

**Goal:** Full validation results for USENIX Security '26 paper (deadline: end of week)
**Servers:** 2 AWS NixOS instances (ARM64 + x86_64, both 16-core/32GB)
**Approach:** Quick harness validation → Medium first-pass → Thorough overnight

---

## Server Access

| Architecture | Instance | IP | SSH |
|--------------|----------|-----|-----|
| x86_64 (AMD) | c5.4xlarge | `54.92.156.192` | `ssh 54.92.156.192` |
| ARM64 (Graviton 3) | c6g.4xlarge | `13.223.200.77` | `ssh 13.223.200.77` |

**Note:** Both servers have passwordless sudo configured.

---

## Tool Selection

**Use `--tools all` for all runs** (catches harness issues early):
- tacet, dudect, timing-tvla, ks-test, ad-test, mona
- rtlf-native (faithful Rust port)
- silent (R reference — **NOT** silent-native)
- tlsfuzzer

**Note:** `--tools all` specifically uses `SilentAdapter` (R reference), not `SilentNativeAdapter`. The native version is NOT included.

---

## Phase 1: Server Setup (both servers)

```bash
# Clone and enter devenv
git clone https://github.com/agucova/tacet.git && cd tacet
nix-shell -p devenv --command "devenv shell"

# Verify tools (especially R references)
cargo --version
rtlf --help 2>&1 | head -1      # RTLF R script
silent --help 2>&1 | head -1    # SILENT R script
which tlsfuzzer || echo "tlsfuzzer not in PATH (OK if in devenv)"

# Build benchmark binary
cargo build --release -p tacet-bench

# Create output directories
mkdir -p ~/bench-results/{quick,medium-synth,medium-real,thorough-synth,thorough-real}/logs

# Enable PMU access for realistic mode (passwordless sudo available)
sudo sysctl -w kernel.perf_event_paranoid=1
```

---

## Phase 2: Quick Harness Validation (~5–10 min, both servers)

**Purpose:** Catch any harness/tool issues before longer runs.

```bash
cargo run --release -p tacet-bench --bin benchmark -- \
    --preset quick --tools all \
    --output ~/bench-results/quick -q \
    2>&1 | tee ~/bench-results/quick/logs/run.log
```

**Verify:**
- All 9 tools ran: `cut -d, -f1 ~/bench-results/quick/benchmark_results.csv | sort | uniq -c`
- No errors: `grep -i error ~/bench-results/quick/benchmark_results.csv | head`
- Silent came from R reference (check logs for R/Rscript invocations)

---

## Phase 3: Medium First-Pass (~30–45 min each mode)

### 3a. Synthetic (all tools)
```bash
cargo run --release -p tacet-bench --bin benchmark -- \
    --preset medium --tools all \
    --output ~/bench-results/medium-synth -q \
    2>&1 | tee ~/bench-results/medium-synth/logs/run.log
```

### 3b. Realistic (all tools, requires sudo)
```bash
sudo -E cargo run --release -p tacet-bench --bin benchmark -- \
    --preset medium --tools all --realistic --realistic-base-ns 1000 \
    --output ~/bench-results/medium-real -q \
    2>&1 | tee ~/bench-results/medium-real/logs/run.log
```

**Expected:** ~9,000 datasets × 9 tools = 81,000 tool runs

---

## Phase 4: Thorough Overnight (~3–5 hours each mode)

### 4a. Synthetic (all tools)
```bash
nohup cargo run --release -p tacet-bench --bin benchmark -- \
    --preset thorough --tools all \
    --output ~/bench-results/thorough-synth -q \
    2>&1 > ~/bench-results/thorough-synth/logs/run.log &
echo $! > ~/bench-results/thorough-synth/pid
```

### 4b. Realistic (all tools, requires sudo)
```bash
nohup sudo -E cargo run --release -p tacet-bench --bin benchmark -- \
    --preset thorough --tools all --realistic --realistic-base-ns 1000 \
    --output ~/bench-results/thorough-real -q \
    2>&1 > ~/bench-results/thorough-real/logs/run.log &
echo $! > ~/bench-results/thorough-real/pid
```

**Expected:** ~102,600 datasets × 9 tools = 923,400 tool runs

---

## Monitoring & Recovery

```bash
# Watch progress
tail -f ~/bench-results/thorough-synth/logs/run.log

# Check completion %
ROWS=$(wc -l < ~/bench-results/thorough-synth/benchmark_results.csv)
echo "$((ROWS * 100 / 923400))% complete"

# Verify all tools are running (not erroring out)
cut -d, -f1 ~/bench-results/thorough-synth/benchmark_results.csv | sort | uniq -c

# Resume if interrupted
cargo run --release -p tacet-bench --bin benchmark -- \
    --preset thorough --tools all \
    --output ~/bench-results/thorough-synth --resume -q
```

---

## Result Collection

```bash
# Create archive
ARCH=$(uname -m) && TIMESTAMP=$(date +%Y%m%d_%H%M%S)
tar -czvf bench-results-${ARCH}-${TIMESTAMP}.tar.gz ~/bench-results/

# SCP to local (run from your machine)
scp 54.92.156.192:bench-results-*.tar.gz ./results/x86_64/
scp 13.223.200.77:bench-results-*.tar.gz ./results/arm64/
```

---

## Verification Checklist

- [ ] All 9 tools present in results
- [ ] Row count matches expected
- [ ] No ERROR/FAIL in status column
- [ ] FPR < 10% at effect=0 for all tools
- [ ] tacet FPR ~5% (well-calibrated)
- [ ] Power increases with effect size
- [ ] ARM64 and x86_64 results comparable
- [ ] SILENT results came from R reference (not native)

---

## Critical Notes

1. **`--tools all` is correct** — it uses `SilentAdapter` (R reference), not `SilentNativeAdapter`. Verified in `benchmark.rs:188-199`.

2. **Run identical benchmarks on both architectures** — don't split work; you want complete cross-platform comparison.

3. **Realistic mode is slower** — uses semaphore limiting concurrent timers to 1; expect ~2× wall time vs synthetic.

4. **If R tools fail:** Check devenv is active (`which rtlf`, `which silent`). First run has R startup overhead.

5. **Passwordless sudo** — Both servers have passwordless sudo, so no need to enter passwords for `sudo -E` commands.

---

## Timeline

| When | Task |
|------|------|
| Day 1 AM | Setup both servers, **quick with all tools** |
| Day 1 PM | Medium synthetic + realistic (both, all tools) |
| Day 1 Evening | Start thorough synthetic (both) |
| Day 2 AM | Verify thorough synthetic, start thorough realistic |
| Day 2–3 | Collect results, verify, analyze |

---

## Quick Reference: Server Commands

### x86_64 Server (54.92.156.192)
```bash
ssh 54.92.156.192
# Then follow setup and run commands above
```

### ARM64 Server (13.223.200.77)
```bash
ssh 13.223.200.77
# Then follow setup and run commands above
```

---

## Key Files

- `crates/tacet-bench/src/bin/benchmark.rs:186-199` — `--tools all` definition (uses R SILENT)
- `crates/tacet-bench/src/sweep.rs` — Preset definitions
- `crates/tacet-bench/src/checkpoint.rs` — Resume functionality
- `devenv.nix` — R packages, RTLF, SILENT dependencies
