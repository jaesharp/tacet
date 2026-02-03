# Benchmark Preset Design Decisions

> Internal documentation for tacet-bench sweep configurations.
> Last updated: 2026-02-03 (pre-USENIX Sec '26 submission)

## Overview

The benchmark presets are designed for a progression from quick CI checks to publication-quality comparative analysis. All presets share a common σ = 50 ns noise floor, which enables meaningful detection at SharedHardware thresholds (θ = 0.4 ns).

## Design Principles

### 1. Consistent σ Across Presets

All presets use **σ = 50 ns** (synthetic_sigma_ns). This value was chosen because:

- Realistic for PMU-based measurements on modern hardware
- Enables detection of SharedHardware-level effects (θ = 0.4 ns)
- With CV = 5%, the noise SD is ~2.5 ns, so effects ≥5 ns are statistically detectable
- Keeps presets comparable—a "pass" in quick should also pass in thorough

Previous versions used σ = 100 μs, which made SharedHardware detection impossible (noise was 250,000× the threshold).

### 2. Stress Testing with Limited Samples

All presets use **5,000 samples per class**. This:

- Stresses tools to work with realistic data budgets
- Reveals which tools rely on large-sample asymptotics
- Better reflects real-world usage (users want quick answers)
- Differentiates adaptive tools (tacet) from fixed-sample tests

### 3. Two Attacker Models for Threshold Comparison

Medium and thorough include both **SharedHardware** (θ = 0.4 ns) and **AdjacentNetwork** (θ = 100 ns). This enables:

- Demonstrating tacet's configurable threat model
- Showing how the same effect can be a "Fail" for one model and "Pass" for another
- Comparing tacet's threshold-aware decisions vs. threshold-less tools

RemoteNetwork (θ = 50 μs) is excluded because effects that large are trivially detected by all tools.

### 4. Effect Size Selection

Effect sizes are chosen to span key regions:

| Effect (ns) | Significance |
|-------------|--------------|
| 0 | FPR testing (null hypothesis) |
| 5 | ~12× SharedHardware θ, challenging to detect |
| 10–20 | SharedHardware detection region |
| 50 | 1σ, moderate effect |
| 100 | AdjacentNetwork θ, transition zone |
| 200–500 | Easily detectable, cache timing scale |
| 1000 | Large effect, diminishing returns |

Beyond 1 μs, all tools achieve ~100% detection, so further granularity is wasteful.

### 5. Noise Model Selection

Autocorrelation (AR1 with φ ∈ [-0.6, 0.6]) is critical because:

- Real timing measurements exhibit autocorrelation from cache state, branch prediction, etc.
- Classical tests (Welch's t, KS) assume independence and inflate FPR under AR noise
- tacet's block bootstrap is designed to handle autocorrelation
- The SILENT paper (arXiv:2504.19821) tested φ ∈ [-0.9, 0.9]; we use a slightly narrower range

We exclude φ = ±0.8 in thorough to reduce runtime; the trend is clear from ±0.6.

#### AR(1) Implementation Details

The AR(1) noise is generated using the standard autoregressive formula:

```
X_t = φ·X_{t-1} + ε_t,  where ε_t ~ N(0, 1-φ²)
```

This noise is then added to log-normal base samples in log-space with a scale factor of 0.10:

```rust
let noisy_log = log_val + ar * 0.10;
```

The scale factor was calibrated so that measured lag-1 ACF approximately matches the nominal φ value. With scale=0.10, we observe:

| Nominal φ | Measured ACF | Effective correlation |
|-----------|--------------|----------------------|
| 0.6 | ~0.55–0.65 | Strong positive |
| 0.3 | ~0.25–0.35 | Moderate positive |
| 0 (IID) | ~0 | No correlation |
| -0.3 | ~-0.25–-0.35 | Moderate negative |
| -0.6 | ~-0.55–-0.65 | Strong negative |

#### How to Describe AR(1) in the Paper

**Heatmap axis label:** "AR(1) coefficient φ" or "Autocorrelation parameter φ"

**Methods section text (suggested):**

> To evaluate robustness to temporal correlation in timing measurements, we generated synthetic datasets with AR(1) autocorrelated noise. The AR(1) process X_t = φX_{t-1} + ε_t was applied to log-normal base samples with coefficient φ ∈ {−0.6, −0.4, −0.2, 0, 0.2, 0.4, 0.6}. Negative φ values model alternating/anti-correlated noise (e.g., from measurement compensation), while positive values model persistent correlation (e.g., from cache state or thermal effects). The range |φ| ≤ 0.6 covers autocorrelation levels commonly observed in real timing measurements.

**Key points:**

1. φ is the standard parameterization for AR(1) models—readers understand it directly
2. φ = 0.6 means "60% correlation with the previous sample"
3. No need to explain internal scaling factors; report the generative parameter
4. The range |φ| ≤ 0.6 is consistent with SILENT paper methodology

**Observed effects at φ = 0.6:**

- ks-test FPR inflates to ~30% (vs. nominal 5%)—demonstrates independence assumption violation
- tacet maintains FPR ≤ 5%—demonstrates block bootstrap robustness
- Power degrades for all tools (expected; correlation reduces effective sample size)

### 6. Effect Pattern Selection

Three patterns cover the main timing leak types:

| Pattern | Description | Real-world example |
|---------|-------------|-------------------|
| Shift | Uniform mean shift | Early-exit comparison, branch on secret |
| Tail | 5% of samples have 5× effect | Cache miss on specific inputs |
| Bimodal | Two-mode distribution | Conditional code paths |

Shift is the primary analysis target; Tail and Bimodal support robustness claims.

---

## Preset Specifications

### Quick

**Purpose:** Fast CI checks, ~15 minutes

| Parameter | Value |
|-----------|-------|
| samples_per_class | 5,000 |
| datasets_per_point | 20 |
| synthetic_sigma_ns | 50.0 |
| effect_multipliers | [0.0, 0.02, 0.1, 0.4, 1.0, 2.0] |
| effect_patterns | [Shift, Null] |
| noise_models | [IID, AR1(0.5), AR1(-0.5)] |
| attacker_models | [SharedHardware] |

**Effect sizes (ns):** 0, 1, 5, 20, 50, 100

**Total runs:** 6 × 2 × 3 × 20 × 1 = **720**

### Medium

**Purpose:** Validation before thorough, ~2 hours

| Parameter | Value |
|-----------|-------|
| samples_per_class | 5,000 |
| datasets_per_point | 30 |
| synthetic_sigma_ns | 50.0 |
| effect_multipliers | [0.0, 0.2, 1.0, 2.0, 4.0, 20.0] |
| effect_patterns | [Shift, Tail] |
| noise_models | [AR1(-0.6), AR1(-0.3), IID, AR1(0.3), AR1(0.6)] |
| attacker_models | [SharedHardware, AdjacentNetwork] |

**Effect sizes (ns):** 0, 10, 50, 100, 200, 1000

**Total runs:** 6 × 2 × 5 × 30 × 2 = **3,600**

### Thorough

**Purpose:** Publication-quality benchmarks for USENIX Sec '26, ~12-18 hours per platform

| Parameter | Value |
|-----------|-------|
| samples_per_class | 5,000 |
| datasets_per_point | 100 |
| synthetic_sigma_ns | 50.0 |
| effect_multipliers | [0.0, 0.1, 0.2, 0.4, 1.0, 2.0, 4.0, 10.0, 20.0] |
| effect_patterns | [Shift, Tail, Bimodal] |
| noise_models | [AR1(-0.6), AR1(-0.4), AR1(-0.2), IID, AR1(0.2), AR1(0.4), AR1(0.6)] |
| attacker_models | [SharedHardware, AdjacentNetwork] |

**Effect sizes (ns):** 0, 5, 10, 20, 50, 100, 200, 500, 1000

**Total runs:** 9 × 3 × 7 × 100 × 2 = **37,800**

---

## Chart Data Extraction

The thorough preset produces data for multiple analyses:

### Chart 1: tacet noise × effect heatmap
```
Filter: tool = "tacet", pattern = "Shift"
X-axis: effect_sigma_mult (9 levels)
Y-axis: noise_model φ value (7 levels)
Cells: 63, each with 100 datasets per attacker model
```

### Chart 2: Tools × effect (fixed autocorrelated noise)
```
Filter: noise_model = "AR1(0.4)", pattern = "Shift"
X-axis: effect_sigma_mult (9 levels)
Y-axis: tool name (~9 tools)
Cells: ~81, each with 100 datasets
```

### Chart 3: Tools × autocorrelation (FPR inflation)
```
Filter: effect = 0 (or 50ns), pattern = "Shift"
X-axis: noise_model φ value (7 levels)
Y-axis: tool name (~9 tools)
Cells: ~63, each with 100 datasets
```

### Chart 4: Tools × pattern robustness
```
Filter: noise_model = "AR1(0.4)", effect = 100ns
X-axis: effect_pattern (3 patterns)
Y-axis: tool name (~9 tools)
Cells: ~27, each with 100 datasets
```

---

## Confidence Interval Quality

With 100 datasets per configuration point, Wilson score 95% CIs:

| True rate | 95% CI |
|-----------|--------|
| 5% (nominal FPR) | [1.6%, 11.3%] |
| 10% | [5.2%, 17.6%] |
| 50% | [40.2%, 59.8%] |
| 90% | [82.4%, 94.8%] |
| 95% | [88.7%, 98.4%] |

This is sufficient to:
- Distinguish FPR control (tacet ≤5% vs. inflated 10-15%)
- Show power differences (80% vs. 60%)
- Support claims with tight error bars

---

## Historical Context

### Pre-2026-02-03 Issues

The original presets had several problems:

1. **σ = 100 μs** made SharedHardware detection impossible
2. **Inconsistent σ** between presets made results incomparable
3. **thorough used 6 patterns** unnecessarily expanding runtime
4. **fine_threshold multipliers assumed wrong σ** (comments didn't match reality)
5. **realistic mode hardcoded σ** ignoring config.synthetic_sigma_ns

### Changes Made

- Unified σ = 50 ns across quick, medium, thorough
- Fixed effect multipliers to match documented ns values
- Reduced thorough to 3 essential patterns
- Added AdjacentNetwork to medium/thorough for threshold comparison
- Fixed realistic mode to use config.synthetic_sigma_ns

---

## Runtime Estimates

Based on actual local benchmark timing (M-series Mac, ~10 cores utilized):

| Preset | Datasets | Work Items | Local (10 cores) | AWS 16 vCPU (projected) |
|--------|----------|------------|------------------|-------------------------|
| Quick | 720 | 5,760 | **3:40** (measured) | ~2-3 min |
| Medium | 1,800 | ~16,200 | ~12 min | ~8-10 min |
| Thorough | 18,900 | ~170,100 | ~2.5 hours | ~1.5-2 hours |

**Per-tool timing (synthetic mode):**

| Tool | Avg time/run | Notes |
|------|--------------|-------|
| rtlf-native | 3,395 ms | R script, bottleneck |
| tacet | 532 ms | Bayesian inference |
| silent-native | 268 ms | R script |
| dudect | 5.7 ms | Fast C implementation |
| ks-test | 0.8 ms | Simple statistic |
| ad-test | 0.1 ms | Simple statistic |
| mona, timing-tvla | <0.1 ms | Trivial computation |

**Synthetic vs Realistic:** Both modes have similar total runtime. Synthetic is faster at data generation but slower at analysis; realistic is the opposite.

**Platform independence:** Synthetic mode doesn't require platform-specific servers—can run anywhere. Realistic mode requires actual timing hardware.

---

## Appendix: Other Presets

### fine_threshold

Focused on AdjacentNetwork threshold graduation. Uses 12 effect sizes densely around 100 ns, all three attacker models, but only Shift pattern.

### threshold_relative

Tests effects scaled to each attacker model's threshold. Uses σ = 100 μs intentionally to cover RemoteNetwork range. SharedHardware will return Inconclusive (expected—demonstrates correct behavior under impossible SNR).

### shared_hardware_stress

Wide dynamic range from 0.2 ns to 100 μs with SharedHardware model. Tests Bayesian prior behavior at extreme effect/threshold ratios.
