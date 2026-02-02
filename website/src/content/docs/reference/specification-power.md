---
title: Power Module Specification (v1.0)
description: Specification for tacet's power and electromagnetic side-channel analysis module
sidebar:
  order: 3
---

This document specifies tacet's power side-channel analysis module. It extends the [main specification](/reference/specification) with power-specific data models, feature extraction, and output types. The statistical engine (Bayesian inference, quality gates, covariance estimation) is shared with timing analysis—this document only defines the **differences**.

For implementation details, see the [Implementation Guide](/reference/implementation-guide). For usage guidance, see the [Power Analysis Guide](/guides/power-analysis).

***

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

***

## 1. Overview

### 1.1 Scope

The power module applies tacet's Bayesian methodology to detect data-dependent leakage in pre-collected power or electromagnetic (EM) trace datasets. Unlike timing analysis (which collects measurements online), power analysis operates on **offline datasets** of acquired traces.

**In scope:**
- Two-class (fixed-vs-random) leakage detection
- Feature extraction from power traces
- Stage-wise analysis for multi-stage operations
- Effect localization (which features/partitions leak)

**Out of scope:**
- Real-time acquisition (external responsibility)
- Differential power analysis (DPA) with known keys
- Template attacks
- Trace compression or storage

### 1.2 Non-Goals

The power module is an **exploratory analysis tool** for security researchers, not a CI gating mechanism:

- **No Pass/Fail verdicts**: Power analysis returns a `Report` with posterior probabilities, not `Outcome` with verdicts
- **No user threshold (θ_user)**: The effective threshold is always the measurement floor
- **No attacker model presets**: Researchers interpret results in context

### 1.3 Relationship to Main Specification

The power module reuses all statistical machinery from the [main specification](/reference/specification):

| Component | Source | Power-Specific Differences |
|-----------|--------|----------------------------|
| Bayesian model | §3.4 | None (same prior, likelihood, Gibbs sampler) |
| Covariance estimation | §3.3.2 | Applied to trace features, not timing quantiles |
| Quality gates | §3.5.2 | Subset applies (no Pass/Fail semantics) |
| IACT estimation | Impl Guide | Applied to acquisition-ordered trace features |
| Prior calibration | §3.3.4 | Same procedure, different θ_floor computation |

**Key difference:** Timing analysis uses d=9 decile differences. Power analysis computes d from `stages × partitions × features`, potentially much larger.

***

## 2. Data Model

### 2.1 Trace

A power trace is a sequence of measurements (samples) acquired during a cryptographic operation:

```
Trace = {
  class: Class,                  // Fixed or Random
  samples: List<Float>,          // Power measurements (f32)
  markers: Option<List<Marker>>, // Stage boundaries (optional)
  id: Int                        // Unique ID preserving acquisition order
}

Class = Fixed | Random
```

**Requirements:**
- Samples MUST be `f32` values (ADC counts, volts, millivolts—units tracked separately)
- All traces MUST have equal sample count, unless stage markers are provided
- The `id` field MUST preserve **acquisition order** for IACT estimation

### 2.2 Dataset

A collection of traces for analysis:

```
Dataset = {
  traces: List<Trace>,           // Interleaved Fixed and Random traces
  units: PowerUnits,             // Measurement units
  sample_rate_hz: Option<Float>, // Acquisition sample rate
  meta: Map<String, String>      // Arbitrary metadata
}

PowerUnits =
  | Volts
  | Millivolts
  | Microvolts
  | ADCCounts { bits: Int, vref: Float }
  | Arbitrary { label: String }
```

**Requirements:**
- Dataset MUST contain at least 500 traces per class (1,000 total minimum)
- Traces SHOULD be interleaved (FRFRFR...) to avoid environmental drift—see §2.4
- Classes need not be perfectly balanced, but SHOULD have ratio within [0.4, 0.6]

### 2.3 Stage Markers

For multi-stage operations (AES rounds, RSA steps), markers segment traces:

```
Marker = {
  stage: StageId,    // Stage identifier (e.g., "round_03")
  start: Int,        // Start sample index (inclusive)
  end: Int           // End sample index (exclusive)
}

StageId = String     // Human-readable stage name
```

**Requirements:**
- Markers MUST be non-overlapping within a trace
- Markers MAY leave gaps (samples outside any stage are ignored)
- If provided, all traces in a dataset MUST have markers

**Stage length normalization:**

Stages may vary in length across traces (trigger jitter, variable-time operations). Implementations MUST normalize to a common length:

1. Compute median length for each stage across all traces
2. Resample each stage to median length (linear interpolation)
3. Emit `StageLengthVariance` warning if coefficient of variation exceeds 0.1

### 2.4 Acquisition Order and Interleaving

**Critical requirement:** Traces MUST be analyzed in acquisition order to correctly estimate temporal dependence (IACT).

**Interleaving requirement:**

Environmental drift (temperature, voltage, EM interference) creates systematic differences over time. If classes are acquired in blocks (all Fixed, then all Random), drift masquerades as data-dependent leakage.

Implementations MUST detect blocked acquisition:
- Compute time span of each class (using trace IDs as proxy for time)
- If classes are fully separated (no overlap in ID ranges) AND span exceeds 1 hour equivalent, emit `BlockedAcquisitionDetected` warning

Implementations SHOULD recommend interleaved acquisition (FRFRFR... or small blocks of 10-50 traces).

***

## 3. Feature Pipeline

Power analysis extracts statistical features from traces, then applies the d-dimensional Bayesian engine from the main specification.

### 3.1 Pipeline Overview

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Raw Traces │──▶│ Preprocess  │──▶│   Segment   │──▶│  Partition  │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
                         │                 │                 │
                         ▼                 ▼                 ▼
                   • Winsorize       • Apply markers   • Divide into
                   • DC removal      • Normalize to      spatial bins
                   • (Scale norm)      median length
                                                            │
┌─────────────┐   ┌─────────────┐   ┌─────────────────────────┘
│   Bayesian  │◀──│   Extract   │◀──┘
│   Engine    │   │   Features  │
└─────────────┘   └─────────────┘
       │                 │
       ▼                 ▼
  • d-dim inference  • Mean, Robust3,
  • Quality gates      or CenteredSquare
  • Posterior          per partition
```

### 3.2 Preprocessing

Applied to each trace before feature extraction:

**Winsorization (REQUIRED):**

Implementations MUST cap outliers at the 99.99th/0.01th percentiles:

$$
y_{\text{cap}} = \text{clamp}(y, q_{0.0001}, q_{0.9999})
$$

where quantiles are computed from the pooled dataset.

**DC removal (RECOMMENDED):**

Subtract per-trace mean to remove baseline drift:

$$
y_{\text{dc}} = y - \bar{y}
$$

**Scale normalization (NOT RECOMMENDED):**

Divide by per-trace standard deviation:

$$
y_{\text{norm}} = \frac{y - \bar{y}}{\sigma_y}
$$

This removes amplitude information. Only enable if amplitude variations are purely environmental noise. Implementations MUST default to OFF.

### 3.3 Stage Segmentation

If markers are present:

1. For each trace, extract samples within each marker's [start, end) range
2. Resample each stage to median length (see §2.3)
3. Proceed with partitioning per stage

If no markers: treat entire trace as a single stage.

### 3.4 Partitioning

Partitioning divides each (stage of each) trace into P spatial bins. Each bin yields one or more features.

**Global partitioning (default):**

All stages use the same partition count P.

**Per-stage partitioning:**

Different stages may use different partition counts (e.g., key schedule: 16, rounds: 64).

**Partition computation:**

For a trace segment of length L with P partitions:
- Partition k contains samples $[\lfloor kL/P \rfloor, \lfloor (k+1)L/P \rfloor)$
- If L is not divisible by P, last partition may be slightly larger

### 3.5 Feature Families

Three feature families extract different statistics from each partition:

**Mean (default):**

Average power per partition. Effective for first-order leakage.

$$
f_{\text{mean}}^{(p)} = \frac{1}{|B_p|} \sum_{i \in B_p} y_i
$$

where $B_p$ is the set of sample indices in partition p.

**Dimension contribution:** 1 feature per partition

**Robust3:**

Median, 10th percentile, and 90th percentile per partition. Robust to outliers and sensitive to tail effects.

$$
f_{\text{robust3}}^{(p)} = \bigl(q_{0.10}(B_p), q_{0.50}(B_p), q_{0.90}(B_p)\bigr)
$$

**Dimension contribution:** 3 features per partition

**Requirements:**
- n_eff ≥ 150 to use Robust3 (otherwise automatic fallback to Mean)
- Emit `Robust3Fallback` warning if fallback occurs

**CenteredSquare:**

Centered second moment per partition. Detects variance-based (second-order) leakage for masked implementations.

$$
f_{\text{cs}}^{(p)} = \frac{1}{|B_p|} \sum_{i \in B_p} (y_i - \bar{y}_p)^2
$$

**Dimension contribution:** 1 feature per partition

### 3.6 Dimension Computation

Total feature dimension:

$$
d = S \times P \times F
$$

where:
- S = number of stages (1 if no markers)
- P = partitions per stage (may vary per stage)
- F = features per partition (1 for Mean/CenteredSquare, 3 for Robust3)

**Dimension limit:**

If d > d_max (default 32), implementations MUST reduce dimension:

1. Merge adjacent partitions (reduce P)
2. Emit `DimensionReduced` warning with original and reduced d

**Rationale:** The Bayesian engine requires n_eff >> d for reliable covariance estimation. High dimension leads to the Overstressed regime (§4.2).

***

## 4. Threshold and Regime

### 4.1 Threshold Semantics

Power analysis uses **exploratory mode**: there is no user-specified threshold θ_user.

**Effective threshold:**

$$
\theta_{\text{eff}} = \text{floor\_multiplier} \times \theta_{\text{floor}}
$$

where:
- $\theta_{\text{floor}}$ = measurement floor computed via main spec §3.3.3
- floor_multiplier = user-configurable (default 1.0)

**Interpretation:**

The reported `leak_probability` is $P(m(\delta) > \theta_{\text{eff}} \mid \text{data})$. Since $\theta_{\text{eff}}$ is based on measurement capabilities (not attacker requirements), this probability answers: *"Is there a detectable effect above measurement noise?"*

Researchers interpret practical significance in context of their threat model.

### 4.2 Dimension Regime

The ratio r = d / n_eff determines covariance estimation quality:

| Regime | r Range | Interpretation |
|--------|---------|----------------|
| WellConditioned | r ≤ 0.05 | Excellent: covariance well-estimated |
| Stressed | 0.05 < r ≤ 0.15 | Acceptable: automatic regularization applied |
| Overstressed | r > 0.15 | Poor: reduce d or collect more data |

Implementations MUST report the regime in output. In Overstressed regime, implementations MUST emit `OverstressedRegime` quality issue.

***

## 5. Inference

Power analysis uses the same Bayesian engine as timing (main spec §3.4), with modifications for the offline setting.

### 5.1 Single-Pass Inference

Unlike timing analysis (adaptive sampling), power analysis processes a fixed dataset:

1. **Calibration phase**: Use first `calibration_traces` traces (default 500) for:
   - Covariance estimation via block bootstrap
   - IACT estimation
   - Prior scale calibration

2. **Inference phase**: Use remaining traces for:
   - Feature computation
   - Posterior inference via Gibbs sampler
   - Quality gate checks

### 5.2 Stage-Wise Analysis

If stage markers are present, implementations MAY perform stage-wise analysis:

1. Run full inference on combined dataset (all stages)
2. Additionally run inference per stage (subset of features)
3. Report both aggregate and per-stage posteriors

**Rationale:** Stage-wise reports help localize leakage ("Round 3 leaks, others safe").

### 5.3 Quality Gates

A subset of quality gates from main spec §3.5.2 apply:

| Gate | Applies | Modification |
|------|---------|--------------|
| Insufficient Information Gain | Yes | — |
| Would Take Too Long | No | (offline data, no projection) |
| Resource Budget Exceeded | No | (process full dataset) |
| Conditions Changed | Yes | Compare cal vs inference phases |

Since power analysis has no Pass/Fail verdicts, quality gates trigger warnings rather than Inconclusive outcomes.

***

## 6. Output: Report

Power analysis returns a `Report`, not an `Outcome`:

```
Report = {
  // Effect estimates
  leak_probability: Float,                // P(m(δ) > θ_eff | data)
  max_effect: Float,                      // Posterior mean of max_k |δ_k|
  max_effect_ci95: (Float, Float),        // 95% CI for max|δ|
  units: PowerUnits,                      // Measurement units

  // Threshold context
  theta_floor: Float,                     // Measurement floor
  theta_eff: Float,                       // Effective threshold used
  floor_multiplier: Float,                // Configured multiplier

  // Dimension diagnostics
  dimension: DimensionInfo,

  // Localization
  top_features: List<FeatureHotspot>,     // Top features by exceedance prob

  // Stage-wise (optional)
  stages: Option<List<StageReport>>,

  // Diagnostics
  diagnostics: Diagnostics,

  // Metadata
  trace_count: Int,
  calibration_traces: Int,
  inference_traces: Int
}

DimensionInfo = {
  d: Int,                                 // Feature dimension
  n_eff: Float,                           // Effective sample size
  r: Float,                               // d / n_eff ratio
  regime: Regime                          // WellConditioned | Stressed | Overstressed
}

Regime = WellConditioned | Stressed | Overstressed
```

### 6.1 Feature Hotspots

Hotspots identify which features show the largest effects:

```
FeatureHotspot = {
  stage: Option<StageId>,        // Stage (if markers present)
  partition: Int,                // Partition index (0-based)
  feature_type: FeatureType,     // Mean | Median | P10 | P90 | CenteredSquare
  effect_mean: Float,            // Posterior mean δ_k for this feature
  effect_ci95: (Float, Float),   // 95% marginal CI
  exceed_prob: Float             // P(|δ_k| > θ_eff | data)
}

FeatureType = Mean | Median | P10 | P90 | CenteredSquare
```

**Ordering:** Implementations MUST order top_features by descending exceed_prob.

**Prominence requirement:** Implementations SHOULD include features with exceed_prob > 0.5 (up to 10 features).

### 6.2 Stage Reports

```
StageReport = {
  stage: StageId,
  leak_probability: Float,       // P(m(δ_stage) > θ_eff | data)
  max_effect: Float,
  max_effect_ci95: (Float, Float),
  top_features: List<FeatureHotspot>
}
```

***

## 7. Configuration

### 7.1 Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| dataset | Dataset | Input traces |

### 7.2 Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| features | Mean | Feature family: Mean, Robust3, CenteredSquare |
| partitions | 32 | Partitions per stage (global) |
| d_max | 32 | Maximum feature dimension |
| floor_multiplier | 1.0 | Effective threshold = floor × multiplier |
| calibration_traces | 500 | Traces for calibration phase |
| preprocessing.dc_removal | true | Subtract per-trace mean |
| preprocessing.scale_normalization | false | Divide by per-trace std |
| preprocessing.winsor_percentile | 0.9999 | Outlier clipping percentile |
| alignment | None | Alignment method (see §7.3) |
| bootstrap_iterations | 2000 | Bootstrap iterations for covariance |
| seed | None | RNG seed for reproducibility |

### 7.3 Alignment Options

```
Alignment =
  | None                                    // No alignment (default if markers)
  | TemplateXCorr { max_shift: Int }        // Cross-correlation to pooled template
  | EdgeAlign { region: (Int, Int) }        // Align to edge in region
```

**TemplateXCorr requirements:**
- Template MUST be computed from both classes (pooled calibration)
- Emit `HighAlignmentVariance` if shift std > 10% trace length
- Emit `HighAlignmentClipping` if >5% traces clipped

***

## 8. Quality Issues

Power-specific quality issues (in addition to main spec §2.6):

| Code | Condition | Guidance |
|------|-----------|----------|
| `BlockedAcquisitionDetected` | Classes fully separated, span >1 hour | Re-acquire with interleaving |
| `Robust3Fallback` | n_eff < 150 with Robust3 requested | Using Mean instead |
| `DimensionReduced` | d > d_max | Partitions merged |
| `OverstressedRegime` | r > 0.15 | Reduce d or collect more traces |
| `StressedRegime` | 0.05 < r ≤ 0.15 | Consider reducing d |
| `StageLengthVariance` | Stage CV > 0.1 | Check trigger consistency |
| `HighAlignmentVariance` | Shift std > 10% trace length | Check trigger jitter |
| `HighAlignmentClipping` | >5% traces clipped | Increase max_shift |
| `HighWinsorRate` | >1% samples winsorized | Check acquisition noise |
| `LowEffectiveSamples` | n_eff < 100 | Collect more traces |

***

## Appendix A: Power-Specific Constants

| Constant | Default | Rationale |
|----------|---------|-----------|
| Min traces per class | 500 | Minimum for covariance estimation |
| Default partitions | 32 | Balance resolution vs dimension |
| Default d_max | 32 | Avoid Overstressed regime |
| Robust3 n_eff threshold | 150 | Quantile estimation requirement |
| Default calibration traces | 500 | Sufficient for IACT and covariance |
| WellConditioned threshold | 0.05 | r ≤ 0.05 |
| Stressed threshold | 0.15 | 0.05 < r ≤ 0.15 |
| Blocked acquisition span | 1 hour | Drift concern threshold |
| Stage CV warning | 0.1 | 10% coefficient of variation |
| Alignment shift warning | 0.1 | 10% of trace length |
| Alignment clipping warning | 0.05 | 5% of traces |
| Winsor rate warning | 0.01 | 1% of samples |

***

## Appendix B: Changelog

### v1.0 (initial)

Extracted from main specification v5.7 §7 as a standalone document. Changes from v5.7:

- **Restructured:** Data model (§2), feature pipeline (§3), output types (§6) now organized as standalone sections rather than subsections of timing spec
- **Clarified:** Relationship to main specification (§1.3)—this document only defines differences
- **Simplified:** Removed duplicate descriptions of Bayesian inference, quality gates, covariance estimation (reference main spec instead)
- **Added:** Explicit dimension regime thresholds (§4.2)
- **Added:** Quality issues table (§8)
