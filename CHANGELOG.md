# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Spec v7.1: Statistical correctness refinements**
  - **Inference uses raw W₁ (§3.1):** Bayesian inference now uses raw W₁ distance without debiasing or clamping. Debiased W₁ is computed only for display purposes to help users interpret effect magnitude above measurement noise. This prevents bias in the likelihood function.
  - **Floor from null distribution (§3.3.3):** Measurement floor constant $c_{\text{floor}}$ is now calibrated from the 95th percentile of null W₁ replicates (via within-class splits) rather than heuristic formulas based on Normal quantiles. Runtime floor: $\theta_{\text{floor}}(n) = \max(\theta_{\text{tick}}, c_{\text{floor}} / \sqrt{n_{\text{blocks}}})$ where $n_{\text{blocks}} = \max(1, \lfloor n / L \rfloor)$.
  - **Prior targets user threshold (§3.3.4):** Half-t prior scale $\sigma$ is calibrated so that $P(\delta > \theta_{\text{user}}) = 0.62$, not $P(\delta > \theta_{\text{eff}})$. The prior encodes security requirements, not measurement limitations.
  - **Robust likelihood (§3.4.2):** Student-t likelihood degrees of freedom changed from $\nu_{\ell} = 8$ to $\nu_{\ell} = 4$ (matching prior ν = 4) for consistency between prior and likelihood tail behavior.
  - **Tail directionality metric (§2.3):** `tail_slow_share` now correctly measures fraction of tail deviation magnitude (p95+) from slowdowns: $\sum_{i \in \text{tail}} \max(d_i - \text{shift}, 0) / \sum_{i \in \text{tail}} |d_i - \text{shift}|$. Operates on quantile-aligned differences.
  - **Block count terminology (Appendix A):** Variable $n_{\text{blocks}}$ replaces ambiguous $n_{\text{eff}}$ in floor calculations. Effective sample size $n_{\text{eff}} = n / \hat{\tau}$ remains for IACT-based diagnostics.
  - **Migration:** Results may differ slightly from v7.0 due to corrected floor calibration and prior targeting. Test outcomes may be more conservative (fewer false positives). No API changes required.


- **Spec v5.5: Threshold elevation decision rule (§2.1, §2.6, §3.3.4, §3.5.2)**
  - Pass now requires θ_eff ≤ θ_user + ε_θ (cannot Pass when threshold is elevated)
  - When θ_floor > θ_user and P < pass_threshold, outcome is `Inconclusive(ThresholdElevated)`, not `Pass`
  - Fail MAY be returned when θ_eff > θ_user (large leaks are still detectable)
  - Renamed `ThresholdUnachievable` → `ThresholdElevated` with additional fields:
    - `leak_probability_at_eff`: posterior probability at elevated threshold
    - `meets_pass_criterion_at_eff`: whether P < pass_threshold at θ_eff
    - `achievable_at_max`: whether θ_user is achievable with max_samples
  - ε_θ tolerance = max(θ_tick, 10⁻⁶ · θ_user) for threshold comparison
  - Gate 4 (ThresholdUnachievable) removed as verdict-blocking gate; subsumed by decision rule
  - Gates renumbered: 5→4 (Time Budget), 6→5 (Sample Budget), 7→6 (Condition Drift)
  - **Rationale:** A Pass at θ_eff does not certify absence of leaks at θ_user when θ_eff > θ_user

- **Spec §3.3.2: Block length selection now uses class-conditional ACF**
  - Previous: Politis-White on pooled acquisition stream (anti-conservative due to class alternation)
  - New: Class-conditional acquisition-lag ACF with conservative combination
  - Added safety floor (b_min = 10) and inflation factor for fragile regimes
  - Fixes elevated FPR (5-8% → 2-5% expected) under null hypothesis

- **Spec §3.8: Strengthened calibration validation requirements**
  - Added explicit FPR metrics: FPR_gated and FPR_overall
  - Recommended 500+ trials (up from 100) for stable estimates
  - Added normative acceptance criteria (FPR_gated ≤ 5%, FPR_overall ≤ 10%)
  - Added anti-conservative remediation escalation steps

### Documentation

- **Major restructure (spec v4.2 → v5.0):**
  - Specification (`docs/spec.md`) refactored to be language-agnostic with RFC 2119 terminology
  - Added Abstract Types section (§2) with pseudocode ADT definitions
  - Added API Design Principles section (§5) for preventing user mistakes
  - Moved implementation details to new `docs/implementation-guide.md`
  - Moved detailed interpretation guidance to `docs/guide.md`
  - Renamed `docs/api-reference.md` to `docs/api-rust.md`
  - Added `docs/api-c.md` for C/C++ bindings
  - Added `docs/api-go.md` for Go bindings

## [0.1.0] - 2025-01-05

### Added

- Initial release
- `TimingOracle` builder with configurable presets (`new`, `balanced`, `quick`, `calibration`)
- `timing_test!` macro - returns `TestResult` directly, panics if unmeasurable
- `timing_test_checked!` macro - returns `Outcome` for explicit unmeasurable handling
- Two-layer statistical analysis:
  - CI gate (frequentist): max-statistic bootstrap with bounded false positive rate
  - Bayesian layer: posterior probability of timing leak via Bayes factor
- Effect decomposition into `UniformShift`, `TailEffect`, or `Mixed` patterns
- Exploitability assessment: `Negligible`, `PossibleLAN`, `LikelyLAN`, `PossibleRemote`
- Measurement quality metrics and minimum detectable effect (MDE) estimation
- `InputPair` helper for generating baseline/sample test inputs
- `skip_if_unreliable!` and `require_reliable!` macros for handling noisy environments
- Adaptive batching for platforms with coarse timer resolution
- Preflight checks for measurement validation

### Features

- `parallel` (default) - Rayon-based parallel bootstrap (4-8x speedup)
- `kperf` (default, macOS ARM64) - PMU-based cycle counting via kperf (~1ns resolution, requires sudo)
- `perf` (default, Linux) - perf_event cycle counting (~1ns resolution, requires sudo/CAP_PERFMON)
- `macros` - Proc macros for ergonomic test syntax

### Platform Support

| Platform | Timer | Resolution |
|----------|-------|------------|
| x86_64 | rdtsc | ~0.3 ns |
| Apple Silicon | kperf | ~1 ns (with sudo) |
| Apple Silicon | cntvct | ~41 ns (fallback) |
| Linux ARM | perf_event | ~1 ns (with sudo) |
