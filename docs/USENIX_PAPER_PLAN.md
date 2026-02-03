# Tacet USENIX Security 2026 Paper Plan

**Target**: USENIX Security 2026, Cycle 2
**Submission Deadline**: Thursday, February 5, 2026, 11:59 PM AoE
**Registration**: Already completed (January 29 deadline passed)

---

## Title

**Tacet: Reliable Timing Side-Channel Detection via Bayesian Inference**

---

## Core Story

> "Existing timing side-channel detection tools are unreliable and can't be trusted; tacet provides calibrated verdicts and is a better fit for almost all use cases."

**Key framing**: Emphasize "calibrated verdicts" / "honest under noise" rather than "three-way decisions" or "Bayesian vs frequentist." The point is tacet won't give you false confidence when data quality is poor.

---

## What's Novel About Tacet

1. **Calibrated verdicts** — when tacet reports Pass, the probability of a leak above threshold is genuinely low. When evidence is insufficient, it says Inconclusive rather than guessing.

2. **Proper uncertainty quantification** — outputs P(leak > θ | data), an interpretable posterior probability, not a p-value.

3. **Quantile-based test statistic** — comparing 9 deciles captures both uniform shifts (branch changes) and tail effects (cache misses). Uses max_k decision functional. (Attribute to SILENT: "We adopt the quantile-difference statistic and max-k decision rule from [SILENT], embedding them in a probabilistic framework that enables calibrated uncertainty quantification.")

4. **Handles autocorrelation** — block bootstrap on the acquisition stream (not per-class) preserves temporal dependence. SILENT also handles autocorrelation via m-dependent block bootstrap, but assumes a specific parametric dependence structure.

5. **Handles non-stationarity** — condition drift detection, quality gates catch drift. SILENT acknowledges stationarity as a limitation; Tacet actively monitors for drift.

6. **Measurement floor as first-class concept** — explicit θ_floor(n_eff) that shrinks with √n_eff. Pass requires θ_eff ≤ θ_user.

7. **Quality gates** — KL divergence checks, κ < 0.3 triggers likelihood inflation, stationarity monitoring. Forces Inconclusive when model can't confidently distinguish signal from noise.

8. **Practical tooling** — Rust core with C/C++/Go bindings (Python planned). Native CI integration. SILENT and RTLF are R-only and require pre-collected sample files.

---

## Comparison with Existing Tools

### Feature Comparison Table

| Feature | dudect | tlsfuzzer | RTLF | SILENT | **tacet** |
|---------|--------|-----------|------|--------|-----------|
| **Calibrated verdicts**¹ | ✗ | ✗ | ✗ | ✗ | ✓ |
| **Posterior probability** | ✗ | ✗ | ✗ | ✗ | ✓ |
| **Stationarity monitoring** | ✗ | ✗ | ✗ | ✗ | ✓ |
| Handles autocorrelation | ✗ | ◐ | ✗ | ✓² | ✓ |
| Non-parametric | ✗ | ◐ | ✓ | ✓ | ✓ |
| Bounded false positive rate | ◐ | ✓ | ✓ | ✓ | ✓ |
| Coarse/discrete timers | ✓ | ✗ | ✗ | ✓ | ✓ |
| Effect size quantification | ✗ | ✗ | ◐³ | ✓ | ✓ |
| Adaptive sampling | ◐ | ✗ | ✗ | ✓ | ✓ |
| **Language support** | C/C++/Rust | Python | R | R | C/C++/Go/Rust |
| Integrated measurement | ✓ | ✓ | ✗ | ✗ | ✓ |

¹ Reports Inconclusive when evidence insufficient, rather than forcing a verdict
² SILENT uses m-dependent block bootstrap, but does not monitor for stationarity violations
³ RTLF reports raw decile differences without confidence intervals

### Key Differentiators (Tacet vs All Competitors)

**Calibrated three-way verdicts** are Tacet's unique contribution—no other tool does this:

| Tool | Says "Inconclusive"? | P(leak > θ \| data)? | Monitors stationarity? |
|------|---------------------|---------------------|----------------------|
| dudect | ✗ | ✗ | ✗ |
| tlsfuzzer | ✗ | ✗ | ✗ |
| RTLF | ✗ | ✗ | ✗ |
| SILENT | ✗ | ✗ | ✗ |
| **tacet** | ✓ | ✓ | ✓ |

### SILENT vs Tacet

SILENT is the closest competitor statistically. Key differences:

| Aspect | SILENT | Tacet |
|--------|--------|-------|
| Autocorrelation | m-dependent block bootstrap | Block bootstrap (no parametric assumption) |
| Output | Binary verdict (bounded Type-I error) | Ternary verdict + posterior probability |
| Stationarity | Acknowledges as limitation | Quality gates actively detect drift |
| When evidence weak | Forces Pass/Fail | Reports Inconclusive |
| Tooling | R-only, pre-collected files | Rust + C/Go bindings, integrated measurement |

### RTLF vs Tacet

| Aspect | RTLF | Tacet |
|--------|------|-------|
| Autocorrelation | iid bootstrap (assumes independence) | Block bootstrap |
| Output | Binary verdict | Ternary + probability |
| Effect size | Raw decile differences | Structured estimate + credible intervals |
| Tooling | R-only | Rust + C/Go bindings |

### Framing Recommendations

1. **Lead with calibrated verdicts**: The unique value is "honest under noise"—Tacet says Inconclusive when evidence is weak, rather than forcing a potentially wrong verdict.

2. **Don't overclaim on autocorrelation**: SILENT also handles it. Focus on Tacet's additional benefits: no parametric dependence assumption, active stationarity monitoring.

3. **Emphasize practical tooling**: SILENT and RTLF are R-only and operate on pre-collected measurement files—impractical for real crypto library maintainers who need native CI integration.

4. **Credit SILENT appropriately**: "We adopt the quantile-difference statistic from SILENT, embedding it in a probabilistic framework that enables calibrated uncertainty quantification and explicit Inconclusive verdicts."

---

## Paper Structure

### Page Budget (13 pages max body)

| Section | Pages | Content |
|---------|-------|---------|
| **1. Introduction** | 1.25 | Hook: existing tools give false confidence under noise. Contributions list. |
| **2. Background & Related Work** | 1.25 | Timing side-channels 101, existing tools, feature comparison table. |
| **3. Tacet's Approach** | 3.5 | Problem→solution structure (see below). Worked example figure. |
| **4. Implementation** | 0.75 | Block bootstrap, adaptive batching, language bindings, CI integration. |
| **5. Evaluation** | 3.5 | Methodology, 3 heatmaps, discussion, crypto library validation + MARVIN mention. |
| **6. Discussion & Limitations** | 0.75 | Pipeline complexity, lower power (but honest), ~100ms overhead. Future: power/EM. |
| **7. Conclusion** | 0.5 | |
| **Ethical Considerations** | 1 (required) | Stakeholder-based analysis (see below). |
| **Open Science** | 1 (required) | MPL v2, anonymous repo link, artifact list. |
| **Appendix A** | optional | Statistical methodology details. |

### Section 3 Structure (Problem → Solution)

| Problem with existing tools | Tacet's solution |
|----------------------------|------------------|
| Binary verdicts conflate "safe" with "couldn't tell" | Three-way decisions with explicit Inconclusive |
| No interpretable uncertainty (p-values misunderstood) | Posterior probability P(leak > θ \| data) |
| RTLF assumes iid measurements; SILENT assumes m-dependence | Block bootstrap without parametric dependence assumption |
| No stationarity monitoring (SILENT acknowledges as limitation) | Quality gates actively detect drift |
| Fixed sample sizes or invalid early stopping | Adaptive sampling (valid because likelihood-based) |
| No concept of "what can we actually resolve?" | Explicit measurement floor θ_floor(n) |
| Flaky in CI under noise | Quality gates force Inconclusive when evidence weak |

### Worked Example (Section 3.5)

~1/3 page figure showing same noisy dataset:
- dudect says "Pass" (t < 10)
- tacet says "Inconclusive" with posterior visualization showing high uncertainty

---

## Benchmarks

### Three Heatmaps

1. **Effect size × Tool** (fixed moderate noise) — power comparison
2. **Autocorrelation × Tool** (fixed small effect) — robustness to dependent data
3. **Noise level × Tool** (null hypothesis) — FPR under stress, showcases calibrated verdicts

### Color Scheme
- ✓ Pass (green)
- ✗ Fail/Leak detected (red)
- ? Inconclusive (yellow/amber)
- ⚠ Error (gray)

### Visual Story
Under high noise/autocorrelation, other tools show scattered red (false positives) or incorrect green (false negatives); tacet shows yellow (Inconclusive) that transitions to correct verdicts as conditions improve.

### Benchmark Types
- **Synthetic**: Generated distributions with controlled effect sizes, injected autocorrelation
- **Realistic**: Real cryptographic implementations on real hardware, fixed sample size across tools, natural autocorrelation

### Crypto Library Validation
Mention test suite against crypto libraries. Incidentally rediscovered timing behavior consistent with MARVIN (CVE-2023-49092).

---

## Required Appendices

### Ethical Considerations (Stakeholder-Based)

> **Stakeholders.** We identify three primary stakeholders: (1) cryptographic library maintainers, who benefit from improved vulnerability detection; (2) end users of cryptographic software, who benefit from more secure implementations; and (3) potential attackers, who could misuse timing analysis techniques.
>
> **Impacts.** Following the Menlo Report principles:
> - *Beneficence*: Tacet enables proactive detection of timing side-channels before deployment, reducing the window of vulnerability for end users.
> - *Respect for Persons*: Our work does not involve human subjects or personal data.
> - *Justice*: By releasing tacet as open-source software (MPL v2), we ensure equal access to improved security testing across organizations of all sizes.
> - *Respect for Law and Public Interest*: Timing side-channel detection is an established defensive practice; we are not introducing novel attack capabilities.
>
> **Potential Harms.** The statistical techniques underlying tacet could theoretically help attackers confirm timing leaks. However, simpler tools (e.g., dudect) already provide this capability; tacet's contribution is primarily in reducing false positives and providing calibrated uncertainty—properties more valuable to defenders than attackers.
>
> **Decision.** We concluded that publication serves the public interest: tacet's practical CI integration lowers the barrier for maintainers to adopt rigorous timing analysis, catching vulnerabilities before they affect users. The marginal benefit to attackers is minimal compared to existing tools.

### Open Science

> All artifacts necessary to evaluate our contributions are publicly available:
>
> - **Source code**: https://anonymous.4open.science/r/tacet-75EB/ (MPL v2 license)
> - **Specification**: Included in repository as `specification.md`
> - **Benchmark scripts**: `benchmarks/` directory, with instructions in `benchmarks/README.md`
> - **Benchmark results**: Raw data in `benchmarks/results/`
>
> The repository includes instructions for reproducing all experiments reported in Section 5. Hardware configuration details are provided in Section 5.1.

---

## Methodological Appendix (Optional) — Suggested Structure

~2-3 pages covering likely reviewer questions:

**A.1 Probabilistic Model**
- Quantile difference as test statistic
- Student-t likelihood (why not Gaussian—heavier tails for robustness)
- Prior specification (reference spec for full derivation)

**A.2 Inference Procedure**
- High-level Gibbs sampler description
- Convergence diagnostics
- Computational cost

**A.3 Block Bootstrap for Autocorrelation**
- Why standard bootstrap fails with dependent data
- Block size selection heuristic
- Effective sample size calculation

**A.4 Quality Gates**
- List of gates and thresholds (κ < 0.3, KL divergence, etc.)
- Brief justification for each

**A.5 Measurement Floor Derivation**
- How θ_floor(n_eff) is computed
- Relationship to posterior uncertainty

> For complete details, see the specification document in the artifact repository.

---

## Limitations to Acknowledge (Section 6)

1. **Pipeline complexity** — tacet's methodology is more complex than a t-test. The spec is detailed. Tradeoff for calibration.
2. **Lower power under noise** — tacet is more conservative; may require more samples to reach Pass/Fail than tools that guess. This is a feature—Inconclusive rate is the price of honesty.
3. **Performance** — ~100ms inference overhead per analysis. Slower than dudect/SILENT, faster than RTLF. Acceptable for CI where measurement dominates.
4. **Future work** — power/EM side-channels (experimental support exists).

---

## USENIX Formatting Requirements

- **Body**: Up to 13 pages, two-column, 10pt Times Roman, 12pt leading, 7"×9" text block
- **Required appendices**: "Ethical Considerations" and "Open Science" (each ≤1 page, immediately after body, before references)
- **Template**: Must use unmodified USENIX Security LaTeX template
- **No space squeezing**: No negative vspaces, savetrees, titlesec, etc.
- **Final version**: Max 20 total pages (body + required appendices + references + optional appendices)
- **Anonymization**: No author names/affiliations, third-person for previous work, anonymous repo links

---

## Competitor Analysis (Completed)

See `paper/analysis/` for detailed analyses:

1. **SILENT** (`paper/analysis/silent_analysis.md`): Closest statistical competitor. Uses m-dependent block bootstrap (handles autocorrelation), but outputs binary verdicts only, acknowledges stationarity as limitation, R-only.

2. **RTLF** (`paper/analysis/rtlf_analysis.md`): USENIX Sec '24. Uses iid bootstrap (does NOT handle autocorrelation), binary verdicts, R-only post-processing on pre-collected files.

---

## Key Files

- **Specification**: `/sessions/epic-quirky-rubin/mnt/uploads/specification.md` (also in repo)
- **Website content**: Check `website/src/content/reference/` for detailed spec
- **Benchmarks**: See `AWS_VALIDATION_RUN.md` for current benchmark setup

---

## Topic Selection (HotCRP)

Primary: **Hardware security → Side channels** or **Applications of cryptography → Analysis of deployed cryptography**

---

## Timeline (as of Feb 3)

- **Today (Tue)**: Finalize benchmarks, draft Section 3 + Section 5
- **Tomorrow (Wed)**: Introduction, Background, Discussion, Conclusion
- **Thursday morning**: Appendix, final polish, anonymization check
- **Thursday 11:59 PM AoE**: SUBMIT
