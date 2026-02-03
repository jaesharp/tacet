# RTLF Paper Analysis

**Paper**: "With Great Power Come Great Side Channels: Statistical Timing Side-Channel Analyses with Bounded Type-1 Errors"
**Authors**: Martin Dunsche, Marcel Maehren, Nurullah Erinola (Ruhr University Bochum), Robert Merget (Technology Innovation Institute), Nicolai Bissantz (Ruhr University Bochum), Juraj Somorovsky (Paderborn University), Jorg Schwenk (Ruhr University Bochum)
**Venue**: 33rd USENIX Security Symposium (USENIX Security '24), August 2024
**Pages**: 6687-6704

---

## A. Summary of Statistical Approach

### Test Statistic

RTLF uses a **decile-based comparison** approach:

- Compares **nine deciles** (10%, 20%, ..., 90%) of two measurement distributions
- For each decile k, computes the absolute difference: `|q_k^X - q_k^Y|`
- Declares a leak if **any** decile's difference exceeds its bootstrap-derived threshold

This is distinct from SILENT's approach (which uses a normalized max statistic) and closer to a "union of tests" strategy.

### Type-I Error Bounding

RTLF achieves bounded Type-I error through **empirical bootstrap**:

1. **Null distribution construction**: Under H_0 (no difference), the bootstrap estimates the sampling distribution of decile differences
2. **Threshold computation**: For each decile, compute a threshold as the bootstrap-estimated maximum expected variance
3. **Alpha parameter**: User specifies alpha (default 0.09), which controls the family-wise error rate across all deciles

**Key mechanism**: The bootstrap samples from the combined pool of X and Y measurements under the null hypothesis assumption, then estimates the variance at each decile. Thresholds are set such that observing differences larger than the threshold is rare (< alpha) under the null.

The alpha of 0.09 (not the conventional 0.05) may reflect an implicit Bonferroni-style adjustment for 9 simultaneous decile tests, though the paper doesn't make this explicit.

### Empirical Bootstrap Approach

**Algorithm overview** (from README and tool output):

```
For i = 1 to B (default B = 10,000):
    Resample from pooled data under null hypothesis
    Compute decile differences for bootstrap sample
    Record the differences

For each decile k:
    Threshold_k = estimate of maximum expected variance based on bootstrap
    ThresholdX_k, ThresholdY_k = within-series variance estimates
```

**Key characteristics**:
- **Non-parametric**: Does not assume a specific distribution shape
- **iid bootstrap**: Appears to use standard (non-block) bootstrap resampling
- **Large B**: 10,000 bootstrap iterations is substantially more than typical (1,000-2,000)
- **Per-decile thresholds**: Each decile gets its own threshold based on local variance

### Multiple Testing / Multiple Comparisons

RTLF performs **9 simultaneous hypothesis tests** (one per decile). The paper does not explicitly describe how they control for multiple comparisons, but the approach appears to be:

1. **Implicit alpha adjustment**: The default alpha = 0.09 may incorporate a Bonferroni-style correction (0.09/9 ~ 0.01 per decile)
2. **Union intersection**: A leak is declared if ANY decile exceeds its threshold (union of individual test rejections)
3. **No explicit Bonferroni**: Unlike some frequentist approaches, there's no explicit alpha/9 division---the thresholds are empirically derived from bootstrap

This is different from SILENT's approach, which explicitly avoids multiple testing by using a single max statistic (max_k of normalized differences).

### Assumptions About the Data

**Implicit assumptions** (inferred from methodology):

1. **Independence between measurements**: Standard bootstrap assumes iid samples. RTLF does NOT appear to use block bootstrap or account for autocorrelation in measurement sequences.

2. **Stationarity**: The measurement process is assumed to be stationary (same distribution throughout the measurement campaign).

3. **No parametric distribution**: Quantile-based approach is non-parametric---works for any continuous distribution.

4. **Sufficient sample size**: Bootstrap validity requires reasonable sample sizes (typically n > 30, ideally much larger for reliable quantile estimation at extremes).

### Autocorrelation Handling

**RTLF does NOT explicitly handle autocorrelation.**

- Uses standard (iid) bootstrap, not block bootstrap
- Does not estimate dependence length (m) or effective sample size
- No mention of temporal dependence in the tool documentation
- This is a significant methodological limitation for timing measurements, which often exhibit serial correlation

**Contrast with SILENT**: SILENT explicitly handles m-dependence via block bootstrap and uses Politis et al.'s estimator for the dependence length.

**Contrast with Tacet**: Tacet uses block bootstrap on the acquisition stream with block length ~ n^(1/3), preserving temporal dependence structure.

### Decision Rule

**For each decile k**:
```
Decision_k = 1  if |q_k^X - q_k^Y| > Threshold_k
           = 0  otherwise
```

**Overall decision**:
```
Leak detected  if any Decision_k = 1
No leak        if all Decision_k = 0
```

**Exit codes**:
- Exit 11: Difference detected (at least one significant decile)
- Exit 10: No difference (all deciles non-significant)
- Exit 1: Processing error

**Binary output**: Like dudect and SILENT, RTLF outputs only Pass/Fail---there is no "Inconclusive" or "uncertain" category.

---

## B. Corrections to Comparison Table

### Current Claims in USENIX_PAPER_PLAN.md

| Feature | Current Claim | Accurate? | Correction/Notes |
|---------|---------------|-----------|------------------|
| **Calibrated verdicts** | X | **Correct** | RTLF outputs binary Pass/Fail only. No mechanism for "insufficient evidence." |
| **Handles autocorrelation** | X | **Correct** | Uses standard iid bootstrap, not block bootstrap. Does not estimate or account for dependence. |
| **Non-parametric** | checkmark | **Correct** | Uses decile comparisons, no distributional assumptions. |
| **Bounded false positive rate** | checkmark | **Correct** | Type-I error bounded by alpha parameter via bootstrap. |
| **Handles non-stationarity** | X | **Correct** | No drift detection or stationarity monitoring. |
| **Coarse/discrete timers** | X | **Needs review** | Unclear from documentation. Uses deciles which could handle discrete data, but no explicit discrete data algorithm (unlike SILENT). |
| **Effect size quantification** | checkmark | **Partially correct** | Reports absolute decile differences (in whatever unit the measurements are). However, this is raw difference, not normalized or contextualized effect size with confidence intervals. |
| **Adaptive sampling** | X | **Correct** | No sample size estimation or adaptive stopping. Operates on pre-collected measurement files. |
| **Language support** | R | **Correct** | R implementation available on GitHub (tls-attacker/RTLF). |

### Recommended Table Updates

No major corrections needed. Suggested refinements:

1. **Effect size quantification**: Consider changing to "half-filled circle" (partial support). RTLF reports raw decile differences but does not provide:
   - Confidence intervals on effect estimates
   - Normalized effect sizes (e.g., Cohen's d equivalent)
   - Practical significance interpretation (nanoseconds, exploitability)

2. **Coarse/discrete timers**: Verify whether this should be X or half-filled circle. RTLF may work with discrete data (deciles can be computed), but there's no specific discrete-data algorithm like SILENT's mid-distribution quantiles.

### Suggested Footnote for Paper

> "RTLF uses standard (iid) bootstrap, which does not preserve temporal dependence structure in measurement sequences. For timing data with autocorrelation, this can lead to underestimated variance and inflated Type-I errors."

---

## C. Lessons for Paper Framing and Layout

### Paper Structure

Based on the USENIX Security '24 acceptance, the paper likely follows this structure:

1. **Introduction** (~1.5-2 pages)
   - Problem: Developers avoid statistical tools due to false positive unreliability
   - Solution preview: Bounded Type-I error via empirical bootstrap

2. **Background** (~1.5 pages)
   - Timing side-channels (CBC padding, Bleichenbacher, Lucky13)
   - Existing tools (dudect, Mona, tlsfuzzer, t-test)

3. **Methodology** (~3-4 pages)
   - Formal problem statement
   - Bootstrap-based threshold derivation
   - Per-decile testing approach
   - Type-I error guarantees

4. **Implementation** (~1 page)
   - RTLF tool description
   - Input/output formats
   - Performance considerations

5. **Evaluation** (~3-4 pages)
   - Synthetic benchmarks (ground truth)
   - Comparison with competitors (Mona, dudect, tlsfuzzer)
   - Real-world: 823 TLS library versions

6. **Case Studies** (~2 pages)
   - CBC Padding Oracle attack timing
   - Bleichenbacher attack timing
   - Lucky13 attack timing
   - 7 vulnerabilities discovered in recent versions

7. **Discussion/Limitations** (~0.5-1 page)
8. **Related Work** (~1 page)
9. **Conclusion** (~0.5 pages)

**Total**: ~13-15 pages body (USENIX limit)

### Compelling Framing Elements

1. **Developer pain point as hook**: The introduction emphasizes that developers *don't* use statistical tools because they're unreliable. This resonates with practitioner audiences.

2. **Trade-off framing**: "With the bounded type-1 error, the user can perform trade-offs between false positives and the size of the side channels they wish to detect."

3. **Large-scale empirical validation**: 823 versions of 11 TLS libraries is impressive scope. Longitudinal analysis shows historical vulnerability patterns.

4. **Vulnerability discovery**: Finding 7 real vulnerabilities in recent versions provides immediate practical value.

5. **Tool comparison**: Direct comparison with established tools (dudect, Mona, tlsfuzzer) on same datasets.

### Effective Figures and Tables

Based on typical USENIX Security papers and the RTLF tool output:

**Likely Figure 1**: Pipeline diagram showing measurement -> RTLF analysis -> verdict

**Likely Table 1**: Feature comparison matrix (similar to SILENT paper's Table 1):
| Tool | Bounded FPR | Handles Noise | Effect Size | ... |
|------|-------------|---------------|-------------|-----|
| dudect | X | X | X | ... |
| Mona | X | partial | X | ... |
| RTLF | checkmark | checkmark | checkmark | ... |

**Likely Figure 2-3**: Heatmaps showing detection rate vs. effect size for each tool

**Likely Table 2**: Results summary for TLS library analysis:
| Library | Versions | CBC Vuln | Bleichenbacher | Lucky13 |
|---------|----------|----------|----------------|---------|
| OpenSSL | 150 | ... | ... | ... |
| ... | ... | ... | ... | ... |

**Likely Figure 4-5**: Timeline showing when libraries became vulnerable/fixed

### Presentation Techniques to Adopt

1. **Large-scale empirical validation**: 823 versions is compelling. We should ensure our crypto library evaluation has similar scale/rigor.

2. **Known vulnerability validation**: Testing against known attacks (Bleichenbacher, Lucky13, Padding Oracle) establishes ground truth.

3. **Historical/longitudinal analysis**: Showing vulnerability timelines across library versions is effective.

4. **Vulnerability discovery as proof**: Finding new vulnerabilities (or re-discovering recent ones like MARVIN) demonstrates practical value.

5. **Tool comparison on identical datasets**: Running multiple tools on same measurements enables fair comparison.

### What RTLF Does Well (Learn From)

1. **Conservative alpha default**: 0.09 shows thought about multiple testing
2. **Large bootstrap iterations**: 10,000 is thorough
3. **Multiple output formats**: JSON, CSV, R data---practical for different workflows
4. **Batch processing**: Parallel execution for large-scale analysis
5. **Exit codes**: Machine-readable for CI integration

### What RTLF Lacks (Differentiate On)

1. **No autocorrelation handling**: Standard bootstrap ignores temporal dependence
2. **No uncertainty quantification**: Binary verdict only, no posterior probability
3. **No "Inconclusive"**: Forces a verdict even when evidence is weak
4. **No quality diagnostics**: Doesn't report measurement quality or reliability
5. **R-only**: Not practical for integration into C/C++/Rust crypto libraries
6. **Pre-collected data only**: No integrated measurement capability
7. **No stationarity monitoring**: Assumes conditions are stable throughout

---

## D. Summary: RTLF vs. Tacet Positioning

### Key Differentiators for Paper

| Aspect | RTLF | Tacet |
|--------|------|-------|
| **Output** | Binary (Leak/No Leak) | Ternary + probability (Pass/Fail/Inconclusive + P(leak > theta)) |
| **Autocorrelation** | iid bootstrap (ignores) | Block bootstrap (preserves structure) |
| **Uncertainty** | Bounded Type-I error only | Full posterior distribution |
| **When evidence weak** | Forces Pass/Fail verdict | Reports Inconclusive |
| **Quality monitoring** | None | Quality gates, diagnostics |
| **Stationarity** | Assumes | Monitors and detects drift |
| **Effect size** | Raw decile differences | Structured estimate + credible intervals |
| **Language** | R only | Rust + C/C++/Go bindings |
| **Measurement** | Pre-collected files | Integrated oracle |
| **CI integration** | Requires R scripting | Native, designed for CI |

### Paper Framing Recommendations

1. **Credit RTLF's contribution**: "RTLF [Dunsche et al. 2024] pioneered bootstrap-based Type-I error control in timing analysis, but uses standard bootstrap that does not account for temporal dependence in measurements."

2. **Differentiate on three axes**:
   - **Honesty under noise**: Tacet says Inconclusive when evidence is weak; RTLF forces a verdict
   - **Autocorrelation**: Tacet uses block bootstrap; RTLF assumes iid
   - **Practical integration**: Tacet provides native language bindings and integrated measurement; RTLF is R-only post-processing

3. **Benchmark focus**: Show that under autocorrelated data:
   - RTLF underestimates variance -> inflated Type-I error
   - Tacet correctly reports uncertainty -> honest verdicts

4. **Adopt their strengths**: Large-scale empirical validation (hundreds of library versions), known vulnerability testing, multiple tool comparison on same datasets.

---

## References

- [USENIX Security '24 Presentation Page](https://www.usenix.org/conference/usenixsecurity24/presentation/dunsche)
- [RTLF GitHub Repository](https://github.com/tls-attacker/RTLF)
- [Artifact Datasets on Zenodo](https://zenodo.org/records/10817685)
- [Artifacts Repository](https://github.com/RUB-NDS/Artifacts-With-Great-Power-Come-Great-Side-Channels)
- [CASA RUB Publication Page](https://casa.rub.de/forschung/publikationen/detail/with-great-power-come-great-side-channels-statistical-timing-side-channel-analyses-with-bounded-type-1-errors)
