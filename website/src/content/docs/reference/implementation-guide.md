---
title: Implementation Guide
description: Detailed algorithms and numerical procedures for implementing the tacet specification
sidebar:
  order: 4
---

This document provides detailed algorithms, numerical procedures, and platform-specific guidance for implementing the [tacet specification](/reference/specification). It is intended for library implementers.

**Relationship to specification:** The specification defines *what* implementations MUST do (normative requirements). This guide explains *how* to do it correctly and efficiently. When there is any conflict, the specification takes precedence.

***

## 1. Timer Implementation

### 1.1 Platform-Specific Timers

| Platform | Timer | Resolution | Notes |
|----------|-------|------------|-------|
| x86_64 (Intel/AMD) | `rdtsc` | ~0.3ns | Invariant TSC required; check CPUID |
| ARM64 (Linux) | `cntvct_el0` | ~42ns | Generic timer; consider perf_event |
| ARM64 (macOS) | `cntvct_el0` | ~42ns | kperf PMU available with sudo |
| Linux (any) | `perf_event` | ~1ns | Requires CAP_PERFMON or sudo |
| macOS ARM64 | kperf PMU | ~1 cycle | Requires sudo |

### 1.2 Adaptive Batching

When timer resolution is coarse relative to operation time, batch multiple operations per measurement.

**Pilot measurement:**

1. Run ~100 warmup iterations (discard)
2. Measure ~100 single operations
3. Compute `ticks_per_call = median(measurements) / tick_duration`

**Batch size selection:**

```
if ticks_per_call >= 50:
    K = 1  // No batching needed
else if ticks_per_call >= 5:
    K = ceil(50 / ticks_per_call)
    K = clamp(K, 1, 20)
else:
    if ticks_per_call < 5 even with K=20:
        return Unmeasurable
    K = 20
```

**Effect scaling:** All reported effects MUST be divided by K.

***

## 2. Covariance Estimation

### 2.1 Stream-Based Block Bootstrap

The block bootstrap resamples contiguous blocks from the acquisition stream to preserve temporal dependence.

**Algorithm:**

```
function stream_block_bootstrap(stream, block_length, n_iterations):
    T = length(stream)
    delta_samples = []

    for iter in 1..n_iterations:
        // Resample acquisition stream
        resampled_indices = []
        while length(resampled_indices) < T:
            start = random_int(0, T - 1)
            for j in 0..block_length:
                resampled_indices.append((start + j) mod T)

        // Construct resampled stream
        resampled_stream = [stream[i] for i in resampled_indices[:T]]

        // Split by class
        F_star = [y for (c, y) in resampled_stream if c == Fixed]
        R_star = [y for (c, y) in resampled_stream if c == Random]

        // Compute quantile differences
        delta_star = quantiles(F_star) - quantiles(R_star)
        delta_samples.append(delta_star)

    // Compute covariance using Welford's algorithm
    return welford_covariance(delta_samples)
```

### 2.2 Politis-White Block Length Selection

**Step 1: Class-conditional ACF**

Compute autocorrelation at acquisition-stream lag k using only same-class pairs:

```
function class_conditional_acf(stream, max_lag):
    // Separate by class while preserving acquisition indices
    F_indices = [t for t in 0..T if stream[t].class == Fixed]
    R_indices = [t for t in 0..T if stream[t].class == Random]

    rho_F = []
    rho_R = []

    for k in 0..max_lag:
        // Find same-class pairs at lag k in acquisition order
        F_pairs = [(t, t+k) for t in F_indices
                   if (t+k) in F_indices]
        R_pairs = [(t, t+k) for t in R_indices
                   if (t+k) in R_indices]

        rho_F[k] = correlation([stream[i].y for (i,_) in F_pairs],
                               [stream[j].y for (_,j) in F_pairs])
        rho_R[k] = correlation([stream[i].y for (i,_) in R_pairs],
                               [stream[j].y for (_,j) in R_pairs])

    // Combine conservatively
    rho_max = [max(abs(rho_F[k]), abs(rho_R[k])) for k in 0..max_lag]
    return rho_max
```

**Step 2: Find truncation point**

```
k_n = max(5, floor(log10(T)))
m_max = ceil(sqrt(T)) + k_n
band = 2 * sqrt(log10(T) / T)

// Find first lag where k_n consecutive values are within band
m_star = 1
for k in 1..m_max:
    if all(rho_max[k:k+k_n] within [-band, band]):
        m_star = k
        break

m = min(2 * max(m_star, 1), m_max)
```

**Step 3: Compute spectral quantities**

```
function flat_top_kernel(x):
    return min(1.0, 2.0 * (1.0 - abs(x)))

sigma_sq = 0
g = 0
for k in -m..m:
    h = flat_top_kernel(k / m)
    gamma_k = rho_max[abs(k)] * var(stream)
    sigma_sq += h * gamma_k
    g += h * abs(k) * gamma_k
```

**Step 4: Compute optimal block length**

```
b_hat = ceil((g^2 / sigma_sq^2)^(1/3) * T^(1/3))
b_max = min(3 * sqrt(T), T / 3)
b_min = 10

b_hat = clamp(b_hat, b_min, b_max)

// Fragile regime inflation
if in_fragile_regime or rho_max[b_min] > 0.3:
    b_hat = ceil(1.5 * b_hat)  // or 2.0 for severe cases
```

### 2.3 Welford's Online Covariance Algorithm

For numerical stability when computing covariance from bootstrap samples:

```
function welford_covariance(samples):
    n = 0
    mean = zeros(d)
    M2 = zeros(d, d)

    for x in samples:
        n += 1
        delta = x - mean
        mean += delta / n
        delta2 = x - mean
        M2 += outer(delta, delta2)

    return M2 / (n - 1)
```

***

## 3. IACT Computation

### 3.1 Geyer Initial Monotone Sequence Algorithm

This algorithm estimates the integrated autocorrelation time (IACT), which determines effective sample size.

**Input:** Scalar series {u_t} of length n

**Algorithm:**

```
function geyer_ims_iact(u):
    n = length(u)

    // Edge case: too few samples
    if n < 20:
        emit_warning("InsufficientSamplesForIACT")
        return 1.0

    // Edge case: zero variance
    if variance(u) == 0:
        emit_warning("ZeroVarianceStream")
        return 1.0

    // Step 1: Compute sample autocorrelations
    K = min(floor(n / 4), 1000)
    rho = []
    for k in 0..K:
        rho[k] = autocorrelation(u, lag=k)
    // Note: rho[0] = 1 by construction

    // Step 2: Form consecutive pairs
    Gamma = []
    m_max = floor((K - 1) / 2)
    for m in 0..m_max:
        Gamma[m] = rho[2*m] + rho[2*m + 1]

    // Step 3: Monotone enforcement (sequential)
    for m in 1..m_max:
        Gamma[m] = min(Gamma[m], Gamma[m-1])

    // Step 4: Truncation - find largest m with all positive pairs
    m_trunc = 0
    for m in 1..m_max:
        if Gamma[m] <= 0:
            break
        m_trunc = m

    // Step 5: IACT computation
    tau = -1.0 + 2.0 * sum(Gamma[0..m_trunc])

    // Step 6: Clamping
    tau = max(tau, 1.0)

    // Optional upper bound (Stan's safeguard)
    tau = min(tau, n * log10(n))

    return tau
```

### 3.2 Scalarization for Timing

For timing analysis, IACT must be computed on indicator series (not raw timings):

```
function timing_iact(stream):
    F_samples = [y for (c, y) in stream if c == Fixed]
    R_samples = [y for (c, y) in stream if c == Random]

    tau_F = 1.0
    tau_R = 1.0

    for p in [0.1, 0.2, ..., 0.9]:
        // Form indicator series for each quantile
        q_F = quantile(F_samples, p)
        q_R = quantile(R_samples, p)

        z_F = [1 if y <= q_F else 0 for y in F_samples]
        z_R = [1 if y <= q_R else 0 for y in R_samples]

        tau_F = max(tau_F, geyer_ims_iact(z_F))
        tau_R = max(tau_R, geyer_ims_iact(z_R))

    return max(tau_F, tau_R)
```

### 3.3 Edge Cases

| Condition | Action |
|-----------|--------|
| n < 20 | Return τ = 1.0, emit `InsufficientSamplesForIACT` |
| variance = 0 | Return τ = 1.0, emit `ZeroVarianceStream` |
| All Γ_m ≤ 0 for m ≥ 1 | Return τ = max(1.0, 2Γ_0 - 1) |
| τ > n·log₁₀(n) | Cap at n·log₁₀(n) (Stan's safeguard) |

***

## 4. Numerical Stability

### 4.1 Cholesky Decomposition

All matrix inversions MUST be performed via Cholesky decomposition and triangular solves, not explicit inversion.

**Computing L such that LLᵀ = A:**

Use a stable implementation (e.g., LAPACK `dpotrf`). If the matrix is not positive definite, Cholesky will fail.

**Solving Ax = b:**

```
function cholesky_solve(A, b):
    L = cholesky(A)  // LLᵀ = A
    y = forward_solve(L, b)    // Ly = b
    x = backward_solve(L.T, y) // Lᵀx = y
    return x
```

**Computing quadratic form xᵀA⁻¹x:**

```
function quadratic_form(A, x):
    L = cholesky(A)
    z = forward_solve(L, x)  // Lz = x, so z = L⁻¹x
    return dot(z, z)         // ||L⁻¹x||² = xᵀA⁻¹x
```

**Sampling from N(μ, Σ):**

```
function sample_mvn(mu, Sigma):
    L = cholesky(Sigma)
    z = sample_standard_normal(d)
    return mu + L @ z
```

### 4.2 Jitter Ladder for SPD Enforcement

When a matrix should be SPD but Cholesky fails due to numerical issues:

```
function ensure_spd(A, name="matrix"):
    jitter_values = [1e-10, 1e-9, 1e-8, 1e-7, 1e-6, 1e-5, 1e-4]

    for jitter in jitter_values:
        A_jittered = A + jitter * I
        try:
            L = cholesky(A_jittered)
            if jitter > 1e-8:
                emit_warning(f"Applied jitter {jitter} to {name}")
            return A_jittered, L
        except CholeskyFailure:
            continue

    // Fallback: use diagonal
    emit_warning(f"Cholesky failed for {name}, using diagonal")
    return diag(diag(A)), cholesky(diag(diag(A)))
```

### 4.3 Condition Number Handling

**Condition number computation:**

```
function condition_number(A):
    eigenvalues = eigenvalues(A)
    return max(eigenvalues) / min(eigenvalues)
```

**Shrinkage for ill-conditioned matrices:**

```
function regularize_by_condition(A, target_cond=1e4):
    cond = condition_number(A)

    if cond <= target_cond:
        return A, 0.0

    // Shrinkage toward identity (for correlation) or diagonal (for covariance)
    // Using Ledoit-Wolf-style shrinkage

    if cond > 1e6:
        // Severe: fall back to diagonal
        return diag(diag(A)), 1.0

    // Moderate: shrink toward target
    // λ chosen so that resulting condition ≈ target_cond
    lambda_shrink = 0.0
    for lambda in [0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 0.7, 0.95]:
        A_shrunk = (1 - lambda) * A + lambda * diag(diag(A))
        if condition_number(A_shrunk) <= target_cond:
            return A_shrunk, lambda
        lambda_shrink = lambda

    return (1 - 0.95) * A + 0.95 * diag(diag(A)), 0.95
```

### 4.4 Diagonal Floor Regularization

Ensure minimum variance on each coordinate:

```
function apply_diagonal_floor(Sigma):
    d = Sigma.shape[0]
    mean_var = trace(Sigma) / d
    epsilon = 1e-10 + mean_var * 1e-8
    floor = 0.01 * mean_var

    for i in 0..d:
        Sigma[i,i] = max(Sigma[i,i], floor) + epsilon

    return Sigma
```

***

## 5. Gibbs Sampler Implementation

### 5.1 Sampling Without Explicit Inverses

The Gibbs sampler for (δ, λ, κ) requires careful numerical implementation.

**Precomputation (once per n):**

```
// Given: R (prior correlation), Sigma_n (likelihood covariance), sigma (prior scale)

L_R = cholesky(R)
L_Sigma = cholesky(Sigma_n)

// Precompute Sigma_n^{-1} @ Delta via solve
Sigma_inv_Delta = cholesky_solve(Sigma_n, Delta)
```

**Per-iteration sampling:**

```
function gibbs_iteration(delta, lambda, kappa,
                         L_R, L_Sigma, Sigma_inv_Delta, Delta, sigma, nu, nu_ell):
    d = length(delta)

    // --- Sample delta | lambda, kappa ---

    // Q = kappa * Sigma_n^{-1} + (lambda / sigma^2) * R^{-1}
    // We need to form Q and factor it

    // Compute R^{-1} via L_R
    R_inv = cholesky_inverse(L_R)  // or form implicitly
    Sigma_inv = cholesky_inverse(L_Sigma)

    Q = kappa * Sigma_inv + (lambda / sigma^2) * R_inv
    L_Q = cholesky(Q)

    // Posterior mean: mu = Q^{-1} @ (kappa * Sigma_n^{-1} @ Delta)
    rhs = kappa * Sigma_inv_Delta
    mu = cholesky_solve_from_factor(L_Q, rhs)

    // Sample: delta = mu + L_Q^{-T} @ z
    z = sample_standard_normal(d)
    delta_new = mu + backward_solve(L_Q.T, z)

    // --- Sample lambda | delta ---

    // q = delta^T @ R^{-1} @ delta
    q = quadratic_form(R, delta_new)  // using L_R

    shape_lambda = (nu + d) / 2
    rate_lambda = (nu + q / sigma^2) / 2
    lambda_new = sample_gamma(shape_lambda, rate_lambda)

    // --- Sample kappa | delta, Delta ---

    // s = (Delta - delta)^T @ Sigma_n^{-1} @ (Delta - delta)
    residual = Delta - delta_new
    s = quadratic_form(Sigma_n, residual)  // using L_Sigma

    shape_kappa = (nu_ell + d) / 2
    rate_kappa = (nu_ell + s) / 2
    kappa_new = sample_gamma(shape_kappa, rate_kappa)

    return delta_new, lambda_new, kappa_new
```

### 5.2 Full Gibbs Sampler

```
function run_gibbs(Delta, Sigma_n, R, sigma, nu=4, nu_ell=8,
                   N_gibbs=256, N_burn=64, seed=0x74696D696E67):

    set_rng_seed(seed)
    d = length(Delta)

    // Precomputation
    L_R = cholesky(R)
    L_Sigma = cholesky(Sigma_n)
    Sigma_inv_Delta = cholesky_solve(Sigma_n, Delta)

    // Initialization
    lambda = 1.0
    kappa = 1.0
    delta = zeros(d)

    // Storage
    delta_samples = []
    lambda_samples = []
    kappa_samples = []

    // Iteration
    for t in 1..N_gibbs:
        delta, lambda, kappa = gibbs_iteration(
            delta, lambda, kappa,
            L_R, L_Sigma, Sigma_inv_Delta, Delta, sigma, nu, nu_ell
        )

        if t > N_burn:
            delta_samples.append(delta)
            lambda_samples.append(lambda)
            kappa_samples.append(kappa)

    return delta_samples, lambda_samples, kappa_samples
```

***

## 6. Quantile Computation

### 6.1 Type 2 Quantiles

For continuous data, use type 2 quantiles (inverse empirical CDF with averaging):

```
function quantile_type2(sorted_x, p):
    n = length(sorted_x)
    h = n * p + 0.5

    lo = floor(h)
    hi = ceil(h)

    // Handle boundaries
    lo = clamp(lo, 1, n)
    hi = clamp(hi, 1, n)

    return (sorted_x[lo-1] + sorted_x[hi-1]) / 2  // 0-indexed
```

### 6.2 Mid-Distribution Quantiles

For discrete data with many ties, use mid-distribution quantiles:

```
function mid_distribution_quantile(sorted_x, p):
    n = length(sorted_x)

    // Compute empirical CDF at each unique value
    unique_vals = unique(sorted_x)

    for v in unique_vals:
        count_below = count(x < v for x in sorted_x)
        count_at = count(x == v for x in sorted_x)

        F_v = count_below / n           // F(v-)
        F_mid_v = F_v + count_at / (2*n) // F_mid(v)

        if F_mid_v >= p:
            return v

    return sorted_x[n-1]
```

***

## 7. Prior Scale Calibration

### 7.1 Monte Carlo Exceedance Estimation

```
function estimate_exceedance(sigma, R, theta_eff, nu=4, M=50000, seed):
    set_rng_seed(seed)
    L_R = cholesky(R)
    d = R.shape[0]

    exceed_count = 0
    for i in 1..M:
        // Sample from Student's t via scale mixture
        lambda = sample_gamma(nu/2, nu/2)
        z = sample_standard_normal(d)
        delta = (sigma / sqrt(lambda)) * (L_R @ z)

        // Check exceedance
        if max(abs(delta)) > theta_eff:
            exceed_count += 1

    return exceed_count / M
```

### 7.2 Root-Finding for σ

```
function calibrate_prior_scale(R, theta_eff, SE_med, pi_0=0.62, nu=4, seed):
    // Search bounds
    sigma_lo = 0.05 * theta_eff
    sigma_hi = max(50 * theta_eff, 10 * SE_med)

    // Target function: f(sigma) = exceedance(sigma) - pi_0
    function f(sigma):
        return estimate_exceedance(sigma, R, theta_eff, nu, seed=seed) - pi_0

    // Bisection (or Brent's method)
    tolerance = 0.001
    max_iter = 50

    for iter in 1..max_iter:
        sigma_mid = (sigma_lo + sigma_hi) / 2
        f_mid = f(sigma_mid)

        if abs(f_mid) < tolerance:
            return sigma_mid

        if f_mid > 0:  // exceedance too high, reduce sigma
            sigma_hi = sigma_mid
        else:
            sigma_lo = sigma_mid

    return (sigma_lo + sigma_hi) / 2
```

***

## 8. Leak Probability Computation

### 8.1 From Gibbs Samples

```
function compute_leak_probability(delta_samples, theta_eff):
    N = length(delta_samples)
    exceed_count = 0

    for delta in delta_samples:
        if max(abs(delta)) > theta_eff:
            exceed_count += 1

    return exceed_count / N
```

### 8.2 Posterior Summaries

```
function compute_posterior_summaries(delta_samples, theta_eff):
    N = length(delta_samples)
    d = length(delta_samples[0])

    // Posterior mean
    delta_post = mean(delta_samples, axis=0)

    // Max effect samples
    max_effects = [max(abs(delta)) for delta in delta_samples]

    // Credible interval for max|δ|
    ci_lo = quantile(max_effects, 0.025)
    ci_hi = quantile(max_effects, 0.975)

    // Top quantiles by exceedance probability
    top_quantiles = []
    for k in 0..d:
        k_effects = [abs(delta[k]) for delta in delta_samples]
        exceed_prob = mean([1 if e > theta_eff else 0 for e in k_effects])

        top_quantiles.append({
            quantile_p: 0.1 * (k + 1),  // 0.1, 0.2, ..., 0.9
            mean_ns: mean(k_effects),
            ci95_ns: (quantile(k_effects, 0.025), quantile(k_effects, 0.975)),
            exceed_prob: exceed_prob
        })

    // Sort by exceedance probability, take top 3
    top_quantiles.sort(by=exceed_prob, descending=True)

    return {
        delta_post: delta_post,
        max_effect_ns: mean(max_effects),
        credible_interval_ns: (ci_lo, ci_hi),
        top_quantiles: top_quantiles[:3]
    }
```

***

## References

1. Politis, D. N. & White, H. (2004). "Automatic Block-Length Selection for the Dependent Bootstrap." Econometric Reviews 23(1):53–70.

2. Welford, B. P. (1962). "Note on a Method for Calculating Corrected Sums of Squares and Products." Technometrics 4(3):419–420.

3. Geyer, C. J. (1992). "Practical Markov Chain Monte Carlo." Statistical Science 7(4):473–483.

4. Stan Development Team. "Stan Reference Manual: Effective Sample Size." https://mc-stan.org/docs/reference-manual/

5. Hyndman, R. J. & Fan, Y. (1996). "Sample quantiles in statistical packages." The American Statistician 50(4):361–365.
