//! Bayesian inference for timing leak detection.
//!
//! This module provides:
//! - 1D Bayesian inference on Wasserstein-1 distance
//! - Monte Carlo utilities for sampling

extern crate alloc;

use alloc::vec::Vec;
use core::f64::consts::PI;

use rand::prelude::*;
use rand::SeedableRng;
use rand_xoshiro::Xoshiro256PlusPlus;

use crate::math;

/// Sample from standard normal using Box-Muller transform.
///
/// This is a public utility function that can be used by other modules
/// for Monte Carlo sampling from N(0, 1).
pub fn sample_standard_normal<R: Rng>(rng: &mut R) -> f64 {
    let u1: f64 = rng.random();
    let u2: f64 = rng.random();
    math::sqrt(-2.0 * math::ln(u1)) * math::cos(2.0 * PI * u2)
}

/// Result from 1D Bayesian inference on Wasserstein-1 distance.
///
/// Models: W₁_obs ~ N(δ, var_n), δ ~ half-t(ν=4, σ_t)
#[derive(Debug, Clone)]
pub struct BayesW1Result {
    /// Posterior probability of a significant leak: P(|δ| > θ | W₁_obs).
    pub leak_probability: f64,

    /// Posterior mean of δ (effect size in nanoseconds).
    pub w1_post: f64,

    /// Posterior variance of δ.
    pub var_post: f64,

    /// Posterior samples of δ from Gibbs sampler.
    pub w1_draws: Vec<f64>,

    /// 95% credible interval for δ: (2.5th, 97.5th percentile).
    pub credible_interval: (f64, f64),
}

/// Compute 1D Bayesian inference on Wasserstein-1 distance.
///
/// # Model
///
/// Likelihood: W₁_obs ~ N(δ, var_n)
///
/// Prior: δ ~ half-t(ν=4, σ_t)
///
/// The half-t prior is represented as a scale mixture of Gaussians:
/// - λ ~ Gamma(ν/2, ν/2) = Gamma(2, 2)
/// - δ | λ ~ N(0, σ_t²/λ)
///
/// # Gibbs Sampling
///
/// 1. Sample λ ~ Gamma(2 + 1/2, 2 + δ²/(2σ_t²))
/// 2. Sample δ | λ ~ N(μ_post, σ²_post) where:
///    - posterior_precision = λ/σ_t² + 1/var_n
///    - μ_post = (W₁_obs/var_n) / posterior_precision
///    - σ²_post = 1 / posterior_precision
///
/// # Arguments
///
/// * `w1_obs` - Observed W₁ distance (can be negative from debiasing)
/// * `var_n` - Likelihood variance (W₁ variance scaled for sample size)
/// * `sigma_t` - Prior scale parameter
/// * `theta` - Minimum effect of concern (threshold)
/// * `seed` - Random seed for reproducibility
///
/// # Returns
///
/// `BayesW1Result` with posterior statistics and leak probability.
pub fn compute_bayes_1d(
    w1_obs: f64,
    var_n: f64,
    sigma_t: f64,
    theta: f64,
    seed: u64,
) -> BayesW1Result {
    const N_ITER: usize = 5000;
    const BURN_IN: usize = 1000;
    const NU: f64 = 4.0; // t-distribution degrees of freedom

    let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed);

    // Initialize δ to observed value (warm start for Gibbs sampler)
    let mut delta = w1_obs;

    let mut delta_draws = Vec::with_capacity(N_ITER - BURN_IN);
    let mut leak_count = 0;

    // Gibbs sampling
    for iter in 0..N_ITER {
        // Step 1: Sample λ ~ Gamma(ν/2 + 1/2, ν/2 + δ²/(2σ_t²))
        let shape = NU / 2.0 + 0.5;
        let rate = NU / 2.0 + (delta * delta) / (2.0 * sigma_t * sigma_t);

        let lambda = sample_gamma(&mut rng, shape, rate);

        // Step 2: Sample δ | λ ~ N(μ_post, σ²_post)
        let posterior_precision = lambda / (sigma_t * sigma_t) + 1.0 / var_n;
        let posterior_mean = (w1_obs / var_n) / posterior_precision;
        let posterior_var = 1.0 / posterior_precision;

        delta = posterior_mean + math::sqrt(posterior_var) * sample_standard_normal(&mut rng);

        // Store samples after burn-in
        if iter >= BURN_IN {
            delta_draws.push(delta);

            // Count leak exceedances
            if delta.abs() > theta {
                leak_count += 1;
            }
        }
    }

    // Compute posterior statistics
    let n_kept = delta_draws.len();
    let leak_probability = leak_count as f64 / n_kept as f64;

    let w1_post = delta_draws.iter().sum::<f64>() / n_kept as f64;
    let var_post = delta_draws
        .iter()
        .map(|d| (d - w1_post).powi(2))
        .sum::<f64>()
        / (n_kept - 1) as f64;

    // Compute 95% credible interval
    let mut sorted_draws = delta_draws.clone();
    sorted_draws.sort_by(|a, b| a.total_cmp(b));
    let lo_idx = math::round(n_kept as f64 * 0.025) as usize;
    let hi_idx = math::round(n_kept as f64 * 0.975) as usize;
    let credible_interval = (
        sorted_draws[lo_idx.min(n_kept - 1)],
        sorted_draws[hi_idx.min(n_kept - 1)],
    );

    BayesW1Result {
        leak_probability,
        w1_post,
        var_post,
        w1_draws: delta_draws,
        credible_interval,
    }
}

/// Sample from Gamma(shape, rate) using Marsaglia-Tsang method.
///
/// Sample from Gamma(shape, rate) distribution.
///
/// This is a public utility function that can be used by other modules
/// for Monte Carlo sampling from Gamma distributions.
///
/// For shape ≥ 1, uses the Marsaglia-Tsang algorithm.
/// For shape < 1, uses the transformation: Gamma(shape, rate) = Gamma(shape+1, rate) × U^(1/shape).
pub fn sample_gamma<R: Rng>(rng: &mut R, shape: f64, rate: f64) -> f64 {
    if shape < 1.0 {
        // Use transformation for shape < 1
        let g = sample_gamma_marsaglia_tsang(rng, shape + 1.0);
        let u: f64 = rng.random();
        return g * u.powf(1.0 / shape) / rate;
    }

    sample_gamma_marsaglia_tsang(rng, shape) / rate
}

/// Marsaglia-Tsang method for Gamma(shape, 1) with shape ≥ 1.
fn sample_gamma_marsaglia_tsang<R: Rng>(rng: &mut R, shape: f64) -> f64 {
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / math::sqrt(9.0 * d);

    loop {
        let z = sample_standard_normal(rng);
        let v = (1.0 + c * z).powi(3);

        if v <= 0.0 {
            continue;
        }

        let u: f64 = rng.random();
        let z_sq = z * z;

        // Accept if u < 1 - 0.0331 * z^4 (quick acceptance)
        if u < 1.0 - 0.0331 * z_sq * z_sq {
            return d * v;
        }

        // Reject if log(u) ≥ 0.5 * z^2 + d * (1 - v + log(v))
        if math::ln(u) < 0.5 * z_sq + d * (1.0 - v + math::ln(v)) {
            return d * v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bayes_1d_determinism() {
        let w1_obs = 5.0;
        let var_n = 10.0;
        let sigma_t = 20.0;
        let theta = 3.0;

        let result1 = compute_bayes_1d(w1_obs, var_n, sigma_t, theta, 42);
        let result2 = compute_bayes_1d(w1_obs, var_n, sigma_t, theta, 42);

        assert_eq!(
            result1.leak_probability, result2.leak_probability,
            "Same seed should give same result"
        );
        assert_eq!(
            result1.w1_post, result2.w1_post,
            "Posterior mean should be deterministic"
        );
    }

    #[test]
    fn test_bayes_1d_handles_negative_w1() {
        // Negative W₁ can occur from debiasing
        let w1_obs = -3.0;
        let var_n = 5.0;
        let sigma_t = 10.0;
        let theta = 2.0;

        let result = compute_bayes_1d(w1_obs, var_n, sigma_t, theta, 42);

        // Should handle negative observations gracefully
        assert!(
            result.w1_post < 0.0,
            "Posterior should reflect negative observation"
        );
        assert!(
            result.leak_probability >= 0.0 && result.leak_probability <= 1.0,
            "Leak probability should be valid"
        );
    }

    #[test]
    fn test_bayes_1d_threshold_sensitivity() {
        let w1_obs = 10.0;
        let var_n = 2.0;
        let sigma_t = 15.0;
        let seed = 42;

        // Small threshold should give high leak probability
        let result_small_theta = compute_bayes_1d(w1_obs, var_n, sigma_t, 1.0, seed);

        // Large threshold should give low leak probability
        let result_large_theta = compute_bayes_1d(w1_obs, var_n, sigma_t, 20.0, seed);

        assert!(
            result_small_theta.leak_probability > result_large_theta.leak_probability,
            "Smaller threshold should yield higher leak probability"
        );
    }

    #[test]
    fn test_bayes_1d_credible_interval() {
        let w1_obs = 5.0;
        let var_n = 10.0;
        let sigma_t = 20.0;
        let theta = 3.0;

        let result = compute_bayes_1d(w1_obs, var_n, sigma_t, theta, 42);

        let (lo, hi) = result.credible_interval;

        // CI should be ordered
        assert!(lo < hi, "CI bounds should be ordered");

        // Posterior mean should be within CI (usually)
        assert!(
            result.w1_post >= lo && result.w1_post <= hi,
            "Posterior mean should be within 95% CI"
        );
    }
}
