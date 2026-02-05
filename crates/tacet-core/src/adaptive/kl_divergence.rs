//! KL divergence computation for Gaussian distributions.
//!
//! Used to track the learning rate during adaptive sampling. When the posterior
//! stops updating (KL divergence becomes very small), we've either converged or
//! the data is uninformative.

use super::Posterior;

/// KL divergence KL(p || q) for 1D Gaussian distributions.
///
/// For 1D Gaussians p ~ N(μ_p, σ²_p) and q ~ N(μ_q, σ²_q):
///
/// KL(p||q) = 0.5 × (σ²_p/σ²_q + (μ_p - μ_q)²/σ²_q - 1 + ln(σ²_q/σ²_p))
///
/// This measures how much the posterior has changed from the previous iteration.
/// Small KL indicates the posterior is no longer updating despite new data.
///
/// Uses the 1D posterior mean and variance for tracking.
///
/// # Arguments
///
/// * `p` - The new posterior (typically more peaked)
/// * `q` - The old posterior (reference distribution)
///
/// # Returns
///
/// KL divergence in nats. Returns `f64::INFINITY` if q has zero or negative variance.
pub fn kl_divergence_gaussian(p: &Posterior, q: &Posterior) -> f64 {
    // Check for degenerate cases
    if q.var_post <= 0.0 || p.var_post <= 0.0 {
        return f64::INFINITY;
    }

    // Mean difference
    let mu_diff = p.w1_post - q.w1_post;

    // Variance ratio
    let var_ratio = p.var_post / q.var_post;

    // Squared Mahalanobis distance
    let mahalanobis = (mu_diff * mu_diff) / q.var_post;

    // Log variance ratio
    let log_var_ratio = libm::log(q.var_post / p.var_post);

    if !log_var_ratio.is_finite() {
        return f64::INFINITY;
    }

    0.5 * (var_ratio + mahalanobis - 1.0 + log_var_ratio)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_posterior(w1_post: f64, variance: f64, leak_prob: f64) -> Posterior {
        Posterior::new(
            w1_post,
            variance,
            Vec::new(), // w1_draws
            leak_prob,
            1.0,
            100,
        )
    }

    #[test]
    fn test_kl_identical_distributions() {
        let p = make_test_posterior(5.0, 1.0, 0.5);
        let q = p.clone();

        let kl = kl_divergence_gaussian(&p, &q);

        // KL divergence of identical distributions should be 0
        assert!(
            libm::fabs(kl) < 1e-10,
            "KL of identical distributions should be 0, got {}",
            kl
        );
    }

    #[test]
    fn test_kl_different_means() {
        let p = make_test_posterior(5.0, 1.0, 0.5);
        let q = make_test_posterior(0.0, 1.0, 0.5);

        let kl = kl_divergence_gaussian(&p, &q);

        // For 1D with same variance: KL = 0.5 × (μ_p - μ_q)² / σ²_q
        // = 0.5 × 25 / 1 = 12.5
        assert!(
            libm::fabs(kl - 12.5) < 1e-10,
            "KL should be 12.5, got {}",
            kl
        );
    }

    #[test]
    fn test_kl_different_variances() {
        let p = make_test_posterior(0.0, 2.0, 0.5);
        let q = make_test_posterior(0.0, 1.0, 0.5);

        let kl = kl_divergence_gaussian(&p, &q);

        // For 1D with same mean: KL = 0.5 × (σ²_p/σ²_q - 1 + ln(σ²_q/σ²_p))
        // = 0.5 × (2 - 1 + ln(1/2)) = 0.5 × (1 - 0.693) ≈ 0.153
        assert!(kl > 0.0, "KL should be positive for different variances");
        assert!((kl - 0.153).abs() < 0.01, "KL should be ~0.153, got {}", kl);
    }
}
