//! Posterior distribution representation for Bayesian inference.
//!
//! The posterior is Gaussian: W₁ | D ~ N(w1_post, var_post) where:
//! - W₁ is the scalar weighted mean timing difference
//! - D is the observed empirical timing difference
//!
//! Effect estimation uses |W₁| as the primary metric.

extern crate alloc;
use alloc::vec::Vec;

use crate::analysis::{compute_effect_estimate, compute_effect_estimate_analytical};
use crate::math::sqrt;
use crate::result::{EffectEstimate, MeasurementQuality};

/// Posterior distribution parameters for the scalar effect W₁.
///
/// The posterior is Gaussian: W₁ | D ~ N(w1_post, var_post) where W₁
/// represents the weighted mean timing difference.
///
/// Uses Student's t prior (ν=4) via Gibbs sampling for robust inference.
#[derive(Clone, Debug)]
pub struct Posterior {
    /// Posterior mean w1_post in nanoseconds.
    pub w1_post: f64,

    /// Posterior variance var_post.
    pub var_post: f64,

    /// Retained W₁ draws from the Gibbs sampler.
    /// Used for effect estimation via `compute_effect_estimate`.
    pub w1_draws: Vec<f64>,

    /// Leak probability: P(|W₁| > θ | D).
    /// Computed via Monte Carlo integration over the 1D posterior.
    pub leak_probability: f64,

    /// Effect threshold used for leak probability computation.
    pub theta: f64,

    /// Number of samples used in this posterior computation.
    pub n: usize,

    // ==================== Gibbs sampler fields ====================
    /// Posterior mean of latent scale λ.
    /// `None` if using simple posterior (no Gibbs sampler).
    pub lambda_mean: Option<f64>,

    /// Whether the Gibbs sampler's lambda chain mixed well.
    /// `None` if using simple posterior.
    /// When `Some(false)`, indicates potential posterior unreliability.
    pub lambda_mixing_ok: Option<bool>,

    /// Posterior mean of likelihood precision κ.
    /// `None` if using simple posterior.
    pub kappa_mean: Option<f64>,

    /// Coefficient of variation of κ.
    /// `None` if using simple posterior.
    pub kappa_cv: Option<f64>,

    /// Effective sample size of κ chain.
    /// `None` if using simple posterior.
    pub kappa_ess: Option<f64>,

    /// Whether the Gibbs sampler's kappa chain mixed well.
    /// `None` if using simple posterior.
    pub kappa_mixing_ok: Option<bool>,
}

impl Posterior {
    /// Create a new posterior with given parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        w1_post: f64,
        var_post: f64,
        w1_draws: Vec<f64>,
        leak_probability: f64,
        theta: f64,
        n: usize,
    ) -> Self {
        Self {
            w1_post,
            var_post,
            w1_draws,
            leak_probability,
            theta,
            n,
            lambda_mean: None,      // v5.4: no Gibbs sampler
            lambda_mixing_ok: None, // v5.4: no Gibbs sampler
            kappa_mean: None,       // v5.6: no Gibbs sampler
            kappa_cv: None,         // v5.6: no Gibbs sampler
            kappa_ess: None,        // v5.6: no Gibbs sampler
            kappa_mixing_ok: None,  // v5.6: no Gibbs sampler
        }
    }

    /// Create a new posterior with Gibbs sampler diagnostics (v5.4, v5.6).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_gibbs(
        w1_post: f64,
        var_post: f64,
        w1_draws: Vec<f64>,
        leak_probability: f64,
        theta: f64,
        n: usize,
        lambda_mean: f64,
        lambda_mixing_ok: bool,
        kappa_mean: f64,
        kappa_cv: f64,
        kappa_ess: f64,
        kappa_mixing_ok: bool,
    ) -> Self {
        Self {
            w1_post,
            var_post,
            w1_draws,
            leak_probability,
            theta,
            n,
            lambda_mean: Some(lambda_mean),
            lambda_mixing_ok: Some(lambda_mixing_ok),
            kappa_mean: Some(kappa_mean),
            kappa_cv: Some(kappa_cv),
            kappa_ess: Some(kappa_ess),
            kappa_mixing_ok: Some(kappa_mixing_ok),
        }
    }

    /// Get the absolute effect from posterior mean.
    pub fn max_effect_ns(&self) -> f64 {
        self.w1_post.abs()
    }

    /// Build an EffectEstimate from this posterior.
    ///
    /// Uses W₁ draws if available, otherwise uses analytical approximation.
    pub fn to_effect_estimate(&self) -> EffectEstimate {
        if !self.w1_draws.is_empty() {
            compute_effect_estimate(&self.w1_draws)
        } else {
            compute_effect_estimate_analytical(self.w1_post, self.var_post, self.theta)
        }
    }

    /// Get measurement quality based on the posterior uncertainty.
    ///
    /// Quality is determined by the minimum detectable effect (MDE),
    /// which is approximately 2 × standard error.
    pub fn measurement_quality(&self) -> MeasurementQuality {
        // MDE is approximately 2 × sqrt(var_post)
        let se = sqrt(self.var_post.max(1e-12));
        MeasurementQuality::from_mde_ns(se * 2.0)
    }

    /// Convert to an FFI-friendly summary containing only scalar fields.
    pub fn to_summary(&self) -> crate::ffi_summary::PosteriorSummary {
        let effect = self.to_effect_estimate();

        crate::ffi_summary::PosteriorSummary {
            max_effect_ns: effect.max_effect_ns,
            ci_low_ns: effect.credible_interval_ns.0,
            ci_high_ns: effect.credible_interval_ns.1,
            leak_probability: self.leak_probability,
            n: self.n,
            lambda_mean: self.lambda_mean.unwrap_or(1.0),
            lambda_mixing_ok: self.lambda_mixing_ok.unwrap_or(true),
            kappa_mean: self.kappa_mean.unwrap_or(1.0),
            kappa_cv: self.kappa_cv.unwrap_or(0.0),
            kappa_ess: self.kappa_ess.unwrap_or(0.0),
            kappa_mixing_ok: self.kappa_mixing_ok.unwrap_or(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posterior_accessors() {
        let w1_post = 10.0;
        let var_post = 1.0;

        let posterior = Posterior::new(
            w1_post,
            var_post,
            Vec::new(), // w1_draws
            0.75,
            5.0, // theta
            1000,
        );

        assert_eq!(posterior.leak_probability, 0.75);
        assert_eq!(posterior.n, 1000);
        assert!((posterior.max_effect_ns() - 10.0).abs() < 1e-10);
    }

    #[test]
    fn test_posterior_clone() {
        let w1_post = 5.0;
        let var_post = 1.0;

        let posterior = Posterior::new(
            w1_post,
            var_post,
            Vec::new(), // w1_draws
            0.5,
            5.0, // theta
            500,
        );

        let cloned = posterior.clone();
        assert_eq!(cloned.leak_probability, posterior.leak_probability);
        assert_eq!(cloned.max_effect_ns(), posterior.max_effect_ns());
    }

    #[test]
    fn test_effect_estimate_from_draws() {
        let w1_post = 10.0;
        let var_post = 1.0;

        // Create some sample draws
        let w1_draws: Vec<f64> = (0..100).map(|_| 10.0).collect();

        let posterior = Posterior::new(w1_post, var_post, w1_draws, 0.99, 5.0, 1000);

        let effect = posterior.to_effect_estimate();
        assert!(effect.max_effect_ns > 9.0, "max effect should be around 10");
    }
}
