//! Calibration data and computation for adaptive sampling (no_std compatible).
//!
//! This module defines the calibration results needed for the adaptive sampling loop,
//! as well as the core calibration computation that can run in no_std environments.
//!
//! For no_std compatibility:
//! - No `std::time::Instant` (throughput measured by caller)
//! - Core preflight checks are no_std compatible
//! - Uses only `alloc` for heap allocation
//!
//! # Usage
//!
//! The `calibrate()` function runs the calibration phase using pre-collected samples.
//! Unlike the `tacet` crate version, it takes `samples_per_second` as a parameter
//! instead of measuring it internally (to avoid `std::time::Instant`).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use rand::SeedableRng;
use rand_xoshiro::Xoshiro256PlusPlus;

use crate::analysis::bayes::{sample_gamma, sample_standard_normal};
use crate::constants::DEFAULT_SEED;
use crate::preflight::{run_core_checks, PreflightResult};
use crate::statistics::{
    bootstrap_w1_variance, timing_iact_combined, timing_iact_direct, timing_iact_per_quantile,
    AcquisitionStream, OnlineStats,
};

use super::CalibrationSnapshot;

/// Degrees of freedom for half-t prior (W₁ distance).
pub const NU: f64 = 4.0;

/// Calibration results from the initial measurement phase (no_std compatible).
///
/// This struct contains the essential statistical data needed for the adaptive
/// sampling loop. It is designed for use in no_std environments like SGX enclaves.
///
/// For full calibration with preflight checks, see `tacet::Calibration`.
///
/// ## Half-t Prior (W₁ distance)
///
/// The prior is a half-t distribution with ν=4 degrees of freedom:
/// δ ~ half-t(ν=4, σ_t)
///
/// This is implemented via scale mixture: λ ~ Gamma(ν/2, ν/2), δ = |σ_t/√λ · z| where z ~ N(0,1).
/// The marginal variance is (ν/(ν-2)) σ_t² = 2σ_t² for ν=4.
#[derive(Debug, Clone)]
pub struct Calibration {
    /// Variance "rate" - multiply by 1/n to get var_n for n samples (W₁ distance).
    /// Computed as var_cal * n_cal where var_cal is calibration variance.
    /// This allows O(1) variance scaling as samples accumulate.
    pub var_rate: f64,

    /// Block length from Politis-White algorithm.
    /// Used for block bootstrap to preserve autocorrelation structure.
    pub block_length: usize,

    /// IACT (Integrated Autocorrelation Time) estimate.
    /// Used when iact_method = GeyersIMS for effective sample size computation.
    pub iact: f64,

    /// Method used for IACT computation.
    pub iact_method: crate::types::IactMethod,

    /// Calibrated half-t prior scale (W₁ distance).
    /// This is the σ_t in δ ~ half-t(ν=4, σ_t).
    pub sigma_t: f64,

    /// The theta threshold being used (in nanoseconds).
    pub theta_ns: f64,

    /// Number of calibration samples collected per class.
    pub calibration_samples: usize,

    /// Whether discrete mode is active (< 10% unique values).
    /// When true, use mid-quantile estimators and m-out-of-n bootstrap.
    pub discrete_mode: bool,

    /// Minimum detectable effect in nanoseconds.
    pub mde_ns: f64,

    /// Statistics snapshot from calibration phase for drift detection.
    pub calibration_snapshot: CalibrationSnapshot,

    /// Timer resolution in nanoseconds.
    pub timer_resolution_ns: f64,

    /// Measured throughput for time estimation (samples per second).
    /// The caller is responsible for measuring this during calibration.
    pub samples_per_second: f64,

    /// Floor-rate constant (W₁ distance).
    /// Computed once at calibration: 95th percentile of |Z| where Z ~ N(0, var_rate).
    /// Used for analytical theta_floor computation: theta_floor_stat(n) = c_floor / sqrt(n).
    pub c_floor: f64,

    /// Projection mismatch threshold.
    /// 99th percentile of bootstrap Q_proj distribution.
    pub projection_mismatch_thresh: f64,

    /// Timer resolution floor component.
    /// theta_tick = (1 tick in ns) / K where K is the batch size.
    pub theta_tick: f64,

    /// Effective threshold for this run.
    /// theta_eff = max(theta_user, theta_floor) or just theta_floor in research mode.
    pub theta_eff: f64,

    /// Initial measurement floor at calibration time.
    pub theta_floor_initial: f64,

    /// Deterministic RNG seed used for this run.
    pub rng_seed: u64,

    /// Batch size K for adaptive batching.
    /// When K > 1, samples contain K iterations worth of timing.
    /// Effect estimates must be divided by K to report per-call differences.
    pub batch_k: u32,

    /// Results of core preflight checks run during calibration (no_std compatible).
    /// Platform-specific checks (like system configuration) are handled by the
    /// `tacet` crate's wrapper.
    pub preflight_result: PreflightResult,
}

impl Calibration {
    /// Create a new Calibration with half-t prior (W₁ distance).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        var_rate: f64,
        block_length: usize,
        iact: f64,
        iact_method: crate::types::IactMethod,
        sigma_t: f64,
        theta_ns: f64,
        calibration_samples: usize,
        discrete_mode: bool,
        mde_ns: f64,
        calibration_snapshot: CalibrationSnapshot,
        timer_resolution_ns: f64,
        samples_per_second: f64,
        c_floor: f64,
        projection_mismatch_thresh: f64,
        theta_tick: f64,
        theta_eff: f64,
        theta_floor_initial: f64,
        rng_seed: u64,
        batch_k: u32,
    ) -> Self {
        Self {
            var_rate,
            block_length,
            iact,
            iact_method,
            sigma_t,
            theta_ns,
            calibration_samples,
            discrete_mode,
            mde_ns,
            calibration_snapshot,
            timer_resolution_ns,
            samples_per_second,
            c_floor,
            projection_mismatch_thresh,
            theta_tick,
            theta_eff,
            theta_floor_initial,
            rng_seed,
            batch_k,
            preflight_result: PreflightResult::new(),
        }
    }

    /// Create a new Calibration with all fields including preflight results.
    #[allow(clippy::too_many_arguments)]
    pub fn with_preflight(
        var_rate: f64,
        block_length: usize,
        iact: f64,
        iact_method: crate::types::IactMethod,
        sigma_t: f64,
        theta_ns: f64,
        calibration_samples: usize,
        discrete_mode: bool,
        mde_ns: f64,
        calibration_snapshot: CalibrationSnapshot,
        timer_resolution_ns: f64,
        samples_per_second: f64,
        c_floor: f64,
        projection_mismatch_thresh: f64,
        theta_tick: f64,
        theta_eff: f64,
        theta_floor_initial: f64,
        rng_seed: u64,
        batch_k: u32,
        preflight_result: PreflightResult,
    ) -> Self {
        Self {
            var_rate,
            block_length,
            iact,
            iact_method,
            sigma_t,
            theta_ns,
            calibration_samples,
            discrete_mode,
            mde_ns,
            calibration_snapshot,
            timer_resolution_ns,
            samples_per_second,
            c_floor,
            projection_mismatch_thresh,
            theta_tick,
            theta_eff,
            theta_floor_initial,
            rng_seed,
            batch_k,
            preflight_result,
        }
    }

    /// Compute effective sample size accounting for dependence (spec §3.3.2 v5.6).
    ///
    /// Under strong temporal dependence, n samples do not provide n independent observations.
    /// The effective sample size approximates the number of effectively independent blocks.
    ///
    /// n_eff = max(1, floor(n / block_length))
    ///
    /// where block_length (PolitisWhite) or IACT (GeyersIMS) is the estimated dependence length.
    pub fn n_eff(&self, n: usize) -> usize {
        use crate::types::IactMethod;
        match self.iact_method {
            IactMethod::PolitisWhite => {
                if self.block_length == 0 {
                    return n.max(1);
                }
                (n / self.block_length).max(1)
            }
            IactMethod::GeyersIMS | IactMethod::DirectDifferences | IactMethod::PerQuantile => {
                if self.iact <= 1.0 {
                    return n.max(1);
                }
                ((n as f64) / self.iact).floor().max(1.0) as usize
            }
        }
    }

    /// Scale var_rate to get variance for n samples (W₁ distance).
    ///
    /// var_n = var_rate / n
    ///
    /// Since var_rate is computed via block bootstrap (which preserves temporal
    /// dependence), it already represents the long-run variance rate. No additional
    /// IACT scaling is needed—the block bootstrap already accounts for autocorrelation.
    pub fn variance_for_n(&self, n: usize) -> f64 {
        if n == 0 {
            return self.var_rate; // Avoid division by zero
        }
        self.var_rate / (n as f64)
    }

    /// Estimate time to collect `n` additional samples based on calibration throughput.
    ///
    /// Returns estimated seconds. Caller should add any overhead.
    pub fn estimate_collection_time_secs(&self, n: usize) -> f64 {
        if self.samples_per_second <= 0.0 {
            return 0.0;
        }
        n as f64 / self.samples_per_second
    }

    /// Convert to an FFI-friendly summary containing only scalar fields.
    pub fn to_summary(&self) -> crate::ffi_summary::CalibrationSummary {
        crate::ffi_summary::CalibrationSummary {
            block_length: self.block_length,
            calibration_samples: self.calibration_samples,
            discrete_mode: self.discrete_mode,
            timer_resolution_ns: self.timer_resolution_ns,
            theta_ns: self.theta_ns,
            theta_eff: self.theta_eff,
            theta_floor_initial: self.theta_floor_initial,
            theta_tick: self.theta_tick,
            mde_ns: self.mde_ns,
            samples_per_second: self.samples_per_second,
        }
    }
}

/// Configuration for calibration phase (no_std compatible).
///
/// This contains parameters for calibration that don't require std features.
#[derive(Debug, Clone)]
pub struct CalibrationConfig {
    /// Number of samples to collect per class during calibration.
    pub calibration_samples: usize,

    /// Number of bootstrap iterations for covariance estimation.
    pub bootstrap_iterations: usize,

    /// Timer resolution in nanoseconds.
    pub timer_resolution_ns: f64,

    /// Theta threshold in nanoseconds.
    pub theta_ns: f64,

    /// Alpha level for MDE computation.
    pub alpha: f64,

    /// Random seed for bootstrap.
    pub seed: u64,

    /// Whether to skip preflight checks.
    pub skip_preflight: bool,

    /// Force discrete mode regardless of uniqueness ratio.
    pub force_discrete_mode: bool,

    /// IACT computation method (PolitisWhite or GeyersIMS).
    pub iact_method: crate::types::IactMethod,
}

impl Default for CalibrationConfig {
    fn default() -> Self {
        Self {
            calibration_samples: 5000,
            bootstrap_iterations: 200, // Fewer iterations for calibration phase
            timer_resolution_ns: 1.0,
            theta_ns: 100.0,
            alpha: 0.01,
            seed: DEFAULT_SEED,
            skip_preflight: false,
            force_discrete_mode: false,
            iact_method: crate::types::IactMethod::default(),
        }
    }
}

/// Errors that can occur during calibration.
#[derive(Debug, Clone)]
pub enum CalibrationError {
    /// Too few samples collected for reliable calibration.
    TooFewSamples {
        /// Number of samples actually collected.
        collected: usize,
        /// Minimum required samples.
        minimum: usize,
    },

    /// Covariance estimation failed (e.g., singular matrix).
    CovarianceEstimationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// A preflight check failed before calibration.
    PreflightCheckFailed {
        /// Which check failed.
        check: String,
        /// Error message.
        message: String,
    },

    /// Timer is too coarse to measure this operation.
    TimerTooCoarse {
        /// Timer resolution in nanoseconds.
        resolution_ns: f64,
        /// Measured operation time in nanoseconds.
        operation_ns: f64,
    },
}

impl core::fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CalibrationError::TooFewSamples { collected, minimum } => {
                write!(
                    f,
                    "Too few samples: collected {}, need at least {}",
                    collected, minimum
                )
            }
            CalibrationError::CovarianceEstimationFailed { reason } => {
                write!(f, "Covariance estimation failed: {}", reason)
            }
            CalibrationError::PreflightCheckFailed { check, message } => {
                write!(f, "Preflight check '{}' failed: {}", check, message)
            }
            CalibrationError::TimerTooCoarse {
                resolution_ns,
                operation_ns,
            } => {
                write!(
                    f,
                    "Timer resolution ({:.1}ns) too coarse for operation ({:.1}ns)",
                    resolution_ns, operation_ns
                )
            }
        }
    }
}

/// Run calibration phase to estimate covariance and set priors (no_std compatible).
///
/// This is the core calibration function that can run in no_std environments.
/// Unlike the `tacet` crate version, throughput (`samples_per_second`) must be
/// provided by the caller since `std::time::Instant` is not available.
///
/// # Arguments
///
/// * `baseline_samples` - Pre-collected baseline timing samples (in native units)
/// * `sample_samples` - Pre-collected sample timing samples (in native units)
/// * `ns_per_tick` - Conversion factor from native units to nanoseconds
/// * `config` - Calibration configuration
/// * `samples_per_second` - Throughput measured by caller (e.g., via performance.now())
///
/// # Returns
///
/// A `Calibration` struct with all computed quantities, or a `CalibrationError`.
pub fn calibrate(
    baseline_samples: &[u64],
    sample_samples: &[u64],
    ns_per_tick: f64,
    config: &CalibrationConfig,
    samples_per_second: f64,
) -> Result<Calibration, CalibrationError> {
    let n = baseline_samples.len().min(sample_samples.len());

    // Check minimum sample requirement
    const MIN_CALIBRATION_SAMPLES: usize = 100;
    if n < MIN_CALIBRATION_SAMPLES {
        return Err(CalibrationError::TooFewSamples {
            collected: n,
            minimum: MIN_CALIBRATION_SAMPLES,
        });
    }

    // Convert to nanoseconds for analysis
    let baseline_ns: Vec<f64> = baseline_samples[..n]
        .iter()
        .map(|&t| t as f64 * ns_per_tick)
        .collect();
    let sample_ns: Vec<f64> = sample_samples[..n]
        .iter()
        .map(|&t| t as f64 * ns_per_tick)
        .collect();

    // Check discrete mode (spec §3.6): < 10% unique values
    let unique_baseline = count_unique(&baseline_ns);
    let unique_sample = count_unique(&sample_ns);
    let min_uniqueness = (unique_baseline as f64 / n as f64).min(unique_sample as f64 / n as f64);
    let discrete_mode = config.force_discrete_mode || min_uniqueness < 0.10;

    // Create acquisition stream for joint bootstrap (spec Section 2.3.1)
    let mut acquisition_stream = AcquisitionStream::with_capacity(2 * n);
    acquisition_stream.push_batch_interleaved(&baseline_ns, &sample_ns);
    let interleaved = acquisition_stream.to_timing_samples();

    // Bootstrap variance estimation for W₁ distance
    let var_estimate = bootstrap_w1_variance(
        &interleaved,
        config.bootstrap_iterations,
        config.seed,
        false, // is_fragile
    );

    // Check variance validity (must be positive and finite)
    if !var_estimate.variance.is_finite() || var_estimate.variance <= 0.0 {
        return Err(CalibrationError::CovarianceEstimationFailed {
            reason: String::from("W₁ variance estimate is not positive and finite"),
        });
    }

    // Compute variance rate: var_rate = var_cal * n_cal
    let var_rate = var_estimate.variance * (n as f64);

    // Invariant check: var_rate / n should equal var_estimate.variance
    // This validates that our variance scaling is consistent (v6.0)
    #[cfg(debug_assertions)]
    {
        let var_n_at_cal = var_rate / (n as f64);
        let diff = (var_n_at_cal - var_estimate.variance).abs();
        assert!(
            diff < 1e-6,
            "Variance scaling invariant violated: difference = {} (expected < 1e-6). \
             This indicates var_rate scaling is incorrect.",
            diff
        );
    }

    // Compute IACT based on method
    let (block_length, iact, iact_method) = match config.iact_method {
        crate::types::IactMethod::PolitisWhite => (
            var_estimate.block_size,
            1.0,
            crate::types::IactMethod::PolitisWhite,
        ),
        crate::types::IactMethod::GeyersIMS => {
            let iact_result = timing_iact_combined(&interleaved);

            // Warnings are captured in iact_result but don't affect calibration
            // They will be logged by the caller if needed

            (
                var_estimate.block_size,
                iact_result.tau,
                crate::types::IactMethod::GeyersIMS,
            )
        }
        crate::types::IactMethod::DirectDifferences => {
            let iact_result = timing_iact_direct(&interleaved);

            // Warnings are captured in iact_result but don't affect calibration
            // They will be logged by the caller if needed

            (
                var_estimate.block_size,
                iact_result.tau,
                crate::types::IactMethod::DirectDifferences,
            )
        }
        crate::types::IactMethod::PerQuantile => {
            let iact_result = timing_iact_per_quantile(&interleaved);

            // Warnings are captured in iact_result but don't affect calibration
            // They will be logged by the caller if needed

            (
                var_estimate.block_size,
                iact_result.tau,
                crate::types::IactMethod::PerQuantile,
            )
        }
    };

    // Compute MDE from variance estimate (1D W₁ distance)
    // MDE ≈ z_α/2 * sqrt(var) for standard normal quantile z_α/2
    let z_alpha = 1.96; // 95% confidence for alpha=0.05
    let mde_ns = z_alpha * var_estimate.variance.sqrt();

    // Run preflight checks (unless skipped)
    let preflight_result = if config.skip_preflight {
        PreflightResult::new()
    } else {
        run_core_checks(
            &baseline_ns,
            &sample_ns,
            config.timer_resolution_ns,
            config.seed,
        )
    };

    // Compute calibration statistics snapshot for drift detection
    let calibration_snapshot = compute_calibration_snapshot(&baseline_ns, &sample_ns);

    // Compute floor-rate constant: c_floor = q_95(|Z|) where Z ~ N(0, var_rate)
    let c_floor = compute_c_floor_1d(var_rate, config.seed);

    // Timer tick floor
    let theta_tick = config.timer_resolution_ns;

    // Initial measurement floor at calibration sample count
    let theta_floor_initial = (c_floor / (n as f64).sqrt()).max(theta_tick);

    // Effective threshold: max(user threshold, measurement floor)
    let theta_eff = if config.theta_ns > 0.0 {
        config.theta_ns.max(theta_floor_initial)
    } else {
        theta_floor_initial
    };

    // Half-t prior (ν=4) calibration for W₁ distance
    let sigma_t = calibrate_halft_prior_scale_1d(var_rate, theta_eff, n, config.seed);

    // Projection mismatch is not applicable to W₁ distance (no projection model)
    // Use placeholder value for compatibility with diagnostics
    let projection_mismatch_thresh = 0.0;

    Ok(Calibration::with_preflight(
        var_rate,
        block_length,
        iact,
        iact_method,
        sigma_t,
        config.theta_ns,
        n,
        discrete_mode,
        mde_ns,
        calibration_snapshot,
        config.timer_resolution_ns,
        samples_per_second,
        c_floor,
        projection_mismatch_thresh,
        theta_tick,
        theta_eff,
        theta_floor_initial,
        config.seed,
        1, // batch_k = 1 (no batching), updated by collector
        preflight_result,
    ))
}

/// Count unique values in a slice (for discrete mode detection).
fn count_unique(values: &[f64]) -> usize {
    use alloc::collections::BTreeSet;

    // Discretize to avoid floating point comparison issues
    // Use 0.001ns buckets (well below any meaningful timing difference)
    let buckets: BTreeSet<i64> = values.iter().map(|&v| (v * 1000.0) as i64).collect();
    buckets.len()
}

/// Compute calibration statistics snapshot for drift detection.
fn compute_calibration_snapshot(baseline_ns: &[f64], sample_ns: &[f64]) -> CalibrationSnapshot {
    let mut baseline_stats = OnlineStats::new();
    let mut sample_stats = OnlineStats::new();

    for &t in baseline_ns {
        baseline_stats.update(t);
    }
    for &t in sample_ns {
        sample_stats.update(t);
    }

    CalibrationSnapshot::new(baseline_stats.finalize(), sample_stats.finalize())
}

// DELETED: compute_prior_cov_9d() - 9D version (no 1D equivalent needed, prior is scalar)

// DELETED: compute_correlation_matrix() - 9D helper
// DELETED: estimate_condition_number() - 9D helper
// DELETED: is_fragile_regime() - 9D helper
// DELETED: apply_correlation_regularization() - 9D helper
// DELETED: compute_median_se() - 9D helper

// DELETED: calibrate_t_prior_scale() - 9D version (replaced by calibrate_halft_prior_scale_1d)

// DELETED: precompute_t_prior_effects() - 9D helper (replaced by 1D calibration)

// DELETED: compute_c_floor_9d() - 9D version (replaced by compute_c_floor_1d)


/// Calibrate half-t prior scale to achieve target exceedance probability (W₁ distance).
///
/// Finds σ_t such that P(|δ| > theta_eff | δ ~ half-t(ν=4, σ_t)) ≈ 0.62
///
/// Uses binary search with Monte Carlo exceedance estimation. The half-t distribution
/// is sampled via scale mixture:
/// - λ ~ Gamma(ν/2, ν/2) = Gamma(2, 2) for ν=4
/// - z ~ N(0, 1)
/// - δ = |σ_t/√λ · z|
///
/// # Arguments
/// * `var_rate` - Variance rate (scalar) from bootstrap
/// * `theta_eff` - Effective threshold in nanoseconds
/// * `n_cal` - Number of calibration samples
/// * `seed` - Deterministic RNG seed
///
/// # Returns
/// Calibrated prior scale σ_t achieving target 62% exceedance probability.
///
/// # Example
/// ```
/// use tacet_core::adaptive::calibration::calibrate_halft_prior_scale_1d;
///
/// let var_rate = 1000.0;
/// let theta_eff = 100.0;
/// let n_cal = 5000;
/// let seed = 42;
///
/// let sigma_t = calibrate_halft_prior_scale_1d(var_rate, theta_eff, n_cal, seed);
/// assert!(sigma_t > 0.0);
/// ```
pub fn calibrate_halft_prior_scale_1d(
    _var_rate: f64,
    theta_eff: f64,
    _n_cal: usize,
    seed: u64,
) -> f64 {
    // Target exceedance probability
    const TARGET_EXCEEDANCE: f64 = 0.62;
    const TOLERANCE: f64 = 0.02;
    const N_SAMPLES: usize = 10_000;
    const NU: f64 = 4.0;

    // Binary search bounds
    let mut sigma_low = theta_eff / 10.0;
    let mut sigma_high = theta_eff * 10.0;

    // Use RNG for Monte Carlo
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed);

    // Binary search loop (max 30 iterations)
    for _ in 0..30 {
        let sigma_mid = (sigma_low + sigma_high) / 2.0;

        // Estimate P(|δ| > theta) via Monte Carlo
        // Sample δ ~ half-t(ν, σ_mid) via scale mixture:
        //   λ ~ Gamma(ν/2, ν/2), z ~ N(0,1), δ = |σ/√λ · z|
        let mut exceed_count = 0;
        for _ in 0..N_SAMPLES {
            let lambda = sample_gamma(&mut rng, NU / 2.0, NU / 2.0);
            let z = sample_standard_normal(&mut rng);
            let delta = (sigma_mid / lambda.sqrt() * z).abs();

            if delta > theta_eff {
                exceed_count += 1;
            }
        }

        let exceedance_prob = exceed_count as f64 / N_SAMPLES as f64;

        // Check convergence
        if (exceedance_prob - TARGET_EXCEEDANCE).abs() < TOLERANCE {
            return sigma_mid;
        }

        // Adjust bounds
        if exceedance_prob < TARGET_EXCEEDANCE {
            sigma_low = sigma_mid;
        } else {
            sigma_high = sigma_mid;
        }
    }

    // Return midpoint if didn't converge
    (sigma_low + sigma_high) / 2.0
}

/// Compute measurement floor constant from null noise distribution (W₁ distance).
///
/// Returns the 95th percentile of |Z| where Z ~ N(0, var_rate).
///
/// Used for theta_floor computation: theta_floor(n) = c_floor / sqrt(n)
///
/// # Arguments
/// * `var_rate` - Variance rate (scalar) from bootstrap
/// * `seed` - Deterministic RNG seed
///
/// # Returns
/// The 95th percentile constant c_floor.
///
/// # Example
/// ```
/// use tacet_core::adaptive::calibration::compute_c_floor_1d;
///
/// let var_rate = 100.0;
/// let seed = 42;
///
/// let c_floor = compute_c_floor_1d(var_rate, seed);
/// assert!(c_floor > 0.0);
/// // For N(0, 100), q95(|Z|) ≈ 1.645 * sqrt(100) ≈ 16.45
/// assert!((c_floor - 16.45).abs() < 3.0);
/// ```
pub fn compute_c_floor_1d(var_rate: f64, seed: u64) -> f64 {
    const N_SAMPLES: usize = 50_000;
    const PERCENTILE: usize = (N_SAMPLES as f64 * 0.95) as usize;

    let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed);
    let std_dev = var_rate.sqrt();

    // Sample |Z| values
    let mut samples: Vec<f64> = (0..N_SAMPLES)
        .map(|_| {
            let z = sample_standard_normal(&mut rng);
            (z * std_dev).abs()
        })
        .collect();

    // Get 95th percentile via selection
    samples.select_nth_unstable_by(PERCENTILE, |a, b| a.total_cmp(b));
    samples[PERCENTILE]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statistics::StatsSnapshot;

    fn make_test_calibration() -> Calibration {
        let snapshot = CalibrationSnapshot::new(
            StatsSnapshot {
                count: 1000,
                mean: 100.0,
                variance: 25.0,
                autocorr_lag1: 0.1,
            },
            StatsSnapshot {
                count: 1000,
                mean: 105.0,
                variance: 30.0,
                autocorr_lag1: 0.12,
            },
        );

        let var_rate = 1000.0;
        let theta_eff = 100.0;

        Calibration::new(
            var_rate,                               // var_rate
            10,                                     // block_length
            1.0,                                    // iact
            crate::types::IactMethod::PolitisWhite, // iact_method
            100.0,                                  // sigma_t
            theta_eff,                              // theta_ns
            5000,                                   // calibration_samples
            false,                                  // discrete_mode
            5.0,                                    // mde_ns
            snapshot,                               // calibration_snapshot
            1.0,                                    // timer_resolution_ns
            10000.0,                                // samples_per_second
            10.0,                                   // c_floor
            18.48,                                  // projection_mismatch_thresh
            0.001,                                  // theta_tick
            theta_eff,                              // theta_eff
            0.1,                                    // theta_floor_initial
            42,                                     // rng_seed
            1,                                      // batch_k
        )
    }

    #[test]
    fn test_variance_scaling() {
        let cal = make_test_calibration();
        // make_test_calibration uses var_rate = 1000.0

        // v6.0: variance_for_n uses raw n (block bootstrap already accounts for dependence)
        // At n=1000: var_n = var_rate / n = 1000 / 1000 = 1.0
        let var_1000 = cal.variance_for_n(1000);
        assert!(
            (var_1000 - 1.0).abs() < 1e-10,
            "expected 1.0, got {}",
            var_1000
        );

        // At n=2000: var_n = 1000 / 2000 = 0.5
        let var_2000 = cal.variance_for_n(2000);
        assert!(
            (var_2000 - 0.5).abs() < 1e-10,
            "expected 0.5, got {}",
            var_2000
        );
    }

    #[test]
    fn test_n_eff() {
        let cal = make_test_calibration();
        // make_test_calibration uses block_length = 10

        // n_eff = max(1, floor(n / block_length))
        assert_eq!(cal.n_eff(100), 10);
        assert_eq!(cal.n_eff(1000), 100);
        assert_eq!(cal.n_eff(10), 1);
        assert_eq!(cal.n_eff(5), 1); // Clamped to 1 when n < block_length
        assert_eq!(cal.n_eff(0), 1); // Edge case: n=0 returns 1
    }

    #[test]
    fn test_variance_zero_n() {
        let cal = make_test_calibration();
        let var = cal.variance_for_n(0);
        // Should return var_rate unchanged (avoid NaN)
        assert!((var - 1000.0).abs() < 1e-10);
    }

    #[test]
    fn test_estimate_collection_time() {
        let cal = make_test_calibration();

        // 10000 samples/sec -> 1000 samples takes 0.1 sec
        let time = cal.estimate_collection_time_secs(1000);
        assert!((time - 0.1).abs() < 1e-10);
    }

    // DELETED: test_compute_prior_cov_9d_unit_diagonal() - 9D test
    // DELETED: test_c_floor_computation() - 9D test

    #[test]
    fn test_calibration_config_default() {
        let config = CalibrationConfig::default();
        assert_eq!(config.calibration_samples, 5000);
        assert_eq!(config.bootstrap_iterations, 200);
        assert!((config.theta_ns - 100.0).abs() < 1e-10);
        assert!((config.timer_resolution_ns - 1.0).abs() < 1e-10);
        assert!(!config.skip_preflight);
        assert!(!config.force_discrete_mode);
    }

    // DELETED: 9D t-prior test helper functions and tests
    // - reference_t_prior_exceedance()
    // - optimized_t_prior_exceedance()
    // - test_t_prior_precompute_exceedance_matches_reference()
    // - test_t_prior_exceedance_monotonicity()
    // - test_calibrate_t_prior_scale_finds_target_exceedance()
    // - test_calibration_determinism()
    // - test_precomputed_effects_distribution()
    // - bench_calibration_timing()

    // =========================================================================
    // W₁ distance (1D) helper function tests
    // =========================================================================

    #[test]
    fn test_calibrate_halft_prior_scale_1d_basic() {
        // Test basic calibration produces reasonable scale
        let var_rate = 100.0;
        let theta_eff = 10.0;
        let n_cal = 5000;
        let seed = 42;

        let sigma_t = calibrate_halft_prior_scale_1d(var_rate, theta_eff, n_cal, seed);

        // Should be positive and in reasonable range relative to theta
        assert!(sigma_t > 0.0, "sigma_t should be positive");
        assert!(
            sigma_t > theta_eff * 0.05,
            "sigma_t {} should be > theta * 0.05 = {}",
            sigma_t,
            theta_eff * 0.05
        );
        assert!(
            sigma_t < theta_eff * 50.0,
            "sigma_t {} should be < theta * 50 = {}",
            sigma_t,
            theta_eff * 50.0
        );
    }

    #[test]
    fn test_calibrate_halft_prior_scale_1d_achieves_target() {
        // Test that calibrated scale achieves target exceedance probability
        let var_rate = 100.0;
        let theta_eff = 10.0;
        let n_cal = 5000;
        let seed = 42;

        let sigma_t = calibrate_halft_prior_scale_1d(var_rate, theta_eff, n_cal, seed);

        // Verify exceedance probability via MC
        const N_VERIFY: usize = 50_000;
        const NU: f64 = 4.0;
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed + 1);
        let mut exceed_count = 0;

        for _ in 0..N_VERIFY {
            let lambda = sample_gamma(&mut rng, NU / 2.0, NU / 2.0);
            let z = sample_standard_normal(&mut rng);
            let delta = (sigma_t / lambda.sqrt() * z).abs();

            if delta > theta_eff {
                exceed_count += 1;
            }
        }

        let exceedance = exceed_count as f64 / N_VERIFY as f64;

        // Should be within 0.05 of target 0.62
        assert!(
            (exceedance - 0.62).abs() < 0.05,
            "Exceedance {} should be near 0.62",
            exceedance
        );
    }

    #[test]
    fn test_calibrate_halft_prior_scale_1d_determinism() {
        // Same seed should give same result
        let var_rate = 100.0;
        let theta_eff = 10.0;
        let n_cal = 5000;
        let seed = 12345;

        let sigma_1 = calibrate_halft_prior_scale_1d(var_rate, theta_eff, n_cal, seed);
        let sigma_2 = calibrate_halft_prior_scale_1d(var_rate, theta_eff, n_cal, seed);

        assert!(
            (sigma_1 - sigma_2).abs() < 1e-10,
            "Same seed should give same sigma_t: {} vs {}",
            sigma_1,
            sigma_2
        );
    }

    #[test]
    fn test_calibrate_halft_prior_scale_1d_scale_invariance() {
        // Scaling var_rate and theta_eff by same factor should scale sigma_t proportionally
        let var_rate = 100.0;
        let theta_eff = 10.0;
        let n_cal = 5000;
        let seed = 42;

        let sigma_1 = calibrate_halft_prior_scale_1d(var_rate, theta_eff, n_cal, seed);
        let sigma_2 = calibrate_halft_prior_scale_1d(var_rate * 4.0, theta_eff * 2.0, n_cal, seed);

        // sigma should scale roughly with sqrt(var_rate) ~ theta
        // But due to discrete binary search, won't be exact
        let expected_ratio = 2.0;
        let actual_ratio = sigma_2 / sigma_1;

        assert!(
            (actual_ratio - expected_ratio).abs() < 0.5,
            "Ratio {} should be near {}",
            actual_ratio,
            expected_ratio
        );
    }

    #[test]
    fn test_compute_c_floor_1d_basic() {
        // Test basic computation produces reasonable value
        let var_rate = 100.0;
        let seed = 42;

        let c_floor = compute_c_floor_1d(var_rate, seed);

        // For N(0, 100), q95(|Z|) ≈ 1.645 * sqrt(100) = 16.45
        // Allow some Monte Carlo variance
        assert!(c_floor > 0.0, "c_floor should be positive");
        assert!(
            c_floor > 13.0 && c_floor < 20.0,
            "c_floor {} should be in range [13, 20] for var=100",
            c_floor
        );
    }

    #[test]
    fn test_compute_c_floor_1d_determinism() {
        // Same seed should give same result
        let var_rate = 100.0;
        let seed = 12345;

        let c_floor_1 = compute_c_floor_1d(var_rate, seed);
        let c_floor_2 = compute_c_floor_1d(var_rate, seed);

        assert!(
            (c_floor_1 - c_floor_2).abs() < 1e-10,
            "Same seed should give same c_floor: {} vs {}",
            c_floor_1,
            c_floor_2
        );
    }

    #[test]
    fn test_compute_c_floor_1d_scaling() {
        // c_floor should scale with sqrt(var_rate)
        let var_base = 100.0;
        let seed = 42;

        let c_floor_base = compute_c_floor_1d(var_base, seed);
        let c_floor_4x = compute_c_floor_1d(var_base * 4.0, seed);

        // Should scale roughly by factor of 2 (sqrt(4))
        let ratio = c_floor_4x / c_floor_base;
        assert!(
            (ratio - 2.0).abs() < 0.3,
            "Ratio {} should be near 2.0",
            ratio
        );
    }

    #[test]
    fn test_compute_c_floor_1d_percentile_property() {
        // Verify that c_floor is indeed near the 95th percentile
        let var_rate = 100.0;
        let seed = 42;

        let c_floor = compute_c_floor_1d(var_rate, seed);

        // Generate fresh samples and check empirical percentile
        const N_VERIFY: usize = 50_000;
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed + 1);
        let std_dev = var_rate.sqrt();

        let mut samples: Vec<f64> = (0..N_VERIFY)
            .map(|_| {
                let z = sample_standard_normal(&mut rng);
                (z * std_dev).abs()
            })
            .collect();

        samples.sort_by(|a, b| a.total_cmp(b));
        let percentile_95_idx = (N_VERIFY as f64 * 0.95) as usize;
        let empirical_q95 = samples[percentile_95_idx];

        // c_floor should be close to empirical 95th percentile
        assert!(
            (c_floor - empirical_q95).abs() < 2.0,
            "c_floor {} should be near empirical q95 {}",
            c_floor,
            empirical_q95
        );
    }

    #[test]
    fn test_compute_c_floor_1d_small_variance() {
        // Test with small variance
        let var_rate = 1.0;
        let seed = 42;

        let c_floor = compute_c_floor_1d(var_rate, seed);

        // For N(0, 1), q95(|Z|) ≈ 1.645
        assert!(
            c_floor > 1.3 && c_floor < 2.0,
            "c_floor {} should be near 1.645 for unit variance",
            c_floor
        );
    }

    #[test]
    fn test_compute_c_floor_1d_large_variance() {
        // Test with large variance
        let var_rate = 10000.0;
        let seed = 42;

        let c_floor = compute_c_floor_1d(var_rate, seed);

        // For N(0, 10000), q95(|Z|) ≈ 1.645 * 100 = 164.5
        assert!(
            c_floor > 130.0 && c_floor < 200.0,
            "c_floor {} should be near 164.5 for var=10000",
            c_floor
        );
    }

    #[test]
    fn test_halft_prior_scale_1d_monotonicity() {
        // Increasing theta_eff should increase sigma_t (for fixed exceedance target)
        let var_rate = 100.0;
        let n_cal = 5000;
        let seed = 42;

        let sigma_10 = calibrate_halft_prior_scale_1d(var_rate, 10.0, n_cal, seed);
        let sigma_20 = calibrate_halft_prior_scale_1d(var_rate, 20.0, n_cal, seed);
        let sigma_50 = calibrate_halft_prior_scale_1d(var_rate, 50.0, n_cal, seed);

        assert!(
            sigma_20 > sigma_10,
            "sigma_t should increase with theta: {} vs {}",
            sigma_20,
            sigma_10
        );
        assert!(
            sigma_50 > sigma_20,
            "sigma_t should increase with theta: {} vs {}",
            sigma_50,
            sigma_20
        );
    }

    // DELETED: test_halft_vs_9d_scale_relationship() - test comparing 1D vs 9D
}
