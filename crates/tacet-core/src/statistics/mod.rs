//! Statistical methods for timing analysis.
//!
//! This module provides the core statistical infrastructure for timing oracle:
//! - Quantile computation using efficient O(n) selection algorithms
//! - Block bootstrap for resampling with autocorrelation preservation
//! - Covariance estimation via bootstrap
//! - Autocorrelation function computation
//! - Optimal block length estimation using Politis-White algorithm
//! - Online statistics for condition drift detection
//! - Acquisition stream model for correct dependence estimation
//! - Discrete mode detection for low-resolution timers

mod acquisition;
mod autocorrelation;
mod block_length;
mod bootstrap;
mod covariance;
mod detection;
mod iact;
mod online_stats;
mod quantile;
mod wasserstein;

pub use acquisition::{AcquisitionStream, SampleClass};
pub use autocorrelation::{estimate_dependence_length, lag1_autocorrelation, lag2_autocorrelation};
pub use block_length::{
    class_conditional_optimal_block_length, optimal_block_length, paired_optimal_block_length,
    OptimalBlockLength,
};
pub use bootstrap::{
    block_bootstrap_resample, block_bootstrap_resample_into, block_bootstrap_resample_joint_into,
    compute_block_size, counter_rng_seed,
};
pub use covariance::{bootstrap_w1_variance, W1VarianceEstimate};
pub use detection::{compute_min_uniqueness_ratio, DISCRETE_MODE_THRESHOLD};
pub use iact::{
    geyer_ims_iact, timing_iact_combined, timing_iact_direct, timing_iact_per_quantile, IactResult,
    IactWarning,
};
pub use online_stats::{OnlineStats, StatsSnapshot};
pub use quantile::{compute_midquantile, compute_quantile};
pub use wasserstein::{compute_w1_debiased, compute_w1_distance};
