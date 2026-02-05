//! Statistical analysis layers for timing leak detection.
//!
//! This module implements the statistical analysis framework (spec §3-5):
//!
//! - **Bayesian inference** (`bayes`): Posterior probability of timing leak
//! - **Effect estimation** (`effect`): Max effect and top quantile computation
//! - **MDE estimation** (`mde`): Minimum detectable effect for power analysis

pub mod bayes;
pub mod effect;
pub mod mde;

pub use bayes::{compute_bayes_1d, BayesW1Result};
pub use effect::{compute_effect_estimate, compute_effect_estimate_analytical, compute_tail_diagnostics};
pub use mde::{analytical_mde, estimate_mde, MdeEstimate};
