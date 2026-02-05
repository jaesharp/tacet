//! JSON serialization for timing analysis results.
//!
//! ## JSON Schema
//!
//! The serialization produces JSON with the following structure:
//!
//! ### Outcome Variants
//!
//! #### Pass/Fail/Inconclusive
//! ```json
//! {
//!   "Pass": {
//!     "leak_probability": 0.02,
//!     "effect": {
//!       "w1_distance_ns": 12.3,
//!       "credible_interval_ns": [10.1, 14.5],
//!       "tail_diagnostics": {
//!         "shift_ns": 8.2,
//!         "tail_ns": 4.1,
//!         "tail_share": 0.33,
//!         "tail_slow_share": 0.78,
//!         "quantile_shifts": {
//!           "p50_ns": 7.5,
//!           "p90_ns": 15.2,
//!           "p95_ns": 18.1,
//!           "p99_ns": 24.3
//!         },
//!         "pattern_label": "Mixed"
//!       }
//!     },
//!     "samples_used": 10000,
//!     "quality": "Good",
//!     "diagnostics": { /* ... */ },
//!     "theta_user": 100.0,
//!     "theta_eff": 100.0,
//!     "theta_floor": 0.0
//!   }
//! }
//! ```
//!
//! **Notes:**
//! - `w1_distance_ns` is the Wasserstein-1 distance (total effect magnitude)
//! - `tail_diagnostics` is omitted when effect is negligible or unavailable
//! - Pattern labels: `"TailEffect"`, `"UniformShift"`, `"Mixed"`, `"Negligible"`
//! - Quality levels: `"Excellent"`, `"Good"`, `"Poor"`, `"TooNoisy"`
//!
//! #### Fail (additional fields)
//! ```json
//! {
//!   "Fail": {
//!     /* ... same fields as Pass ... */
//!     "exploitability": "Http2Multiplexing"
//!   }
//! }
//! ```
//!
//! Exploitability levels: `"SharedHardwareOnly"`, `"Http2Multiplexing"`,
//! `"StandardRemote"`, `"ObviousLeak"`
//!
//! #### Unmeasurable
//! ```json
//! {
//!   "Unmeasurable": {
//!     "operation_ns": 0.5,
//!     "threshold_ns": 10.0,
//!     "platform": "macos (cntvct)",
//!     "recommendation": "Run with sudo for cycle counting"
//!   }
//! }
//! ```

use crate::result::Outcome;

/// Serialize an Outcome to a compact JSON string.
///
/// See module documentation for JSON schema details.
///
/// # Errors
///
/// Returns an error if serialization fails (should not happen for Outcome).
pub fn to_json(outcome: &Outcome) -> Result<String, serde_json::Error> {
    serde_json::to_string(outcome)
}

/// Serialize an Outcome to a pretty-printed JSON string.
///
/// See module documentation for JSON schema details.
///
/// # Errors
///
/// Returns an error if serialization fails (should not happen for Outcome).
pub fn to_json_pretty(outcome: &Outcome) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{
        Diagnostics, EffectEstimate, Exploitability, InconclusiveReason, MeasurementQuality,
    };

    fn make_pass_outcome() -> Outcome {
        Outcome::Pass {
            leak_probability: 0.02,
            effect: EffectEstimate::default(),
            samples_used: 10000,
            quality: MeasurementQuality::Good,
            diagnostics: Diagnostics::all_ok(),
            theta_user: 100.0,
            theta_eff: 100.0,
            theta_floor: 0.0,
        }
    }

    fn make_fail_outcome() -> Outcome {
        use crate::result::{EffectPattern, QuantileShifts, TailDiagnostics};
        Outcome::Fail {
            leak_probability: 0.98,
            effect: EffectEstimate::with_tail_diagnostics(
                150.0,
                (100.0, 200.0),
                TailDiagnostics {
                    shift_ns: 120.0,
                    tail_ns: 30.0,
                    tail_share: 0.2,
                    tail_slow_share: 0.8,
                    quantile_shifts: QuantileShifts {
                        p50_ns: 115.0,
                        p90_ns: 145.0,
                        p95_ns: 160.0,
                        p99_ns: 180.0,
                    },
                    pattern_label: EffectPattern::UniformShift,
                },
            ),
            exploitability: Exploitability::Http2Multiplexing,
            samples_used: 10000,
            quality: MeasurementQuality::Good,
            diagnostics: Diagnostics::all_ok(),
            theta_user: 100.0,
            theta_eff: 100.0,
            theta_floor: 0.0,
        }
    }

    fn make_inconclusive_outcome() -> Outcome {
        Outcome::Inconclusive {
            reason: InconclusiveReason::TimeBudgetExceeded {
                current_probability: 0.5,
                samples_collected: 50000,
            },
            leak_probability: 0.5,
            effect: EffectEstimate::default(),
            samples_used: 50000,
            quality: MeasurementQuality::Good,
            diagnostics: Diagnostics::all_ok(),
            theta_user: 100.0,
            theta_eff: 100.0,
            theta_floor: 0.0,
        }
    }

    fn make_unmeasurable_outcome() -> Outcome {
        Outcome::Unmeasurable {
            operation_ns: 0.5,
            threshold_ns: 10.0,
            platform: "macos (cntvct)".to_string(),
            recommendation: "Run with sudo for cycle counting".to_string(),
        }
    }

    #[test]
    fn test_to_json_pass() {
        let outcome = make_pass_outcome();
        let json = to_json(&outcome).unwrap();
        assert!(json.contains("Pass"));
        assert!(json.contains("\"leak_probability\":0.02"));
    }

    #[test]
    fn test_to_json_fail() {
        let outcome = make_fail_outcome();
        let json = to_json(&outcome).unwrap();
        assert!(json.contains("Fail"));
        assert!(json.contains("\"leak_probability\":0.98"));
        assert!(json.contains("\"w1_distance_ns\":150.0"));
        assert!(json.contains("\"tail_diagnostics\""));
        assert!(json.contains("\"shift_ns\":120.0"));
        assert!(json.contains("\"tail_ns\":30.0"));
        assert!(json.contains("\"tail_share\":0.2"));
        assert!(json.contains("\"pattern_label\":\"UniformShift\""));
        assert!(json.contains("\"quantile_shifts\""));
        assert!(json.contains("\"p50_ns\":115.0"));
        assert!(json.contains("\"p90_ns\":145.0"));
        assert!(json.contains("\"p95_ns\":160.0"));
        assert!(json.contains("\"p99_ns\":180.0"));
    }

    #[test]
    fn test_to_json_inconclusive() {
        let outcome = make_inconclusive_outcome();
        let json = to_json(&outcome).unwrap();
        assert!(json.contains("Inconclusive"));
        assert!(json.contains("TimeBudgetExceeded"));
    }

    #[test]
    fn test_to_json_unmeasurable() {
        let outcome = make_unmeasurable_outcome();
        let json = to_json(&outcome).unwrap();
        assert!(json.contains("Unmeasurable"));
        assert!(json.contains("operation_ns"));
    }

    #[test]
    fn test_to_json_pretty() {
        let outcome = make_pass_outcome();
        let json = to_json_pretty(&outcome).unwrap();
        assert!(json.contains('\n')); // Pretty print has newlines
        assert!(json.contains("leak_probability"));
    }

    #[test]
    fn test_json_roundtrip() {
        let outcome = make_fail_outcome();
        let json = to_json(&outcome).unwrap();

        // Parse the JSON to verify it's valid
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify structure
        assert!(parsed.get("Fail").is_some());
        let fail = parsed.get("Fail").unwrap();
        assert!(fail.get("effect").is_some());
        let effect = fail.get("effect").unwrap();
        assert_eq!(
            effect.get("w1_distance_ns").unwrap().as_f64().unwrap(),
            150.0
        );

        // Verify tail diagnostics
        assert!(effect.get("tail_diagnostics").is_some());
        let tail = effect.get("tail_diagnostics").unwrap();
        assert_eq!(tail.get("shift_ns").unwrap().as_f64().unwrap(), 120.0);
        assert_eq!(tail.get("tail_ns").unwrap().as_f64().unwrap(), 30.0);
        assert_eq!(tail.get("tail_share").unwrap().as_f64().unwrap(), 0.2);
        assert_eq!(
            tail.get("pattern_label").unwrap().as_str().unwrap(),
            "UniformShift"
        );

        // Verify quantile shifts
        let quantile_shifts = tail.get("quantile_shifts").unwrap();
        assert_eq!(
            quantile_shifts.get("p50_ns").unwrap().as_f64().unwrap(),
            115.0
        );
        assert_eq!(
            quantile_shifts.get("p90_ns").unwrap().as_f64().unwrap(),
            145.0
        );
        assert_eq!(
            quantile_shifts.get("p95_ns").unwrap().as_f64().unwrap(),
            160.0
        );
        assert_eq!(
            quantile_shifts.get("p99_ns").unwrap().as_f64().unwrap(),
            180.0
        );

        // Verify top_quantiles is NOT serialized (deprecated)
        assert!(effect.get("top_quantiles").is_none());
    }

    #[test]
    fn test_json_no_tail_diagnostics_when_none() {
        let outcome = make_pass_outcome();
        let json = to_json(&outcome).unwrap();

        // Parse and verify tail_diagnostics is not present when None
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let pass = parsed.get("Pass").unwrap();
        let effect = pass.get("effect").unwrap();
        assert!(effect.get("tail_diagnostics").is_none());
    }
}
