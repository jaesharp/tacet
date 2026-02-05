//! Quantile computation using Type 2 quantiles (inverse empirical CDF with averaging).
//!
//! This module implements Type 2 quantiles following Hyndman & Fan (1996),
//! which is more appropriate for bootstrap-based inference than interpolating estimators.
//!
//! **Type 2 formula** (for sorted sample x of size n at probability p):
//! ```text
//! h = n * p + 0.5
//! q = (x[floor(h)] + x[ceil(h)]) / 2
//! ```
//!
//! This uses the inverse of the empirical distribution function with averaging
//! at discontinuities. See spec §3.1 for theoretical justification.
//!
//! # Input Requirements
//!
//! All input data must be finite (no NaN or infinity values). In debug builds,
//! this is checked via assertions. NaN values would produce meaningless statistical
//! results since `total_cmp` orders them but their presence indicates invalid data.
//!
//! # Reference
//!
//! Hyndman, R. J. & Fan, Y. (1996). "Sample quantiles in statistical packages."
//! The American Statistician 50(4):361–365.

extern crate alloc;

use crate::math;

/// Debug assertion that all values in the slice are finite.
#[inline]
fn debug_assert_finite(data: &[f64]) {
    debug_assert!(
        data.iter().all(|x| x.is_finite()),
        "quantile input must be finite (no NaN or infinity)"
    );
}

/// Compute a single quantile from a mutable slice using Type 2 quantiles.
///
/// Uses Type 2 quantile definition (Hyndman & Fan 1996):
/// ```text
/// h = n * p + 0.5
/// q = (x[floor(h)] + x[ceil(h)]) / 2
/// ```
///
/// Uses `select_nth_unstable()` for O(n) expected time complexity.
/// The slice is partially reordered as a side effect.
///
/// # Arguments
///
/// * `data` - Mutable slice of measurements (will be partially reordered)
/// * `p` - Quantile probability in [0, 1]
///
/// # Returns
///
/// The quantile value at probability `p`.
///
/// # Panics
///
/// Panics if `data` is empty or if `p` is outside [0, 1].
pub fn compute_quantile(data: &mut [f64], p: f64) -> f64 {
    assert!(!data.is_empty(), "Cannot compute quantile of empty slice");
    assert!(
        (0.0..=1.0).contains(&p),
        "Quantile probability must be in [0, 1]"
    );
    debug_assert_finite(data);

    let n = data.len();

    // Handle edge cases
    if n == 1 {
        return data[0];
    }

    // Type 2 quantile: h = n * p + 0.5
    let h = n as f64 * p + 0.5;

    // Convert to 0-based indices with bounds checking
    let floor_idx = (math::floor(h) as usize).saturating_sub(1).min(n - 1);
    let ceil_idx = (math::ceil(h) as usize).saturating_sub(1).min(n - 1);

    let cmp = |a: &f64, b: &f64| a.total_cmp(b);

    if floor_idx == ceil_idx {
        // Single index case - just select that element
        let (_, mid, _) = data.select_nth_unstable_by(floor_idx, cmp);
        return *mid;
    }

    // Need both elements - select the larger index first
    let (_, mid, _) = data.select_nth_unstable_by(ceil_idx, cmp);
    let ceil_val = *mid; // Copy out (borrow ends here under NLL)

    // Select floor only within the left partition - avoids touching ceil position
    let (_, mid, _) = data[..ceil_idx].select_nth_unstable_by(floor_idx, cmp);
    let floor_val = *mid;

    // Average the two values for Type 2
    (floor_val + ceil_val) / 2.0
}

/// Compute mid-distribution quantiles for discrete data (spec §3.6).
///
/// Mid-distribution quantiles handle ties correctly by using:
/// ```text
/// F_mid(x) = F(x) - ½p(x)
/// q̂_mid = F⁻¹_mid(k)
/// ```
///
/// where F(x) is the empirical CDF and p(x) is the probability mass at x.
///
/// This is recommended for discrete/heavily-tied data where standard quantile
/// estimators may produce biased results.
///
/// # Reference
///
/// Geraci, M. & Jones, M. C. (2015). "Improved transformation-based quantile
/// regression." Canadian Journal of Statistics 43(1):118-132.
pub fn compute_midquantile(data: &mut [f64], p: f64) -> f64 {
    assert!(!data.is_empty(), "Cannot compute quantile of empty slice");
    assert!(
        (0.0..=1.0).contains(&p),
        "Quantile probability must be in [0, 1]"
    );
    debug_assert_finite(data);

    let n = data.len();

    // Sort the data
    data.sort_by(|a, b| a.total_cmp(b));

    // Handle edge cases
    if n == 1 {
        return data[0];
    }

    // Compute mid-distribution CDF values for each unique value
    // F_mid(x) = F(x) - ½p(x) = (rank + 0.5 * count_at_x) / n - 0.5 * count_at_x / n
    //          = (rank - 0.5 * count_at_x + 0.5 * count_at_x) / n
    //          = (rank_start + 0.5 * count_at_x) / n
    // where rank_start is the 0-based index of first occurrence

    // Find where in the mid-CDF our target probability p falls
    let mut i = 0;
    while i < n {
        let value = data[i];

        // Count how many times this value appears
        let mut count = 1;
        while i + count < n && data[i + count] == value {
            count += 1;
        }

        // Mid-CDF at this value: (i + count/2 + 0.5) / n
        // This is the "center" of the step in the CDF
        let f_mid = (i as f64 + count as f64 / 2.0) / n as f64;

        // If p <= f_mid, return this value
        if p <= f_mid {
            return value;
        }

        i += count;
    }

    // If we get here, p is very close to 1, return the last value
    data[n - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_quantile_median() {
        // With Type 2 quantiles: h = n * p + 0.5 = 5 * 0.5 + 0.5 = 3.0
        // floor(3) = 3, ceil(3) = 3 (both point to index 2 in 0-based)
        // So median = x[2] = 3.0
        let mut data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let median = compute_quantile(&mut data, 0.5);
        assert!((median - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_quantile_extremes() {
        // Type 2 at p=0: h = n * 0 + 0.5 = 0.5
        // floor(0.5) = 0, ceil(0.5) = 1, both as 1-based then -1 for 0-based
        // floor_idx = 0 - 1 = -1 -> saturating_sub gives 0
        // ceil_idx = 1 - 1 = 0
        // So min = (x[0] + x[0]) / 2 = 1.0
        //
        // Type 2 at p=1: h = n * 1 + 0.5 = 5.5
        // floor(5.5) = 5, ceil(5.5) = 6, as 1-based indices
        // floor_idx = 5 - 1 = 4 (clamped to n-1 = 4)
        // ceil_idx = 6 - 1 = 5 (clamped to n-1 = 4)
        // So max = (x[4] + x[4]) / 2 = 5.0
        let mut data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let min = compute_quantile(&mut data.clone(), 0.0);
        let max = compute_quantile(&mut data, 1.0);
        assert!((min - 1.0).abs() < 1e-10, "min was {}", min);
        assert!((max - 5.0).abs() < 1e-10, "max was {}", max);
    }

    #[test]
    #[should_panic(expected = "Cannot compute quantile of empty slice")]
    fn test_empty_slice_panics() {
        let mut data: Vec<f64> = vec![];
        compute_quantile(&mut data, 0.5);
    }

    // ========== Mid-distribution Quantile Tests ==========

    #[test]
    fn test_midquantile_no_ties() {
        // Without ties, mid-quantile should behave similarly to regular quantiles
        let mut data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let median = compute_midquantile(&mut data, 0.5);

        // For 10 elements, mid-CDF at 5.0 is (4 + 0.5) / 10 = 0.45
        // mid-CDF at 6.0 is (5 + 0.5) / 10 = 0.55
        // So 0.5 should return 6.0
        assert!((median - 6.0).abs() < 1e-10, "Median was {}", median);
    }

    #[test]
    fn test_midquantile_with_ties() {
        // Data with ties - this is where mid-quantile shines
        let mut data = vec![1.0, 1.0, 1.0, 2.0, 2.0, 3.0, 3.0, 3.0, 3.0, 4.0];
        let median = compute_midquantile(&mut data, 0.5);

        // Value 1.0 appears 3 times: mid-CDF = (0 + 1.5) / 10 = 0.15
        // Value 2.0 appears 2 times: mid-CDF = (3 + 1) / 10 = 0.40
        // Value 3.0 appears 4 times: mid-CDF = (5 + 2) / 10 = 0.70
        // So 0.5 falls in the 3.0 range
        assert!((median - 3.0).abs() < 1e-10, "Median was {}", median);
    }

    #[test]
    fn test_midquantile_all_same() {
        // All values the same
        let mut data = vec![42.0; 100];
        let median = compute_midquantile(&mut data, 0.5);
        assert!((median - 42.0).abs() < 1e-10);

        let q10 = compute_midquantile(&mut data, 0.1);
        assert!((q10 - 42.0).abs() < 1e-10);

        let q90 = compute_midquantile(&mut data, 0.9);
        assert!((q90 - 42.0).abs() < 1e-10);
    }

    #[test]
    fn test_midquantile_single_element() {
        let mut data = vec![42.0];
        let result = compute_midquantile(&mut data, 0.5);
        assert!((result - 42.0).abs() < 1e-10);
    }
}
