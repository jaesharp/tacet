//! Demo of histogram rendering for timing distributions.
//!
//! This example shows how to visualize timing distributions using the
//! built-in histogram renderer.

use tacet::output::{render_histogram, render_histogram_with_w1, HistogramConfig};

fn main() {
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║  Tacet Histogram Demo - Timing Distribution Viz      ║");
    println!("╚═══════════════════════════════════════════════════════╝\n");

    // Simulate a constant-time operation (tight distributions, similar medians)
    println!("Example 1: Constant-time operation (no leak)\n");
    let baseline_safe: Vec<f64> = (0..500).map(|i| 100.0 + (i % 10) as f64).collect();
    let sample_safe: Vec<f64> = (0..500).map(|i| 101.0 + (i % 11) as f64).collect();

    let config = HistogramConfig {
        bins: 20,
        height: 10,
        column_width: 2,
        show_percentiles: true,
    };

    println!("{}", render_histogram(&baseline_safe, &sample_safe, &config));

    // Simulate a leaky operation (shifted distributions)
    println!("\n\nExample 2: Timing leak (early exit on mismatch)\n");
    let baseline_leak: Vec<f64> = (0..500).map(|i| 100.0 + (i % 8) as f64).collect();
    let sample_leak: Vec<f64> = (0..500).map(|i| 125.0 + (i % 12) as f64).collect();

    let w1_distance = 24.5; // Simulated W₁ distance
    println!(
        "{}",
        render_histogram_with_w1(&baseline_leak, &sample_leak, &config, Some(w1_distance))
    );

    // Compact version for terminal output
    println!("\n\nExample 3: Compact format (for debug output)\n");
    let compact = HistogramConfig {
        bins: 15,
        height: 6,
        column_width: 2,
        show_percentiles: true,
    };

    println!(
        "{}",
        render_histogram_with_w1(&baseline_leak, &sample_leak, &compact, Some(w1_distance))
    );

    // Very compact for inline display
    println!("\n\nExample 4: Minimal format (for test assertions)\n");
    let minimal = HistogramConfig {
        bins: 12,
        height: 5,
        column_width: 1,
        show_percentiles: false,
    };

    println!("{}", render_histogram(&baseline_leak, &sample_leak, &minimal));

    println!("\n╔═══════════════════════════════════════════════════════╗");
    println!("║  Integration Note:                                    ║");
    println!("║  These histograms can be included in verbose output  ║");
    println!("║  or debug summaries to help diagnose timing issues.  ║");
    println!("╚═══════════════════════════════════════════════════════╝");
}
