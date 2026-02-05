# Histogram Rendering for Timing Distributions

## Overview

The `tacet-core::histogram` module provides compact terminal-based visualization of timing distributions using Unicode block characters (▁▂▃▄▅▆▇█). This enables quick visual inspection of distribution differences between baseline and sample classes.

## Location

- **Implementation**: `crates/tacet-core/src/histogram.rs`
- **Public API**: Re-exported via `tacet::output::{render_histogram, render_histogram_with_w1, HistogramConfig}`
- **Example**: `examples/histogram_demo.rs`

## Features

### Vertical Bar Charts
- Uses Unicode block characters for vertical bars
- Supports configurable bin count, height, and column width
- Side-by-side comparison of baseline vs sample distributions

### Percentile Markers
- Optional display of p50 (median) and p90 percentiles
- Shows actual timing values in nanoseconds

### W₁ Distance Display
- Optional header showing Wasserstein-1 distance between distributions
- Useful for quantifying distribution separation

## API

```rust
use tacet::output::{render_histogram, render_histogram_with_w1, HistogramConfig};

// Basic usage
let config = HistogramConfig {
    bins: 20,           // Number of histogram bins
    height: 10,         // Height in character rows
    column_width: 2,    // Width of each bar in characters
    show_percentiles: true,  // Show p50/p90 markers
};

let histogram = render_histogram(&baseline_ns, &sample_ns, &config);
println!("{}", histogram);

// With W₁ distance
let histogram = render_histogram_with_w1(
    &baseline_ns,
    &sample_ns,
    &config,
    Some(w1_distance_ns)
);
```

## Example Output

### Standard Format (20 bins, height 10)
```
Baseline                                           │ Sample          W₁ = 24.5ns
  ▄▄  ██  ██  ██  ██                               │                       ▄▄  ██  ▄▄  ▄▄
  ██  ██  ██  ██  ██                               │                       ██  ██  ██  ██
  ██▄▄██  ██▄▄██  ██▄▄                             │                       ██  ██▄▄██  ██▄▄
  ██████▄▄██████▄▄████▄▄                           │                       ██▄▄██████▄▄████
  ██████████████████████                           │                       ████████████████
  ██████████████████████                           │                     ▄▄████████████████
▄▄██████████████████████                           │                   ▄▄██████████████████
████████████████████████                           │                   ████████████████████
████████████████████████                           │                   ████████████████████
████████████████████████▄▄                         │                 ▄▄████████████████████
──────────────────────────────────────────────────┼──────────────────────────────────────
p50      p90                                       │ p50      p90
104.0ns  109.0ns                               │ 130.5ns  136.5ns
```

### Compact Format (15 bins, height 6)
```
Baseline                       │ Sample          W₁ = 24.5ns
  ▄▄██▄▄▄▄▄▄▄▄                 │             ▄▄  ██▄▄▄▄████▄▄
  ████████████                 │             ██▄▄████████████
▄▄████████████                 │             ████████████████
██████████████▄▄               │           ▄▄████████████████▄▄
████████████████▄▄▄▄▄▄▄▄▄▄▄▄▄▄ │ ▄▄▄▄▄▄▄▄▄▄████████████████████
──────────────────────────────┼──────────────────────────────
p50      p90                   │ p50      p90
104.0ns  109.0ns           │ 130.5ns  136.5ns
```

### Minimal Format (12 bins, height 5, no percentiles)
```
Baseline     │ Sample
 ▄██▄▄▄▄▄    │      ▄ █▄▄▄██▄
 ███████     │      ███████████
▄███████     │      ███████████
████████▄▄▄▄▄│▄▄▄▄▄▄███████████
────────────┼────────────────
```

## Use Cases

### 1. Verbose Output Mode
Include histograms in verbose diagnostic output to help users understand distribution characteristics:

```rust
if is_verbose() {
    let baseline_ns = state.baseline_ns(ns_per_tick);
    let sample_ns = state.sample_ns(ns_per_tick);
    let config = HistogramConfig::default();

    println!("\nTiming Distributions:");
    println!("{}", render_histogram_with_w1(
        &baseline_ns, &sample_ns, &config, Some(w1_distance)
    ));
}
```

### 2. Debug Summaries
Add compact histograms to debug output for test assertion failures:

```rust
pub fn format_debug_summary(outcome: &Outcome) -> String {
    let mut out = String::new();
    // ... existing debug output ...

    // Add compact histogram
    let compact = HistogramConfig {
        bins: 12,
        height: 5,
        column_width: 1,
        show_percentiles: false,
    };
    out.push_str(&render_histogram(&baseline_ns, &sample_ns, &compact));

    out
}
```

### 3. Research/Profiling Mode
Use detailed histograms when running in research mode to understand distribution shapes:

```rust
if matches!(attacker_model, AttackerModel::Research) {
    let detailed = HistogramConfig {
        bins: 30,
        height: 15,
        column_width: 3,
        show_percentiles: true,
    };
    println!("{}", render_histogram_with_w1(
        &baseline_ns, &sample_ns, &detailed, Some(w1_distance)
    ));
}
```

## Design Rationale

### Vertical vs Horizontal
- **Vertical bars** are more compact for side-by-side comparison
- Fits well in terminal width constraints (typically 80-120 chars)
- Natural left-to-right reading order for baseline → sample comparison

### Unicode Block Characters
- **8 levels of granularity** (▁▂▃▄▅▆▇█) provide smoother visual transitions
- **Terminal-compatible** - works in all modern terminals
- **No dependencies** - pure standard library implementation

### Configurable Sizing
- **Default (20 bins, height 10)**: Good balance for detailed view
- **Compact (15 bins, height 6)**: Suitable for debug output
- **Minimal (12 bins, height 5)**: Inline display in test failures

### Percentile Markers
- **p50 (median)**: Central tendency indicator
- **p90**: Tail behavior indicator
- These two percentiles are most useful for spotting:
  - Location shifts (p50 difference)
  - Tail effects (p90 difference relative to p50)

## Implementation Details

### Binning Strategy
- Shared bin edges computed from combined min/max of both distributions
- Ensures visual alignment between baseline and sample histograms
- Handles edge cases (empty, degenerate, infinite values)

### Normalization
- Height normalization based on maximum bin count across both distributions
- Preserves relative heights within each distribution
- Allows direct visual comparison of distribution shapes

### Percentile Computation
- Uses linear interpolation for fractional indices
- Filters out non-finite values (NaN, Infinity)
- Sorts data once per percentile calculation

## Testing

Run the example:
```bash
cargo run --example histogram_demo
```

Run the histogram module tests:
```bash
cargo test --package tacet-core histogram
```

## Future Enhancements

### Potential additions (not currently implemented):
1. **Color coding**: Different colors for baseline vs sample bars
2. **Overlaid mode**: Single histogram with overlapping bars
3. **Difference view**: Show bin-by-bin differences
4. **ASCII fallback**: For terminals without Unicode support
5. **Export formats**: SVG/PNG generation for documentation
6. **Multiple distributions**: Compare >2 distributions simultaneously

## Integration with W₁ Refactor

This histogram feature is designed to work seamlessly with the Wasserstein-1 (W₁) distance metric refactor:

- **Input data**: Directly uses the `baseline_samples` and `sample_samples` vectors from `AdaptiveState`
- **W₁ display**: `render_histogram_with_w1()` shows the computed W₁ distance in the header
- **Diagnostic value**: Visual confirmation of W₁ distance magnitude
  - Small W₁ (~1-5ns): Distributions should overlap significantly
  - Medium W₁ (~10-50ns): Clear separation visible
  - Large W₁ (>100ns): Distinct non-overlapping distributions

## References

- Unicode block characters: U+2581 through U+2588
- Box drawing characters: U+2500 through U+257F (for separators)
- Implementation inspired by sparklines and terminal-based data viz tools
