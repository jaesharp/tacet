#!/usr/bin/env python3
"""Generate tail effect power curve analysis for paper §5.3.

This script extracts tail-effect detection rates from benchmark data and generates
a figure showing Tacet's ability to detect rare tail effects across effect sizes.
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# Setup paths
REPO_ROOT = Path(__file__).parent.parent.parent  # tacet/
RESULTS_DIR = REPO_ROOT / "results" / "medium-w1-distance"
OUTPUT_DIR = Path(__file__).parent / "outputs" / "figures"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def load_tail_data():
    """Load tail pattern data from benchmark results."""
    df = pd.read_csv(RESULTS_DIR / "benchmark_summary.csv")

    # Filter for tail pattern only
    tail_df = df[df["effect_pattern"] == "tail"].copy()

    # Filter for threshold 0.4ns (most sensitive, for detection power)
    tail_df = tail_df[tail_df["attacker_threshold_ns"] == 0.4].copy()

    return tail_df

def extract_detection_summary():
    """Extract key detection rates for paper text."""
    df = load_tail_data()

    # Group by effect size and compute detection statistics
    summary = df.groupby("effect_sigma_mult").agg({
        "detection_rate": "mean",
        "ci_low": "mean",
        "ci_high": "mean",
        "n_datasets": "sum"
    }).reset_index()

    print("=== Tail Effect Detection Summary ===\n")
    print("Effect Size | Detection Rate | 95% CI | Total Trials")
    print("-" * 60)
    for _, row in summary.iterrows():
        effect = row["effect_sigma_mult"]
        rate = row["detection_rate"]
        ci_low = row["ci_low"]
        ci_high = row["ci_high"]
        n = int(row["n_datasets"])
        print(f"{effect:>10}σ | {rate:>13.1%} | [{ci_low:.1%}, {ci_high:.1%}] | {n:>12}")

    # Extract specific values for paper text
    results_20sigma = summary[summary["effect_sigma_mult"] == 20.0]
    if not results_20sigma.empty:
        rate_20 = results_20sigma["detection_rate"].iloc[0]
        ci_low_20 = results_20sigma["ci_low"].iloc[0]
        ci_high_20 = results_20sigma["ci_high"].iloc[0]
        print(f"\n✓ At 20σ tail effects: {rate_20:.1%} detection")
        print(f"  95% CI: [{ci_low_20:.1%}, {ci_high_20:.1%}]")

    return summary

def plot_power_curve(summary):
    """Generate power curve figure for paper."""
    fig, ax = plt.subplots(figsize=(8, 5))

    # Plot detection rate with confidence interval
    effect_sizes = summary["effect_sigma_mult"]
    detection = summary["detection_rate"] * 100  # Convert to percentage
    ci_low = summary["ci_low"] * 100
    ci_high = summary["ci_high"] * 100

    # Main line
    ax.plot(effect_sizes, detection, 'o-', linewidth=2, markersize=8,
            color='#14b8a6', label='Tacet (W₁ distance)')

    # Confidence interval shading
    ax.fill_between(effect_sizes, ci_low, ci_high,
                    alpha=0.2, color='#14b8a6')

    # Formatting
    ax.set_xlabel('Effect Size (σ, tail-only shift)', fontsize=12)
    ax.set_ylabel('Detection Rate (%)', fontsize=12)
    ax.set_title('Detection Power for Tail Effects\n(upper 5% of distribution shifted)',
                fontsize=13, fontweight='bold')

    # Add grid
    ax.grid(True, alpha=0.3, linestyle='--')

    # Y-axis: 0-100%
    ax.set_ylim(-5, 105)
    ax.set_yticks([0, 25, 50, 75, 100])

    # X-axis: log scale for effect sizes
    ax.set_xscale('log')
    ax.set_xlim(0.15, 25)

    # Add reference line at 95% (Fail threshold)
    ax.axhline(95, color='gray', linestyle=':', linewidth=1.5, alpha=0.7,
              label='Fail threshold (95%)')

    # Legend
    ax.legend(loc='lower right', framealpha=0.95)

    plt.tight_layout()

    # Save
    output_path = OUTPUT_DIR / "tail_power_curve.png"
    fig.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"\n✓ Figure saved: {output_path}")

    return fig

def main():
    """Generate analysis and figure."""
    print("Generating tail-effect power curve analysis...\n")

    # Extract summary statistics
    summary = extract_detection_summary()

    # Generate figure
    plot_power_curve(summary)

    print("\n" + "="*60)
    print("Analysis complete!")
    print("="*60)
    print("\nTo use in paper:")
    print("1. Replace §5.3 TODO (line 788) with figure reference:")
    print("   Figure~\\ref{fig:tail_power} shows detection rates.")
    print("\n2. Update bullet points (lines 792-800) with:")
    print("   - Tacet: 100% at 20σ (95% CI: [98.1%, 100%])")
    print("   - Context: W₁ distance captures tail transport directly")
    print("\n3. Add figure in paper.tex after line 762")

if __name__ == "__main__":
    main()
