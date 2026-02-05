"""Detailed analysis of medium benchmark results."""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Import utils
import sys
sys.path.insert(0, str(Path(__file__).parent / "src"))
from tacet_analysis.utils import (
    setup_paper_style,
    COLORS,
    TOOL_NAMES,
    NOISE_ORDER_MEDIUM,
    EFFECT_ORDER_MEDIUM,
    NOISE_NAMES,
    EFFECT_NAMES,
    TOOL_ORDER,
)

# Data directory
DATA_DIR = Path("/Users/agucova/repos/tacet/results/medium-w1-v7.1-round2-local")
OUTPUT_DIR = Path("/tmp/medium_analysis_detailed")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

setup_paper_style()

def load_data():
    """Load benchmark results."""
    results = pd.read_csv(DATA_DIR / "benchmark_results.csv")
    summary = pd.read_csv(DATA_DIR / "benchmark_summary.csv")
    return results, summary

def analyze_power_by_effect(results):
    """Analyze power curves for each tool."""
    print("\n" + "="*60)
    print("POWER ANALYSIS BY EFFECT SIZE")
    print("="*60)

    # Focus on shift pattern, iid noise
    shift_iid = results[
        (results["effect_pattern"] == "shift") &
        (results["noise_model"] == "iid")
    ]

    print("\nPower by effect size (shift pattern, i.i.d. noise):\n")

    # Calculate power for each tool at each effect size
    power_table = []
    for tool in TOOL_ORDER:
        tool_data = shift_iid[shift_iid["tool"] == tool]
        row = {"Tool": TOOL_NAMES.get(tool, tool)}

        for effect in EFFECT_ORDER_MEDIUM:
            effect_data = tool_data[tool_data["effect_sigma_mult"] == effect]
            if len(effect_data) > 0:
                power = effect_data["detected"].mean()
                n = len(effect_data)
                se = np.sqrt(power * (1 - power) / n)
                row[EFFECT_NAMES[effect]] = f"{power:.3f} (±{se:.3f})"
            else:
                row[EFFECT_NAMES[effect]] = "N/A"

        power_table.append(row)

    df_power = pd.DataFrame(power_table)
    print(df_power.to_string(index=False))

def analyze_fpr_by_noise(results):
    """Analyze FPR across noise models."""
    print("\n" + "="*60)
    print("FALSE POSITIVE RATE BY NOISE MODEL")
    print("="*60)

    null_data = results[
        (results["effect_sigma_mult"] == 0) &
        (results["effect_pattern"] == "shift")
    ]

    print("\nFPR by noise model (null effects, shift pattern):\n")

    fpr_table = []
    for tool in TOOL_ORDER:
        tool_data = null_data[null_data["tool"] == tool]
        row = {"Tool": TOOL_NAMES.get(tool, tool)}

        for noise in NOISE_ORDER_MEDIUM:
            noise_data = tool_data[tool_data["noise_model"] == noise]
            if len(noise_data) > 0:
                fpr = noise_data["detected"].mean()
                n = len(noise_data)
                row[NOISE_NAMES[noise]] = f"{fpr:.3f} ({n})"
            else:
                row[NOISE_NAMES[noise]] = "N/A"

        fpr_table.append(row)

    df_fpr = pd.DataFrame(fpr_table)
    print(df_fpr.to_string(index=False))

def analyze_shift_vs_tail(results):
    """Compare shift vs tail pattern detection."""
    print("\n" + "="*60)
    print("SHIFT VS TAIL PATTERN COMPARISON")
    print("="*60)

    # Focus on 1σ and 2σ effects on iid noise
    for effect_size in [1, 2]:
        print(f"\n--- Effect Size: {EFFECT_NAMES[effect_size]} ---\n")

        effect_data = results[
            (results["effect_sigma_mult"] == effect_size) &
            (results["noise_model"] == "iid")
        ]

        pattern_table = []
        for tool in TOOL_ORDER:
            tool_data = effect_data[effect_data["tool"] == tool]
            row = {"Tool": TOOL_NAMES.get(tool, tool)}

            for pattern in ["shift", "tail"]:
                pattern_data = tool_data[tool_data["effect_pattern"] == pattern]
                if len(pattern_data) > 0:
                    power = pattern_data["detected"].mean()
                    n = len(pattern_data)
                    row[pattern.title()] = f"{power:.3f} ({n})"
                else:
                    row[pattern.title()] = "N/A"

            pattern_table.append(row)

        df_pattern = pd.DataFrame(pattern_table)
        print(df_pattern.to_string(index=False))

def analyze_tacet_specifics(results):
    """Detailed analysis of Tacet behavior."""
    print("\n" + "="*60)
    print("TACET DETAILED ANALYSIS")
    print("="*60)

    tacet_data = results[results["tool"] == "tacet"]

    # FPR by attacker model and noise
    print("\nTacet FPR by attacker threshold and noise model:\n")

    null_tacet = tacet_data[tacet_data["effect_sigma_mult"] == 0]

    fpr_breakdown = []
    for thresh in sorted(null_tacet["attacker_threshold_ns"].unique()):
        for noise in NOISE_ORDER_MEDIUM:
            subset = null_tacet[
                (null_tacet["attacker_threshold_ns"] == thresh) &
                (null_tacet["noise_model"] == noise)
            ]
            if len(subset) > 0:
                fpr = subset["detected"].mean()
                n = len(subset)
                fpr_breakdown.append({
                    "Threshold (ns)": f"{thresh:.1f}",
                    "Noise Model": NOISE_NAMES[noise],
                    "FPR": f"{fpr:.3f}",
                    "N": n
                })

    df_tacet_fpr = pd.DataFrame(fpr_breakdown)
    print(df_tacet_fpr.to_string(index=False))

    # Power by attacker model
    print("\n\nTacet power at 1σ by attacker threshold:\n")

    power_1sigma = tacet_data[
        (tacet_data["effect_sigma_mult"] == 1) &
        (tacet_data["effect_pattern"] == "shift")
    ]

    power_breakdown = []
    for thresh in sorted(power_1sigma["attacker_threshold_ns"].unique()):
        for noise in NOISE_ORDER_MEDIUM:
            subset = power_1sigma[
                (power_1sigma["attacker_threshold_ns"] == thresh) &
                (power_1sigma["noise_model"] == noise)
            ]
            if len(subset) > 0:
                power = subset["detected"].mean()
                n = len(subset)
                power_breakdown.append({
                    "Threshold (ns)": f"{thresh:.1f}",
                    "Noise Model": NOISE_NAMES[noise],
                    "Power": f"{power:.3f}",
                    "N": n
                })

    df_tacet_power = pd.DataFrame(power_breakdown)
    print(df_tacet_power.to_string(index=False))

def plot_detailed_power_curves(results, output_dir):
    """Generate detailed power curve plots."""
    print("\n" + "="*60)
    print("GENERATING DETAILED POWER CURVES")
    print("="*60)

    # Power curves for each noise model (shift pattern only)
    for noise in NOISE_ORDER_MEDIUM:
        fig, ax = plt.subplots(figsize=(10, 6))

        noise_data = results[
            (results["noise_model"] == noise) &
            (results["effect_pattern"] == "shift")
        ]

        for tool in ["tacet", "silent", "rtlf", "dudect", "timing-tvla", "ad-test", "ks-test"]:
            tool_data = noise_data[noise_data["tool"] == tool]

            # Calculate power at each effect size
            power_curve = []
            for effect in EFFECT_ORDER_MEDIUM:
                effect_data = tool_data[tool_data["effect_sigma_mult"] == effect]
                if len(effect_data) > 0:
                    power = effect_data["detected"].mean()
                    power_curve.append((effect, power))

            if power_curve:
                effects, powers = zip(*power_curve)
                ax.plot(effects, [p * 100 for p in powers],
                       marker="o", label=TOOL_NAMES.get(tool, tool),
                       linewidth=2, markersize=6)

        ax.set_xlabel("Effect Size (σ)", fontweight="medium")
        ax.set_ylabel("Detection Power (%)", fontweight="medium")
        ax.set_title(f"Power Curves: {NOISE_NAMES[noise]}, Shift Pattern",
                    fontweight="bold", pad=10)
        ax.grid(True, alpha=0.3)
        ax.legend(frameon=True, fancybox=False, edgecolor=COLORS["border"])
        ax.set_ylim(-5, 105)
        ax.set_xticks(EFFECT_ORDER_MEDIUM)
        ax.set_xticklabels([EFFECT_NAMES[e] for e in EFFECT_ORDER_MEDIUM])

        filename = output_dir / f"power_curve_{noise.replace('-', '_')}.png"
        plt.savefig(filename, dpi=300, bbox_inches="tight")
        plt.close()
        print(f"  Saved: {filename}")

def plot_fpr_heatmap(results, output_dir):
    """Generate FPR heatmap."""
    print("\n" + "="*60)
    print("GENERATING FPR HEATMAP")
    print("="*60)

    null_data = results[
        (results["effect_sigma_mult"] == 0) &
        (results["effect_pattern"] == "shift")
    ]

    # Pivot: tools x noise models
    fpr_pivot = null_data.groupby(["tool", "noise_model"])["detected"].mean().unstack()

    # Reorder
    fpr_pivot = fpr_pivot.reindex(index=[t for t in TOOL_ORDER if t in fpr_pivot.index])
    fpr_pivot = fpr_pivot.reindex(columns=[n for n in NOISE_ORDER_MEDIUM if n in fpr_pivot.columns])

    # Rename for display
    fpr_pivot.index = [TOOL_NAMES.get(t, t) for t in fpr_pivot.index]
    fpr_pivot.columns = [NOISE_NAMES.get(n, n) for n in fpr_pivot.columns]

    # Plot
    fig, ax = plt.subplots(figsize=(10, 7))
    sns.heatmap(
        fpr_pivot * 100,
        annot=True,
        fmt=".1f",
        cmap="RdYlGn_r",
        vmin=0,
        vmax=20,
        cbar_kws={"label": "False Positive Rate (%)"},
        ax=ax,
        linewidths=0.5,
        linecolor=COLORS["border"]
    )
    ax.set_title("False Positive Rate by Tool and Noise Model", fontweight="bold", pad=10)
    ax.set_xlabel("Noise Model", fontweight="medium")
    ax.set_ylabel("Tool", fontweight="medium")

    filename = output_dir / "fpr_heatmap_detailed.png"
    plt.savefig(filename, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {filename}")

def main():
    print("="*60)
    print("DETAILED MEDIUM BENCHMARK ANALYSIS")
    print("="*60)

    results, summary = load_data()
    print(f"\nLoaded {len(results):,} tests from medium dataset")

    # Run analyses
    analyze_fpr_by_noise(results)
    analyze_power_by_effect(results)
    analyze_shift_vs_tail(results)
    analyze_tacet_specifics(results)

    # Generate plots
    plot_fpr_heatmap(results, OUTPUT_DIR)
    plot_detailed_power_curves(results, OUTPUT_DIR)

    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    print(f"\nOutputs saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
