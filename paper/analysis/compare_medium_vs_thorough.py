"""Compare medium vs thorough benchmark results."""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from scipy import stats

# Import utils
import sys
sys.path.insert(0, str(Path(__file__).parent / "src"))
from tacet_analysis.utils import (
    setup_paper_style,
    COLORS,
    TOOL_NAMES,
    NOISE_ORDER_MEDIUM,
    NOISE_ORDER_THOROUGH,
    EFFECT_ORDER_MEDIUM,
    EFFECT_ORDER_THOROUGH,
    NOISE_NAMES,
    EFFECT_NAMES,
    TOOL_ORDER,
)

# Data directories
MEDIUM_DIR = Path("/Users/agucova/repos/tacet/results/medium-w1-v7.1-round2-local")
THOROUGH_DIR = Path("/Users/agucova/repos/tacet/results/thorough-w1-v7.1-round2")
OUTPUT_DIR = Path("/Users/agucova/repos/tacet/paper/analysis/outputs/comparison_medium_vs_thorough")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

setup_paper_style()

def load_data(data_dir, preset_name):
    """Load benchmark data and add preset identifier."""
    results = pd.read_csv(data_dir / "benchmark_results.csv")
    summary = pd.read_csv(data_dir / "benchmark_summary.csv")
    results["data_preset"] = preset_name
    summary["data_preset"] = preset_name
    return results, summary

def calculate_fpr(df):
    """Calculate FPR for null effects (effect_sigma_mult=0)."""
    null_df = df[df["effect_sigma_mult"] == 0].copy()

    if len(null_df) == 0:
        return pd.DataFrame()

    # Group by tool, noise model, preset
    fpr = null_df.groupby(["tool", "noise_model", "data_preset"]).agg(
        fpr=("detected", "mean"),
        n_tests=("detected", "count")
    ).reset_index()

    # Calculate standard error for confidence intervals
    fpr["se"] = np.sqrt(fpr["fpr"] * (1 - fpr["fpr"]) / fpr["n_tests"])
    fpr["ci_lower"] = fpr["fpr"] - 1.96 * fpr["se"]
    fpr["ci_upper"] = fpr["fpr"] + 1.96 * fpr["se"]

    return fpr

def calculate_power(df, effect_size):
    """Calculate detection power at a specific effect size."""
    effect_df = df[df["effect_sigma_mult"] == effect_size].copy()

    if len(effect_df) == 0:
        return pd.DataFrame()

    # Group by tool, noise model, pattern, preset
    power = effect_df.groupby(["tool", "noise_model", "effect_pattern", "data_preset"]).agg(
        power=("detected", "mean"),
        n_tests=("detected", "count")
    ).reset_index()

    # Calculate standard error
    power["se"] = np.sqrt(power["power"] * (1 - power["power"]) / power["n_tests"])
    power["ci_lower"] = power["power"] - 1.96 * power["se"]
    power["ci_upper"] = power["power"] + 1.96 * power["se"]

    return power

def plot_fpr_comparison(fpr_data, output_path):
    """Plot FPR comparison heatmap for medium vs thorough."""
    # Pivot for heatmap: tools x noise models, separate for each preset
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    presets = ["medium", "thorough"]
    titles = ["Medium (30 datasets)", "Thorough (100 datasets)"]

    for ax, preset, title in zip(axes, presets, titles):
        preset_data = fpr_data[fpr_data["data_preset"] == preset]

        if preset == "medium":
            noise_order = NOISE_ORDER_MEDIUM
        else:
            noise_order = NOISE_ORDER_THOROUGH

        # Pivot: rows=tools, cols=noise models
        pivot = preset_data.pivot_table(
            index="tool",
            columns="noise_model",
            values="fpr",
            aggfunc="mean"
        )

        # Reorder
        pivot = pivot.reindex(index=[t for t in TOOL_ORDER if t in pivot.index])
        pivot = pivot.reindex(columns=[n for n in noise_order if n in pivot.columns])

        # Rename for display
        pivot.index = [TOOL_NAMES.get(t, t) for t in pivot.index]
        pivot.columns = [NOISE_NAMES.get(n, n) for n in pivot.columns]

        # Plot heatmap
        sns.heatmap(
            pivot * 100,  # Convert to percentage
            annot=True,
            fmt=".1f",
            cmap="RdYlGn_r",
            vmin=0,
            vmax=20,  # 0-20% range
            cbar_kws={"label": "False Positive Rate (%)"},
            ax=ax,
            linewidths=0.5,
            linecolor=COLORS["border"]
        )
        ax.set_title(title, fontweight="bold", pad=10)
        ax.set_xlabel("Noise Model", fontweight="medium")
        ax.set_ylabel("Tool", fontweight="medium")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {output_path}")

def plot_power_comparison(power_data, effect_size, output_path):
    """Plot power comparison for shift pattern across noise models."""
    shift_data = power_data[power_data["effect_pattern"] == "shift"]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=True)

    presets = ["medium", "thorough"]
    titles = [f"Medium (30 datasets) - {EFFECT_NAMES[effect_size]} Effect",
              f"Thorough (100 datasets) - {EFFECT_NAMES[effect_size]} Effect"]

    for ax, preset, title in zip(axes, presets, titles):
        preset_data = shift_data[shift_data["data_preset"] == preset]

        if preset == "medium":
            noise_order = NOISE_ORDER_MEDIUM
        else:
            noise_order = NOISE_ORDER_THOROUGH

        # Pivot: rows=tools, cols=noise models
        pivot = preset_data.pivot_table(
            index="tool",
            columns="noise_model",
            values="power",
            aggfunc="mean"
        )

        # Reorder
        pivot = pivot.reindex(index=[t for t in TOOL_ORDER if t in pivot.index])
        pivot = pivot.reindex(columns=[n for n in noise_order if n in pivot.columns])

        # Rename for display
        pivot.index = [TOOL_NAMES.get(t, t) for t in pivot.index]
        pivot.columns = [NOISE_NAMES.get(n, n) for n in pivot.columns]

        # Plot heatmap
        sns.heatmap(
            pivot * 100,  # Convert to percentage
            annot=True,
            fmt=".1f",
            cmap="RdYlGn",
            vmin=0,
            vmax=100,
            cbar_kws={"label": "Detection Power (%)"},
            ax=ax,
            linewidths=0.5,
            linecolor=COLORS["border"]
        )
        ax.set_title(title, fontweight="bold", pad=10)
        ax.set_xlabel("Noise Model", fontweight="medium")
        ax.set_ylabel("Tool", fontweight="medium")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {output_path}")

def plot_power_curves_comparison(results_data, noise_model, pattern, output_path):
    """Plot power curves for selected tools comparing medium vs thorough."""
    data = results_data[
        (results_data["noise_model"] == noise_model) &
        (results_data["effect_pattern"] == pattern)
    ]

    # Focus on key tools
    key_tools = ["tacet", "silent", "rtlf", "dudect", "timing-tvla"]
    data = data[data["tool"].isin(key_tools)]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    presets = ["medium", "thorough"]
    titles = ["Medium (30 datasets)", "Thorough (100 datasets)"]

    for ax, preset, title in zip(axes, presets, titles):
        preset_data = data[data["data_preset"] == preset]

        if preset == "medium":
            effect_order = EFFECT_ORDER_MEDIUM
        else:
            effect_order = EFFECT_ORDER_THOROUGH

        for tool in key_tools:
            tool_data = preset_data[preset_data["tool"] == tool]

            # Calculate mean power at each effect size
            power_curve = tool_data.groupby("effect_sigma_mult").agg(
                power=("detected", "mean"),
                se=("detected", lambda x: np.sqrt(x.mean() * (1 - x.mean()) / len(x)))
            ).reset_index()

            # Filter to available effects
            power_curve = power_curve[power_curve["effect_sigma_mult"].isin(effect_order)]

            # Plot
            ax.plot(
                power_curve["effect_sigma_mult"],
                power_curve["power"] * 100,
                marker="o",
                label=TOOL_NAMES.get(tool, tool),
                linewidth=2,
                markersize=6
            )

            # Add confidence bands
            ax.fill_between(
                power_curve["effect_sigma_mult"],
                (power_curve["power"] - 1.96 * power_curve["se"]) * 100,
                (power_curve["power"] + 1.96 * power_curve["se"]) * 100,
                alpha=0.2
            )

        ax.set_xlabel("Effect Size (σ)", fontweight="medium")
        ax.set_ylabel("Detection Power (%)", fontweight="medium")
        ax.set_title(title, fontweight="bold", pad=10)
        ax.grid(True, alpha=0.3)
        ax.legend(frameon=True, fancybox=False, edgecolor=COLORS["border"])
        ax.set_ylim(-5, 105)

        # Set x-axis to show effect sizes
        if preset == "medium":
            ax.set_xticks(EFFECT_ORDER_MEDIUM)
            ax.set_xticklabels([EFFECT_NAMES[e] for e in EFFECT_ORDER_MEDIUM])
        else:
            ax.set_xticks(EFFECT_ORDER_THOROUGH)
            ax.set_xticklabels([EFFECT_NAMES[e] for e in EFFECT_ORDER_THOROUGH])

    fig.suptitle(f"Power Curves: {NOISE_NAMES[noise_model]}, {pattern.title()} Pattern",
                 fontweight="bold", y=1.02)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {output_path}")

def analyze_fpr_differences(fpr_data):
    """Statistical analysis of FPR differences between presets."""
    print("\n" + "="*60)
    print("FALSE POSITIVE RATE ANALYSIS")
    print("="*60)

    # Overall FPR by tool and preset
    overall = fpr_data.groupby(["tool", "data_preset"]).agg(
        mean_fpr=("fpr", "mean"),
        max_fpr=("fpr", "max"),
        total_tests=("n_tests", "sum")
    ).reset_index()

    print("\nOverall FPR by Tool:")
    print(overall.pivot(index="tool", columns="data_preset", values="mean_fpr").round(4))

    # Check for significant differences
    print("\nFPR Comparison (Medium vs Thorough):")
    for tool in overall["tool"].unique():
        tool_data = overall[overall["tool"] == tool]
        medium_fpr = tool_data[tool_data["data_preset"] == "medium"]["mean_fpr"].values[0]
        thorough_fpr = tool_data[tool_data["data_preset"] == "thorough"]["mean_fpr"].values[0]
        diff = medium_fpr - thorough_fpr
        print(f"  {TOOL_NAMES.get(tool, tool):20s}: Δ={diff:+.4f} (Med={medium_fpr:.4f}, Thor={thorough_fpr:.4f})")

    # Noise model breakdown
    print("\nFPR by Noise Model:")
    for noise in fpr_data["noise_model"].unique():
        noise_data = fpr_data[fpr_data["noise_model"] == noise]
        print(f"\n  {NOISE_NAMES.get(noise, noise)}:")
        for tool in TOOL_ORDER:
            tool_data = noise_data[noise_data["tool"] == tool]
            if len(tool_data) > 0:
                med = tool_data[tool_data["data_preset"] == "medium"]["fpr"].values
                thor = tool_data[tool_data["data_preset"] == "thorough"]["fpr"].values
                if len(med) > 0 and len(thor) > 0:
                    print(f"    {TOOL_NAMES.get(tool, tool):20s}: Med={med[0]:.3f}, Thor={thor[0]:.3f}")

def analyze_power_differences(power_data, effect_size):
    """Statistical analysis of power differences between presets."""
    print("\n" + "="*60)
    print(f"DETECTION POWER ANALYSIS (Effect = {EFFECT_NAMES[effect_size]})")
    print("="*60)

    # Filter to shift pattern (most common)
    shift_data = power_data[power_data["effect_pattern"] == "shift"]

    # Overall power by tool and preset
    overall = shift_data.groupby(["tool", "data_preset"]).agg(
        mean_power=("power", "mean"),
        min_power=("power", "min"),
        total_tests=("n_tests", "sum")
    ).reset_index()

    print(f"\nOverall Power by Tool (Shift Pattern):")
    print(overall.pivot(index="tool", columns="data_preset", values="mean_power").round(4))

    # Check for significant differences
    print("\nPower Comparison (Medium vs Thorough):")
    for tool in overall["tool"].unique():
        tool_data = overall[overall["tool"] == tool]
        medium_power = tool_data[tool_data["data_preset"] == "medium"]["mean_power"].values[0]
        thorough_power = tool_data[tool_data["data_preset"] == "thorough"]["mean_power"].values[0]
        diff = medium_power - thorough_power
        print(f"  {TOOL_NAMES.get(tool, tool):20s}: Δ={diff:+.4f} (Med={medium_power:.4f}, Thor={thorough_power:.4f})")

def generate_markdown_report(fpr_data, power_data, output_path):
    """Generate comprehensive markdown comparison report."""
    with open(output_path, "w") as f:
        f.write("# Medium vs Thorough Benchmark Comparison\n\n")
        f.write("**Date:** 2026-02-05\n\n")
        f.write("**Datasets:**\n")
        f.write("- Medium (local): `/Users/agucova/repos/tacet/results/medium-w1-v7.1-round2-local/`\n")
        f.write("  - 23,980 tests\n")
        f.write("  - 5,000 samples/class\n")
        f.write("  - 30 datasets per condition\n")
        f.write("  - Noise models: ar1-n0.6, ar1-n0.3, iid, ar1-0.3, ar1-0.6, ar1-0.8\n")
        f.write("  - Effect sizes: 0σ, 0.2σ, 1σ, 2σ, 4σ, 20σ\n\n")
        f.write("- Thorough: `/Users/agucova/repos/tacet/results/thorough-w1-v7.1-round2/`\n")
        f.write("  - 237,600 tests\n")
        f.write("  - 5,000 samples/class\n")
        f.write("  - 100 datasets per condition\n")
        f.write("  - Noise models: ar1-n0.6, ar1-n0.4, ar1-n0.2, iid, ar1-0.2, ar1-0.4, ar1-0.6\n")
        f.write("  - Effect sizes: 0σ, 0.1σ, 0.2σ, 0.4σ, 1σ, 2σ, 4σ, 10σ, 20σ\n\n")

        f.write("---\n\n")
        f.write("## Executive Summary\n\n")

        # FPR summary
        fpr_summary = fpr_data.groupby(["tool", "data_preset"]).agg(
            mean_fpr=("fpr", "mean"),
            max_fpr=("fpr", "max")
        ).reset_index()

        f.write("### False Positive Rates\n\n")
        f.write("| Tool | Medium (Mean) | Medium (Max) | Thorough (Mean) | Thorough (Max) | Δ Mean |\n")
        f.write("|------|---------------|--------------|-----------------|----------------|--------|\n")

        for tool in TOOL_ORDER:
            tool_data = fpr_summary[fpr_summary["tool"] == tool]
            if len(tool_data) > 0:
                med_data = tool_data[tool_data["data_preset"] == "medium"]
                thor_data = tool_data[tool_data["data_preset"] == "thorough"]
                if len(med_data) > 0 and len(thor_data) > 0:
                    med_mean = med_data["mean_fpr"].values[0]
                    med_max = med_data["max_fpr"].values[0]
                    thor_mean = thor_data["mean_fpr"].values[0]
                    thor_max = thor_data["max_fpr"].values[0]
                    delta = med_mean - thor_mean
                    f.write(f"| {TOOL_NAMES.get(tool, tool)} | {med_mean:.3f} | {med_max:.3f} | "
                           f"{thor_mean:.3f} | {thor_max:.3f} | {delta:+.3f} |\n")

        f.write("\n")

        # Power summary at key effect sizes
        for effect_size in [0.2, 1, 2, 4]:
            effect_power = power_data[
                (power_data["effect_pattern"] == "shift") &
                (power_data["noise_model"] == "iid")
            ]
            effect_power = effect_power.groupby(["tool", "data_preset"]).agg(
                mean_power=("power", "mean")
            ).reset_index()

            f.write(f"### Detection Power ({EFFECT_NAMES[effect_size]} Effect, i.i.d. Noise)\n\n")
            f.write("| Tool | Medium | Thorough | Δ |\n")
            f.write("|------|--------|----------|---|\n")

            for tool in TOOL_ORDER:
                tool_data = effect_power[effect_power["tool"] == tool]
                if len(tool_data) > 0:
                    med_data = tool_data[tool_data["data_preset"] == "medium"]
                    thor_data = tool_data[tool_data["data_preset"] == "thorough"]
                    if len(med_data) > 0 and len(thor_data) > 0:
                        med_power = med_data["mean_power"].values[0]
                        thor_power = thor_data["mean_power"].values[0]
                        delta = med_power - thor_power
                        f.write(f"| {TOOL_NAMES.get(tool, tool)} | {med_power:.3f} | "
                               f"{thor_power:.3f} | {delta:+.3f} |\n")
            f.write("\n")

        f.write("---\n\n")
        f.write("## Key Findings\n\n")

        # Tacet FPR check
        tacet_fpr = fpr_data[fpr_data["tool"] == "tacet"]
        if len(tacet_fpr) > 0:
            med_tacet_fpr = tacet_fpr[tacet_fpr["data_preset"] == "medium"]["fpr"].max()
            thor_tacet_fpr = tacet_fpr[tacet_fpr["data_preset"] == "thorough"]["fpr"].max()
            f.write(f"1. **Tacet FPR Consistency**: Medium={med_tacet_fpr:.3f}, Thorough={thor_tacet_fpr:.3f}\n")

        # Tools with FPR issues
        fpr_issues_med = fpr_summary[(fpr_summary["data_preset"] == "medium") &
                                     (fpr_summary["mean_fpr"] > 0.10)]
        fpr_issues_thor = fpr_summary[(fpr_summary["data_preset"] == "thorough") &
                                      (fpr_summary["mean_fpr"] > 0.10)]

        f.write(f"\n2. **FPR Inflation (>10% mean)**:\n")
        f.write(f"   - Medium: {', '.join([TOOL_NAMES.get(t, t) for t in fpr_issues_med['tool']])}\n")
        f.write(f"   - Thorough: {', '.join([TOOL_NAMES.get(t, t) for t in fpr_issues_thor['tool']])}\n")

        f.write("\n3. **Statistical Consistency**: ")
        # Check if power differences are within expected Monte Carlo variation
        # For 30 vs 100 datasets, we expect SE to be ~1.8x larger for medium
        f.write("To be assessed based on confidence interval overlap.\n")

        f.write("\n4. **Recommendation**: ")
        # Check if medium preset is sufficient
        max_fpr_diff = fpr_summary.groupby("tool").apply(
            lambda x: abs(x[x["data_preset"] == "medium"]["mean_fpr"].values[0] -
                         x[x["data_preset"] == "thorough"]["mean_fpr"].values[0])
            if len(x) == 2 else 0
        ).max()

        if max_fpr_diff < 0.05:
            f.write("Medium preset (30 datasets) appears sufficient for reliable conclusions. "
                   "Max FPR difference < 5% across tools.\n")
        else:
            f.write(f"Medium preset may be insufficient. Max FPR difference = {max_fpr_diff:.3f}. "
                   "Consider thorough preset for final results.\n")

        f.write("\n---\n\n")
        f.write("## Detailed Analysis\n\n")
        f.write("See generated figures in `outputs/comparison_medium_vs_thorough/`:\n\n")
        f.write("- `fpr_comparison.png` - FPR heatmaps side-by-side\n")
        f.write("- `power_comparison_*.png` - Power heatmaps for different effect sizes\n")
        f.write("- `power_curves_*.png` - Power curves for different noise models\n")

    print(f"\nReport saved to: {output_path}")

def main():
    print("="*60)
    print("COMPARING MEDIUM VS THOROUGH BENCHMARKS")
    print("="*60)

    # Load data
    print("\nLoading data...")
    medium_results, medium_summary = load_data(MEDIUM_DIR, "medium")
    thorough_results, thorough_summary = load_data(THOROUGH_DIR, "thorough")

    print(f"  Medium: {len(medium_results):,} tests")
    print(f"  Thorough: {len(thorough_results):,} tests")

    # Combine datasets
    all_results = pd.concat([medium_results, thorough_results], ignore_index=True)
    all_summary = pd.concat([medium_summary, thorough_summary], ignore_index=True)

    # Calculate FPR
    print("\nCalculating false positive rates...")
    fpr_data = calculate_fpr(all_results)

    # Calculate power at key effect sizes
    print("Calculating detection power...")
    power_data_list = []
    for effect in [0.2, 1, 2, 4, 20]:
        power = calculate_power(all_results, effect)
        power["effect_size"] = effect
        power_data_list.append(power)
    power_data = pd.concat(power_data_list, ignore_index=True)

    # Generate visualizations
    print("\nGenerating comparison figures...")

    # FPR comparison
    plot_fpr_comparison(fpr_data, OUTPUT_DIR / "fpr_comparison.png")

    # Power comparisons for different effect sizes
    for effect in [1, 2, 4]:
        effect_power = power_data[power_data["effect_size"] == effect]
        plot_power_comparison(effect_power, effect,
                            OUTPUT_DIR / f"power_comparison_{effect}sigma.png")

    # Power curves for selected noise models
    for noise in ["iid", "ar1-0.6", "ar1-n0.3"]:
        # Check if noise model exists in both datasets
        if noise in NOISE_ORDER_MEDIUM or noise in NOISE_ORDER_THOROUGH:
            try:
                plot_power_curves_comparison(all_results, noise, "shift",
                                           OUTPUT_DIR / f"power_curves_{noise}.png")
            except Exception as e:
                print(f"  Skipping {noise}: {e}")

    # Statistical analysis
    analyze_fpr_differences(fpr_data)
    analyze_power_differences(power_data, 1)
    analyze_power_differences(power_data, 2)

    # Generate report
    print("\nGenerating markdown report...")
    generate_markdown_report(fpr_data, power_data,
                           Path("/tmp/medium_vs_thorough_comparison.md"))

    print("\n" + "="*60)
    print("COMPARISON COMPLETE")
    print("="*60)
    print(f"\nAll outputs saved to: {OUTPUT_DIR}")
    print("Report saved to: /tmp/medium_vs_thorough_comparison.md")

if __name__ == "__main__":
    main()
