#!/usr/bin/env python3
"""Main entry point for tacet benchmark data analysis.

Usage:
    uv run python run_analysis.py [--checks-only] [--figures-only]
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from tacet_analysis.data import load_benchmark_data, load_summary_data, load_thorough_data, load_thorough_summary
from tacet_analysis.robustness import print_check_results, run_all_checks
from tacet_analysis.charts import (
    generate_all_figures,
    plot_fpr_grouped_bars,
    plot_power_curves_dual_panel,
    plot_verdict_breakdown,
    plot_fpr_heatmap_v3,
    plot_power_heatmap_v3,
    plot_power_heatmap_v3_trimodal,
    plot_tail_power_curve_v3,
    plot_fpr_small_multiples,
    plot_fpr_grouped_bars_stages,
    plot_fpr_heatmap_seaborn,
    print_ablation_summary,
)
from tacet_analysis.utils import FIGURES_DIR, OUTPUT_DIR


def main():
    parser = argparse.ArgumentParser(description="Analyze tacet benchmark data")
    parser.add_argument("--checks-only", action="store_true", help="Only run robustness checks")
    parser.add_argument("--figures-only", action="store_true", help="Only generate figures")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="Output directory")
    args = parser.parse_args()

    print("=" * 60)
    print("TACET BENCHMARK DATA ANALYSIS")
    print(f"Time: {datetime.now().isoformat()}")
    print("=" * 60)

    # Load data
    print("\nLoading data...")
    try:
        raw_df = load_benchmark_data()
        summary_df = load_summary_data()
        print(f"  Raw data: {len(raw_df):,} rows")
        print(f"  Summary data: {len(summary_df):,} rows")
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        print("\nMake sure benchmark data exists at results/medium-v2/")
        sys.exit(1)

    # Run robustness checks
    if not args.figures_only:
        print("\n" + "=" * 60)
        print("ROBUSTNESS CHECKS")
        print("=" * 60)

        results = run_all_checks(raw_df, summary_df)
        print_check_results(results)

        # Write results to file
        report_path = args.output_dir / "robustness_report.txt"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as f:
            f.write("ROBUSTNESS CHECK RESULTS\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")

            for check_name, result in results.items():
                if check_name == "_summary":
                    continue
                status = "PASS" if result["passed"] else "FAIL"
                f.write(f"{check_name}: {status}\n")
                if not result["passed"] and "issues" in result:
                    for issue in result["issues"]:
                        f.write(f"  - {issue}\n")
                f.write("\n")

            summary = results["_summary"]
            f.write(f"\nSUMMARY: {summary['checks_passed']}/{summary['total_checks']} checks passed\n")

        print(f"\nReport saved to: {report_path}")

        if args.checks_only:
            return

    # Generate figures
    if not args.checks_only:
        print("\n" + "=" * 60)
        print("GENERATING FIGURES")
        print("=" * 60)

        figures_dir = args.output_dir / "figures"
        figures = generate_all_figures(raw_df, summary_df, figures_dir)

        print(f"\nGenerated {len(figures)} figures:")
        for name in figures:
            print(f"  - {name}")

    # Generate new paper figures (v2) from thorough dataset
    if not args.checks_only:
        print("\n" + "=" * 60)
        print("GENERATING NEW PAPER FIGURES (v2)")
        print("=" * 60)

        try:
            thorough_raw = load_thorough_data()
            thorough_summary = load_thorough_summary()
            print(f"  Thorough raw data: {len(thorough_raw):,} rows")
            print(f"  Thorough summary data: {len(thorough_summary):,} rows")

            figures_dir = args.output_dir / "figures"

            print("\n  Generating v2-fig1: FPR grouped bars...")
            plot_fpr_grouped_bars(
                thorough_raw,
                output_path=figures_dir / "v2-fig1_fpr_grouped_bars.png",
            )

            print("  Generating v2-fig2: power curves dual panel...")
            plot_power_curves_dual_panel(
                thorough_summary,
                output_path=figures_dir / "v2-fig2_power_dual_panel.png",
            )

            print("  Generating v2-fig3: verdict breakdown...")
            plot_verdict_breakdown(
                thorough_raw,
                output_path=figures_dir / "v2-fig3_verdict_breakdown.png",
            )

            print("\n  v2 figures saved to:", figures_dir)

            # v3 figures (original chart types with targeted fixes)
            print("\n" + "=" * 60)
            print("GENERATING v3 FIGURES (original types, minimal fixes)")
            print("=" * 60)

            print("\n  Generating v3-fig1: FPR heatmap (with annotations)...")
            plot_fpr_heatmap_v3(
                thorough_raw,
                output_path=figures_dir / "v3-fig1_fpr_heatmap.png",
            )

            print("  Generating v3-fig2: power heatmap (shift + tail)...")
            plot_power_heatmap_v3(
                thorough_raw,
                output_path=figures_dir / "v3-fig2_power_heatmap_dual.png",
            )

            print("  Generating v3-fig3: tail power curve (fixed axis + ns)...")
            plot_tail_power_curve_v3(
                thorough_summary,
                noise_model="iid",  # Use i.i.d. for cleaner visualization
                output_path=figures_dir / "v3-fig3_tail_power_curve.png",
            )

            print("\n  v3 figures saved to:", figures_dir)

            # Experimental: v3-fig2 with bimodal
            print("\n" + "=" * 60)
            print("GENERATING EXPERIMENTAL FIGURE (v3-fig2 with bimodal)")
            print("=" * 60)

            print("\n  Generating v3-fig2-experimental: power heatmap (shift + tail + bimodal)...")
            plot_power_heatmap_v3_trimodal(
                thorough_raw,
                output_path=figures_dir / "v3-fig2-experimental_with_bimodal.png",
            )

            print("\n  Experimental figure saved to:", figures_dir)

            # v4 figures (alternative autocorrelation visualizations)
            print("\n" + "=" * 60)
            print("GENERATING v4 FIGURES (alternative autocorrelation viz)")
            print("=" * 60)

            print("\n  Generating v4-fig1: small multiples (sparkline grid)...")
            plot_fpr_small_multiples(
                thorough_raw,
                output_path=figures_dir / "v4-fig1_fpr_small_multiples.png",
            )

            print("  Generating v4-fig2: grouped bars (3 stages)...")
            plot_fpr_grouped_bars_stages(
                thorough_raw,
                output_path=figures_dir / "v4-fig2_fpr_grouped_bars_stages.png",
            )

            print("  Generating v4-fig3: seaborn FPR heatmap (EDA-style)...")
            plot_fpr_heatmap_seaborn(
                thorough_raw,
                output_path=figures_dir / "v4-fig3_fpr_heatmap_seaborn.png",
            )

            print("\n  v4 figures saved to:", figures_dir)

        except FileNotFoundError as e:
            print(f"\n  WARNING: Could not generate v2/v3/v4 figures: {e}")
            print("  Thorough dataset not found. Skipping v2/v3/v4 figures.")

    # Ablation study summaries (for paper verification)
    print_ablation_summary()

    # Generate summary report
    print("\n" + "=" * 60)
    print("SUMMARY STATISTICS")
    print("=" * 60)

    # Key metrics
    print("\nFalse Positive Rates (effect=0σ, shift pattern):")
    fpr_df = summary_df[
        (summary_df["effect_sigma_mult"] == 0)
        & (summary_df["effect_pattern"] == "shift")
    ]

    # For tacet, show 100ns threshold
    tacet_fpr = fpr_df[(fpr_df["tool"] == "tacet") & (fpr_df["attacker_threshold_ns"] == 100)]
    non_tacet_fpr = fpr_df[fpr_df["tool"] != "tacet"]
    fpr_display = pd.concat([non_tacet_fpr, tacet_fpr])

    fpr_summary = fpr_display.groupby("tool")["detection_rate"].agg(["mean", "max"]).round(3)
    fpr_summary.columns = ["Mean FPR", "Max FPR"]
    print(fpr_summary.to_string())

    print("\nDetection Power at 1σ effect (shift pattern, iid noise):")
    power_df = summary_df[
        (summary_df["effect_sigma_mult"] == 1)
        & (summary_df["effect_pattern"] == "shift")
        & (summary_df["noise_model"] == "iid")
    ]

    tacet_power = power_df[(power_df["tool"] == "tacet") & (power_df["attacker_threshold_ns"] == 100)]
    non_tacet_power = power_df[power_df["tool"] != "tacet"]
    power_display = pd.concat([non_tacet_power, tacet_power])

    print(power_display[["tool", "detection_rate"]].to_string(index=False))

    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    import pandas as pd
    main()
