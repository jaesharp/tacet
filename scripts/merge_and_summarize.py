#!/usr/bin/env python3
"""Merge tacet benchmark results into a multi-tool thorough run and regenerate summary CSV.

Usage:
    python scripts/merge_and_summarize.py \
        --base results/thorough-post-bugfix-merged \
        --tacet results/thorough-null-var-floor \
        --output results/thorough-final-merged

This script:
1. Reads the base multi-tool results (non-tacet tools)
2. Reads the new tacet-only results
3. Merges them into a single benchmark_results.csv
4. Generates a benchmark_summary.csv with Wilson CIs
"""

import argparse
import math
import sys
from pathlib import Path

import pandas as pd


def wilson_ci(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for a proportion."""
    if total == 0:
        return (0.0, 1.0)
    n = float(total)
    p_hat = successes / n
    z2 = z * z
    center = (p_hat + z2 / (2 * n)) / (1 + z2 / n)
    margin = (z / (1 + z2 / n)) * math.sqrt(p_hat * (1 - p_hat) / n + z2 / (4 * n * n))
    return (max(0.0, center - margin), min(1.0, center + margin))


def generate_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Generate summary CSV matching the Rust write_summary_csv format.

    Groups by (tool, effect_pattern, effect_sigma_mult, noise_model, attacker_threshold_ns)
    and computes detection_rate, Wilson CIs, median_time_ms, median_samples.
    """
    group_cols = ["tool", "effect_pattern", "effect_sigma_mult", "noise_model", "attacker_threshold_ns"]

    rows = []
    for keys, group in df.groupby(group_cols, dropna=False):
        tool, pattern, mult, noise, threshold = keys
        n = len(group)
        detected = int(group["detected"].sum())
        rate = detected / n if n > 0 else 0.0
        ci_low, ci_high = wilson_ci(detected, n)

        times = group["time_ms"].sort_values()
        median_time = int(times.iloc[len(times) // 2]) if len(times) > 0 else 0

        samples = group["samples_used"].dropna()
        if len(samples) > 0:
            sorted_samples = samples.sort_values()
            median_samples = int(sorted_samples.iloc[len(sorted_samples) // 2])
        else:
            median_samples = None

        rows.append({
            "tool": tool,
            "effect_pattern": pattern,
            "effect_sigma_mult": mult,
            "noise_model": noise,
            "attacker_threshold_ns": threshold if pd.notna(threshold) else "",
            "n_datasets": n,
            "detection_rate": f"{rate:.4f}",
            "ci_low": f"{ci_low:.4f}",
            "ci_high": f"{ci_high:.4f}",
            "median_time_ms": median_time,
            "median_samples": median_samples if median_samples is not None else "",
        })

    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser(description="Merge tacet results into multi-tool benchmark")
    parser.add_argument("--base", type=Path, required=True, help="Base multi-tool results directory")
    parser.add_argument("--tacet", type=Path, required=True, help="New tacet-only results directory")
    parser.add_argument("--output", type=Path, required=True, help="Output directory for merged results")
    args = parser.parse_args()

    # Validate inputs
    base_csv = args.base / "benchmark_results.csv"
    tacet_csv = args.tacet / "benchmark_results.csv"
    if not base_csv.exists():
        print(f"ERROR: Base results not found at {base_csv}", file=sys.stderr)
        sys.exit(1)
    if not tacet_csv.exists():
        print(f"ERROR: Tacet results not found at {tacet_csv}", file=sys.stderr)
        sys.exit(1)

    # Load data
    print(f"Loading base results from {base_csv}...")
    base_df = pd.read_csv(base_csv)
    print(f"  {len(base_df):,} rows, tools: {sorted(base_df['tool'].unique())}")

    print(f"Loading tacet results from {tacet_csv}...")
    tacet_df = pd.read_csv(tacet_csv)
    print(f"  {len(tacet_df):,} rows, tools: {sorted(tacet_df['tool'].unique())}")

    # Remove old tacet rows from base
    non_tacet = base_df[base_df["tool"] != "tacet"]
    print(f"  Non-tacet rows from base: {len(non_tacet):,}")

    # Ensure column compatibility
    base_cols = set(base_df.columns)
    tacet_cols = set(tacet_df.columns)
    if base_cols != tacet_cols:
        missing_in_tacet = base_cols - tacet_cols
        missing_in_base = tacet_cols - base_cols
        if missing_in_tacet:
            print(f"  WARNING: Columns in base but not tacet: {missing_in_tacet}")
        if missing_in_base:
            print(f"  WARNING: Columns in tacet but not base: {missing_in_base}")

    # Merge
    merged = pd.concat([non_tacet, tacet_df], ignore_index=True)
    print(f"\nMerged: {len(merged):,} rows, tools: {sorted(merged['tool'].unique())}")

    # Write output
    args.output.mkdir(parents=True, exist_ok=True)
    merged_csv = args.output / "benchmark_results.csv"
    merged.to_csv(merged_csv, index=False)
    print(f"Wrote merged results to {merged_csv}")

    # Generate summary
    print("Generating summary...")
    summary = generate_summary(merged)
    summary_csv = args.output / "benchmark_summary.csv"
    summary.to_csv(summary_csv, index=False)
    print(f"Wrote summary ({len(summary)} rows) to {summary_csv}")

    # Quick sanity check
    print("\n--- Quick FPR check (effect=0, shift pattern) ---")
    null_shift = merged[(merged["effect_sigma_mult"] == 0) & (merged["effect_pattern"] == "shift")]
    for tool in sorted(null_shift["tool"].unique()):
        tool_data = null_shift[null_shift["tool"] == tool]
        n = len(tool_data)
        fails = (tool_data["outcome"] == "fail").sum()
        fpr = fails / n if n > 0 else 0
        print(f"  {tool:<20s}: {fails}/{n} = {fpr:.1%}")


if __name__ == "__main__":
    main()
