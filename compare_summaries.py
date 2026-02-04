#!/usr/bin/env python3
"""Compare old vs new benchmark summaries to find regressions."""

import pandas as pd
import numpy as np

# Load summaries
old_summary = pd.read_csv('/Users/agucova/repos/tacet/results/medium-v2/benchmark_summary.csv')
new_summary = pd.read_csv('/Users/agucova/repos/tacet/results/medium-aws/benchmark_summary.csv')

# Filter for tacet only
old_tacet = old_summary[old_summary['tool'] == 'tacet'].copy()
new_tacet = new_summary[new_summary['tool'] == 'tacet'].copy()

print("=" * 80)
print("SUMMARY COMPARISON: OLD vs NEW")
print("=" * 80)

print(f"\nOld summary: {len(old_tacet)} tacet rows")
print(f"New summary: {len(new_tacet)} tacet rows")

# Merge on all condition columns
merge_cols = ['effect_pattern', 'effect_sigma_mult', 'noise_model', 'attacker_threshold_ns']

comparison = old_tacet.merge(
    new_tacet,
    on=merge_cols,
    how='outer',
    suffixes=('_old', '_new')
)

# Focus on cases with effect > 0
leak_cases = comparison[comparison['effect_sigma_mult'] > 0].copy()

# Compute delta
leak_cases['detection_delta'] = leak_cases['detection_rate_new'] - leak_cases['detection_rate_old']

# Show largest regressions
print("\n" + "=" * 80)
print("TOP 20 LARGEST REGRESSIONS (by detection_delta)")
print("=" * 80)

regressions = leak_cases[leak_cases['detection_delta'] < -0.05].sort_values('detection_delta')

if len(regressions) > 0:
    print(f"\nFound {len(regressions)} cases with >5% detection rate drop\n")
    for _, row in regressions.head(20).iterrows():
        print(f"{row['effect_pattern']:8s} effect={row['effect_sigma_mult']:4.1f}σ "
              f"noise={row['noise_model']:12s} threshold={row['attacker_threshold_ns']:.0f}ns: "
              f"  {row['detection_rate_old']:.2%} → {row['detection_rate_new']:.2%} "
              f"(Δ = {row['detection_delta']:+.2%})")
else:
    print("No regressions found with >5% detection rate drop")

# Check improvements too
print("\n" + "=" * 80)
print("TOP 10 IMPROVEMENTS (by detection_delta)")
print("=" * 80)

improvements = leak_cases[leak_cases['detection_delta'] > 0.05].sort_values('detection_delta', ascending=False)

if len(improvements) > 0:
    print(f"\nFound {len(improvements)} cases with >5% detection rate improvement\n")
    for _, row in improvements.head(10).iterrows():
        print(f"{row['effect_pattern']:8s} effect={row['effect_sigma_mult']:4.1f}σ "
              f"noise={row['noise_model']:12s} threshold={row['attacker_threshold_ns']:.0f}ns: "
              f"  {row['detection_rate_old']:.2%} → {row['detection_rate_new']:.2%} "
              f"(Δ = {row['detection_delta']:+.2%})")
else:
    print("No improvements found with >5% detection rate increase")

# Aggregate by effect size
print("\n" + "=" * 80)
print("AGGREGATE BY EFFECT SIZE")
print("=" * 80)

for effect in sorted(leak_cases['effect_sigma_mult'].unique()):
    effect_rows = leak_cases[leak_cases['effect_sigma_mult'] == effect]

    # Only include rows where we have both old and new
    paired = effect_rows[effect_rows['detection_rate_old'].notna() & effect_rows['detection_rate_new'].notna()]

    if len(paired) == 0:
        continue

    old_mean = paired['detection_rate_old'].mean()
    new_mean = paired['detection_rate_new'].mean()

    print(f"\nEffect {effect:4.1f}σ ({len(paired)} conditions):")
    print(f"  Old mean: {old_mean:.2%}")
    print(f"  New mean: {new_mean:.2%}")
    print(f"  Delta: {new_mean - old_mean:+.2%}")

# Focus on threshold=0.4 specifically (SharedHardware)
print("\n" + "=" * 80)
print("THRESHOLD = 0.4ns (SharedHardware) ANALYSIS")
print("=" * 80)

threshold_04 = leak_cases[leak_cases['attacker_threshold_ns'] == 0.4].copy()
paired_04 = threshold_04[threshold_04['detection_rate_old'].notna() & threshold_04['detection_rate_new'].notna()]

if len(paired_04) > 0:
    print(f"\n{len(paired_04)} conditions at threshold=0.4ns")

    # Group by effect size
    for effect in sorted(paired_04['effect_sigma_mult'].unique()):
        effect_rows = paired_04[paired_04['effect_sigma_mult'] == effect]

        old_mean = effect_rows['detection_rate_old'].mean()
        new_mean = effect_rows['detection_rate_new'].mean()

        print(f"\n  Effect {effect:4.1f}σ ({len(effect_rows)} noise models):")
        print(f"    Old mean: {old_mean:.2%}")
        print(f"    New mean: {new_mean:.2%}")
        print(f"    Delta: {new_mean - old_mean:+.2%}")

        # Show individual noise models
        for _, row in effect_rows.iterrows():
            print(f"      {row['noise_model']:12s}: {row['detection_rate_old']:.2%} → {row['detection_rate_new']:.2%} "
                  f"(Δ = {row['detection_delta']:+.2%})")

print("\n" + "=" * 80)
print("END OF COMPARISON")
print("=" * 80)
