#!/usr/bin/env python3
"""Final analysis of tacet regression."""

import pandas as pd
import numpy as np

# Load summaries
old_summary = pd.read_csv('/Users/agucova/repos/tacet/results/medium-v2/benchmark_summary.csv')
new_summary = pd.read_csv('/Users/agucova/repos/tacet/results/medium-aws/benchmark_summary.csv')

# Filter for tacet only
old_tacet = old_summary[old_summary['tool'] == 'tacet'].copy()
new_tacet = new_summary[new_summary['tool'] == 'tacet'].copy()

print("=" * 80)
print("FINAL REGRESSION ANALYSIS")
print("=" * 80)

# Check unique thresholds
print("\nUnique thresholds in old:", sorted(old_tacet['attacker_threshold_ns'].unique()))
print("Unique thresholds in new:", sorted(new_tacet['attacker_threshold_ns'].unique()))

# Focus on "tail" pattern only
old_tail = old_tacet[old_tacet['effect_pattern'] == 'tail'].copy()
new_tail = new_tacet[new_tacet['effect_pattern'] == 'tail'].copy()

print(f"\n{len(old_tail)} old tail tests")
print(f"{len(new_tail)} new tail tests")

# The new dataset has 2x rows because it tests both threshold=0.4 and threshold=100
# So we should compare apples-to-apples: threshold=0.4 only

old_tail_04 = old_tail[old_tail['attacker_threshold_ns'] == 0.4]
new_tail_04 = new_tail[new_tail['attacker_threshold_ns'] == 0.4]

print(f"\n{len(old_tail_04)} old tail tests at threshold=0.4")
print(f"{len(new_tail_04)} new tail tests at threshold=0.4")

# Merge on conditions
merge_cols = ['effect_pattern', 'effect_sigma_mult', 'noise_model', 'attacker_threshold_ns']

comparison = old_tail_04.merge(
    new_tail_04,
    on=merge_cols,
    how='outer',
    suffixes=('_old', '_new')
)

comparison['detection_delta'] = comparison['detection_rate_new'] - comparison['detection_rate_old']

print("\n" + "=" * 80)
print("TAIL PATTERN REGRESSIONS (threshold=0.4ns)")
print("=" * 80)

# Show all non-zero changes
changes = comparison[comparison['detection_delta'].abs() > 0.001].sort_values('detection_delta')

if len(changes) > 0:
    print(f"\n{len(changes)} cases with changed detection rate:\n")
    for _, row in changes.iterrows():
        print(f"Effect={row['effect_sigma_mult']:4.1f}σ Noise={row['noise_model']:12s}: "
              f"{row['detection_rate_old']:.2%} → {row['detection_rate_new']:.2%} "
              f"(Δ = {row['detection_delta']:+.2%})")
else:
    print("\nNO CHANGES in tail pattern detection rates at threshold=0.4")

# Now check if the issue is that new tests include tail+threshold=100 which wasn't in old
new_tail_100 = new_tail[new_tail['attacker_threshold_ns'] == 100]

print("\n" + "=" * 80)
print("NEW TESTS: tail pattern at threshold=100ns (didn't exist in old)")
print("=" * 80)

print(f"\n{len(new_tail_100)} new tests at threshold=100ns")

# Group by effect size
for effect in sorted(new_tail_100['effect_sigma_mult'].unique()):
    effect_rows = new_tail_100[new_tail_100['effect_sigma_mult'] == effect]
    mean_rate = effect_rows['detection_rate'].mean()
    print(f"\nEffect {effect:4.1f}σ: mean detection rate = {mean_rate:.2%}")
    for _, row in effect_rows.iterrows():
        print(f"  {row['noise_model']:12s}: {row['detection_rate']:.2%}")

# Check shift pattern for sanity
print("\n" + "=" * 80)
print("SANITY CHECK: shift pattern (should be unchanged)")
print("=" * 80)

old_shift = old_tacet[old_tacet['effect_pattern'] == 'shift'].copy()
new_shift = new_tacet[new_tacet['effect_pattern'] == 'shift'].copy()

old_shift_04 = old_shift[old_shift['attacker_threshold_ns'] == 0.4]
new_shift_04 = new_shift[new_shift['attacker_threshold_ns'] == 0.4]

shift_comp = old_shift_04.merge(
    new_shift_04,
    on=merge_cols,
    how='inner',
    suffixes=('_old', '_new')
)

shift_comp['detection_delta'] = shift_comp['detection_rate_new'] - shift_comp['detection_rate_old']

changes_shift = shift_comp[shift_comp['detection_delta'].abs() > 0.001]

if len(changes_shift) > 0:
    print(f"\nWARNING: {len(changes_shift)} shift pattern cases changed (unexpected!)")
    for _, row in changes_shift.head(10).iterrows():
        print(f"  Effect={row['effect_sigma_mult']:4.1f}σ Noise={row['noise_model']:12s}: "
              f"{row['detection_rate_old']:.2%} → {row['detection_rate_new']:.2%}")
else:
    print("\nGOOD: No changes in shift pattern (as expected)")

print("\n" + "=" * 80)
print("END OF ANALYSIS")
print("=" * 80)
