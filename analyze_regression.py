#!/usr/bin/env python3
"""Analyze regression in tacet benchmark results after Geyer's IMS switch."""

import pandas as pd
import numpy as np
from pathlib import Path

# Load data
old_results = pd.read_csv('/Users/agucova/repos/tacet/results/medium-v2/benchmark_results.csv')
new_results = pd.read_csv('/Users/agucova/repos/tacet/results/medium-aws/benchmark_results.csv')

print("=" * 80)
print("REGRESSION ANALYSIS: PolitisWhite → Geyer's IMS")
print("=" * 80)

# Filter for tacet results only
old_tacet = old_results[old_results['tool'] == 'tacet'].copy()
new_tacet = new_results[new_results['tool'] == 'tacet'].copy()

print(f"\nOld results (PolitisWhite): {len(old_tacet)} rows")
print(f"New results (Geyer's IMS): {len(new_tacet)} rows")

# Parse outcome field to get more details
def parse_outcome(outcome_str):
    """Extract outcome type and reason from outcome string."""
    if pd.isna(outcome_str):
        return 'Unknown', None
    if outcome_str.startswith('Pass'):
        return 'Pass', None
    elif outcome_str.startswith('Fail'):
        return 'Fail', None
    elif outcome_str.startswith('Inconclusive:'):
        reason = outcome_str.split(':', 1)[1].strip()
        return 'Inconclusive', reason
    elif outcome_str.startswith('Unmeasurable'):
        return 'Unmeasurable', None
    return 'Unknown', None

old_tacet[['outcome_type', 'inconclusive_reason']] = old_tacet['outcome'].apply(
    lambda x: pd.Series(parse_outcome(x))
)
new_tacet[['outcome_type', 'inconclusive_reason']] = new_tacet['outcome'].apply(
    lambda x: pd.Series(parse_outcome(x))
)

print("\n" + "=" * 80)
print("OUTCOME DISTRIBUTION")
print("=" * 80)

print("\nOld (PolitisWhite):")
print(old_tacet['outcome_type'].value_counts())

print("\nNew (Geyer's IMS):")
print(new_tacet['outcome_type'].value_counts())

print("\n" + "=" * 80)
print("INCONCLUSIVE REASONS")
print("=" * 80)

print("\nOld (PolitisWhite):")
old_inconclusive = old_tacet[old_tacet['outcome_type'] == 'Inconclusive']
if len(old_inconclusive) > 0:
    print(old_inconclusive['inconclusive_reason'].value_counts())
else:
    print("No Inconclusive outcomes")

print("\nNew (Geyer's IMS):")
new_inconclusive = new_tacet[new_tacet['outcome_type'] == 'Inconclusive']
if len(new_inconclusive) > 0:
    print(new_inconclusive['inconclusive_reason'].value_counts())
else:
    print("No Inconclusive outcomes")

# Compare detection rates by condition
print("\n" + "=" * 80)
print("DETECTION RATE COMPARISON")
print("=" * 80)

def compute_detection_rate(df):
    """Compute detection rate (Pass + Fail) / Total."""
    total = len(df)
    if total == 0:
        return 0.0
    detected = len(df[df['detected'] == True])
    return detected / total

# Group by key conditions
groupby_cols = ['effect_pattern', 'effect_sigma_mult', 'noise_model', 'attacker_threshold_ns']

old_grouped = old_tacet.groupby(groupby_cols).agg({
    'detected': ['sum', 'count'],
}).reset_index()
old_grouped.columns = groupby_cols + ['detected_count', 'total_count']
old_grouped['detection_rate_old'] = old_grouped['detected_count'] / old_grouped['total_count']

new_grouped = new_tacet.groupby(groupby_cols).agg({
    'detected': ['sum', 'count'],
}).reset_index()
new_grouped.columns = groupby_cols + ['detected_count', 'total_count']
new_grouped['detection_rate_new'] = new_grouped['detected_count'] / new_grouped['total_count']

# Merge and compute delta
comparison = old_grouped.merge(
    new_grouped[groupby_cols + ['detection_rate_new']],
    on=groupby_cols,
    how='outer'
).fillna(0)

comparison['delta'] = comparison['detection_rate_new'] - comparison['detection_rate_old']

# Show biggest regressions
print("\nTop 20 BIGGEST REGRESSIONS (sorted by delta):")
print("=" * 80)
regressions = comparison[comparison['delta'] < -0.1].sort_values('delta')
if len(regressions) > 0:
    for _, row in regressions.head(20).iterrows():
        print(f"\nEffect: {row['effect_pattern']}, Mult: {row['effect_sigma_mult']:.1f}, "
              f"Noise: {row['noise_model']}, Threshold: {row['attacker_threshold_ns']:.1f}ns")
        print(f"  Old: {row['detection_rate_old']:.3f} → New: {row['detection_rate_new']:.3f} "
              f"(Δ = {row['delta']:+.3f})")
else:
    print("No significant regressions found (delta < -0.1)")

# Focus on specific known regression case
print("\n" + "=" * 80)
print("DETAILED ANALYSIS: effect_mult=0.2, noise=ar1-n0.6, threshold=0.4")
print("=" * 80)

old_case = old_tacet[
    (old_tacet['effect_sigma_mult'] == 0.2) &
    (old_tacet['noise_model'] == 'ar1-n0.6') &
    (old_tacet['attacker_threshold_ns'] == 0.4)
]

new_case = new_tacet[
    (new_tacet['effect_sigma_mult'] == 0.2) &
    (new_tacet['noise_model'] == 'ar1-n0.6') &
    (new_tacet['attacker_threshold_ns'] == 0.4)
]

print(f"\nOld: {len(old_case)} samples")
print(old_case['outcome_type'].value_counts())
if 'p_value' in old_case.columns:
    print(f"P-value range: {old_case['p_value'].min():.4f} - {old_case['p_value'].max():.4f}")
    print(f"P-value mean: {old_case['p_value'].mean():.4f}")

print(f"\nNew: {len(new_case)} samples")
print(new_case['outcome_type'].value_counts())
if 'p_value' in new_case.columns:
    print(f"P-value range: {new_case['p_value'].min():.4f} - {new_case['p_value'].max():.4f}")
    print(f"P-value mean: {new_case['p_value'].mean():.4f}")

# Check samples_used distribution for Inconclusive outcomes
print("\n" + "=" * 80)
print("SAMPLES USED ANALYSIS")
print("=" * 80)

print("\nNew Inconclusive outcomes - samples_used distribution:")
if len(new_inconclusive) > 0:
    print(f"Mean: {new_inconclusive['samples_used'].mean():.0f}")
    print(f"Median: {new_inconclusive['samples_used'].median():.0f}")
    print(f"Max: {new_inconclusive['samples_used'].max():.0f}")
    print(f"Min: {new_inconclusive['samples_used'].min():.0f}")

    # Check if hitting sample budget
    sample_budget_hits = new_inconclusive[new_inconclusive['inconclusive_reason'] == 'SampleBudgetExceeded']
    print(f"\nSampleBudgetExceeded: {len(sample_budget_hits)} / {len(new_inconclusive)} "
          f"({100*len(sample_budget_hits)/len(new_inconclusive):.1f}%)")

# Check p_value distribution for Inconclusive outcomes
print("\n" + "=" * 80)
print("P-VALUE ANALYSIS FOR INCONCLUSIVE OUTCOMES")
print("=" * 80)

if len(new_inconclusive) > 0 and 'p_value' in new_inconclusive.columns:
    print("\nNew Inconclusive p_value distribution:")
    # Note: p_value in tacet output is leak_probability (P(leak > θ | data))
    pvals = new_inconclusive['p_value'].dropna()
    if len(pvals) > 0:
        print(f"Mean: {pvals.mean():.4f}")
        print(f"Median: {pvals.median():.4f}")
        print(f"Std: {pvals.std():.4f}")
        print(f"\nDistribution:")
        print(f"  < 0.50: {(pvals < 0.50).sum()} ({100*(pvals < 0.50).sum()/len(pvals):.1f}%)")
        print(f"  0.50-0.80: {((pvals >= 0.50) & (pvals < 0.80)).sum()} ({100*((pvals >= 0.50) & (pvals < 0.80)).sum()/len(pvals):.1f}%)")
        print(f"  0.80-0.90: {((pvals >= 0.80) & (pvals < 0.90)).sum()} ({100*((pvals >= 0.80) & (pvals < 0.90)).sum()/len(pvals):.1f}%)")
        print(f"  0.90-0.95: {((pvals >= 0.90) & (pvals < 0.95)).sum()} ({100*((pvals >= 0.90) & (pvals < 0.95)).sum()/len(pvals):.1f}%)")
        print(f"  >= 0.95: {(pvals >= 0.95).sum()} ({100*(pvals >= 0.95).sum()/len(pvals):.1f}%)")

# Summary by noise model
print("\n" + "=" * 80)
print("DETECTION RATE BY NOISE MODEL")
print("=" * 80)

for noise in ['iid', 'ar1-n0.3', 'ar1-n0.6', 'ar1-n0.9']:
    old_noise = old_tacet[old_tacet['noise_model'] == noise]
    new_noise = new_tacet[new_tacet['noise_model'] == noise]

    old_rate = compute_detection_rate(old_noise)
    new_rate = compute_detection_rate(new_noise)

    print(f"\n{noise:12s}: Old={old_rate:.3f}, New={new_rate:.3f}, Δ={new_rate-old_rate:+.3f}")

    # Show outcome breakdown
    print(f"  Old: {old_noise['outcome_type'].value_counts().to_dict()}")
    print(f"  New: {new_noise['outcome_type'].value_counts().to_dict()}")

print("\n" + "=" * 80)
print("END OF ANALYSIS")
print("=" * 80)
