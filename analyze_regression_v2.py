#!/usr/bin/env python3
"""Detailed regression analysis for tacet benchmark results."""

import pandas as pd
import numpy as np
from pathlib import Path

# Load data
old_results = pd.read_csv('/Users/agucova/repos/tacet/results/medium-v2/benchmark_results.csv')
new_results = pd.read_csv('/Users/agucova/repos/tacet/results/medium-aws/benchmark_results.csv')

# Filter for tacet only
old_tacet = old_results[old_results['tool'] == 'tacet'].copy()
new_tacet = new_results[new_results['tool'] == 'tacet'].copy()

print("=" * 80)
print("TACET REGRESSION ANALYSIS: PolitisWhite → Geyer's IMS")
print("=" * 80)
print(f"\nOld results: {len(old_tacet)} rows")
print(f"New results: {len(new_tacet)} rows")

# Parse outcome status
def parse_status(status):
    if pd.isna(status):
        return 'unknown'
    return status.lower()

old_tacet['status_clean'] = old_tacet['status'].apply(parse_status)
new_tacet['status_clean'] = new_tacet['status'].apply(parse_status)

print("\n" + "=" * 80)
print("OVERALL STATUS DISTRIBUTION")
print("=" * 80)

print("\nOld (PolitisWhite):")
print(old_tacet['status_clean'].value_counts())

print("\nNew (Geyer's IMS):")
print(new_tacet['status_clean'].value_counts())

# Parse inconclusive reasons from outcome field
def parse_inconclusive_reason(outcome):
    if pd.isna(outcome):
        return None
    if 'ThresholdElevated' in outcome:
        return 'ThresholdElevated'
    elif 'SampleBudgetExceeded' in outcome:
        return 'SampleBudgetExceeded'
    elif 'TimeBudgetExceeded' in outcome:
        return 'TimeBudgetExceeded'
    elif 'DataTooNoisy' in outcome:
        return 'DataTooNoisy'
    elif 'NotLearning' in outcome:
        return 'NotLearning'
    elif 'WouldTakeTooLong' in outcome:
        return 'WouldTakeTooLong'
    elif 'ConditionsChanged' in outcome:
        return 'ConditionsChanged'
    return None

old_tacet['inconclusive_reason'] = old_tacet['outcome'].apply(parse_inconclusive_reason)
new_tacet['inconclusive_reason'] = new_tacet['outcome'].apply(parse_inconclusive_reason)

print("\n" + "=" * 80)
print("INCONCLUSIVE BREAKDOWN")
print("=" * 80)

old_inc = old_tacet[old_tacet['status_clean'] == 'inconclusive']
new_inc = new_tacet[new_tacet['status_clean'] == 'inconclusive']

print(f"\nOld Inconclusive: {len(old_inc)} / {len(old_tacet)} ({100*len(old_inc)/len(old_tacet):.1f}%)")
if len(old_inc) > 0:
    print(old_inc['inconclusive_reason'].value_counts())

print(f"\nNew Inconclusive: {len(new_inc)} / {len(new_tacet)} ({100*len(new_inc)/len(new_tacet):.1f}%)")
if len(new_inc) > 0:
    print(new_inc['inconclusive_reason'].value_counts())

# Focus on cases with actual leaks (effect > 0)
print("\n" + "=" * 80)
print("LEAK DETECTION PERFORMANCE (effect_sigma_mult > 0)")
print("=" * 80)

old_leak = old_tacet[old_tacet['effect_sigma_mult'] > 0]
new_leak = new_tacet[new_tacet['effect_sigma_mult'] > 0]

print(f"\nOld: {len(old_leak)} test cases with leaks")
print(old_leak['status_clean'].value_counts())

print(f"\nNew: {len(new_leak)} test cases with leaks")
print(new_leak['status_clean'].value_counts())

# Detection rate by effect size and noise
print("\n" + "=" * 80)
print("DETECTION RATE BY EFFECT SIZE AND NOISE MODEL")
print("=" * 80)

def compute_stats(df, name):
    """Compute detection statistics."""
    total = len(df)
    if total == 0:
        return None

    detected = len(df[df['detected'] == True])
    passed = len(df[df['status_clean'] == 'pass'])
    failed = len(df[df['status_clean'] == 'fail'])
    inconclusive = len(df[df['status_clean'] == 'inconclusive'])

    return {
        'name': name,
        'total': total,
        'detected': detected,
        'passed': passed,
        'failed': failed,
        'inconclusive': inconclusive,
        'detection_rate': detected / total,
        'inconclusive_rate': inconclusive / total
    }

# Compare by effect size
for effect in sorted(old_leak['effect_sigma_mult'].unique()):
    if effect == 0:
        continue

    print(f"\n{'='*80}")
    print(f"EFFECT SIZE = {effect}σ")
    print('='*80)

    old_effect = old_leak[old_leak['effect_sigma_mult'] == effect]
    new_effect = new_leak[new_leak['effect_sigma_mult'] == effect]

    # Overall for this effect size
    old_stats = compute_stats(old_effect, 'Old')
    new_stats = compute_stats(new_effect, 'New')

    if old_stats and new_stats:
        print(f"\nOverall:")
        print(f"  Old: {old_stats['detected']}/{old_stats['total']} detected ({old_stats['detection_rate']:.2%}), "
              f"{old_stats['inconclusive']} inconclusive ({old_stats['inconclusive_rate']:.2%})")
        print(f"  New: {new_stats['detected']}/{new_stats['total']} detected ({new_stats['detection_rate']:.2%}), "
              f"{new_stats['inconclusive']} inconclusive ({new_stats['inconclusive_rate']:.2%})")
        print(f"  Δ detection: {new_stats['detection_rate'] - old_stats['detection_rate']:+.2%}")
        print(f"  Δ inconclusive: {new_stats['inconclusive_rate'] - old_stats['inconclusive_rate']:+.2%}")

    # By noise model
    for noise in ['iid', 'ar1-n0.3', 'ar1-n0.6', 'ar1-0.3', 'ar1-0.6', 'ar1-0.8']:
        old_noise = old_effect[old_effect['noise_model'] == noise]
        new_noise = new_effect[new_effect['noise_model'] == noise]

        if len(old_noise) == 0 and len(new_noise) == 0:
            continue

        old_n_stats = compute_stats(old_noise, 'Old')
        new_n_stats = compute_stats(new_noise, 'New')

        if old_n_stats and new_n_stats:
            print(f"\n  {noise}:")
            print(f"    Old: {old_n_stats['detected']}/{old_n_stats['total']} detected ({old_n_stats['detection_rate']:.2%}), "
                  f"status: P={old_n_stats['passed']} F={old_n_stats['failed']} I={old_n_stats['inconclusive']}")
            print(f"    New: {new_n_stats['detected']}/{new_n_stats['total']} detected ({new_n_stats['detection_rate']:.2%}), "
                  f"status: P={new_n_stats['passed']} F={new_n_stats['failed']} I={new_n_stats['inconclusive']}")

# Analyze the "near-miss" cases
print("\n" + "=" * 80)
print("NEAR-MISS ANALYSIS: SampleBudgetExceeded with high P(leak)")
print("=" * 80)

sample_budget_exceeded = new_inc[new_inc['inconclusive_reason'] == 'SampleBudgetExceeded']

if len(sample_budget_exceeded) > 0:
    print(f"\nFound {len(sample_budget_exceeded)} SampleBudgetExceeded cases")

    # Look at p_value (which is leak_probability in tacet)
    pvals = sample_budget_exceeded['p_value'].dropna()

    if len(pvals) > 0:
        print(f"\nP(leak) distribution:")
        print(f"  Min: {pvals.min():.4f}")
        print(f"  25th percentile: {pvals.quantile(0.25):.4f}")
        print(f"  Median: {pvals.median():.4f}")
        print(f"  75th percentile: {pvals.quantile(0.75):.4f}")
        print(f"  Max: {pvals.max():.4f}")
        print(f"  Mean: {pvals.mean():.4f}")

        # Count how many are "near misses" (90-95%)
        near_miss = pvals[(pvals >= 0.90) & (pvals < 0.95)]
        print(f"\n  Near-miss (90-95%): {len(near_miss)} / {len(pvals)} ({100*len(near_miss)/len(pvals):.1f}%)")

        # Show some examples
        print("\nExample near-miss cases:")
        near_miss_df = sample_budget_exceeded[
            (sample_budget_exceeded['p_value'] >= 0.90) &
            (sample_budget_exceeded['p_value'] < 0.95)
        ][['effect_sigma_mult', 'noise_model', 'attacker_threshold_ns', 'p_value', 'samples_used']].head(10)

        for _, row in near_miss_df.iterrows():
            print(f"  Effect={row['effect_sigma_mult']:.1f}σ, Noise={row['noise_model']}, "
                  f"Threshold={row['attacker_threshold_ns']:.1f}ns, P={row['p_value']:.4f}, "
                  f"Samples={row['samples_used']:.0f}")

# Compare specific case: effect=0.2, noise=ar1-n0.6, threshold=0.4
print("\n" + "=" * 80)
print("SPECIFIC CASE: effect=0.2σ, noise=ar1-n0.6, threshold=0.4ns")
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
if len(old_case) > 0:
    print(f"  Status: {old_case['status_clean'].value_counts().to_dict()}")
    print(f"  Detection rate: {(old_case['detected'] == True).sum() / len(old_case):.2%}")
    pvals_old = old_case['p_value'].dropna()
    if len(pvals_old) > 0:
        print(f"  P(leak): min={pvals_old.min():.4f}, mean={pvals_old.mean():.4f}, max={pvals_old.max():.4f}")

print(f"\nNew: {len(new_case)} samples")
if len(new_case) > 0:
    print(f"  Status: {new_case['status_clean'].value_counts().to_dict()}")
    print(f"  Detection rate: {(new_case['detected'] == True).sum() / len(new_case):.2%}")
    pvals_new = new_case['p_value'].dropna()
    if len(pvals_new) > 0:
        print(f"  P(leak): min={pvals_new.min():.4f}, mean={pvals_new.mean():.4f}, max={pvals_new.max():.4f}")

    # Show inconclusive reasons
    inc_case = new_case[new_case['status_clean'] == 'inconclusive']
    if len(inc_case) > 0:
        print(f"\n  Inconclusive reasons:")
        print(f"    {inc_case['inconclusive_reason'].value_counts().to_dict()}")

print("\n" + "=" * 80)
print("END OF ANALYSIS")
print("=" * 80)
