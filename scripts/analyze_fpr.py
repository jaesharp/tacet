#!/usr/bin/env python3
"""
Analyze False Positive Rate (FPR) results from measure_fpr.sh

Computes:
- Overall FPR with Wilson score confidence intervals
- Per-ecosystem breakdown
- Per-library breakdown
- Identifies specific false positives
- Generates summary statistics
"""

import sys
import csv
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Tuple
import math


def wilson_score_interval(successes: int, trials: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Compute Wilson score confidence interval for a binomial proportion.

    Args:
        successes: Number of successes (e.g., false positives)
        trials: Total number of trials
        confidence: Confidence level (default 0.95 for 95% CI)

    Returns:
        (lower_bound, upper_bound) as proportions [0, 1]
    """
    if trials == 0:
        return (0.0, 1.0)

    # Z-score for confidence level
    z_scores = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}
    z = z_scores.get(confidence, 1.96)

    p = successes / trials
    denominator = 1 + z**2 / trials
    center = (p + z**2 / (2 * trials)) / denominator
    margin = z * math.sqrt((p * (1 - p) / trials + z**2 / (4 * trials**2))) / denominator

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return (lower, upper)


def load_results(csv_file: Path) -> List[Dict]:
    """Load results from CSV file."""
    results = []
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append(row)
    return results


def analyze_results(results: List[Dict]) -> None:
    """Analyze and print comprehensive FPR statistics."""

    total_runs = len(results)
    if total_runs == 0:
        print("No results found in CSV file.")
        return

    # Count outcomes
    outcomes = Counter(r['outcome'] for r in results)
    pass_count = outcomes['PASS']
    fail_count = outcomes['FAIL']
    inconclusive_count = outcomes['INCONCLUSIVE']
    skip_count = outcomes.get('SKIP', 0)
    unknown_count = outcomes.get('UNKNOWN', 0)

    # Overall statistics
    print("=" * 70)
    print("FALSE POSITIVE RATE ANALYSIS")
    print("=" * 70)
    print(f"\nTotal test runs: {total_runs}")
    print(f"  Pass:          {pass_count:5d} ({100*pass_count/total_runs:5.1f}%)")
    print(f"  Fail (FP):     {fail_count:5d} ({100*fail_count/total_runs:5.1f}%)")
    print(f"  Inconclusive:  {inconclusive_count:5d} ({100*inconclusive_count/total_runs:5.1f}%)")
    if skip_count > 0:
        print(f"  Skipped:       {skip_count:5d} ({100*skip_count/total_runs:5.1f}%)")
    if unknown_count > 0:
        print(f"  Unknown:       {unknown_count:5d} ({100*unknown_count/total_runs:5.1f}%)")

    # False Positive Rate
    print(f"\n{'─' * 70}")
    print("FALSE POSITIVE RATE")
    print('─' * 70)

    fpr = fail_count / total_runs
    lower, upper = wilson_score_interval(fail_count, total_runs, confidence=0.95)

    print(f"Point estimate: {fpr:.4f} ({100*fpr:.2f}%)")
    print(f"Wilson 95% CI:  [{100*lower:.2f}%, {100*upper:.2f}%]")

    if fail_count == 0:
        print("\n✓ NO FALSE POSITIVES DETECTED")
        print(f"  This validates the calibration property with 95% confidence")
        print(f"  that the true FPR is below {100*upper:.2f}%")
    else:
        print(f"\n✗ {fail_count} FALSE POSITIVE(S) DETECTED")
        print(f"  This exceeds the expected rate of {0.05 * 100:.0f}% (α = 0.05)")

    # Per-ecosystem breakdown
    print(f"\n{'─' * 70}")
    print("PER-ECOSYSTEM BREAKDOWN")
    print('─' * 70)

    ecosystems = defaultdict(lambda: {'total': 0, 'pass': 0, 'fail': 0, 'inconclusive': 0})
    for r in results:
        eco = r['ecosystem']
        ecosystems[eco]['total'] += 1
        if r['outcome'] == 'PASS':
            ecosystems[eco]['pass'] += 1
        elif r['outcome'] == 'FAIL':
            ecosystems[eco]['fail'] += 1
        elif r['outcome'] == 'INCONCLUSIVE':
            ecosystems[eco]['inconclusive'] += 1

    for eco in sorted(ecosystems.keys()):
        stats = ecosystems[eco]
        total = stats['total']
        print(f"\n{eco}:")
        print(f"  Runs:         {total}")
        print(f"  Pass:         {stats['pass']} ({100*stats['pass']/total:.1f}%)")
        print(f"  Fail:         {stats['fail']} ({100*stats['fail']/total:.1f}%)")
        print(f"  Inconclusive: {stats['inconclusive']} ({100*stats['inconclusive']/total:.1f}%)")

        if stats['fail'] > 0:
            lower_eco, upper_eco = wilson_score_interval(stats['fail'], total)
            print(f"  FPR:          {stats['fail']/total:.4f} (95% CI: [{100*lower_eco:.2f}%, {100*upper_eco:.2f}%])")

    # Per-library breakdown
    print(f"\n{'─' * 70}")
    print("PER-LIBRARY BREAKDOWN")
    print('─' * 70)

    libraries = defaultdict(lambda: {'total': 0, 'pass': 0, 'fail': 0, 'inconclusive': 0})
    for r in results:
        lib = r['library']
        libraries[lib]['total'] += 1
        if r['outcome'] == 'PASS':
            libraries[lib]['pass'] += 1
        elif r['outcome'] == 'FAIL':
            libraries[lib]['fail'] += 1
        elif r['outcome'] == 'INCONCLUSIVE':
            libraries[lib]['inconclusive'] += 1

    # Sort by total runs (most tested first)
    for lib in sorted(libraries.keys(), key=lambda x: libraries[x]['total'], reverse=True):
        stats = libraries[lib]
        total = stats['total']

        if stats['fail'] > 0:
            marker = "✗"
        elif stats['pass'] == total:
            marker = "✓"
        else:
            marker = "~"

        print(f"\n{marker} {lib}:")
        print(f"    Runs: {total:3d}  |  Pass: {stats['pass']:3d}  |  Fail: {stats['fail']:3d}  |  Inconcl: {stats['inconclusive']:3d}")

        if stats['fail'] > 0:
            fpr_lib = stats['fail'] / total
            print(f"    FPR: {100*fpr_lib:.2f}%")

    # List specific false positives
    if fail_count > 0:
        print(f"\n{'─' * 70}")
        print("FALSE POSITIVE DETAILS")
        print('─' * 70)

        false_positives = [r for r in results if r['outcome'] == 'FAIL']

        # Group by test
        fp_by_test = defaultdict(list)
        for fp in false_positives:
            key = (fp['ecosystem'], fp['library'], fp['test_name'])
            fp_by_test[key].append(fp)

        for (eco, lib, test), fps in sorted(fp_by_test.items()):
            print(f"\n{eco} / {lib} / {test}")
            print(f"  Failed {len(fps)} out of {len([r for r in results if r['ecosystem']==eco and r['library']==lib and r['test_name']==test])} iterations")

            # Show first few failures
            for i, fp in enumerate(fps[:3], 1):
                leak_prob = fp['leak_probability']
                samples = fp['samples']
                elapsed = fp['elapsed_sec']
                print(f"    Iter {fp['iteration']}: P(leak)={leak_prob}%, samples={samples}, time={elapsed}s")

            if len(fps) > 3:
                print(f"    ... and {len(fps)-3} more")

    # Test-level reliability
    print(f"\n{'─' * 70}")
    print("TEST-LEVEL RELIABILITY")
    print('─' * 70)

    # Count unique tests
    unique_tests = set((r['ecosystem'], r['library'], r['test_name']) for r in results)
    tests_with_fp = set((r['ecosystem'], r['library'], r['test_name']) for r in results if r['outcome'] == 'FAIL')

    print(f"\nUnique tests:              {len(unique_tests)}")
    print(f"Tests with ≥1 FP:          {len(tests_with_fp)}")
    print(f"Tests with 0 FP:           {len(unique_tests) - len(tests_with_fp)}")

    if len(tests_with_fp) > 0:
        print(f"\nTests with false positives:")
        for eco, lib, test in sorted(tests_with_fp):
            # Count failures for this test
            test_results = [r for r in results if r['ecosystem']==eco and r['library']==lib and r['test_name']==test]
            test_failures = len([r for r in test_results if r['outcome'] == 'FAIL'])
            fpr_test = test_failures / len(test_results)
            print(f"  - {eco}/{lib}/{test}: {test_failures}/{len(test_results)} ({100*fpr_test:.1f}%)")

    # Summary for paper
    print(f"\n{'─' * 70}")
    print("PAPER-READY SUMMARY")
    print('─' * 70)

    print(f"\nAcross {len(unique_tests)} unique tests run {total_runs} times")
    print(f"(average {total_runs/len(unique_tests):.1f} iterations per test),")
    print(f"tacet returned {fail_count} false positives")
    print(f"(FPR = {100*fpr:.2f}%, Wilson 95% CI: [{100*lower:.2f}%, {100*upper:.2f}%]).")

    if fail_count == 0:
        print(f"\nThis validates the calibration property: with 95% confidence,")
        print(f"the true false positive rate is below {100*upper:.2f}%.")
    else:
        print(f"\nNote: Expected FPR at α=0.05 is 5%. Observed rate of {100*fpr:.2f}%")
        print(f"{'is within' if fpr <= 0.05 else 'exceeds'} expected bounds.")


def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_fpr.py <results.csv>")
        sys.exit(1)

    csv_file = Path(sys.argv[1])
    if not csv_file.exists():
        print(f"Error: File not found: {csv_file}")
        sys.exit(1)

    results = load_results(csv_file)
    analyze_results(results)


if __name__ == '__main__':
    main()
