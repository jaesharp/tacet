"""Robustness checks for benchmark data quality."""

from typing import Any

import pandas as pd
import numpy as np

from tacet_analysis.data import get_expected_combinations, load_benchmark_data, load_summary_data


def check_completeness(df: pd.DataFrame, preset: str = "medium") -> dict[str, Any]:
    """Check if all expected experimental combinations are present."""
    expected = get_expected_combinations(preset)
    issues = []

    # Check tools
    tools_present = set(df["tool"].unique())
    tools_expected = set(expected["tools"])
    missing_tools = tools_expected - tools_present
    extra_tools = tools_present - tools_expected
    if missing_tools:
        issues.append(f"Missing tools: {missing_tools}")
    if extra_tools:
        issues.append(f"Unexpected tools: {extra_tools}")

    # Check effect patterns
    patterns_present = set(df["effect_pattern"].unique())
    patterns_expected = set(expected["effect_patterns"])
    if patterns_present != patterns_expected:
        issues.append(f"Effect patterns mismatch: expected {patterns_expected}, got {patterns_present}")

    # Check effect sizes
    effects_present = set(df["effect_sigma_mult"].dropna().unique())
    effects_expected = set(expected["effect_sigma_mults"])
    missing_effects = effects_expected - effects_present
    if missing_effects:
        issues.append(f"Missing effect sizes: {missing_effects}")

    # Check noise models
    noise_present = set(df["noise_model"].unique())
    noise_expected = set(expected["noise_models"])
    if noise_present != noise_expected:
        issues.append(f"Noise models mismatch: expected {noise_expected}, got {noise_present}")

    # Check tacet thresholds
    tacet_df = df[df["tool"] == "tacet"]
    thresholds_present = set(tacet_df["attacker_threshold_ns"].dropna().unique())
    thresholds_expected = set(expected["tacet_thresholds"])
    if thresholds_present != thresholds_expected:
        issues.append(f"Tacet thresholds mismatch: expected {thresholds_expected}, got {thresholds_present}")

    return {
        "passed": len(issues) == 0,
        "issues": issues,
        "tools_found": sorted(tools_present),
        "effects_found": sorted(effects_present),
        "noise_models_found": sorted(noise_present),
    }


def check_duplicates(df: pd.DataFrame) -> dict[str, Any]:
    """Check for duplicate entries in the raw data."""
    # Define the key columns that should uniquely identify a measurement
    key_cols = [
        "tool", "effect_pattern", "effect_sigma_mult", "noise_model",
        "attacker_threshold_ns", "dataset_id"
    ]

    # For non-tacet tools, threshold is NaN, so we need to handle that
    df_check = df.copy()
    df_check["attacker_threshold_ns"] = df_check["attacker_threshold_ns"].fillna(-1)

    duplicates = df_check[df_check.duplicated(subset=key_cols, keep=False)]
    n_duplicates = len(duplicates)

    if n_duplicates > 0:
        # Get sample of duplicated rows
        sample_groups = duplicates.groupby(key_cols).size().reset_index(name="count")
        sample = sample_groups[sample_groups["count"] > 1].head(5)
    else:
        sample = None

    return {
        "passed": n_duplicates == 0,
        "n_duplicates": n_duplicates,
        "sample": sample,
    }


def check_ci_sanity(summary_df: pd.DataFrame) -> dict[str, Any]:
    """Verify detection_rate is within [ci_low, ci_high]."""
    issues = []

    # Check if detection rate is within CI bounds (with small tolerance for rounding)
    tolerance = 0.001
    mask_below = summary_df["detection_rate"] < (summary_df["ci_low"] - tolerance)
    mask_above = summary_df["detection_rate"] > (summary_df["ci_high"] + tolerance)

    violations = summary_df[mask_below | mask_above]

    if len(violations) > 0:
        issues.append(f"{len(violations)} rows have detection_rate outside CI bounds")

    return {
        "passed": len(issues) == 0,
        "issues": issues,
        "n_violations": len(violations),
        "violations": violations[["tool", "effect_pattern", "effect_sigma_mult", "noise_model",
                                   "detection_rate", "ci_low", "ci_high"]].head(10) if len(violations) > 0 else None,
    }


def check_suspicious_patterns(df: pd.DataFrame) -> dict[str, Any]:
    """Flag tools with suspicious uniform results."""
    issues = []

    # Aggregate detection rates by tool and effect_sigma_mult
    agg = df.groupby(["tool", "effect_pattern"]).agg(
        n_datasets=("detected", "count"),
        n_detected=("detected", "sum"),
    ).reset_index()
    agg["detection_rate"] = agg["n_detected"] / agg["n_datasets"]

    # Check for tools with 0% detection on all non-null effects for a pattern
    for tool in df["tool"].unique():
        for pattern in ["shift", "tail"]:
            tool_pattern_df = df[(df["tool"] == tool) & (df["effect_pattern"] == pattern)]
            # Only check for effect > 0
            nonzero_effect = tool_pattern_df[tool_pattern_df["effect_sigma_mult"] > 0]
            if len(nonzero_effect) > 0:
                detection_rate = nonzero_effect["detected"].sum() / len(nonzero_effect)
                if detection_rate == 0:
                    issues.append(
                        f"{tool}: 0% detection on ALL {pattern} patterns with effect > 0 "
                        f"({len(nonzero_effect)} measurements)"
                    )
                elif detection_rate == 1.0:
                    # 100% detection on everything including 0.2σ might also be suspicious
                    pass  # This is less concerning

    # Check for tools with high FPR (effect=0)
    null_effect = df[df["effect_sigma_mult"] == 0]
    fpr_by_tool = null_effect.groupby("tool").agg(
        n=("detected", "count"),
        fpr=("detected", "mean"),
    ).reset_index()

    high_fpr = fpr_by_tool[fpr_by_tool["fpr"] > 0.25]
    for _, row in high_fpr.iterrows():
        issues.append(f"{row['tool']}: FPR={row['fpr']:.1%} (>25%) on null effect across all conditions")

    return {
        "passed": len(issues) == 0,
        "issues": issues,
        "fpr_summary": fpr_by_tool.to_dict("records"),
    }


def check_dataset_counts(df: pd.DataFrame, preset: str = "medium") -> dict[str, Any]:
    """Verify each condition has the expected number of datasets."""
    expected = get_expected_combinations(preset)
    expected_n = expected["n_datasets"]

    # Group by experimental conditions
    counts = df.groupby(
        ["tool", "effect_pattern", "effect_sigma_mult", "noise_model", "attacker_threshold_ns"]
    ).size().reset_index(name="count")

    # For non-tacet tools, threshold is NaN
    wrong_counts = counts[counts["count"] != expected_n]

    issues = []
    if len(wrong_counts) > 0:
        issues.append(f"{len(wrong_counts)} conditions have != {expected_n} datasets")

    return {
        "passed": len(issues) == 0,
        "issues": issues,
        "expected_n": expected_n,
        "wrong_counts": wrong_counts.head(10) if len(wrong_counts) > 0 else None,
    }


def run_all_checks(
    raw_df: pd.DataFrame | None = None,
    summary_df: pd.DataFrame | None = None,
    preset: str = "thorough",
) -> dict[str, dict[str, Any]]:
    """Run all robustness checks and return results.

    Args:
        raw_df: Raw benchmark results DataFrame (loaded if None)
        summary_df: Summary DataFrame (loaded if None)
        preset: Benchmark preset used ("medium" or "thorough")
    """
    if raw_df is None:
        raw_df = load_benchmark_data()
    if summary_df is None:
        summary_df = load_summary_data()

    results = {
        "completeness": check_completeness(raw_df, preset=preset),
        "duplicates": check_duplicates(raw_df),
        "ci_sanity": check_ci_sanity(summary_df),
        "suspicious_patterns": check_suspicious_patterns(raw_df),
        "dataset_counts": check_dataset_counts(raw_df, preset=preset),
    }

    # Overall summary
    all_passed = all(r["passed"] for r in results.values())
    results["_summary"] = {
        "all_passed": all_passed,
        "checks_passed": sum(1 for r in results.values() if isinstance(r, dict) and r.get("passed", False)),
        "total_checks": len(results) - 1,  # Exclude _summary
    }

    return results


def print_check_results(results: dict[str, dict[str, Any]]) -> None:
    """Print formatted check results."""
    print("=" * 60)
    print("ROBUSTNESS CHECK RESULTS")
    print("=" * 60)

    for check_name, result in results.items():
        if check_name == "_summary":
            continue

        status = "✓ PASS" if result["passed"] else "✗ FAIL"
        print(f"\n{check_name}: {status}")

        if not result["passed"] and "issues" in result:
            for issue in result["issues"]:
                print(f"  - {issue}")

    summary = results["_summary"]
    print("\n" + "=" * 60)
    print(f"SUMMARY: {summary['checks_passed']}/{summary['total_checks']} checks passed")
    if summary["all_passed"]:
        print("All robustness checks passed!")
    else:
        print("Some checks failed - review issues above")
    print("=" * 60)
