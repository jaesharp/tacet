"""Data loading and preprocessing for tacet benchmark results."""

from pathlib import Path
from typing import Optional

import pandas as pd

from tacet_analysis.utils import DATA_DIR, THOROUGH_DATA_DIR


def load_benchmark_data(data_dir: Optional[Path] = None) -> pd.DataFrame:
    """Load raw benchmark results with parsed outcome field.

    Returns DataFrame with columns:
        tool, preset, effect_pattern, effect_sigma_mult, noise_model,
        synthetic_sigma_ns, attacker_threshold_ns, dataset_id, samples_per_class,
        detected, statistic, p_value, time_ms, samples_used, status, outcome,
        verdict (parsed from outcome)
    """
    if data_dir is None:
        data_dir = DATA_DIR

    csv_path = data_dir / "benchmark_results.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Benchmark results not found at {csv_path}")

    df = pd.read_csv(csv_path)

    # Parse the outcome field to extract verdict
    # outcome is one of: pass, fail, inconclusive
    df["verdict"] = df["outcome"].str.lower()

    # For tacet, extract inconclusive reason from status field
    df["inconclusive_reason"] = None
    mask = df["verdict"] == "inconclusive"
    df.loc[mask, "inconclusive_reason"] = df.loc[mask, "status"].apply(_extract_inconclusive_reason)

    # Convert effect_sigma_mult to numeric (handle any string issues)
    df["effect_sigma_mult"] = pd.to_numeric(df["effect_sigma_mult"], errors="coerce")

    # Convert threshold to numeric
    df["attacker_threshold_ns"] = pd.to_numeric(df["attacker_threshold_ns"], errors="coerce")

    # Convert synthetic_sigma_ns to numeric (may be missing in older data)
    if "synthetic_sigma_ns" in df.columns:
        df["synthetic_sigma_ns"] = pd.to_numeric(df["synthetic_sigma_ns"], errors="coerce")
    else:
        df["synthetic_sigma_ns"] = 50.0  # Default for older data

    return df


def _extract_inconclusive_reason(status: str) -> Optional[str]:
    """Extract the reason code from tacet's inconclusive status message."""
    if pd.isna(status):
        return None
    status = str(status)
    if "ThresholdElevated" in status:
        return "ThresholdElevated"
    elif "SampleBudgetExceeded" in status:
        return "SampleBudgetExceeded"
    elif "TimeBudgetExceeded" in status:
        return "TimeBudgetExceeded"
    elif "DataTooNoisy" in status:
        return "DataTooNoisy"
    elif "NotLearning" in status:
        return "NotLearning"
    elif "ConditionsChanged" in status:
        return "ConditionsChanged"
    else:
        return "Unknown"


def load_summary_data(data_dir: Optional[Path] = None) -> pd.DataFrame:
    """Load aggregated benchmark summary with detection rates and CIs.

    Returns DataFrame with columns:
        tool, effect_pattern, effect_sigma_mult, noise_model,
        attacker_threshold_ns, n_datasets, detection_rate,
        ci_low, ci_high, median_time_ms, median_samples
    """
    if data_dir is None:
        data_dir = DATA_DIR

    csv_path = data_dir / "benchmark_summary.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Benchmark summary not found at {csv_path}")

    df = pd.read_csv(csv_path)

    # Convert numeric columns
    df["effect_sigma_mult"] = pd.to_numeric(df["effect_sigma_mult"], errors="coerce")
    df["attacker_threshold_ns"] = pd.to_numeric(df["attacker_threshold_ns"], errors="coerce")

    return df


def get_expected_combinations(preset: str = "medium") -> dict:
    """Return the expected combinations of experimental factors for a given preset.

    Args:
        preset: One of "medium" or "thorough"

    Note: This reflects the targeted config approach for the three paper heatmaps:
    - Heatmap 1 (Effect × Tool): All effects, IID noise, σ=50ns
    - Heatmap 2 (Autocorr × Tool): effect=0, all noise models, σ=50ns
    - Heatmap 3 (NoiseLevel × Tool): effect=0, IID noise, all σ values
    """
    # Common across presets
    # Note: "silent" is R reference implementation, "rtlf-native" is Rust reimplementation, "tlsfuzzer" is Python
    base = {
        "tools": [
            "dudect", "rtlf-native", "silent", "tacet", "timing-tvla", "tlsfuzzer"
        ],
        "tacet_thresholds": [0.4, 100.0],  # SharedHardware and AdjacentNetwork
    }

    if preset == "thorough":
        return {
            **base,
            "effect_patterns": ["shift", "tail", "bimodal"],
            "effect_sigma_mults": [0, 0.1, 0.2, 0.4, 1, 2, 4, 10, 20],
            "noise_models": [
                "ar1-n0.6", "ar1-n0.4", "ar1-n0.2", "iid",
                "ar1-0.2", "ar1-0.4", "ar1-0.6", "ar1-0.8"
            ],
            "synthetic_sigma_ns_values": [5],
            "n_datasets": 100,
        }
    else:  # medium (default)
        return {
            **base,
            "effect_patterns": ["shift", "tail"],
            "effect_sigma_mults": [0, 0.2, 1, 2, 4, 20],
            "noise_models": ["ar1-n0.6", "ar1-n0.3", "iid", "ar1-0.3", "ar1-0.6", "ar1-0.8"],
            "synthetic_sigma_ns_values": [2, 5, 10, 20, 50],
            "n_datasets": 30,
        }


def aggregate_by_tool_and_conditions(
    df: pd.DataFrame,
    group_cols: list[str],
    tacet_threshold_ns: Optional[float] = None,
) -> pd.DataFrame:
    """Aggregate raw results to compute detection rates.

    Args:
        df: Raw benchmark results DataFrame
        group_cols: Columns to group by
        tacet_threshold_ns: If set, filter tacet results to this threshold only

    Returns:
        DataFrame with detection_rate, pass_rate, fail_rate, inconclusive_rate
    """
    df = df.copy()

    # Filter tacet to specific threshold if requested
    if tacet_threshold_ns is not None:
        tacet_mask = df["tool"] == "tacet"
        threshold_mask = df["attacker_threshold_ns"] == tacet_threshold_ns
        # Keep non-tacet rows OR tacet rows with matching threshold
        df = df[~tacet_mask | (tacet_mask & threshold_mask)]

    agg = df.groupby(group_cols).agg(
        n_datasets=("detected", "count"),
        n_detected=("detected", "sum"),
        n_pass=("verdict", lambda x: (x == "pass").sum()),
        n_fail=("verdict", lambda x: (x == "fail").sum()),
        n_inconclusive=("verdict", lambda x: (x == "inconclusive").sum()),
    ).reset_index()

    agg["detection_rate"] = agg["n_detected"] / agg["n_datasets"]
    agg["pass_rate"] = agg["n_pass"] / agg["n_datasets"]
    agg["fail_rate"] = agg["n_fail"] / agg["n_datasets"]
    agg["inconclusive_rate"] = agg["n_inconclusive"] / agg["n_datasets"]

    return agg


def load_thorough_data() -> pd.DataFrame:
    """Load raw benchmark data from the thorough dataset (100 trials/condition)."""
    return load_benchmark_data(data_dir=THOROUGH_DATA_DIR)


def load_thorough_summary() -> pd.DataFrame:
    """Load summary data from the thorough dataset (100 trials/condition)."""
    return load_summary_data(data_dir=THOROUGH_DATA_DIR)
