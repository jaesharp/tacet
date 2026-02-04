"""Analysis of calibration test results for the USENIX paper."""

import math
from pathlib import Path
from typing import NamedTuple

import pandas as pd

CALIBRATION_DATA_DIR = Path(__file__).parent.parent.parent.parent.parent / "results"


class WilsonCI(NamedTuple):
    """Wilson score confidence interval."""
    estimate: float
    lower: float
    upper: float
    n: int
    k: int


def wilson_ci(k: int, n: int, z: float = 1.96) -> WilsonCI:
    """Compute Wilson score confidence interval for a proportion.

    Args:
        k: Number of successes (e.g., false positives)
        n: Total trials
        z: Z-score for confidence level (1.96 for 95% CI)

    Returns:
        WilsonCI with estimate, lower, upper bounds, n, k
    """
    if n == 0:
        return WilsonCI(0.0, 0.0, 1.0, 0, 0)

    p_hat = k / n
    denominator = 1 + z**2 / n
    center = (p_hat + z**2 / (2*n)) / denominator
    margin = (z / denominator) * math.sqrt(p_hat * (1 - p_hat) / n + z**2 / (4 * n**2))

    lower = max(0, center - margin)
    upper = min(1, center + margin)

    return WilsonCI(p_hat, lower, upper, n, k)


def load_calibration_csv(filename: str) -> pd.DataFrame:
    """Load a calibration CSV file."""
    path = CALIBRATION_DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Calibration data not found: {path}")
    return pd.read_csv(path)


def compute_fpr_statistics() -> dict:
    """Compute false positive rate statistics from calibration data."""
    results = {}

    # Rigorous FPR test (1000 trials)
    try:
        df = load_calibration_csv("fpr_validation_rigorous.csv")
        # Filter out rows with 'research' decision type (these are metadata)
        df = df[df["decision"].isin(["pass", "fail", "inconclusive"])]
        n = len(df)
        fails = len(df[df["decision"] == "fail"])
        ci = wilson_ci(fails, n)
        results["rigorous"] = {
            "trials": n,
            "false_positives": fails,
            "fpr": ci.estimate,
            "wilson_ci": (ci.lower, ci.upper),
        }
    except FileNotFoundError:
        pass

    # Bayesian calibration 0.0x (null hypothesis)
    for model in ["adjacent_network", "pmu", "remote_network"]:
        try:
            df = load_calibration_csv(f"bayesian_calibration_validation_{model}_0.0x.csv")
            n = len(df)
            fails = len(df[df["decision"] == "fail"])
            ci = wilson_ci(fails, n)
            results[f"bayesian_{model}_0x"] = {
                "trials": n,
                "false_positives": fails,
                "fpr": ci.estimate,
                "wilson_ci": (ci.lower, ci.upper),
            }
        except FileNotFoundError:
            pass

    return results


def compute_power_statistics() -> dict:
    """Compute detection power statistics at various effect sizes."""
    results = {}

    # AdjacentNetwork power curve
    for mult in ["0.5x", "1.0x", "2.0x", "5.0x", "10.0x"]:
        try:
            df = load_calibration_csv(f"power_validation_curve_adjacent_network_{mult}.csv")
            n = len(df)
            detects = len(df[df["decision"] == "fail"])
            ci = wilson_ci(detects, n)
            results[f"adjacent_network_{mult}"] = {
                "trials": n,
                "detections": detects,
                "power": ci.estimate,
                "wilson_ci": (ci.lower, ci.upper),
            }
        except FileNotFoundError:
            pass

    return results


def compute_estimation_accuracy() -> dict:
    """Compute effect size estimation accuracy."""
    results = {}

    for effect_ns in [50, 100, 200, 500, 1000]:
        try:
            df = load_calibration_csv(f"estimation_accuracy_validation_adjacent_network_{effect_ns}ns.csv")
            # Get estimated effects
            effects = df["max_effect_ns"].dropna()
            if len(effects) > 0:
                mean_est = effects.mean()
                std_est = effects.std()
                bias = mean_est - effect_ns
                results[f"{effect_ns}ns"] = {
                    "true_effect": effect_ns,
                    "mean_estimate": mean_est,
                    "std_estimate": std_est,
                    "bias": bias,
                    "relative_bias": bias / effect_ns if effect_ns > 0 else 0,
                    "trials": len(effects),
                }
        except FileNotFoundError:
            pass

    return results


def generate_paper_statistics() -> str:
    """Generate statistics formatted for the paper."""
    lines = []
    lines.append("=" * 60)
    lines.append("CALIBRATION STATISTICS FOR PAPER")
    lines.append("=" * 60)

    # FPR
    lines.append("\n## False Positive Rate (FPR)")
    fpr_stats = compute_fpr_statistics()
    for name, stats in fpr_stats.items():
        ci_low, ci_high = stats["wilson_ci"]
        lines.append(f"  {name}:")
        lines.append(f"    Trials: {stats['trials']}")
        lines.append(f"    False positives: {stats['false_positives']}")
        lines.append(f"    FPR: {stats['fpr']*100:.2f}%")
        lines.append(f"    Wilson 95% CI: [{ci_low*100:.2f}%, {ci_high*100:.2f}%]")

    # Power
    lines.append("\n## Detection Power (AdjacentNetwork)")
    power_stats = compute_power_statistics()
    for name, stats in sorted(power_stats.items()):
        ci_low, ci_high = stats["wilson_ci"]
        lines.append(f"  {name}:")
        lines.append(f"    Trials: {stats['trials']}")
        lines.append(f"    Detections: {stats['detections']}")
        lines.append(f"    Power: {stats['power']*100:.1f}%")
        lines.append(f"    Wilson 95% CI: [{ci_low*100:.1f}%, {ci_high*100:.1f}%]")

    # Estimation accuracy
    lines.append("\n## Effect Size Estimation Accuracy")
    est_stats = compute_estimation_accuracy()
    for name, stats in sorted(est_stats.items(), key=lambda x: x[1]["true_effect"]):
        lines.append(f"  {name}:")
        lines.append(f"    True effect: {stats['true_effect']} ns")
        lines.append(f"    Mean estimate: {stats['mean_estimate']:.1f} ns")
        lines.append(f"    Bias: {stats['bias']:+.1f} ns ({stats['relative_bias']*100:+.1f}%)")
        lines.append(f"    Std: {stats['std_estimate']:.1f} ns")

    return "\n".join(lines)


if __name__ == "__main__":
    print(generate_paper_statistics())
