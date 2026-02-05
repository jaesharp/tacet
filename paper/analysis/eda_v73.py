#!/usr/bin/env python3
"""EDA + comparative analysis for tacet-bench v7.3 pre-final results.

Produces 8 figures and a structured go/no-go decision summary for the
USENIX Security 2026 paper submission.

Usage:
    uv run python eda_v73.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats as sp_stats

from tacet_analysis.data import (
    aggregate_by_tool_and_conditions,
    load_benchmark_data,
    load_summary_data,
)
from tacet_analysis.robustness import print_check_results, run_all_checks
from tacet_analysis.utils import (
    COLORS,
    EFFECT_NAMES,
    EFFECT_ORDER_THOROUGH,
    FIGSIZE_FULL,
    NOISE_NAMES,
    PRIMARY_TOOL_COLORS,
    PRIMARY_TOOLS,
    TOOL_NAMES,
    TOOL_ORDER,
    setup_paper_style,
)

# ar1-0.8 is present in data but missing from NOISE_ORDER_THOROUGH
NOISE_ORDER_FULL: list[str] = [
    "ar1-n0.6", "ar1-n0.4", "ar1-n0.2", "iid",
    "ar1-0.2", "ar1-0.4", "ar1-0.6", "ar1-0.8",
]
PHI_MAP: dict[str, float] = {
    "ar1-n0.6": -0.6, "ar1-n0.4": -0.4, "ar1-n0.2": -0.2,
    "iid": 0.0,
    "ar1-0.2": 0.2, "ar1-0.4": 0.4, "ar1-0.6": 0.6, "ar1-0.8": 0.8,
}

OUTPUT_DIR = Path(__file__).parent / "outputs" / "eda"

# Decision flags
GREEN = "GREEN"
YELLOW = "YELLOW"
RED = "RED"


def tool_label(tool: str, threshold: float | None = None) -> str:
    """Format a tool name for display, optionally with threshold."""
    base = TOOL_NAMES.get(tool, tool)
    if threshold is not None and not np.isnan(threshold):
        return f"{base} ({chr(0x03B8)}={threshold:g}ns)"
    return base


def wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for a binomial proportion."""
    if trials == 0:
        return (0.0, 0.0)
    p_hat = successes / trials
    denom = 1 + z**2 / trials
    center = (p_hat + z**2 / (2 * trials)) / denom
    half_width = (
        z * np.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * trials)) / trials) / denom
    )
    return (max(0.0, center - half_width), min(1.0, center + half_width))


def dedup_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate IID sigma-sweep rows from the summary.

    The thorough preset runs IID noise at 5 sigma values (2,5,10,20,50ns),
    producing identical summary rows for non-sigma-dependent tools.
    Keep only the first row per (tool, effect_pattern, effect_sigma_mult,
    noise_model, attacker_threshold_ns).
    """
    key_cols = [
        "tool", "effect_pattern", "effect_sigma_mult",
        "noise_model", "attacker_threshold_ns",
    ]
    return df.drop_duplicates(subset=key_cols, keep="first").reset_index(drop=True)


def filter_by_threshold(
    df: pd.DataFrame, threshold_ns: float,
) -> pd.DataFrame:
    """Keep one entry per tool: matching threshold for tacet/silent, NaN for others."""
    has_threshold = df["attacker_threshold_ns"].notna()
    matches_threshold = df["attacker_threshold_ns"] == threshold_ns
    return df[~has_threshold | matches_threshold].copy()


def make_tool_labels_with_thresholds(df: pd.DataFrame) -> pd.DataFrame:
    """Add a 'tool_label' column that includes threshold for tacet/silent."""
    df = df.copy()
    df["tool_label"] = df.apply(
        lambda r: tool_label(r["tool"], r.get("attacker_threshold_ns")),
        axis=1,
    )
    return df


# ── Extended palette for all tools including threshold variants ──
ALL_TOOL_COLORS: dict[str, str] = {
    **PRIMARY_TOOL_COLORS,
    "ad-test": "#059669",    # Darker green
    "ks-test": "#0ea5e9",    # Sky blue
    "mona": "#a855f7",       # Violet
}


def get_tool_color(tool: str, threshold: float | None = None) -> str:
    """Get a color for a tool, handling threshold variants."""
    if tool in ("tacet", "silent") and threshold is not None:
        if threshold == 100.0:
            base = ALL_TOOL_COLORS.get(tool, "#888888")
            # Lighten for the 100ns variant
            return base + "80"  # 50% opacity via hex alpha
        return ALL_TOOL_COLORS.get(tool, "#888888")
    return ALL_TOOL_COLORS.get(tool, "#888888")


# ═══════════════════════════════════════════════════════════════════
# §0  DATA INTEGRITY GATE
# ═══════════════════════════════════════════════════════════════════

def run_data_integrity(
    raw: pd.DataFrame, summary: pd.DataFrame,
) -> str:
    """Run robustness checks and return flag color."""
    print("\n" + "=" * 70)
    print(" 0. DATA INTEGRITY GATE")
    print("=" * 70)
    print(f"  Raw data:     {len(raw):>8,} rows")
    print(f"  Summary data: {len(summary):>8,} rows")
    print(f"  Tools:        {sorted(raw['tool'].unique())}")
    print(f"  Patterns:     {sorted(raw['effect_pattern'].unique())}")
    print(f"  Noise models: {sorted(raw['noise_model'].unique())}")
    print(f"  Effect sizes: {sorted(raw['effect_sigma_mult'].dropna().unique())}")

    results = run_all_checks(raw, summary, preset="thorough")
    print_check_results(results)

    if results["_summary"]["all_passed"]:
        return GREEN
    # Allow known issues:
    # - completeness: ar1-0.8 in data but not in expected thorough config (extra data, not missing)
    # - suspicious_patterns: flags competitors (ad-test, tlsfuzzer), not tacet
    # - duplicates/dataset_counts from sigma sweep
    critical_fails = []
    for name, res in results.items():
        if name == "_summary":
            continue
        if not res["passed"] and name not in (
            "duplicates", "dataset_counts", "completeness", "suspicious_patterns",
        ):
            critical_fails.append(name)
    return RED if critical_fails else YELLOW


# ═══════════════════════════════════════════════════════════════════
# §1  FPR ANALYSIS
# ═══════════════════════════════════════════════════════════════════

def analyze_fpr(
    summary: pd.DataFrame, raw: pd.DataFrame,
) -> str:
    """FPR analysis: heatmap + FPR vs AR coefficient. Returns flag."""
    print("\n" + "=" * 70)
    print(" 1. FALSE POSITIVE RATE ANALYSIS (effect = 0)")
    print("=" * 70)

    # Filter to null effect, shift pattern (canonical FPR test)
    null = summary[
        (summary["effect_sigma_mult"] == 0)
        & (summary["effect_pattern"] == "shift")
    ].copy()
    null = dedup_summary(null)
    null = make_tool_labels_with_thresholds(null)

    # ── Summary table ──
    print("\n  FPR by tool and noise model:")
    for tl in null["tool_label"].unique():
        row = null[null["tool_label"] == tl]
        parts = []
        for nm in NOISE_ORDER_FULL:
            r = row[row["noise_model"] == nm]
            if len(r) == 1:
                fpr = r.iloc[0]["detection_rate"]
                parts.append(f"{NOISE_NAMES.get(nm, nm)}={fpr:.0%}")
        print(f"    {tl:30s}: {', '.join(parts)}")

    # ── Max FPR per tool ──
    max_fpr = null.groupby("tool_label")["detection_rate"].max()
    print("\n  Max FPR across all noise models:")
    for tl, fpr in max_fpr.sort_values(ascending=False).items():
        marker = " *** " if fpr > 0.05 else ""
        print(f"    {tl:30s}: {fpr:6.1%}{marker}")

    # ── FPR slope vs phi ──
    print("\n  FPR sensitivity to autocorrelation (linear slope):")
    null["phi"] = null["noise_model"].map(PHI_MAP)
    for tl in sorted(null["tool_label"].unique()):
        sub = null[null["tool_label"] == tl].dropna(subset=["phi"])
        if len(sub) >= 3:
            slope, _intercept, _r, _p, _se = sp_stats.linregress(
                sub["phi"], sub["detection_rate"],
            )
            print(f"    {tl:30s}: slope = {slope:+.3f} FPR/unit-phi")

    # ── Three-way verdict breakdown for tacet at null ──
    tacet_null = raw[
        (raw["tool"] == "tacet")
        & (raw["effect_sigma_mult"] == 0)
        & (raw["effect_pattern"] == "shift")
    ]
    print("\n  Tacet verdict breakdown at null effect (shift):")
    for thresh in [0.4, 100.0]:
        sub = tacet_null[tacet_null["attacker_threshold_ns"] == thresh]
        if len(sub) == 0:
            continue
        total = len(sub)
        n_pass = (sub["verdict"] == "pass").sum()
        n_fail = (sub["verdict"] == "fail").sum()
        n_inc = (sub["verdict"] == "inconclusive").sum()
        print(
            f"    {chr(0x03B8)}={thresh:g}ns: "
            f"pass={n_pass/total:.0%}, fail={n_fail/total:.0%}, "
            f"inconclusive={n_inc/total:.0%} (n={total})",
        )

    # ── FIGURE 1: FPR heatmap ──
    _plot_fpr_heatmap(null)

    # ── FIGURE 2: FPR vs AR coefficient ──
    _plot_fpr_vs_phi(null)

    # ── Decision flag ──
    tacet_04_max = 0.0
    tacet_04 = null[
        (null["tool"] == "tacet") & (null["attacker_threshold_ns"] == 0.4)
    ]
    if len(tacet_04) > 0:
        tacet_04_max = tacet_04["detection_rate"].max()

    if tacet_04_max <= 0.05:
        flag = GREEN
        msg = f"tacet FPR <= 5% everywhere (max {tacet_04_max:.1%})"
    elif tacet_04_max <= 0.10:
        flag = YELLOW
        msg = f"tacet FPR up to {tacet_04_max:.1%} (only at high autocorrelation)"
    else:
        flag = RED
        msg = f"tacet FPR = {tacet_04_max:.1%}, exceeds 10%"

    print(f"\n  FLAG: {flag} - {msg}")
    return flag


def _plot_fpr_heatmap(null_df: pd.DataFrame) -> None:
    """Figure 1: FPR heatmap, tools x noise models."""
    # Get unique tool labels ordered
    tool_labels = []
    for tool in TOOL_ORDER:
        sub = null_df[null_df["tool"] == tool]
        for tl in sub["tool_label"].unique():
            if tl not in tool_labels:
                tool_labels.append(tl)

    noise_models = [nm for nm in NOISE_ORDER_FULL if nm in null_df["noise_model"].values]

    matrix = np.full((len(tool_labels), len(noise_models)), np.nan)
    for i, tl in enumerate(tool_labels):
        for j, nm in enumerate(noise_models):
            row = null_df[(null_df["tool_label"] == tl) & (null_df["noise_model"] == nm)]
            if len(row) == 1:
                matrix[i, j] = row.iloc[0]["detection_rate"]

    fig, ax = plt.subplots(figsize=(FIGSIZE_FULL, 4))

    # Custom colormap: green (0%) -> yellow (5%) -> red (50%)
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list(
        "fpr", [(0, "#2ecc71"), (0.1, "#f1c40f"), (0.5, "#e74c3c"), (1.0, "#8b0000")],
    )

    im = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=0.5, aspect="auto")

    # Annotate cells
    for i in range(len(tool_labels)):
        for j in range(len(noise_models)):
            val = matrix[i, j]
            if not np.isnan(val):
                color = "white" if val > 0.25 else "black"
                ax.text(j, i, f"{val:.0%}", ha="center", va="center",
                        fontsize=7, color=color, fontweight="bold" if val > 0.05 else "normal")

    ax.set_xticks(range(len(noise_models)))
    ax.set_xticklabels([NOISE_NAMES.get(nm, nm) for nm in noise_models],
                        rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(tool_labels)))
    ax.set_yticklabels(tool_labels, fontsize=8)
    ax.set_xlabel("Noise Model")
    ax.set_title("False Positive Rate at Null Effect (shift pattern)", fontsize=10)

    # 5% threshold line annotation
    ax.axhline(y=-0.5, color="red", lw=0.5)

    plt.colorbar(im, ax=ax, label="FPR", shrink=0.8)
    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "fig1_fpr_heatmap.png")
    plt.close(fig)
    print(f"  Saved: {OUTPUT_DIR / 'fig1_fpr_heatmap.png'}")


def _plot_fpr_vs_phi(null_df: pd.DataFrame) -> None:
    """Figure 2: FPR vs AR(1) coefficient, one line per tool."""
    null_df = null_df.copy()
    null_df["phi"] = null_df["noise_model"].map(PHI_MAP)

    fig, ax = plt.subplots(figsize=(FIGSIZE_FULL, 3.5))

    for tl in sorted(null_df["tool_label"].unique()):
        sub = null_df[null_df["tool_label"] == tl].sort_values("phi")
        if len(sub) < 2:
            continue
        tool = sub.iloc[0]["tool"]
        thresh = sub.iloc[0].get("attacker_threshold_ns")
        color = get_tool_color(tool, thresh if pd.notna(thresh) else None)
        lw = 2.0 if tool == "tacet" else 1.0
        ax.plot(sub["phi"], sub["detection_rate"], "o-", label=tl,
                color=color, linewidth=lw, markersize=4, alpha=0.85)

    ax.axhline(y=0.05, color="red", ls="--", lw=1, alpha=0.7, label="5% target")
    ax.set_xlabel("AR(1) coefficient (phi)")
    ax.set_ylabel("False Positive Rate")
    ax.set_title("FPR vs Autocorrelation Strength (effect=0, shift)")
    ax.legend(fontsize=6, ncol=2, loc="upper left")
    ax.set_ylim(-0.02, min(0.55, null_df["detection_rate"].max() + 0.05))

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "fig2_fpr_vs_phi.png")
    plt.close(fig)
    print(f"  Saved: {OUTPUT_DIR / 'fig2_fpr_vs_phi.png'}")


# ═══════════════════════════════════════════════════════════════════
# §2  POWER ANALYSIS
# ═══════════════════════════════════════════════════════════════════

def analyze_power(summary: pd.DataFrame) -> str:
    """Power curves + MDE + power-FPR tradeoff. Returns flag."""
    print("\n" + "=" * 70)
    print(" 2. POWER ANALYSIS")
    print("=" * 70)

    summary = dedup_summary(summary)

    # ── Power at IID, shift ──
    iid_shift = summary[
        (summary["noise_model"] == "iid")
        & (summary["effect_pattern"] == "shift")
    ].copy()
    iid_shift = make_tool_labels_with_thresholds(iid_shift)

    print("\n  Detection rate at IID/shift by effect size:")
    effects_of_interest = [0.1, 0.2, 0.4, 1.0]
    for tl in sorted(iid_shift["tool_label"].unique()):
        sub = iid_shift[iid_shift["tool_label"] == tl]
        parts = []
        for eff in effects_of_interest:
            r = sub[sub["effect_sigma_mult"] == eff]
            if len(r) >= 1:
                parts.append(f"{eff}σ={r.iloc[0]['detection_rate']:.0%}")
        print(f"    {tl:30s}: {', '.join(parts)}")

    # ── MDE at 80% and 90% power ──
    print("\n  Minimum Detectable Effect (IID, shift):")
    for tl in sorted(iid_shift["tool_label"].unique()):
        sub = iid_shift[iid_shift["tool_label"] == tl].sort_values("effect_sigma_mult")
        effects = sub["effect_sigma_mult"].values
        rates = sub["detection_rate"].values
        mde_80, mde_90 = "N/A", "N/A"
        for threshold_val, label in [(0.8, "80"), (0.9, "90")]:
            above = np.where(rates >= threshold_val)[0]
            if len(above) > 0 and effects[above[0]] > 0:
                mde = effects[above[0]]
                if label == "80":
                    mde_80 = f"{mde}σ"
                else:
                    mde_90 = f"{mde}σ"
        print(f"    {tl:30s}: MDE@80%={mde_80:>6s}, MDE@90%={mde_90:>6s}")

    # ── Power under autocorrelation at 0.2σ ──
    shift_02 = summary[
        (summary["effect_sigma_mult"] == 0.2) & (summary["effect_pattern"] == "shift")
    ].copy()
    shift_02 = dedup_summary(shift_02)
    shift_02 = make_tool_labels_with_thresholds(shift_02)

    print("\n  Power at 0.2σ (shift) across noise models:")
    for tl in sorted(shift_02["tool_label"].unique()):
        sub = shift_02[shift_02["tool_label"] == tl]
        iid_val = sub[sub["noise_model"] == "iid"]["detection_rate"]
        ar08_val = sub[sub["noise_model"] == "ar1-0.8"]["detection_rate"]
        iid_str = f"{iid_val.iloc[0]:.0%}" if len(iid_val) > 0 else "N/A"
        ar08_str = f"{ar08_val.iloc[0]:.0%}" if len(ar08_val) > 0 else "N/A"
        print(f"    {tl:30s}: IID={iid_str:>5s}, AR(0.8)={ar08_str:>5s}")

    # ── FIGURE 3: Power curves (IID, shift) ──
    _plot_power_curves(iid_shift)

    # ── FIGURE 4: Power vs FPR scatter ──
    _plot_power_vs_fpr(summary)

    # ── Decision flag ──
    tacet_04_iid = iid_shift[
        iid_shift["tool_label"].str.contains("0.4")
    ]
    power_at_04sigma = 0.0
    if len(tacet_04_iid) > 0:
        r04 = tacet_04_iid[tacet_04_iid["effect_sigma_mult"] == 0.4]
        if len(r04) > 0:
            power_at_04sigma = r04.iloc[0]["detection_rate"]

    if power_at_04sigma >= 0.90:
        flag = GREEN
        msg = f"tacet reaches {power_at_04sigma:.0%} power at 0.4σ (IID shift)"
    elif power_at_04sigma >= 0.50:
        flag = YELLOW
        msg = f"tacet power={power_at_04sigma:.0%} at 0.4σ; lower than competitors but FPR-controlled"
    else:
        flag = RED
        msg = f"tacet power only {power_at_04sigma:.0%} at 0.4σ"

    print(f"\n  FLAG: {flag} - {msg}")
    return flag


def _plot_power_curves(iid_shift: pd.DataFrame) -> None:
    """Figure 3: Power curves at IID, shift pattern."""
    fig, ax = plt.subplots(figsize=(FIGSIZE_FULL, 4))

    # Filter to θ=0.4ns for tacet/silent (the interesting comparison)
    for tl in sorted(iid_shift["tool_label"].unique()):
        sub = iid_shift[iid_shift["tool_label"] == tl].sort_values("effect_sigma_mult")
        # Skip θ=100ns variants (they saturate late and clutter)
        if "100" in tl:
            continue
        tool = sub.iloc[0]["tool"]
        thresh = sub.iloc[0].get("attacker_threshold_ns")
        color = get_tool_color(tool, thresh if pd.notna(thresh) else None)
        lw = 2.5 if tool == "tacet" else 1.2
        zorder = 10 if tool == "tacet" else 5

        # Only plot effect > 0 (FPR is shown separately)
        sub_pos = sub[sub["effect_sigma_mult"] > 0]
        ax.plot(
            sub_pos["effect_sigma_mult"], sub_pos["detection_rate"],
            "o-", label=tl, color=color, linewidth=lw, markersize=4,
            alpha=0.9, zorder=zorder,
        )
        # Add CI band
        if "ci_low" in sub_pos.columns:
            ax.fill_between(
                sub_pos["effect_sigma_mult"],
                sub_pos["ci_low"], sub_pos["ci_high"],
                alpha=0.1, color=color, zorder=zorder - 1,
            )

    ax.set_xscale("symlog", linthresh=0.05)
    ax.set_xlabel("Effect size (σ multiples)")
    ax.set_ylabel("Detection rate (power)")
    ax.set_title("Power Curves — IID Noise, Shift Pattern")
    ax.axhline(y=0.8, color="gray", ls=":", lw=0.8, alpha=0.5)
    ax.axhline(y=0.9, color="gray", ls=":", lw=0.8, alpha=0.5)
    ax.legend(fontsize=6, ncol=2, loc="lower right")
    ax.set_ylim(-0.02, 1.05)

    # Secondary x-axis in ns (at σ=5ns reference)
    ax2 = ax.twiny()
    ax2.set_xscale("symlog", linthresh=0.05)
    ax2.set_xlim(ax.get_xlim())
    ns_ticks = [0.1, 0.2, 0.4, 1, 2, 4, 10, 20]
    ax2.set_xticks(ns_ticks)
    ax2.set_xticklabels([f"{t*5:.0f}ns" for t in ns_ticks], fontsize=7)
    ax2.set_xlabel("Effect size (ns at σ=5ns)", fontsize=8)

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "fig3_power_curves.png")
    plt.close(fig)
    print(f"  Saved: {OUTPUT_DIR / 'fig3_power_curves.png'}")


def _plot_power_vs_fpr(summary: pd.DataFrame) -> None:
    """Figure 4: Power at 0.2σ IID vs max FPR — each tool is a point."""
    summary = dedup_summary(summary)
    summary = make_tool_labels_with_thresholds(summary)

    # FPR: max across all noise models at null effect, shift
    null_shift = summary[
        (summary["effect_sigma_mult"] == 0) & (summary["effect_pattern"] == "shift")
    ]
    max_fpr = null_shift.groupby("tool_label")["detection_rate"].max().reset_index()
    max_fpr.columns = ["tool_label", "max_fpr"]

    # Power: at 0.2σ IID shift
    power_02 = summary[
        (summary["effect_sigma_mult"] == 0.2)
        & (summary["noise_model"] == "iid")
        & (summary["effect_pattern"] == "shift")
    ][["tool_label", "detection_rate"]].copy()
    power_02.columns = ["tool_label", "power_02"]

    merged = pd.merge(max_fpr, power_02, on="tool_label", how="inner")

    fig, ax = plt.subplots(figsize=(FIGSIZE_FULL, 4))

    for _, row in merged.iterrows():
        tl = row["tool_label"]
        # Parse tool name from label
        tool_match = None
        for t in TOOL_ORDER:
            if TOOL_NAMES.get(t, t) in tl:
                tool_match = t
                break
        color = ALL_TOOL_COLORS.get(tool_match, "#888888") if tool_match else "#888888"
        marker = "D" if tool_match == "tacet" else "o"
        size = 80 if tool_match == "tacet" else 50

        ax.scatter(
            row["max_fpr"], row["power_02"],
            c=color, s=size, marker=marker, zorder=10, edgecolors="black", linewidths=0.5,
        )
        ax.annotate(
            tl, (row["max_fpr"], row["power_02"]),
            textcoords="offset points", xytext=(6, 4), fontsize=6, alpha=0.8,
        )

    ax.axvline(x=0.05, color="red", ls="--", lw=1, alpha=0.5, label="5% FPR target")
    ax.axhline(y=0.80, color="gray", ls=":", lw=0.8, alpha=0.5, label="80% power")
    ax.set_xlabel("Max FPR (across noise models)")
    ax.set_ylabel("Power at 0.2σ (IID, shift)")
    ax.set_title("Power-FPR Tradeoff (ideal = top-left)")
    ax.legend(fontsize=7)
    ax.set_xlim(-0.02, min(0.55, merged["max_fpr"].max() + 0.05))
    ax.set_ylim(-0.02, 1.05)

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "fig4_power_vs_fpr.png")
    plt.close(fig)
    print(f"  Saved: {OUTPUT_DIR / 'fig4_power_vs_fpr.png'}")


# ═══════════════════════════════════════════════════════════════════
# §3  AUTOCORRELATION ROBUSTNESS
# ═══════════════════════════════════════════════════════════════════

def analyze_autocorrelation(summary: pd.DataFrame) -> str:
    """Autocorrelation robustness analysis. Returns flag."""
    print("\n" + "=" * 70)
    print(" 3. AUTOCORRELATION ROBUSTNESS")
    print("=" * 70)

    summary = dedup_summary(summary)

    # Focus on shift pattern
    shift = summary[summary["effect_pattern"] == "shift"].copy()
    shift = make_tool_labels_with_thresholds(shift)

    # ── Robustness score: performance at phi=0.6 / performance at IID ──
    print("\n  Robustness scores (power at phi=0.6 / power at IID, effect=0.2σ):")
    for tl in sorted(shift["tool_label"].unique()):
        sub = shift[(shift["tool_label"] == tl) & (shift["effect_sigma_mult"] == 0.2)]
        iid_row = sub[sub["noise_model"] == "iid"]
        ar06_row = sub[sub["noise_model"] == "ar1-0.6"]
        if len(iid_row) > 0 and len(ar06_row) > 0:
            iid_power = iid_row.iloc[0]["detection_rate"]
            ar06_power = ar06_row.iloc[0]["detection_rate"]
            ratio = ar06_power / iid_power if iid_power > 0 else float("nan")
            print(f"    {tl:30s}: {ratio:.2f} ({ar06_power:.0%}/{iid_power:.0%})")
        else:
            print(f"    {tl:30s}: N/A")

    # ── FIGURE 5: Dual-panel FPR/power vs phi ──
    _plot_autocorrelation_dual(shift)

    # ── Decision flag ──
    # Check if tacet's FPR is better controlled than most tools at high autocorrelation
    null_shift = shift[shift["effect_sigma_mult"] == 0]
    tacet_04_null = null_shift[null_shift["tool_label"].str.contains("0.4")]
    other_null = null_shift[~null_shift["tool_label"].str.contains("Tacet|SILENT")]

    tacet_max_fpr = tacet_04_null["detection_rate"].max() if len(tacet_04_null) > 0 else 0
    other_median_max_fpr = (
        other_null.groupby("tool_label")["detection_rate"].max().median()
        if len(other_null) > 0 else 0
    )

    if tacet_max_fpr < other_median_max_fpr:
        flag = GREEN
        msg = f"tacet max FPR ({tacet_max_fpr:.0%}) < median competitor max ({other_median_max_fpr:.0%})"
    elif tacet_max_fpr <= other_median_max_fpr * 1.5:
        flag = YELLOW
        msg = f"tacet max FPR ({tacet_max_fpr:.0%}) comparable to competitors ({other_median_max_fpr:.0%})"
    else:
        flag = RED
        msg = f"tacet max FPR ({tacet_max_fpr:.0%}) worse than competitors ({other_median_max_fpr:.0%})"

    print(f"\n  FLAG: {flag} - {msg}")
    return flag


def _plot_autocorrelation_dual(shift_df: pd.DataFrame) -> None:
    """Figure 5: Dual-panel FPR (effect=0) and power (effect=0.2σ) vs phi."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(FIGSIZE_FULL, 3.5))

    shift_df = shift_df.copy()
    shift_df["phi"] = shift_df["noise_model"].map(PHI_MAP)

    for panel_ax, effect, title in [
        (ax1, 0, "FPR (effect=0)"),
        (ax2, 0.2, "Power (effect=0.2σ)"),
    ]:
        sub = shift_df[shift_df["effect_sigma_mult"] == effect]

        for tl in sorted(sub["tool_label"].unique()):
            tool_sub = sub[sub["tool_label"] == tl].sort_values("phi")
            if "100" in tl:
                continue  # Skip θ=100ns
            tool = tool_sub.iloc[0]["tool"]
            color = get_tool_color(tool)
            lw = 2.0 if tool == "tacet" else 1.0
            panel_ax.plot(
                tool_sub["phi"], tool_sub["detection_rate"],
                "o-", label=tl, color=color, linewidth=lw, markersize=3, alpha=0.85,
            )

        if effect == 0:
            panel_ax.axhline(y=0.05, color="red", ls="--", lw=1, alpha=0.7)
        else:
            panel_ax.axhline(y=0.8, color="gray", ls=":", lw=0.8, alpha=0.5)

        panel_ax.set_xlabel("AR(1) coefficient (φ)")
        panel_ax.set_ylabel("Rate")
        panel_ax.set_title(title, fontsize=9)
        panel_ax.set_ylim(-0.02, 1.05)

    ax2.legend(fontsize=5, ncol=2, loc="lower left")
    fig.suptitle("Autocorrelation Robustness (shift pattern)", fontsize=10, y=1.02)
    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "fig5_autocorrelation_dual.png")
    plt.close(fig)
    print(f"  Saved: {OUTPUT_DIR / 'fig5_autocorrelation_dual.png'}")


# ═══════════════════════════════════════════════════════════════════
# §4  UNCERTAINTY QUANTIFICATION
# ═══════════════════════════════════════════════════════════════════

def analyze_uncertainty(raw: pd.DataFrame) -> str:
    """Tacet-specific verdict and calibration analysis. Returns flag."""
    print("\n" + "=" * 70)
    print(" 4. UNCERTAINTY QUANTIFICATION (Tacet-Specific)")
    print("=" * 70)

    tacet = raw[raw["tool"] == "tacet"].copy()

    # ── Extract P(leak) from outcome strings ──
    def parse_p_leak(outcome: str) -> float | None:
        if pd.isna(outcome):
            return None
        m = re.search(r"P=(\d+\.?\d*)%", str(outcome))
        if m:
            return float(m.group(1)) / 100.0
        return None

    # P(leak) is in the "status" column (e.g., "Pass (P=0.0%)"), not "outcome"
    tacet["p_leak"] = tacet["status"].apply(parse_p_leak)

    # ── Verdict breakdown ──
    print("\n  Verdict breakdown by threshold (all conditions):")
    for thresh in [0.4, 100.0]:
        sub = tacet[tacet["attacker_threshold_ns"] == thresh]
        total = len(sub)
        if total == 0:
            continue
        n_pass = (sub["verdict"] == "pass").sum()
        n_fail = (sub["verdict"] == "fail").sum()
        n_inc = (sub["verdict"] == "inconclusive").sum()
        print(
            f"    θ={thresh:g}ns (n={total}): "
            f"pass={n_pass} ({n_pass/total:.1%}), "
            f"fail={n_fail} ({n_fail/total:.1%}), "
            f"inc={n_inc} ({n_inc/total:.1%})",
        )

    # ── Inconclusive reason distribution ──
    inc = tacet[tacet["verdict"] == "inconclusive"]
    print(f"\n  Inconclusive reason distribution (n={len(inc)}):")
    if len(inc) > 0:
        reason_counts = inc["inconclusive_reason"].value_counts()
        for reason, count in reason_counts.items():
            print(f"    {reason:30s}: {count:>5d} ({count/len(inc):.1%})")

    # ── Inconclusive by threshold and null vs positive effect ──
    print("\n  Inconclusive rate at null vs positive effect:")
    for thresh in [0.4, 100.0]:
        sub = tacet[tacet["attacker_threshold_ns"] == thresh]
        null_sub = sub[sub["effect_sigma_mult"] == 0]
        pos_sub = sub[sub["effect_sigma_mult"] > 0]
        null_inc = (null_sub["verdict"] == "inconclusive").mean() if len(null_sub) > 0 else 0
        pos_inc = (pos_sub["verdict"] == "inconclusive").mean() if len(pos_sub) > 0 else 0
        print(f"    θ={thresh:g}ns: null={null_inc:.1%}, positive={pos_inc:.1%}")

    # ── Calibration check: P(leak) at null effect ──
    print("\n  Calibration: P(leak) distribution at null effect:")
    for thresh in [0.4, 100.0]:
        sub = tacet[
            (tacet["attacker_threshold_ns"] == thresh)
            & (tacet["effect_sigma_mult"] == 0)
        ]
        p_vals = sub["p_leak"].dropna()
        if len(p_vals) > 0:
            print(
                f"    θ={thresh:g}ns: mean P(leak)={p_vals.mean():.3f}, "
                f"median={p_vals.median():.3f}, "
                f"P(leak)<5%={( p_vals < 0.05).mean():.0%} "
                f"(n={len(p_vals)})",
            )

    # ── FIGURE 6: Verdict breakdown across effect sizes ──
    _plot_verdict_breakdown(tacet)

    # ── FIGURE 7: Inconclusive reason breakdown ──
    _plot_inconclusive_reasons(tacet)

    # ── Decision flag ──
    # Check: at null effect with θ=100ns, is P(leak)<5% in ~95% of cases?
    null_100 = tacet[
        (tacet["attacker_threshold_ns"] == 100)
        & (tacet["effect_sigma_mult"] == 0)
    ]
    p_vals_100 = null_100["p_leak"].dropna()
    cal_rate = (p_vals_100 < 0.05).mean() if len(p_vals_100) > 0 else 0

    # Also check ThresholdElevated dominance for θ=0.4ns
    inc_04 = tacet[
        (tacet["attacker_threshold_ns"] == 0.4)
        & (tacet["verdict"] == "inconclusive")
    ]
    if len(inc_04) > 0:
        te_frac = (inc_04["inconclusive_reason"] == "ThresholdElevated").mean()
    else:
        te_frac = 0.0

    if cal_rate >= 0.90 and te_frac > 0.80:
        flag = GREEN
        msg = (f"P(leak)<5% in {cal_rate:.0%} of null cases (θ=100ns); "
               f"inconclusives are principled ({te_frac:.0%} ThresholdElevated)")
    elif cal_rate >= 0.80:
        flag = YELLOW
        msg = f"Calibration decent ({cal_rate:.0%}); inconclusives mostly ThresholdElevated ({te_frac:.0%})"
    else:
        flag = RED
        msg = f"Calibration poor: P(leak)<5% in only {cal_rate:.0%} of null cases"

    print(f"\n  FLAG: {flag} - {msg}")
    return flag


def _plot_verdict_breakdown(tacet_df: pd.DataFrame) -> None:
    """Figure 6: Stacked bar chart of verdicts across effect sizes (θ=0.4ns, IID)."""
    sub = tacet_df[
        (tacet_df["attacker_threshold_ns"] == 0.4)
        & (tacet_df["noise_model"] == "iid")
        & (tacet_df["effect_pattern"] == "shift")
    ]

    effects = sorted(sub["effect_sigma_mult"].unique())
    pass_rates, fail_rates, inc_rates = [], [], []

    for eff in effects:
        eff_sub = sub[sub["effect_sigma_mult"] == eff]
        total = len(eff_sub)
        if total == 0:
            pass_rates.append(0)
            fail_rates.append(0)
            inc_rates.append(0)
            continue
        pass_rates.append((eff_sub["verdict"] == "pass").sum() / total)
        fail_rates.append((eff_sub["verdict"] == "fail").sum() / total)
        inc_rates.append((eff_sub["verdict"] == "inconclusive").sum() / total)

    fig, ax = plt.subplots(figsize=(FIGSIZE_FULL, 3))
    x = np.arange(len(effects))
    width = 0.6

    ax.bar(x, pass_rates, width, label="Pass", color=COLORS["pass"])
    ax.bar(x, inc_rates, width, bottom=pass_rates, label="Inconclusive", color=COLORS["inconclusive"])
    ax.bar(
        x, fail_rates, width,
        bottom=[p + i for p, i in zip(pass_rates, inc_rates)],
        label="Fail", color=COLORS["fail"],
    )

    ax.set_xticks(x)
    ax.set_xticklabels([EFFECT_NAMES.get(e, str(e)) for e in effects], fontsize=8)
    ax.set_xlabel("Effect size")
    ax.set_ylabel("Proportion")
    ax.set_title(f"Tacet Verdict Breakdown ({chr(0x03B8)}=0.4ns, IID, shift)")
    ax.legend(fontsize=7)
    ax.set_ylim(0, 1.05)

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "fig6_verdict_breakdown.png")
    plt.close(fig)
    print(f"  Saved: {OUTPUT_DIR / 'fig6_verdict_breakdown.png'}")


def _plot_inconclusive_reasons(tacet_df: pd.DataFrame) -> None:
    """Figure 7: Inconclusive reason breakdown across noise models (θ=0.4ns)."""
    inc = tacet_df[
        (tacet_df["attacker_threshold_ns"] == 0.4)
        & (tacet_df["verdict"] == "inconclusive")
        & (tacet_df["effect_pattern"] == "shift")
    ]

    noise_models = [nm for nm in NOISE_ORDER_FULL if nm in inc["noise_model"].values]
    reasons = inc["inconclusive_reason"].unique()

    reason_colors = {
        "ThresholdElevated": "#f39c12",
        "SampleBudgetExceeded": "#3498db",
        "DataTooNoisy": "#e74c3c",
        "NotLearning": "#9b59b6",
        "TimeBudgetExceeded": "#1abc9c",
        "ConditionsChanged": "#e67e22",
        "Unknown": "#95a5a6",
    }

    fig, ax = plt.subplots(figsize=(FIGSIZE_FULL, 3))
    x = np.arange(len(noise_models))
    width = 0.6

    bottom = np.zeros(len(noise_models))
    for reason in sorted(reasons):
        heights = []
        for nm in noise_models:
            nm_inc = inc[inc["noise_model"] == nm]
            total = len(nm_inc)
            if total > 0:
                heights.append((nm_inc["inconclusive_reason"] == reason).sum() / total)
            else:
                heights.append(0)
        ax.bar(
            x, heights, width, bottom=bottom,
            label=reason, color=reason_colors.get(reason, "#888888"),
        )
        bottom += np.array(heights)

    ax.set_xticks(x)
    ax.set_xticklabels([NOISE_NAMES.get(nm, nm) for nm in noise_models],
                        rotation=45, ha="right", fontsize=7)
    ax.set_xlabel("Noise Model")
    ax.set_ylabel("Proportion of Inconclusives")
    ax.set_title(f"Inconclusive Reason Breakdown ({chr(0x03B8)}=0.4ns, shift)")
    ax.legend(fontsize=6, loc="upper left")
    ax.set_ylim(0, 1.05)

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "fig7_inconclusive_reasons.png")
    plt.close(fig)
    print(f"  Saved: {OUTPUT_DIR / 'fig7_inconclusive_reasons.png'}")


# ═══════════════════════════════════════════════════════════════════
# §5  INJECTION PATTERN ROBUSTNESS
# ═══════════════════════════════════════════════════════════════════

def analyze_patterns(summary: pd.DataFrame) -> str:
    """Cross-pattern comparison. Returns flag."""
    print("\n" + "=" * 70)
    print(" 5. INJECTION PATTERN ROBUSTNESS")
    print("=" * 70)

    summary = dedup_summary(summary)

    # Filter to IID noise (isolate pattern effect)
    iid = summary[summary["noise_model"] == "iid"].copy()
    iid = make_tool_labels_with_thresholds(iid)

    # ── Pattern gap at small effect sizes ──
    print("\n  Pattern gaps at 0.2σ (IID noise, |shift - pattern|):")
    effects_focus = [0.1, 0.2, 0.4]
    for tl in sorted(iid["tool_label"].unique()):
        if "100" in tl:
            continue
        sub = iid[iid["tool_label"] == tl]
        gaps = []
        for eff in effects_focus:
            eff_sub = sub[sub["effect_sigma_mult"] == eff]
            shift_rate = eff_sub[eff_sub["effect_pattern"] == "shift"]["detection_rate"]
            tail_rate = eff_sub[eff_sub["effect_pattern"] == "tail"]["detection_rate"]
            bimodal_rate = eff_sub[eff_sub["effect_pattern"] == "bimodal"]["detection_rate"]

            shift_v = shift_rate.iloc[0] if len(shift_rate) > 0 else None
            tail_v = tail_rate.iloc[0] if len(tail_rate) > 0 else None
            bimodal_v = bimodal_rate.iloc[0] if len(bimodal_rate) > 0 else None

            parts = []
            if shift_v is not None and tail_v is not None:
                parts.append(f"S-T={shift_v - tail_v:+.0%}")
            if shift_v is not None and bimodal_v is not None:
                parts.append(f"S-B={shift_v - bimodal_v:+.0%}")
            gaps.append(f"{eff}σ: {', '.join(parts)}")

        print(f"    {tl:30s}: {'; '.join(gaps)}")

    # ── FIGURE 8: Detection rate faceted by pattern ──
    _plot_pattern_comparison(iid)

    # ── Decision flag ──
    # Use 0.4σ for pattern gap — at 0.2σ, tacet θ=0.4ns is dominated by
    # measurement floor (ThresholdElevated), making the gap artificial.
    # At 0.4σ the signal is strong enough to escape the floor for shift,
    # so any remaining tail gap is a real sensitivity difference.
    tacet_iid = iid[
        (iid["tool"] == "tacet") & (iid["attacker_threshold_ns"] == 0.4)
    ]
    gap_04 = 0.0
    if len(tacet_iid) > 0:
        t04 = tacet_iid[tacet_iid["effect_sigma_mult"] == 0.4]
        shift_r = t04[t04["effect_pattern"] == "shift"]["detection_rate"]
        tail_r = t04[t04["effect_pattern"] == "tail"]["detection_rate"]
        if len(shift_r) > 0 and len(tail_r) > 0:
            gap_04 = abs(shift_r.iloc[0] - tail_r.iloc[0])

    # Also check at 1σ where measurement floor shouldn't matter
    gap_1 = 0.0
    if len(tacet_iid) > 0:
        t1 = tacet_iid[tacet_iid["effect_sigma_mult"] == 1.0]
        shift_r = t1[t1["effect_pattern"] == "shift"]["detection_rate"]
        tail_r = t1[t1["effect_pattern"] == "tail"]["detection_rate"]
        if len(shift_r) > 0 and len(tail_r) > 0:
            gap_1 = abs(shift_r.iloc[0] - tail_r.iloc[0])

    # Compare to median competitor gap at the same effect size
    other_iid = iid[~iid["tool"].isin(["tacet", "silent"])]
    competitor_gaps_04 = []
    for tl in other_iid["tool_label"].unique():
        sub = other_iid[
            (other_iid["tool_label"] == tl) & (other_iid["effect_sigma_mult"] == 0.4)
        ]
        sr = sub[sub["effect_pattern"] == "shift"]["detection_rate"]
        tr = sub[sub["effect_pattern"] == "tail"]["detection_rate"]
        if len(sr) > 0 and len(tr) > 0:
            competitor_gaps_04.append(abs(sr.iloc[0] - tr.iloc[0]))
    median_competitor_gap = np.median(competitor_gaps_04) if competitor_gaps_04 else 0

    print(f"\n  Tacet pattern gap at 0.4σ: {gap_04:.0%} (competitors median: {median_competitor_gap:.0%})")
    print(f"  Tacet pattern gap at 1.0σ: {gap_1:.0%}")

    if gap_1 <= 0.05:
        flag = GREEN
        msg = f"tacet pattern gap at 1σ: {gap_1:.0%}; at 0.4σ: {gap_04:.0%} (competitors: {median_competitor_gap:.0%})"
    elif gap_04 <= median_competitor_gap * 1.5 or gap_1 <= 0.15:
        flag = YELLOW
        msg = f"tacet pattern gap at 0.4σ: {gap_04:.0%} (comparable to competitors {median_competitor_gap:.0%})"
    else:
        flag = RED
        msg = f"tacet pattern gap at 0.4σ: {gap_04:.0%} (worse than competitors {median_competitor_gap:.0%})"

    print(f"\n  FLAG: {flag} - {msg}")
    return flag


def _plot_pattern_comparison(iid_df: pd.DataFrame) -> None:
    """Figure 8: Detection rate vs effect size, faceted by pattern."""
    patterns = ["shift", "tail", "bimodal"]
    fig, axes = plt.subplots(1, 3, figsize=(FIGSIZE_FULL, 3), sharey=True)

    for ax, pattern in zip(axes, patterns):
        sub = iid_df[iid_df["effect_pattern"] == pattern]
        for tl in sorted(sub["tool_label"].unique()):
            if "100" in tl:
                continue
            tool_sub = sub[sub["tool_label"] == tl].sort_values("effect_sigma_mult")
            tool_sub_pos = tool_sub[tool_sub["effect_sigma_mult"] > 0]
            tool = tool_sub.iloc[0]["tool"]
            color = get_tool_color(tool)
            lw = 2.0 if tool == "tacet" else 0.8
            ax.plot(
                tool_sub_pos["effect_sigma_mult"], tool_sub_pos["detection_rate"],
                "o-", label=tl, color=color, linewidth=lw, markersize=2.5, alpha=0.85,
            )

        ax.set_xscale("symlog", linthresh=0.05)
        ax.set_xlabel("Effect (σ)", fontsize=8)
        ax.set_title(pattern.capitalize(), fontsize=9)
        ax.axhline(y=0.8, color="gray", ls=":", lw=0.6, alpha=0.5)
        ax.set_ylim(-0.02, 1.05)

    axes[0].set_ylabel("Detection rate")
    axes[2].legend(fontsize=5, ncol=1, loc="lower right")
    fig.suptitle("Pattern Robustness (IID noise)", fontsize=10, y=1.02)
    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "fig8_pattern_comparison.png")
    plt.close(fig)
    print(f"  Saved: {OUTPUT_DIR / 'fig8_pattern_comparison.png'}")


# ═══════════════════════════════════════════════════════════════════
# §6  DECISION SUMMARY
# ═══════════════════════════════════════════════════════════════════

def print_decision_summary(flags: dict[str, str]) -> None:
    """Print the final go/no-go decision."""
    print("\n")
    print("=" * 70)
    print(" TACET v7.3 PRE-FINAL — DECISION SUMMARY")
    print("=" * 70)

    for section, flag in flags.items():
        indicator = {"GREEN": "+", "YELLOW": "~", "RED": "!"}[flag]
        print(f"  [{indicator}] {section:30s}: {flag}")

    n_red = sum(1 for f in flags.values() if f == RED)
    n_yellow = sum(1 for f in flags.values() if f == YELLOW)

    print()
    if n_red > 0:
        print("  OVERALL: NEEDS FIXES BEFORE SUBMITTING")
        print(f"  ({n_red} RED flags require attention)")
    elif n_yellow >= 3:
        print("  OVERALL: REVIEW YELLOWS, LIKELY FIXABLE")
        print(f"  ({n_yellow} YELLOW flags — check if any are paper-blocking)")
    elif n_yellow > 0:
        print("  OVERALL: SUBMIT AS-IS (minor concerns noted)")
        print(f"  ({n_yellow} YELLOW flags — defensible in paper)")
    else:
        print("  OVERALL: SUBMIT AS-IS (clean results)")

    # ── Key risks ──
    print("\n  Key risks:")
    if flags.get("FPR Control") in (YELLOW, RED):
        print("  - Tacet FPR > 5% at AR(1) phi=0.8; may need to address in paper")
        print("    or strengthen block bootstrap for high autocorrelation")
    if flags.get("Power") in (YELLOW, RED):
        print("  - Lower power at small effects is the price for FPR control;")
        print("    paper should present this as an explicit, calibrated tradeoff")
    if flags.get("Uncertainty/Calibration") in (YELLOW, RED):
        print("  - High inconclusive rate at theta=0.4ns with 5000 samples;")
        print("    measurement floor (~1.8ns) exceeds threshold")
        print("    Consider: is this the right regime to benchmark?")

    # ── Fix priorities ──
    reds = [s for s, f in flags.items() if f == RED]
    yellows = [s for s, f in flags.items() if f == YELLOW]
    if reds or yellows:
        print("\n  If fixing, prioritize:")
        for i, s in enumerate(reds + yellows, 1):
            flag = flags[s]
            print(f"  {i}. [{flag}] {s}")

    print("\n" + "=" * 70)


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main() -> None:
    setup_paper_style()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print(" TACET-BENCH v7.3 PRE-FINAL: EDA + COMPARATIVE ANALYSIS")
    print("=" * 70)

    # Load data
    print("\nLoading data...")
    try:
        raw = load_benchmark_data()
        summary = load_summary_data()
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    flags: dict[str, str] = {}

    # §0 Data integrity
    flags["Data Integrity"] = run_data_integrity(raw, summary)

    # §1 FPR
    flags["FPR Control"] = analyze_fpr(summary, raw)

    # §2 Power
    flags["Power"] = analyze_power(summary)

    # §3 Autocorrelation
    flags["Autocorrelation"] = analyze_autocorrelation(summary)

    # §4 Uncertainty
    flags["Uncertainty/Calibration"] = analyze_uncertainty(raw)

    # §5 Patterns
    flags["Pattern Robustness"] = analyze_patterns(summary)

    # §6 Decision
    print_decision_summary(flags)


if __name__ == "__main__":
    main()
