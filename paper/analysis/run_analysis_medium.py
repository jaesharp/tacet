#!/usr/bin/env python3
"""Generate paper figures from the medium benchmark dataset.

Only produces the two figures referenced in the paper:
  - v3-fig1: FPR heatmap (Autocorrelation × Tool)
  - v3-fig2-combined: Combined power heatmap (shift + tail, no bimodal)

Usage:
    uv run python run_analysis_medium.py
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from tacet_analysis.data import load_benchmark_data
from tacet_analysis.utils import (
    COLORS,
    EFFECT_NAMES,
    EFFECT_ORDER_MEDIUM,
    FIGURES_DIR,
    FIGSIZE_FULL,
    NOISE_NAMES,
    NOISE_ORDER_MEDIUM,
    PRIMARY_TOOLS,
    TOOL_NAMES,
    setup_paper_style,
)

# Medium dataset path
MEDIUM_DATA_DIR = Path(__file__).parent.parent.parent / "results" / "medium-null-var-floor"

# Verdict colors (same as charts.py)
VERDICT_COLORS = {
    "found": "#2563eb",
    "not_found": "#d4d4d8",
    "uncertain": "#f59e0b",
}

# Medium has "silent-native" instead of "silent"
MEDIUM_TOOL_NAMES = {
    **TOOL_NAMES,
    "silent-native": "SILENT",
}

MEDIUM_PRIMARY_TOOLS = [
    "tacet", "silent-native", "rtlf-native", "dudect", "timing-tvla",
]


def _filter_by_threshold(df: pd.DataFrame, threshold_ns: float) -> pd.DataFrame:
    has_threshold = df["attacker_threshold_ns"].notna()
    matches_threshold = df["attacker_threshold_ns"] == threshold_ns
    return df[~has_threshold | matches_threshold].copy()


def _format_tool_label_with_threshold(tool: str, threshold_ns: float) -> str:
    base_name = MEDIUM_TOOL_NAMES.get(tool, tool)
    if threshold_ns >= 1000:
        threshold_str = f"{threshold_ns/1000:.0f}μs"
    elif threshold_ns >= 1:
        threshold_str = f"{threshold_ns:.0f}ns"
    else:
        threshold_str = f"{threshold_ns:.1f}ns"
    if tool in ("tacet", "silent", "silent-native"):
        return f"{base_name} (θ={threshold_str})"
    return base_name


def _draw_stacked_bar_cell(
    ax: plt.Axes, x: float, y: float,
    width: float, height: float,
    found_rate: float, not_found_rate: float, uncertain_rate: float,
) -> None:
    padding_x = width * 0.08
    padding_y = height * 0.2
    bar_width = width - 2 * padding_x
    bar_height = height - 2 * padding_y
    bar_x = x + padding_x
    bar_y = y + padding_y

    current_x = bar_x
    for rate, color in [
        (found_rate, VERDICT_COLORS["found"]),
        (not_found_rate, VERDICT_COLORS["not_found"]),
        (uncertain_rate, VERDICT_COLORS["uncertain"]),
    ]:
        if rate > 0.005:
            seg_width = bar_width * rate
            rect = plt.Rectangle(
                (current_x, bar_y), seg_width, bar_height,
                facecolor=color, edgecolor="none",
            )
            ax.add_patch(rect)
            current_x += seg_width


def _sigma_to_ns(sigma: float, ref_sigma_ns: float) -> float:
    return sigma * ref_sigma_ns


def _format_ns_label(sigma: float, ref_sigma_ns: float) -> str:
    if sigma == 0:
        return "0"
    ns = _sigma_to_ns(sigma, ref_sigma_ns)
    return f"{ns:.1f}" if ns < 1.0 else f"{ns:.0f}"


# ── Figure 1: FPR Heatmap ──────────────────────────────────────────────


def plot_fpr_heatmap_medium(
    raw_df: pd.DataFrame,
    tacet_threshold_ns: float = 0.4,
    output_path: Path | None = None,
    figsize: tuple[float, float] = (13, 6),
) -> plt.Figure:
    """FPR heatmap: Autocorrelation × Tool (null effect only)."""
    setup_paper_style()

    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == "shift")
    ].copy()

    df = _filter_by_threshold(df, tacet_threshold_ns)

    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        pass_rate=("verdict", lambda x: (x == "pass").mean()),
        fail_rate=("verdict", lambda x: (x == "fail").mean()),
        inc_rate=("verdict", lambda x: (x == "inconclusive").mean()),
    ).reset_index()

    # Non-negative autocorrelation only (matching thorough figures)
    noise_present = [n for n in NOISE_ORDER_MEDIUM if n in agg["noise_model"].unique() and not n.startswith("ar1-n")]

    tools_present = [t for t in MEDIUM_PRIMARY_TOOLS if t in agg["tool"].unique()]

    fig, ax = plt.subplots(figsize=figsize)

    n_tools = len(tools_present)
    n_noise = len(noise_present)

    for i, tool in enumerate(tools_present):
        for j, noise in enumerate(noise_present):
            rect = plt.Rectangle(
                (j, i), 1, 1, facecolor="white",
                edgecolor=COLORS["border"], linewidth=0.4,
            )
            ax.add_patch(rect)

            row = agg[(agg["tool"] == tool) & (agg["noise_model"] == noise)]
            if len(row) > 0:
                row = row.iloc[0]
                _draw_stacked_bar_cell(
                    ax, j, i, 1, 1,
                    found_rate=row["fail_rate"],
                    not_found_rate=row["pass_rate"],
                    uncertain_rate=row["inc_rate"],
                )

                fpr_pct = row["fail_rate"] * 100
                inc_pct = row["inc_rate"] * 100
                if inc_pct > 1:
                    label = f"{fpr_pct:.0f}%\n({inc_pct:.0f}% Inc)"
                else:
                    label = f"{fpr_pct:.0f}%"
                ax.text(
                    j + 0.5, i + 0.5, label, ha="center", va="center",
                    fontsize=12, color=COLORS["text"], fontweight="medium",
                )

    ax.set_xlim(0, n_noise)
    ax.set_ylim(0, n_tools)
    ax.set_xticks([x + 0.5 for x in range(n_noise)])
    ax.set_yticks([y + 0.5 for y in range(n_tools)])
    ax.set_xticklabels([NOISE_NAMES.get(n, n) for n in noise_present], fontsize=13)
    tool_labels = [_format_tool_label_with_threshold(t, tacet_threshold_ns) for t in tools_present]
    ax.set_yticklabels(tool_labels, fontsize=13)
    ax.invert_yaxis()
    ax.set_ylabel("Tool", fontsize=14)

    legend_elements = [
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["found"], edgecolor=COLORS["border"], label="False positive"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["not_found"], edgecolor=COLORS["border"], label="Effect not found"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["uncertain"], edgecolor=COLORS["border"], label="Inconclusive"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", bbox_to_anchor=(1.02, 1), fontsize=13)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"  Saved: {output_path}")

    return fig


# ── Figure 2: Combined Power Heatmap (shift + tail only) ───────────────


def plot_power_heatmap_combined_medium(
    raw_df: pd.DataFrame,
    noise_model: str = "ar1-0.6",
    tacet_threshold_ns: float = 0.4,
    ref_sigma_ns: float = 5.0,
    effect_sizes: list[float] | None = None,
    output_path: Path | None = None,
    figsize: tuple[float, float] = (10.5, 5.5),
) -> plt.Figure:
    """Combined power heatmap with sub-rows per effect pattern (shift + tail only).

    Adapted from plot_power_heatmap_combined but with bimodal removed.
    """
    setup_paper_style()

    if effect_sizes is None:
        # Medium has: [0, 0.2, 1, 2, 4, 20]
        # Drop 20σ (all tools at 100%); keep rest
        effect_sizes = [0, 0.2, 1, 2, 4]

    df = raw_df[raw_df["noise_model"] == noise_model].copy()
    df = _filter_by_threshold(df, tacet_threshold_ns)

    tools_present = [t for t in MEDIUM_PRIMARY_TOOLS if t in df["tool"].unique()]
    effects_present = [e for e in effect_sizes if e in df["effect_sigma_mult"].unique()]

    # Only shift and tail (no bimodal in medium)
    patterns = ["shift", "tail"]
    pattern_abbrev = {"shift": "shift", "tail": "tail"}

    n_tools = len(tools_present)
    n_effects = len(effects_present)
    n_patterns = len(patterns)
    group_gap = 0.4

    def row_y(tool_idx: int, pattern_idx: int) -> float:
        return tool_idx * (n_patterns + group_gap) + pattern_idx

    total_height = n_tools * n_patterns + (n_tools - 1) * group_gap

    fig, ax = plt.subplots(figsize=figsize)

    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_linewidth(0.5)
        spine.set_color(COLORS["border"])

    # Aggregate
    pattern_filter = df["effect_pattern"].isin(patterns)
    effect_filter = df["effect_sigma_mult"].isin(effects_present)
    agg = df[pattern_filter & effect_filter].groupby(
        ["tool", "effect_sigma_mult", "effect_pattern"]
    ).agg(
        n_trials=("verdict", "count"),
        pass_rate=("verdict", lambda x: (x == "pass").mean()),
        fail_rate=("verdict", lambda x: (x == "fail").mean()),
        inc_rate=("verdict", lambda x: (x == "inconclusive").mean()),
    ).reset_index()

    # Draw cells
    for i, tool in enumerate(tools_present):
        for p, pattern in enumerate(patterns):
            y = row_y(i, p)
            for j, effect in enumerate(effects_present):
                rect = plt.Rectangle(
                    (j, y), 1, 1, facecolor="white", edgecolor="none",
                )
                ax.add_patch(rect)

                mask = (
                    (agg["tool"] == tool)
                    & (agg["effect_sigma_mult"] == effect)
                    & (agg["effect_pattern"] == pattern)
                )
                rows = agg[mask]
                if len(rows) > 0:
                    r = rows.iloc[0]
                    _draw_stacked_bar_cell(
                        ax, j, y, 1, 1,
                        found_rate=r["fail_rate"],
                        not_found_rate=r["pass_rate"],
                        uncertain_rate=r["inc_rate"],
                    )

    # Horizontal lines between tool groups
    for i in range(1, n_tools):
        sep_y = row_y(i, 0) - group_gap / 2
        ax.axhline(y=sep_y, color=COLORS["border"], linewidth=0.6, zorder=5)

    ax.set_xlim(0, n_effects)
    ax.set_ylim(-0.2, total_height + 0.2)
    ax.invert_yaxis()

    # X-axis: effect sizes (σ)
    ax.set_xticks([x + 0.5 for x in range(n_effects)])
    ax.set_xticklabels(
        [EFFECT_NAMES.get(e, str(e)) for e in effects_present], fontsize=11,
    )
    ax.set_xlabel("Effect size (σ)", fontsize=12)

    # Secondary x-axis: nanoseconds
    ax_top = ax.twiny()
    ax_top.set_xlim(0, n_effects)
    ax_top.set_xticks([x + 0.5 for x in range(n_effects)])
    ns_labels = [_format_ns_label(e, ref_sigma_ns) for e in effects_present]
    ax_top.set_xticklabels(ns_labels, fontsize=11)
    ax_top.set_xlabel(f"Effect size (ns, σ = {ref_sigma_ns:.0f} ns)", fontsize=12)
    ax_top.spines["top"].set_visible(True)
    ax_top.spines["top"].set_linewidth(0.5)
    ax_top.spines["top"].set_color(COLORS["border"])

    # Y-axis: tool names centered on their sub-row groups
    tool_centers = [row_y(i, 0) + (n_patterns - 1) / 2 for i in range(n_tools)]
    ax.set_yticks(tool_centers)
    ax.set_yticklabels([""] * n_tools)
    ax.tick_params(axis="y", length=0)

    from matplotlib.transforms import blended_transform_factory
    label_trans = blended_transform_factory(ax.transAxes, ax.transData)
    for i, tool in enumerate(tools_present):
        is_tacet = tool == "tacet"
        if is_tacet:
            threshold_str = f"{tacet_threshold_ns:.1f}" if tacet_threshold_ns < 1 else f"{tacet_threshold_ns:.0f}"
            label = r"$\mathbf{Tacet}$" + f" (θ={threshold_str}ns)"
        else:
            label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)
        ax.text(
            -0.10, tool_centers[i], label,
            ha="right", va="center", fontsize=11,
            transform=label_trans,
        )

    # Pattern sub-labels
    trans = blended_transform_factory(ax.transAxes, ax.transData)
    for i in range(n_tools):
        for p, pattern in enumerate(patterns):
            y_pos = row_y(i, p) + 0.5
            lbl = pattern_abbrev[pattern]
            is_tacet = tools_present[i] == "tacet"
            ax.text(
                -0.01, y_pos, lbl,
                ha="right", va="center", fontsize=9,
                color=COLORS["text"] if is_tacet else COLORS["text_secondary"],
                fontweight="bold" if is_tacet else "normal",
                transform=trans,
            )

    # Legend
    legend_elements = [
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["found"], edgecolor=COLORS["border"], label="Effect found"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["not_found"], edgecolor=COLORS["border"], label="Effect not found"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["uncertain"], edgecolor=COLORS["border"], label="Inconclusive"),
    ]
    ax.legend(
        handles=legend_elements, loc="upper left",
        bbox_to_anchor=(1.02, 1.0), ncol=1, frameon=False, fontsize=10,
    )

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"  Saved: {output_path}")

    return fig


# ── Main ────────────────────────────────────────────────────────────────


def main():
    print("=" * 60)
    print("MEDIUM DATASET → PAPER FIGURES")
    print("=" * 60)

    print(f"\nLoading medium data from {MEDIUM_DATA_DIR}...")
    raw_df = load_benchmark_data(data_dir=MEDIUM_DATA_DIR)
    print(f"  {len(raw_df):,} rows")
    print(f"  Tools: {sorted(raw_df['tool'].unique())}")
    print(f"  Effect patterns: {sorted(raw_df['effect_pattern'].unique())}")
    print(f"  Noise models: {sorted(raw_df['noise_model'].unique())}")
    print(f"  Effect sizes (σ): {sorted(raw_df['effect_sigma_mult'].unique())}")

    figures_dir = FIGURES_DIR
    figures_dir.mkdir(parents=True, exist_ok=True)

    # Figure 1: FPR heatmap
    print("\nGenerating v3-fig1: FPR heatmap (medium)...")
    plot_fpr_heatmap_medium(
        raw_df,
        output_path=figures_dir / "v3-fig1_fpr_heatmap.png",
    )

    # Figure 2: Combined power heatmap (shift + tail only)
    print("Generating v3-fig2-combined: power heatmap (medium, shift+tail)...")
    plot_power_heatmap_combined_medium(
        raw_df,
        output_path=figures_dir / "v3-fig2-combined_power_heatmap.png",
    )

    print(f"\nFigures saved to {figures_dir}")
    print("Done.")


if __name__ == "__main__":
    main()
