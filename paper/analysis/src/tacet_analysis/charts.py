"""Visualization functions for tacet benchmark analysis."""

from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from tacet_analysis.data import aggregate_by_tool_and_conditions, load_benchmark_data, load_summary_data
from tacet_analysis.utils import (
    COLORS,
    EFFECT_NAMES,
    EFFECT_ORDER,
    EFFECT_ORDER_PAPER,
    EFFECT_ORDER_THOROUGH,
    FIGURES_DIR,
    FIGSIZE_FULL,
    FIGSIZE_SINGLE,
    NOISE_NAMES,
    NOISE_ORDER,
    PRIMARY_TOOL_COLORS,
    PRIMARY_TOOLS,
    TOOL_NAMES,
    TOOL_ORDER,
    setup_paper_style,
)


# Verdict color scheme: context-independent (works for both FPR and power plots)
VERDICT_COLORS = {
    "found": "#2563eb",       # Deep blue - detection occurred (neutral)
    "not_found": "#d4d4d8",   # Light gray - no detection (neutral)
    "uncertain": "#f59e0b",   # Amber - caution/unknown (universal)
}


def _draw_stacked_bar_cell(ax: plt.Axes, x: float, y: float,
                           width: float, height: float,
                           found_rate: float, not_found_rate: float, uncertain_rate: float) -> None:
    """Draw a mini stacked bar in a heatmap cell.

    Args:
        ax: Matplotlib axes
        x, y: Bottom-left corner of the cell
        width, height: Cell dimensions
        found_rate, not_found_rate, uncertain_rate: Proportions (should sum to 1)
    """
    # Add padding around the bar
    padding_x = width * 0.08
    padding_y = height * 0.2
    bar_width = width - 2 * padding_x
    bar_height = height - 2 * padding_y
    bar_x = x + padding_x
    bar_y = y + padding_y

    # Draw segments left to right: found (blue) | not_found (gray) | uncertain (purple)
    current_x = bar_x

    if found_rate > 0.005:  # Skip tiny segments
        seg_width = bar_width * found_rate
        rect = plt.Rectangle((current_x, bar_y), seg_width, bar_height,
                             facecolor=VERDICT_COLORS["found"], edgecolor="none")
        ax.add_patch(rect)
        current_x += seg_width

    if not_found_rate > 0.005:
        seg_width = bar_width * not_found_rate
        rect = plt.Rectangle((current_x, bar_y), seg_width, bar_height,
                             facecolor=VERDICT_COLORS["not_found"], edgecolor="none")
        ax.add_patch(rect)
        current_x += seg_width

    if uncertain_rate > 0.005:
        seg_width = bar_width * uncertain_rate
        rect = plt.Rectangle((current_x, bar_y), seg_width, bar_height,
                             facecolor=VERDICT_COLORS["uncertain"], edgecolor="none")
        ax.add_patch(rect)


def _make_tacet_bold(tool_labels: list[str]) -> list[str]:
    """Return tool labels with Tacet in bold using mathtext."""
    return [r"$\mathbf{Tacet}$" if "Tacet" in str(label) else label for label in tool_labels]


def _format_tool_label_with_threshold(tool: str, threshold_ns: float) -> str:
    """Format tool label to include threshold for tacet/silent.

    Args:
        tool: Tool name (internal key like 'tacet', 'silent')
        threshold_ns: Threshold value in nanoseconds

    Returns:
        Formatted label like "Tacet (θ=0.4ns)" or "SILENT (θ=100ns)"
    """
    base_name = TOOL_NAMES.get(tool, tool)

    # Format threshold value - use appropriate precision
    if threshold_ns >= 1000:
        threshold_str = f"{threshold_ns/1000:.0f}μs"
    elif threshold_ns >= 1:
        threshold_str = f"{threshold_ns:.0f}ns"
    else:
        threshold_str = f"{threshold_ns:.1f}ns"

    # Add threshold to tacet/silent labels
    if tool == "tacet":
        return f"{base_name} (θ={threshold_str})"
    elif tool == "silent":
        return f"{base_name} (θ={threshold_str})"
    else:
        return base_name


def plot_power_heatmap(
    raw_df: pd.DataFrame,
    noise_model: str = "ar1-0.6",
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 100.0,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (10, 5),
) -> plt.Figure:
    """Create heatmap of detection power: Effect Size × Tool.

    Each cell contains a mini stacked bar showing the proportion of:
    - Effect found (blue)
    - Effect not found (gray)
    - Couldn't determine (purple)

    Args:
        raw_df: Raw benchmark data with verdict column
        noise_model: Fixed noise model (default: ar1-0.6 for moderate autocorrelation)
        effect_pattern: Fixed effect pattern (default: shift)
        tacet_threshold_ns: Tacet threshold to use (default: 100ns)
        output_path: Path to save figure
        figsize: Figure size in inches

    Returns:
        matplotlib Figure
    """
    setup_paper_style()

    # Filter data
    df = raw_df[
        (raw_df["noise_model"] == noise_model)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    # Filter tacet to specific threshold
    tacet_mask = df["tool"] == "tacet"
    threshold_mask = df["attacker_threshold_ns"] == tacet_threshold_ns
    df = df[~tacet_mask | (tacet_mask & threshold_mask)]

    # Aggregate by tool and effect to get verdict proportions
    agg = df.groupby(["tool", "effect_sigma_mult"]).agg(
        n_trials=("verdict", "count"),
        pass_rate=("verdict", lambda x: (x == "pass").mean()),
        fail_rate=("verdict", lambda x: (x == "fail").mean()),
        inc_rate=("verdict", lambda x: (x == "inconclusive").mean()),
    ).reset_index()

    # Reorder tools and effects
    tools_present = [t for t in PRIMARY_TOOLS if t in agg["tool"].unique()]
    effects_present = [e for e in EFFECT_ORDER if e in agg["effect_sigma_mult"].unique()]

    # Create figure
    fig, ax = plt.subplots(figsize=figsize)

    n_tools = len(tools_present)
    n_effects = len(effects_present)

    # Draw cell backgrounds and stacked bars
    for i, tool in enumerate(tools_present):
        for j, effect in enumerate(effects_present):
            # Draw cell background
            rect = plt.Rectangle((j, i), 1, 1, facecolor="white",
                                 edgecolor=COLORS["border"], linewidth=0.5)
            ax.add_patch(rect)

            # Get data for this cell
            row = agg[(agg["tool"] == tool) & (agg["effect_sigma_mult"] == effect)]
            if len(row) > 0:
                row = row.iloc[0]
                _draw_stacked_bar_cell(
                    ax, j, i, 1, 1,
                    found_rate=row["fail_rate"],
                    not_found_rate=row["pass_rate"],
                    uncertain_rate=row["inc_rate"]
                )

    # Configure axes
    ax.set_xlim(0, n_effects)
    ax.set_ylim(0, n_tools)
    ax.set_xticks([x + 0.5 for x in range(n_effects)])
    ax.set_yticks([y + 0.5 for y in range(n_tools)])
    ax.set_xticklabels([EFFECT_NAMES.get(e, str(e)) for e in effects_present])
    tool_labels = [_format_tool_label_with_threshold(t, tacet_threshold_ns) for t in tools_present]
    ax.set_yticklabels(tool_labels)
    ax.invert_yaxis()

    ax.set_xlabel("Effect Size (σ)")
    ax.set_ylabel("Tool")
    ax.set_title(
        f"Detection Power by Effect Size\n"
        f"(noise: {NOISE_NAMES[noise_model]}, pattern: {effect_pattern})",
        pad=10,
    )

    # Add legend
    legend_elements = [
        plt.Rectangle((0,0), 1, 1, facecolor=VERDICT_COLORS["found"], edgecolor=COLORS["border"], label="Effect found"),
        plt.Rectangle((0,0), 1, 1, facecolor=VERDICT_COLORS["not_found"], edgecolor=COLORS["border"], label="Effect not found"),
        plt.Rectangle((0,0), 1, 1, facecolor=VERDICT_COLORS["uncertain"], edgecolor=COLORS["border"], label="Couldn't determine"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", bbox_to_anchor=(1.02, 1), frameon=False)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_fpr_heatmap(
    raw_df: pd.DataFrame,
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 100.0,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (10, 5),
) -> plt.Figure:
    """Create heatmap of false positive rates: Autocorrelation × Tool.

    Each cell contains a mini stacked bar showing the proportion of:
    - Effect found (blue) = false positive under null hypothesis
    - Effect not found (gray) = correct
    - Couldn't determine (purple)

    Args:
        raw_df: Raw benchmark data with verdict column
        effect_pattern: Fixed effect pattern (default: shift)
        tacet_threshold_ns: Tacet threshold to use (default: 100ns)
        output_path: Path to save figure
        figsize: Figure size in inches

    Returns:
        matplotlib Figure
    """
    setup_paper_style()

    # Filter to null effect (effect = 0)
    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    # Filter tacet to specific threshold
    tacet_mask = df["tool"] == "tacet"
    threshold_mask = df["attacker_threshold_ns"] == tacet_threshold_ns
    df = df[~tacet_mask | (tacet_mask & threshold_mask)]

    # Aggregate by tool and noise model to get verdict proportions
    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        pass_rate=("verdict", lambda x: (x == "pass").mean()),
        fail_rate=("verdict", lambda x: (x == "fail").mean()),
        inc_rate=("verdict", lambda x: (x == "inconclusive").mean()),
    ).reset_index()

    # Reorder tools and noise models
    tools_present = [t for t in PRIMARY_TOOLS if t in agg["tool"].unique()]
    noise_present = [n for n in NOISE_ORDER if n in agg["noise_model"].unique()]

    # Filter out negative autocorrelation (focus on non-negative: iid and positive ρ)
    noise_present = [n for n in noise_present if not n.startswith("ar1-n")]

    # Create figure
    fig, ax = plt.subplots(figsize=figsize)

    n_tools = len(tools_present)
    n_noise = len(noise_present)

    # Draw cell backgrounds and stacked bars
    for i, tool in enumerate(tools_present):
        for j, noise in enumerate(noise_present):
            # Draw cell background
            rect = plt.Rectangle((j, i), 1, 1, facecolor="white",
                                 edgecolor=COLORS["border"], linewidth=0.5)
            ax.add_patch(rect)

            # Get data for this cell
            row = agg[(agg["tool"] == tool) & (agg["noise_model"] == noise)]
            if len(row) > 0:
                row = row.iloc[0]
                _draw_stacked_bar_cell(
                    ax, j, i, 1, 1,
                    found_rate=row["fail_rate"],
                    not_found_rate=row["pass_rate"],
                    uncertain_rate=row["inc_rate"]
                )

    # Configure axes
    ax.set_xlim(0, n_noise)
    ax.set_ylim(0, n_tools)
    ax.set_xticks([x + 0.5 for x in range(n_noise)])
    ax.set_yticks([y + 0.5 for y in range(n_tools)])
    ax.set_xticklabels([NOISE_NAMES.get(n, n) for n in noise_present], rotation=45, ha="right")
    tool_labels = [_format_tool_label_with_threshold(t, tacet_threshold_ns) for t in tools_present]
    ax.set_yticklabels(tool_labels)
    ax.invert_yaxis()

    ax.set_xlabel("Autocorrelation Structure")
    ax.set_ylabel("Tool")
    ax.set_title(
        f"False Positive Rate by Autocorrelation\n"
        f"(null effect, pattern: {effect_pattern}, nominal α=5%)",
        pad=10,
    )

    # Add legend
    legend_elements = [
        plt.Rectangle((0,0), 1, 1, facecolor=VERDICT_COLORS["found"], edgecolor=COLORS["border"], label="Effect found (FP)"),
        plt.Rectangle((0,0), 1, 1, facecolor=VERDICT_COLORS["not_found"], edgecolor=COLORS["border"], label="Effect not found"),
        plt.Rectangle((0,0), 1, 1, facecolor=VERDICT_COLORS["uncertain"], edgecolor=COLORS["border"], label="Couldn't determine"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", bbox_to_anchor=(1.02, 1), frameon=False)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_verdict_distribution(
    raw_df: pd.DataFrame,
    effect_sigma_mult: float = 0.2,
    effect_pattern: str = "shift",
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (14, 6),
) -> plt.Figure:
    """Create stacked bar chart of verdict distribution by tool and noise.

    Args:
        raw_df: Raw benchmark results with verdict column
        effect_sigma_mult: Fixed effect size (default: 0.2σ, challenging)
        effect_pattern: Fixed effect pattern (default: shift)
        output_path: Path to save figure
        figsize: Figure size in inches

    Returns:
        matplotlib Figure
    """
    setup_paper_style()

    # Filter data
    df = raw_df[
        (raw_df["effect_sigma_mult"] == effect_sigma_mult)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    # For tacet, show both thresholds - create separate entries
    tacet_df = df[df["tool"] == "tacet"].copy()
    non_tacet_df = df[df["tool"] != "tacet"].copy()

    # Rename tacet entries to show threshold
    tacet_04 = tacet_df[tacet_df["attacker_threshold_ns"] == 0.4].copy()
    tacet_04["tool"] = "Tacet (0.4ns)"
    tacet_100 = tacet_df[tacet_df["attacker_threshold_ns"] == 100].copy()
    tacet_100["tool"] = "Tacet (100ns)"

    # Combine and rename tools
    non_tacet_df["tool"] = non_tacet_df["tool"].map(TOOL_NAMES)
    df_combined = pd.concat([non_tacet_df, tacet_04, tacet_100], ignore_index=True)

    # Aggregate by tool and noise_model
    agg = df_combined.groupby(["tool", "noise_model", "verdict"]).size().unstack(fill_value=0)
    agg = agg.div(agg.sum(axis=1), axis=0)  # Convert to proportions

    # Ensure all verdict columns exist
    for v in ["pass", "fail", "inconclusive"]:
        if v not in agg.columns:
            agg[v] = 0

    # Tool order for this plot (including tacet variants)
    tool_order = [
        "Tacet (100ns)",
        "Tacet (0.4ns)",
        "SILENT",
        "RTLF",
        "dudect",
        "TVLA",
        "AD Test",
        "KS Test",
        "MONA",
    ]

    # Create figure with subplots for each noise model
    # Note: Not using sharey=True because it suppresses y-axis labels
    fig, axes = plt.subplots(1, len(NOISE_ORDER), figsize=figsize)

    # Pre-compute the tool order for consistent y-axis
    all_tools = []
    for noise in NOISE_ORDER:
        if noise in agg.index.get_level_values("noise_model"):
            noise_data = agg.xs(noise, level="noise_model", drop_level=True)
            tools_present = [t for t in tool_order if t in noise_data.index]
            if len(tools_present) > len(all_tools):
                all_tools = tools_present

    for i, noise in enumerate(NOISE_ORDER):
        ax = axes[i]

        # Get data for this noise model
        if noise not in agg.index.get_level_values("noise_model"):
            ax.set_title(NOISE_NAMES[noise], fontsize=9)
            ax.set_visible(False)
            continue

        noise_data = agg.xs(noise, level="noise_model", drop_level=True)

        # Reorder tools
        tools_present = [t for t in tool_order if t in noise_data.index]
        noise_data = noise_data.reindex(tools_present)

        # Create stacked bar
        bottom = np.zeros(len(noise_data))
        bar_width = 0.8

        # Plot in order with semantic labels and neutral colors:
        # - fail (effect found) → blue (neutral)
        # - pass (effect not found) → gray (neutral)
        # - inconclusive (couldn't determine) → amber
        verdict_config = [
            ("fail", VERDICT_COLORS["found"], "Effect found"),
            ("pass", VERDICT_COLORS["not_found"], "Effect not found"),
            ("inconclusive", VERDICT_COLORS["uncertain"], "Couldn't determine"),
        ]
        for verdict, color, label in verdict_config:
            if verdict in noise_data.columns:
                values = noise_data[verdict].values
                ax.barh(range(len(noise_data)), values, left=bottom, color=color, label=label, height=bar_width)
                bottom += values

        ax.set_xlim(0, 1)
        ax.set_yticks(range(len(noise_data)))
        ax.set_title(NOISE_NAMES[noise], fontsize=9)
        ax.set_xlabel("Proportion" if i == len(NOISE_ORDER) // 2 else "")

        # Only show y-axis labels on leftmost subplot
        if i == 0:
            ax.set_yticklabels(list(noise_data.index), fontsize=9)
            ax.tick_params(axis='y', which='both', length=0)
        else:
            ax.set_yticklabels([])

        # Grid
        ax.set_axisbelow(True)
        ax.xaxis.grid(True, color=COLORS["grid"], linestyle="-", linewidth=0.5)

    # Add legend
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.02))

    fig.suptitle(
        f"Verdict Distribution by Tool and Autocorrelation\n"
        f"(effect: {EFFECT_NAMES[effect_sigma_mult]}, pattern: {effect_pattern})",
        y=1.08,
    )

    plt.subplots_adjust(left=0.12, right=0.98, wspace=0.08)

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_power_curves(
    summary_df: pd.DataFrame,
    noise_model: str = "iid",
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 100.0,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (8, 5),
) -> plt.Figure:
    """Create line plot of power curves across effect sizes.

    Args:
        summary_df: Summary data with detection rates
        noise_model: Fixed noise model
        effect_pattern: Fixed effect pattern
        tacet_threshold_ns: Tacet threshold to use
        output_path: Path to save figure
        figsize: Figure size in inches

    Returns:
        matplotlib Figure
    """
    setup_paper_style()

    # Filter data
    df = summary_df[
        (summary_df["noise_model"] == noise_model)
        & (summary_df["effect_pattern"] == effect_pattern)
    ].copy()

    # Filter tacet to specific threshold
    tacet_mask = df["tool"] == "tacet"
    threshold_mask = df["attacker_threshold_ns"] == tacet_threshold_ns
    df = df[~tacet_mask | (tacet_mask & threshold_mask)]

    # Create figure
    fig, ax = plt.subplots(figsize=figsize)

    # Define colors for tools
    tool_colors = {
        "tacet": COLORS["pass"],
        "silent-native": "#9b59b6",  # Purple
        "rtlf-native": "#3498db",    # Blue
        "dudect": "#e67e22",         # Orange
        "timing-tvla": "#1abc9c",    # Teal
        "ad-test": "#95a5a6",        # Gray
        "ks-test": "#7f8c8d",        # Dark gray
        "mona": "#bdc3c7",           # Light gray
    }

    # Plot each tool
    for tool in PRIMARY_TOOLS:
        tool_df = df[df["tool"] == tool].sort_values("effect_sigma_mult")
        if len(tool_df) == 0:
            continue

        x = tool_df["effect_sigma_mult"]
        y = tool_df["detection_rate"]
        ci_low = tool_df["ci_low"]
        ci_high = tool_df["ci_high"]

        color = tool_colors.get(tool, "#ffffff")
        label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)

        # Plot line with CI band
        ax.plot(x, y, marker="o", label=label, color=color, linewidth=2, markersize=6)
        ax.fill_between(x, ci_low, ci_high, alpha=0.2, color=color)

    ax.set_xlabel("Effect Size (σ)")
    ax.set_ylabel("Detection Rate")
    ax.set_title(
        f"Power Curves by Effect Size\n"
        f"(noise: {NOISE_NAMES[noise_model]}, pattern: {effect_pattern})"
    )
    ax.set_ylim(-0.05, 1.05)
    # Use symmetric log scale to show detail at small effect sizes while handling 0
    ax.set_xscale("symlog", linthresh=0.1)
    ax.set_xlim(-0.05, 25)
    ax.legend(loc="lower right", fontsize=8)

    # Reference lines
    ax.axhline(y=0.05, color=COLORS["fail"], linestyle="--", alpha=0.5, label="α=5%")
    ax.axhline(y=0.80, color=COLORS["pass"], linestyle="--", alpha=0.5, label="80% power")

    ax.grid(True, color=COLORS["grid"], linestyle="-", linewidth=0.5)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_shift_vs_tail(
    summary_df: pd.DataFrame,
    noise_model: str = "iid",
    tacet_threshold_ns: float = 100.0,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (10, 5),
) -> plt.Figure:
    """Compare detection rates for shift vs tail patterns.

    Args:
        summary_df: Summary data with detection rates
        noise_model: Fixed noise model
        tacet_threshold_ns: Tacet threshold to use
        output_path: Path to save figure
        figsize: Figure size in inches

    Returns:
        matplotlib Figure
    """
    setup_paper_style()

    # Filter data
    df = summary_df[summary_df["noise_model"] == noise_model].copy()

    # Filter tacet to specific threshold
    tacet_mask = df["tool"] == "tacet"
    threshold_mask = df["attacker_threshold_ns"] == tacet_threshold_ns
    df = df[~tacet_mask | (tacet_mask & threshold_mask)]

    # Create figure with two subplots
    fig, axes = plt.subplots(1, 2, figsize=figsize, sharey=True)

    for i, pattern in enumerate(["shift", "tail"]):
        ax = axes[i]
        pattern_df = df[df["effect_pattern"] == pattern]

        # Pivot for heatmap
        pivot = pattern_df.pivot_table(
            index="tool",
            columns="effect_sigma_mult",
            values="detection_rate",
            aggfunc="first",
        )

        # Reorder
        tools_present = [t for t in PRIMARY_TOOLS if t in pivot.index]
        effects_present = [e for e in EFFECT_ORDER if e in pivot.columns]
        pivot = pivot.reindex(index=tools_present, columns=effects_present)

        # Rename for display, including threshold for tacet/silent
        tool_label_map = {t: _format_tool_label_with_threshold(t, tacet_threshold_ns) for t in pivot.index}
        pivot.index = pivot.index.map(tool_label_map)
        pivot.columns = pivot.columns.map(EFFECT_NAMES)

        # Create colormap
        cmap = sns.diverging_palette(10, 130, s=80, l=55, as_cmap=True)

        # Plot heatmap
        sns.heatmap(
            pivot,
            annot=True,
            fmt=".0%",
            cmap=cmap,
            center=0.5,
            vmin=0,
            vmax=1,
            linewidths=0.5,
            linecolor=COLORS["grid"],
            cbar=i == 1,
            cbar_kws={"label": "Detection Rate", "shrink": 0.8} if i == 1 else {},
            ax=ax,
        )

        ax.set_xlabel("Effect Size (σ)")
        ax.set_ylabel("Tool" if i == 0 else "")
        ax.set_title(f"{pattern.capitalize()} Pattern")

    fig.suptitle(
        f"Shift vs Tail Pattern Detection\n(noise: {NOISE_NAMES[noise_model]})",
        y=1.02,
    )

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


# ---------------------------------------------------------------------------
# Alternative autocorrelation visualizations (prototypes)
# ---------------------------------------------------------------------------


def plot_fpr_line_with_ci(
    raw_df: pd.DataFrame,
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 0.4,
    tools: Optional[list[str]] = None,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (8, 5),
) -> plt.Figure:
    """Line plot of FPR vs autocorrelation with confidence bands.

    Shows false positive rate as autocorrelation increases, with one line
    per tool and shaded confidence intervals.
    """
    setup_paper_style()

    if tools is None:
        tools = list(PRIMARY_TOOLS)

    # Filter to null effect, specified pattern
    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    df = _filter_by_threshold(df, tacet_threshold_ns)
    df = df[df["tool"].isin(tools)]

    # Get positive autocorrelation only (iid + ar1-0.X)
    noise_order = ["iid", "ar1-0.2", "ar1-0.4", "ar1-0.6", "ar1-0.8"]
    df = df[df["noise_model"].isin(noise_order)]

    # Aggregate by tool and noise model
    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        n_fail=("verdict", lambda x: (x == "fail").sum()),
    ).reset_index()
    agg["fpr"] = agg["n_fail"] / agg["n_trials"]

    # Wilson CIs
    agg["ci_low"] = agg.apply(lambda r: _wilson_ci(int(r["n_fail"]), int(r["n_trials"]))[0], axis=1)
    agg["ci_high"] = agg.apply(lambda r: _wilson_ci(int(r["n_fail"]), int(r["n_trials"]))[1], axis=1)

    # Create figure
    fig, ax = plt.subplots(figsize=figsize)

    # Map noise models to numeric x-values
    noise_to_rho = {"iid": 0, "ar1-0.2": 0.2, "ar1-0.4": 0.4, "ar1-0.6": 0.6, "ar1-0.8": 0.8}

    for tool in tools:
        tool_df = agg[agg["tool"] == tool].copy()
        if len(tool_df) == 0:
            continue

        # Sort by autocorrelation strength
        tool_df["rho"] = tool_df["noise_model"].map(noise_to_rho)
        tool_df = tool_df.sort_values("rho")

        x = tool_df["rho"].values
        y = tool_df["fpr"].values * 100  # Convert to percentage
        ci_low = tool_df["ci_low"].values * 100
        ci_high = tool_df["ci_high"].values * 100

        color = PRIMARY_TOOL_COLORS.get(tool, "#999999")
        label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)

        # Plot line with markers
        ax.plot(x, y, marker="o", label=label, color=color, linewidth=2, markersize=6)
        ax.fill_between(x, ci_low, ci_high, alpha=0.2, color=color)

    # Reference line at 5%
    ax.axhline(y=5, color=COLORS["fail"], linestyle="--", linewidth=1, alpha=0.7,
               label="Nominal α = 5%")

    ax.set_xlabel("Autocorrelation (ρ)")
    ax.set_ylabel("False Positive Rate (%)")
    ax.set_title("False Positive Rate vs. Autocorrelation Strength")
    ax.set_xlim(-0.05, 0.85)
    ax.set_ylim(-2, 45)
    ax.set_xticks([0, 0.2, 0.4, 0.6, 0.8])
    ax.set_xticklabels(["0\n(i.i.d.)", "0.2", "0.4", "0.6", "0.8"])
    ax.legend(loc="upper left", frameon=False, fontsize=9)
    ax.grid(True, alpha=0.3, linestyle="--", linewidth=0.5)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_fpr_slope_graph(
    raw_df: pd.DataFrame,
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 0.4,
    tools: Optional[list[str]] = None,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (10, 6),
) -> plt.Figure:
    """Slope graph showing FPR trajectory from iid → moderate → strong autocorrelation.

    Tufte-style visualization with three columns (iid, ρ=0.4, ρ=0.8) showing
    how each tool's FPR changes as autocorrelation increases.
    """
    setup_paper_style()

    if tools is None:
        tools = list(PRIMARY_TOOLS)

    # Filter to null effect, specified pattern
    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    df = _filter_by_threshold(df, tacet_threshold_ns)
    df = df[df["tool"].isin(tools)]

    # Get three key points
    noise_points = ["iid", "ar1-0.4", "ar1-0.8"]
    df = df[df["noise_model"].isin(noise_points)]

    # Aggregate by tool and noise model
    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        n_fail=("verdict", lambda x: (x == "fail").sum()),
    ).reset_index()
    agg["fpr"] = agg["n_fail"] / agg["n_trials"]

    # Pivot to get one row per tool
    pivot = agg.pivot(index="tool", columns="noise_model", values="fpr")
    pivot = pivot.reindex(index=tools, columns=noise_points)

    # Create figure
    fig, ax = plt.subplots(figsize=figsize)

    # Column positions
    x_positions = [0, 1, 2]
    x_labels = ["i.i.d.\n(ρ = 0)", "Moderate\n(ρ = 0.4)", "Strong\n(ρ = 0.8)"]

    # Draw lines for each tool
    for i, tool in enumerate(tools):
        if tool not in pivot.index:
            continue

        values = pivot.loc[tool].values * 100  # Convert to percentage

        # Skip if missing data
        if any(pd.isna(values)):
            continue

        color = PRIMARY_TOOL_COLORS.get(tool, "#999999")
        label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)

        # Draw line connecting the three points
        ax.plot(x_positions, values, marker="o", color=color, linewidth=2,
                markersize=8, alpha=0.8, zorder=2)

        # Add text labels at endpoints
        # Left side
        ax.text(-0.15, values[0], f"{values[0]:.1f}%",
                ha="right", va="center", fontsize=9, color=color, fontweight="medium")

        # Right side with tool name
        ax.text(2.15, values[2], f"{values[2]:.1f}%  {label}",
                ha="left", va="center", fontsize=9, color=color, fontweight="medium")

    # Reference line at 5%
    ax.axhline(y=5, color=COLORS["fail"], linestyle=":", linewidth=1.5, alpha=0.5,
               zorder=1, label="Nominal α = 5%")

    # Styling
    ax.set_xlim(-0.3, 2.6)
    ax.set_ylim(-2, 42)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(x_labels)
    ax.set_ylabel("False Positive Rate (%)")
    ax.set_title("FPR Trajectory Under Increasing Autocorrelation", pad=15)

    # Clean up axes
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.tick_params(left=False)
    ax.yaxis.grid(True, alpha=0.3, linestyle="--", linewidth=0.5, zorder=0)
    ax.set_axisbelow(True)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_fpr_small_multiples(
    raw_df: pd.DataFrame,
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 0.4,
    tools: Optional[list[str]] = None,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (12, 8),
) -> plt.Figure:
    """Small multiples: one mini line plot per tool showing FPR trajectory.

    Grid layout with each tool in its own subplot, making individual
    trajectories crystal clear without any overlap.
    """
    setup_paper_style()

    if tools is None:
        tools = list(PRIMARY_TOOLS)

    # Filter to null effect, specified pattern
    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    df = _filter_by_threshold(df, tacet_threshold_ns)
    df = df[df["tool"].isin(tools)]

    # Get positive autocorrelation only (iid + ar1-0.X)
    noise_order = ["iid", "ar1-0.2", "ar1-0.4", "ar1-0.6", "ar1-0.8"]
    df = df[df["noise_model"].isin(noise_order)]

    # Aggregate by tool and noise model
    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        n_fail=("verdict", lambda x: (x == "fail").sum()),
    ).reset_index()
    agg["fpr"] = agg["n_fail"] / agg["n_trials"]

    # Map noise models to numeric x-values
    noise_to_rho = {"iid": 0, "ar1-0.2": 0.2, "ar1-0.4": 0.4, "ar1-0.6": 0.6, "ar1-0.8": 0.8}

    # Create grid (3 rows × 3 columns, with one empty cell)
    n_tools = len(tools)
    n_cols = 3
    n_rows = (n_tools + n_cols - 1) // n_cols

    fig, axes = plt.subplots(n_rows, n_cols, figsize=figsize, sharex=True, sharey=True)
    axes = axes.flatten()

    for idx, tool in enumerate(tools):
        ax = axes[idx]
        tool_df = agg[agg["tool"] == tool].copy()

        if len(tool_df) == 0:
            ax.set_visible(False)
            continue

        # Sort by autocorrelation strength
        tool_df["rho"] = tool_df["noise_model"].map(noise_to_rho)
        tool_df = tool_df.sort_values("rho")

        x = tool_df["rho"].values
        y = tool_df["fpr"].values * 100  # Convert to percentage

        color = PRIMARY_TOOL_COLORS.get(tool, "#999999")
        label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)

        # Plot line with area fill
        ax.plot(x, y, marker="o", color=color, linewidth=2, markersize=4)
        ax.fill_between(x, 0, y, alpha=0.2, color=color)

        # Shade acceptable zone (<5%)
        ax.axhspan(0, 5, alpha=0.1, color="#10b981", zorder=0)

        # Reference line at 5%
        ax.axhline(y=5, color=COLORS["fail"], linestyle="--", linewidth=0.8,
                   alpha=0.5, zorder=1)

        ax.set_title(label, fontsize=10, fontweight="medium", color=color)
        ax.set_ylim(-1, 42)
        ax.set_xlim(-0.05, 0.85)
        ax.grid(True, alpha=0.2, linestyle="--", linewidth=0.5)

    # Hide unused subplots
    for idx in range(n_tools, len(axes)):
        axes[idx].set_visible(False)

    # Set x-axis labels only on bottom row
    for idx in range(n_cols * (n_rows - 1), n_tools):
        axes[idx].set_xlabel("Autocorrelation (ρ)", fontsize=9)
        axes[idx].set_xticks([0, 0.2, 0.4, 0.6, 0.8])
        axes[idx].set_xticklabels(["0", "0.2", "0.4", "0.6", "0.8"])

    # Set y-axis label only on leftmost column
    for idx in range(0, n_tools, n_cols):
        axes[idx].set_ylabel("FPR (%)", fontsize=9)

    fig.suptitle("False Positive Rate Under Increasing Autocorrelation", y=0.995, fontsize=12)
    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_fpr_grouped_bars_stages(
    raw_df: pd.DataFrame,
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 0.4,
    tools: Optional[list[str]] = None,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (12, 6),
) -> plt.Figure:
    """Grouped bar chart showing FPR at three autocorrelation stages.

    Three groups (iid, ρ=0.4, ρ=0.8) with side-by-side bars for each tool.
    Makes before/middle/after comparison extremely clear.
    """
    setup_paper_style()

    if tools is None:
        tools = list(PRIMARY_TOOLS)

    # Filter to null effect, specified pattern
    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    df = _filter_by_threshold(df, tacet_threshold_ns)
    df = df[df["tool"].isin(tools)]

    # Get three key stages
    noise_stages = ["iid", "ar1-0.4", "ar1-0.8"]
    stage_labels = ["i.i.d.\n(ρ = 0)", "Moderate\n(ρ = 0.4)", "Strong\n(ρ = 0.8)"]
    df = df[df["noise_model"].isin(noise_stages)]

    # Aggregate by tool and noise model
    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        n_fail=("verdict", lambda x: (x == "fail").sum()),
    ).reset_index()
    agg["fpr"] = agg["n_fail"] / agg["n_trials"] * 100  # Percentage

    # Create figure
    fig, ax = plt.subplots(figsize=figsize)

    n_stages = len(noise_stages)
    n_tools = len(tools)
    bar_width = 0.11
    group_spacing = 0.3
    group_width = n_tools * bar_width

    for stage_idx, (noise, label) in enumerate(zip(noise_stages, stage_labels)):
        stage_data = agg[agg["noise_model"] == noise]

        for tool_idx, tool in enumerate(tools):
            tool_data = stage_data[stage_data["tool"] == tool]

            if len(tool_data) == 0:
                fpr = 0
            else:
                fpr = tool_data.iloc[0]["fpr"]

            # Calculate position
            x_pos = stage_idx * (group_width + group_spacing) + tool_idx * bar_width

            color = PRIMARY_TOOL_COLORS.get(tool, "#999999")
            tool_label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)

            # Draw bar (only label once for legend)
            label_text = tool_label if stage_idx == 0 else ""
            bar = ax.bar(x_pos, fpr, bar_width, color=color, label=label_text,
                        edgecolor="white", linewidth=0.5)

            # Add value label on top if > 1%
            if fpr > 1:
                ax.text(x_pos, fpr + 0.5, f"{fpr:.0f}%", ha="center", va="bottom",
                       fontsize=7, color=color, fontweight="medium")

    # Reference line at 5%
    ax.axhline(y=5, color=COLORS["fail"], linestyle="--", linewidth=1, alpha=0.6,
               label="Nominal α = 5%", zorder=0)

    # Set x-axis labels (centered on each group)
    group_centers = [(i * (group_width + group_spacing) + group_width / 2)
                     for i in range(n_stages)]
    ax.set_xticks(group_centers)
    ax.set_xticklabels(stage_labels)

    ax.set_ylabel("False Positive Rate (%)")
    ax.set_title("FPR Comparison Across Autocorrelation Stages")
    ax.set_ylim(0, 44)
    ax.legend(loc="upper left", frameon=False, fontsize=9, ncol=2)
    ax.grid(axis="y", alpha=0.3, linestyle="--", linewidth=0.5, zorder=0)
    ax.set_axisbelow(True)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_fpr_heatmap_seaborn(
    raw_df: pd.DataFrame,
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 0.4,
    tools: Optional[list[str]] = None,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (10, 6),
) -> plt.Figure:
    """EDA-style FPR heatmap with seaborn color gradient and percentage values.

    Traditional seaborn heatmap with:
    - Color gradient (green to red)
    - Percentage values in each cell
    - Tools on y-axis, noise models on x-axis
    - Filtered to primary tools and non-negative autocorrelation
    """
    setup_paper_style()

    if tools is None:
        tools = list(PRIMARY_TOOLS)

    # Filter to null effect, specified pattern
    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    df = _filter_by_threshold(df, tacet_threshold_ns)
    df = df[df["tool"].isin(tools)]

    # Get positive autocorrelation only (iid + ar1-0.X)
    from tacet_analysis.utils import NOISE_ORDER_THOROUGH, NOISE_NAMES
    noise_order = ["iid", "ar1-0.2", "ar1-0.4", "ar1-0.6", "ar1-0.8"]
    df = df[df["noise_model"].isin(noise_order)]

    # Aggregate by tool and noise model
    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        n_fail=("verdict", lambda x: (x == "fail").sum()),
    ).reset_index()
    agg["fpr"] = agg["n_fail"] / agg["n_trials"]

    # Pivot for heatmap
    pivot = agg.pivot_table(
        index="tool",
        columns="noise_model",
        values="fpr",
        aggfunc="first",
    )

    # Reorder
    tools_present = [t for t in tools if t in pivot.index]
    noise_present = [n for n in noise_order if n in pivot.columns]
    pivot = pivot.reindex(index=tools_present, columns=noise_present)

    # Rename for display
    tool_label_map = {t: _format_tool_label_with_threshold(t, tacet_threshold_ns) for t in pivot.index}
    pivot.index = pivot.index.map(tool_label_map)
    pivot.columns = pivot.columns.map(NOISE_NAMES)

    # Create figure
    fig, ax = plt.subplots(figsize=figsize)

    # Match the original EDA script: simple green-to-red gradient
    # Use seaborn's default RdYlGn reversed
    sns.heatmap(
        pivot,
        annot=True,
        fmt=".0%",
        cmap="RdYlGn_r",  # Standard matplotlib/seaborn colormap
        vmin=0,
        vmax=0.5,
        linewidths=0.5,
        linecolor="#cccccc",
        cbar=True,
        cbar_kws={"label": "FPR"},
        ax=ax,
    )

    ax.set_xlabel("Autocorrelation Structure")
    ax.set_ylabel("Tool")
    ax.set_title(f"False Positive Rate at Null Effect ({effect_pattern} pattern)")

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def generate_all_figures(
    raw_df: Optional[pd.DataFrame] = None,
    summary_df: Optional[pd.DataFrame] = None,
    output_dir: Optional[Path] = None,
) -> dict[str, plt.Figure]:
    """Generate all figures for the paper.

    Args:
        raw_df: Raw benchmark results
        summary_df: Summary data
        output_dir: Directory to save figures

    Returns:
        Dictionary mapping figure names to Figure objects
    """
    if raw_df is None:
        raw_df = load_benchmark_data()
    if summary_df is None:
        summary_df = load_summary_data()
    if output_dir is None:
        output_dir = FIGURES_DIR

    output_dir.mkdir(parents=True, exist_ok=True)

    figures = {}

    # v1 paper figures (current figures in the paper)
    # Note: v1-fig3 (tail power curve) is generated by generate_tail_power_curves.py
    print("\nGenerating v1 paper figures...")

    figures["v1_fig1"] = plot_fpr_heatmap(
        raw_df,
        effect_pattern="shift",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "v1-fig1_fpr_heatmap.png",
    )

    figures["v1_fig2"] = plot_power_heatmap(
        raw_df,
        noise_model="ar1-0.6",
        effect_pattern="shift",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "v1-fig2_power_heatmap.png",
    )

    # Extra/supplementary figures (not in paper)
    print("\nGenerating extra figures...")

    figures["extra_verdict_distribution"] = plot_verdict_distribution(
        raw_df,
        effect_sigma_mult=0.2,
        effect_pattern="shift",
        output_path=output_dir / "extra-verdict_distribution.png",
    )

    figures["extra_power_curves_iid"] = plot_power_curves(
        summary_df,
        noise_model="iid",
        effect_pattern="shift",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "extra-power_curves_iid.png",
    )

    figures["extra_power_curves_ar1"] = plot_power_curves(
        summary_df,
        noise_model="ar1-0.6",
        effect_pattern="shift",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "extra-power_curves_ar1.png",
    )

    figures["extra_shift_vs_tail"] = plot_shift_vs_tail(
        summary_df,
        noise_model="iid",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "extra-shift_vs_tail.png",
    )

    figures["extra_power_heatmap_tail"] = plot_power_heatmap(
        raw_df,
        noise_model="iid",
        effect_pattern="tail",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "extra-heatmap_power_tail.png",
    )

    print(f"\nAll figures saved to {output_dir}")

    return figures


# ---------------------------------------------------------------------------
# New paper figures (v2) — added alongside existing functions
# ---------------------------------------------------------------------------


def _sigma_to_ns(sigma: float, ref_sigma_ns: float = 10.0) -> float:
    """Convert effect size in σ to nanoseconds at a reference noise level."""
    return sigma * ref_sigma_ns


def _format_ns_label(sigma: float, ref_sigma_ns: float) -> str:
    """Format nanosecond label from sigma value.

    Uses smart formatting:
    - 0σ → "0"
    - < 1ns → one decimal place (e.g., "0.5")
    - ≥ 1ns → integer (e.g., "5", "100")
    """
    if sigma == 0:
        return "0"
    ns = _sigma_to_ns(sigma, ref_sigma_ns)
    if ns < 1.0:
        return f"{ns:.1f}"
    else:
        return f"{ns:.0f}"


def _ns_to_sigma(ns: float, ref_sigma_ns: float = 10.0) -> float:
    """Convert nanoseconds to σ at a reference noise level."""
    return ns / ref_sigma_ns if ref_sigma_ns > 0 else 0.0


def _filter_by_threshold(df: pd.DataFrame, threshold_ns: float) -> pd.DataFrame:
    """Filter dataframe to keep one entry per tool: matching threshold or NaN.

    Tools like tacet and silent have multiple threshold entries (0.4ns, 100ns).
    This keeps the entry matching threshold_ns for those tools, and keeps all
    rows where attacker_threshold_ns is NaN (tools without threshold config).
    """
    has_threshold = df["attacker_threshold_ns"].notna()
    matches_threshold = df["attacker_threshold_ns"] == threshold_ns
    return df[~has_threshold | matches_threshold].copy()


def _wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for a binomial proportion."""
    if trials == 0:
        return (0.0, 0.0)
    p_hat = successes / trials
    denom = 1 + z**2 / trials
    center = (p_hat + z**2 / (2 * trials)) / denom
    half_width = z * np.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * trials)) / trials) / denom
    return (max(0.0, center - half_width), min(1.0, center + half_width))


def plot_fpr_grouped_bars(
    raw_df: pd.DataFrame,
    noise_models: Optional[list[str]] = None,
    tacet_threshold_ns: float = 0.4,
    tools: Optional[list[str]] = None,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (12, 5),
) -> plt.Figure:
    """Grouped bar chart of FPR by tool across autocorrelation levels.

    Each group is a noise model; within each group, one bar per tool showing FPR.
    Tacet's Inconclusive rate annotated above its bar.
    """
    setup_paper_style()

    if noise_models is None:
        noise_models = ["iid", "ar1-0.6", "ar1-0.8"]
    if tools is None:
        tools = list(PRIMARY_TOOLS)

    # Filter to null effect, shift pattern
    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == "shift")
    ].copy()

    df = _filter_by_threshold(df, tacet_threshold_ns)
    df = df[df["tool"].isin(tools)]

    # Aggregate by tool and noise model
    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        n_fail=("verdict", lambda x: (x == "fail").sum()),
        n_inc=("verdict", lambda x: (x == "inconclusive").sum()),
    ).reset_index()
    agg["fpr"] = agg["n_fail"] / agg["n_trials"]
    agg["inc_rate"] = agg["n_inc"] / agg["n_trials"]

    # Wilson CIs
    agg["ci_low"] = agg.apply(lambda r: _wilson_ci(int(r["n_fail"]), int(r["n_trials"]))[0], axis=1)
    agg["ci_high"] = agg.apply(lambda r: _wilson_ci(int(r["n_fail"]), int(r["n_trials"]))[1], axis=1)

    fig, ax = plt.subplots(figsize=figsize)

    n_groups = len(noise_models)
    n_tools = len(tools)
    bar_width = 0.8 / n_tools
    group_width = 1.0

    for i, tool in enumerate(tools):
        x_positions = []
        fprs = []
        ci_lows = []
        ci_highs = []
        inc_rates = []

        for j, noise in enumerate(noise_models):
            row = agg[(agg["tool"] == tool) & (agg["noise_model"] == noise)]
            x = j * group_width + i * bar_width
            x_positions.append(x)
            if len(row) > 0:
                r = row.iloc[0]
                fprs.append(r["fpr"])
                ci_lows.append(r["fpr"] - r["ci_low"])
                ci_highs.append(r["ci_high"] - r["fpr"])
                inc_rates.append(r["inc_rate"])
            else:
                fprs.append(0)
                ci_lows.append(0)
                ci_highs.append(0)
                inc_rates.append(0)

        color = PRIMARY_TOOL_COLORS.get(tool, "#999999")
        label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)
        bars = ax.bar(
            x_positions, fprs, bar_width,
            color=color, label=label, edgecolor="white", linewidth=0.5,
            yerr=[ci_lows, ci_highs], capsize=1.5, error_kw={"linewidth": 0.6},
        )

        # Hatch bars exceeding 5% FPR
        for bar, fpr_val in zip(bars, fprs):
            if fpr_val > 0.05:
                bar.set_hatch("//")
                bar.set_edgecolor(color)

        # Annotate Tacet's Inconclusive rate
        if tool == "tacet":
            for x_pos, inc_rate, fpr_val in zip(x_positions, inc_rates, fprs):
                if inc_rate > 0.01:
                    ax.annotate(
                        f"{inc_rate:.0%} Inc.",
                        xy=(x_pos, fpr_val + 0.008),
                        fontsize=8, ha="center", va="bottom",
                        color="#996600",
                        fontweight="bold",
                    )

    # Reference line at α=5%
    ax.axhline(y=0.05, color=COLORS["fail"], linestyle="--", linewidth=0.8, alpha=0.7,
               label="α = 5%", zorder=0)

    # Configure axes
    group_centers = [j * group_width + (n_tools - 1) * bar_width / 2 for j in range(n_groups)]
    ax.set_xticks(group_centers)
    ax.set_xticklabels([NOISE_NAMES.get(n, n) for n in noise_models])
    ax.set_xlabel("Autocorrelation structure")
    ax.set_ylabel("False positive rate")
    ax.set_ylim(0, min(0.55, ax.get_ylim()[1] * 1.1))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{y:.0%}"))

    # Legend to the right
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1))
    ax.grid(axis="y", linestyle="-", linewidth=0.4, alpha=0.5)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_power_curves_dual_panel(
    summary_df: pd.DataFrame,
    noise_model: str = "iid",
    tacet_threshold_ns: float = 0.4,
    tools: Optional[list[str]] = None,
    max_effect_sigma: float = 4.0,
    ref_sigma_ns: float = 5.0,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (12, 5),
) -> plt.Figure:
    """Two-panel power curves: shift (left) vs tail (right)."""
    setup_paper_style()

    if tools is None:
        tools = list(PRIMARY_TOOLS)

    fig, axes = plt.subplots(1, 2, figsize=figsize, sharey=True)

    patterns = ["shift", "tail"]
    panel_labels = ["(a) Shift", "(b) Tail (upper 5%)"]

    for panel_idx, (pattern, panel_label) in enumerate(zip(patterns, panel_labels)):
        ax = axes[panel_idx]

        df = summary_df[
            (summary_df["noise_model"] == noise_model)
            & (summary_df["effect_pattern"] == pattern)
            & (summary_df["effect_sigma_mult"] <= max_effect_sigma)
        ].copy()

        df = _filter_by_threshold(df, tacet_threshold_ns)
        df = df[df["tool"].isin(tools)]

        for tool in tools:
            tool_df = df[df["tool"] == tool].sort_values("effect_sigma_mult")
            if len(tool_df) == 0:
                continue

            x = tool_df["effect_sigma_mult"].values
            y = tool_df["detection_rate"].values
            ci_low = tool_df["ci_low"].values
            ci_high = tool_df["ci_high"].values

            color = PRIMARY_TOOL_COLORS.get(tool, "#999999")
            label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)

            ax.plot(x, y, marker="o", label=label, color=color,
                    linewidth=1.5, markersize=4)
            ax.fill_between(x, ci_low, ci_high, alpha=0.15, color=color)

        # Reference lines
        ax.axhline(y=0.05, color=COLORS["fail"], linestyle="--", linewidth=0.8, alpha=0.6)
        ax.axhline(y=0.80, color=COLORS["pass"], linestyle="--", linewidth=0.8, alpha=0.6)

        ax.set_xscale("symlog", linthresh=0.3, linscale=0.5)
        ax.set_xlim(-0.02, max_effect_sigma + 0.2)
        ax.set_ylim(-0.05, 1.05)
        ax.set_xlabel("Effect size (σ)")
        ax.set_title(panel_label)

        tick_vals = [e for e in EFFECT_ORDER_THOROUGH if e <= max_effect_sigma]
        ax.set_xticks(tick_vals)
        ax.set_xticklabels([EFFECT_NAMES.get(e, str(e)) for e in tick_vals])

        if panel_idx == 0:
            ax.set_ylabel("Detection rate")

        ax.grid(True, linestyle="-", linewidth=0.4, alpha=0.4)

        # Secondary ns axis
        ax_top = ax.twiny()
        ax_top.set_xscale("symlog", linthresh=0.3, linscale=0.5)
        ax_top.set_xlim(ax.get_xlim())
        ax_top.set_xticks(tick_vals)
        ns_labels = [_format_ns_label(e, ref_sigma_ns) for e in tick_vals]
        ax_top.set_xticklabels(ns_labels)
        ax_top.set_xlabel("ns (at σ = 5 ns)")

    # Legend to the right of the last panel
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper left", bbox_to_anchor=(1.02, 0.95))

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_verdict_breakdown(
    raw_df: pd.DataFrame,
    noise_models: Optional[list[str]] = None,
    effect_sizes: Optional[list[float]] = None,
    tacet_threshold_ns: float = 0.4,
    effect_pattern: str = "shift",
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (6, 6),
) -> plt.Figure:
    """Stacked bar showing Tacet's three-way verdict across conditions.

    Two row groups (noise models) × N effect sizes showing Pass/Fail/Inconclusive.

    Args:
        raw_df: Raw benchmark data with verdict column
        noise_models: Noise models to show (default: ["iid", "ar1-0.8"])
        effect_sizes: Effect sizes to show (default: [0, 0.2, 0.4, 1, 2, 4])
        tacet_threshold_ns: Tacet threshold
        effect_pattern: Effect pattern
        output_path: Path to save figure
        figsize: Figure size
    """
    setup_paper_style()

    if noise_models is None:
        noise_models = ["iid", "ar1-0.8"]
    if effect_sizes is None:
        effect_sizes = [0, 0.2, 0.4, 1, 2, 4]

    # Filter to Tacet only at specified threshold
    df = raw_df[
        (raw_df["tool"] == "tacet")
        & (raw_df["attacker_threshold_ns"] == tacet_threshold_ns)
        & (raw_df["effect_pattern"] == effect_pattern)
        & (raw_df["effect_sigma_mult"].isin(effect_sizes))
    ].copy()

    fig, axes = plt.subplots(len(noise_models), 1, figsize=figsize, sharex=True)
    if len(noise_models) == 1:
        axes = [axes]

    panel_labels = ["(a)", "(b)", "(c)", "(d)"]
    for row_idx, noise in enumerate(noise_models):
        ax = axes[row_idx]
        noise_df = df[df["noise_model"] == noise]

        agg = noise_df.groupby("effect_sigma_mult").agg(
            n=("verdict", "count"),
            pass_rate=("verdict", lambda x: (x == "pass").mean()),
            fail_rate=("verdict", lambda x: (x == "fail").mean()),
            inc_rate=("verdict", lambda x: (x == "inconclusive").mean()),
        ).reindex(effect_sizes).fillna(0)

        x = np.arange(len(effect_sizes))
        bar_width = 0.6

        pass_vals = agg["pass_rate"].values
        inc_vals = agg["inc_rate"].values
        fail_vals = agg["fail_rate"].values

        ax.bar(x, pass_vals, bar_width,
               color=VERDICT_COLORS["not_found"], label="Pass" if row_idx == 0 else "")
        ax.bar(x, inc_vals, bar_width, bottom=pass_vals,
               color=VERDICT_COLORS["uncertain"], label="Inconclusive" if row_idx == 0 else "")
        ax.bar(x, fail_vals, bar_width, bottom=pass_vals + inc_vals,
               color=VERDICT_COLORS["found"], label="Fail" if row_idx == 0 else "")

        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Proportion")
        noise_label = NOISE_NAMES.get(noise, noise)
        ax.set_title(f"{panel_labels[row_idx]} {noise_label}", loc="left")
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{y:.0%}"))
        ax.grid(axis="y", linestyle="-", linewidth=0.4, alpha=0.4)

    # X-axis labels on bottom subplot
    axes[-1].set_xticks(np.arange(len(effect_sizes)))
    axes[-1].set_xticklabels([EFFECT_NAMES.get(e, f"{e}σ") for e in effect_sizes])
    axes[-1].set_xlabel("Effect size (σ)")

    # Legend to the right
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper left", bbox_to_anchor=(1.02, 0.95))

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


# ---------------------------------------------------------------------------
# v3 figures — original chart types with targeted fixes only
# ---------------------------------------------------------------------------


def plot_fpr_heatmap_v3(
    raw_df: pd.DataFrame,
    effect_pattern: str = "shift",
    tacet_threshold_ns: float = 0.4,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (13, 6),
) -> plt.Figure:
    """FPR heatmap with numeric annotations for readability."""
    setup_paper_style()

    df = raw_df[
        (raw_df["effect_sigma_mult"] == 0)
        & (raw_df["effect_pattern"] == effect_pattern)
    ].copy()

    df = _filter_by_threshold(df, tacet_threshold_ns)

    agg = df.groupby(["tool", "noise_model"]).agg(
        n_trials=("verdict", "count"),
        pass_rate=("verdict", lambda x: (x == "pass").mean()),
        fail_rate=("verdict", lambda x: (x == "fail").mean()),
        inc_rate=("verdict", lambda x: (x == "inconclusive").mean()),
    ).reset_index()

    all_noise = agg["noise_model"].unique()
    from tacet_analysis.utils import NOISE_ORDER_THOROUGH
    noise_present = [n for n in NOISE_ORDER_THOROUGH if n in all_noise]
    if not noise_present:
        noise_present = [n for n in NOISE_ORDER if n in all_noise]

    # Filter out negative autocorrelation (focus on non-negative: iid and positive ρ)
    noise_present = [n for n in noise_present if not n.startswith("ar1-n")]

    tools_present = [t for t in PRIMARY_TOOLS if t in agg["tool"].unique()]

    fig, ax = plt.subplots(figsize=figsize)

    n_tools = len(tools_present)
    n_noise = len(noise_present)

    for i, tool in enumerate(tools_present):
        for j, noise in enumerate(noise_present):
            rect = plt.Rectangle((j, i), 1, 1, facecolor="white",
                                 edgecolor=COLORS["border"], linewidth=0.4)
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
                # Always use black text for better contrast with orange/teal backgrounds
                ax.text(j + 0.5, i + 0.5, label, ha="center", va="center",
                        fontsize=12, color=COLORS["text"], fontweight="medium")

    ax.set_xlim(0, n_noise)
    ax.set_ylim(0, n_tools)
    ax.set_xticks([x + 0.5 for x in range(n_noise)])
    ax.set_yticks([y + 0.5 for y in range(n_tools)])
    ax.set_xticklabels([NOISE_NAMES.get(n, n) for n in noise_present], fontsize=13)
    tool_labels = [_format_tool_label_with_threshold(t, tacet_threshold_ns) for t in tools_present]
    ax.set_yticklabels(tool_labels, fontsize=13)
    ax.invert_yaxis()

    ax.set_ylabel("Tool", fontsize=14)

    # Legend to the right
    legend_elements = [
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["found"], edgecolor=COLORS["border"], label="False positive"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["not_found"], edgecolor=COLORS["border"], label="Effect not found"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["uncertain"], edgecolor=COLORS["border"], label="Inconclusive"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", bbox_to_anchor=(1.02, 1), fontsize=13)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_power_heatmap_v3(
    raw_df: pd.DataFrame,
    noise_model: str = "ar1-0.6",
    tacet_threshold_ns: float = 0.4,
    ref_sigma_ns: float = 5.0,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (16, 6),
) -> plt.Figure:
    """Dual-panel power heatmap: shift (left) + tail (right)."""
    setup_paper_style()

    df = raw_df[raw_df["noise_model"] == noise_model].copy()
    df = _filter_by_threshold(df, tacet_threshold_ns)

    tools_present = [t for t in PRIMARY_TOOLS if t in df["tool"].unique()]

    effects_in_data = sorted(df["effect_sigma_mult"].unique())
    effects_present = [e for e in EFFECT_ORDER_PAPER if e in effects_in_data]
    if not effects_present:
        effects_present = [e for e in EFFECT_ORDER if e in effects_in_data]

    n_tools = len(tools_present)
    n_effects = len(effects_present)
    patterns = ["shift", "tail"]
    panel_labels = ["(a) Shift", "(b) Tail (upper 5%)"]

    fig, axes = plt.subplots(1, 2, figsize=figsize, sharey=True)

    for panel_idx, (pattern, panel_label) in enumerate(zip(patterns, panel_labels)):
        ax = axes[panel_idx]

        pattern_df = df[df["effect_pattern"] == pattern]
        agg = pattern_df.groupby(["tool", "effect_sigma_mult"]).agg(
            n_trials=("verdict", "count"),
            pass_rate=("verdict", lambda x: (x == "pass").mean()),
            fail_rate=("verdict", lambda x: (x == "fail").mean()),
            inc_rate=("verdict", lambda x: (x == "inconclusive").mean()),
        ).reset_index()

        for i, tool in enumerate(tools_present):
            for j, effect in enumerate(effects_present):
                rect = plt.Rectangle((j, i), 1, 1, facecolor="white",
                                     edgecolor=COLORS["border"], linewidth=0.4)
                ax.add_patch(rect)

                row = agg[(agg["tool"] == tool) & (agg["effect_sigma_mult"] == effect)]
                if len(row) > 0:
                    row = row.iloc[0]
                    _draw_stacked_bar_cell(
                        ax, j, i, 1, 1,
                        found_rate=row["fail_rate"],
                        not_found_rate=row["pass_rate"],
                        uncertain_rate=row["inc_rate"],
                    )

        ax.set_xlim(0, n_effects)
        ax.set_ylim(0, n_tools)

        ax.set_xticks([x + 0.5 for x in range(n_effects)])
        sigma_labels = [EFFECT_NAMES.get(e, str(e)) for e in effects_present]
        ax.set_xticklabels(sigma_labels, fontsize=13)
        ax.set_xlabel("Effect size (σ)", fontsize=14)

        # Secondary ns axis
        ax_top = ax.twiny()
        ax_top.set_xlim(0, n_effects)
        ax_top.set_xticks([x + 0.5 for x in range(n_effects)])
        ns_labels = [_format_ns_label(e, ref_sigma_ns) for e in effects_present]
        ax_top.set_xticklabels(ns_labels, fontsize=13)
        ax_top.set_xlabel("ns (at σ = 5 ns)", fontsize=14)

        ax.set_yticks([y + 0.5 for y in range(n_tools)])
        ax.set_title(panel_label, pad=20, fontsize=15)

        if panel_idx == 0:
            tool_labels = [_format_tool_label_with_threshold(t, tacet_threshold_ns) for t in tools_present]
            ax.set_yticklabels(tool_labels, fontsize=13)
            ax.set_ylabel("Tool", fontsize=14)

        ax.invert_yaxis()

    # Legend to the right
    legend_elements = [
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["found"], edgecolor=COLORS["border"], label="Effect found"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["not_found"], edgecolor=COLORS["border"], label="Effect not found"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["uncertain"], edgecolor=COLORS["border"], label="Inconclusive"),
    ]
    fig.legend(handles=legend_elements, loc="upper left", bbox_to_anchor=(1.02, 0.95), fontsize=13)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_power_heatmap_v3_trimodal(
    raw_df: pd.DataFrame,
    noise_model: str = "ar1-0.6",
    tacet_threshold_ns: float = 0.4,
    ref_sigma_ns: float = 5.0,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (24, 6),
) -> plt.Figure:
    """Triple-panel power heatmap: shift (left) + tail (middle) + bimodal (right)."""
    setup_paper_style()

    df = raw_df[raw_df["noise_model"] == noise_model].copy()
    df = _filter_by_threshold(df, tacet_threshold_ns)

    tools_present = [t for t in PRIMARY_TOOLS if t in df["tool"].unique()]

    effects_in_data = sorted(df["effect_sigma_mult"].unique())
    effects_present = [e for e in EFFECT_ORDER_PAPER if e in effects_in_data]
    if not effects_present:
        effects_present = [e for e in EFFECT_ORDER if e in effects_in_data]

    n_tools = len(tools_present)
    n_effects = len(effects_present)
    patterns = ["shift", "tail", "bimodal"]
    panel_labels = ["(a) Shift", "(b) Tail (upper 5%)", "(c) Bimodal"]

    fig, axes = plt.subplots(1, 3, figsize=figsize, sharey=True)

    for panel_idx, (pattern, panel_label) in enumerate(zip(patterns, panel_labels)):
        ax = axes[panel_idx]

        pattern_df = df[df["effect_pattern"] == pattern]
        agg = pattern_df.groupby(["tool", "effect_sigma_mult"]).agg(
            n_trials=("verdict", "count"),
            pass_rate=("verdict", lambda x: (x == "pass").mean()),
            fail_rate=("verdict", lambda x: (x == "fail").mean()),
            inc_rate=("verdict", lambda x: (x == "inconclusive").mean()),
        ).reset_index()

        for i, tool in enumerate(tools_present):
            for j, effect in enumerate(effects_present):
                rect = plt.Rectangle((j, i), 1, 1, facecolor="white",
                                     edgecolor=COLORS["border"], linewidth=0.4)
                ax.add_patch(rect)

                row = agg[(agg["tool"] == tool) & (agg["effect_sigma_mult"] == effect)]
                if len(row) > 0:
                    row = row.iloc[0]
                    _draw_stacked_bar_cell(
                        ax, j, i, 1, 1,
                        found_rate=row["fail_rate"],
                        not_found_rate=row["pass_rate"],
                        uncertain_rate=row["inc_rate"],
                    )

        ax.set_xlim(0, n_effects)
        ax.set_ylim(0, n_tools)

        ax.set_xticks([x + 0.5 for x in range(n_effects)])
        sigma_labels = [EFFECT_NAMES.get(e, str(e)) for e in effects_present]
        ax.set_xticklabels(sigma_labels, fontsize=13)
        ax.set_xlabel("Effect size (σ)", fontsize=14)

        # Secondary ns axis
        ax_top = ax.twiny()
        ax_top.set_xlim(0, n_effects)
        ax_top.set_xticks([x + 0.5 for x in range(n_effects)])
        ns_labels = [_format_ns_label(e, ref_sigma_ns) for e in effects_present]
        ax_top.set_xticklabels(ns_labels, fontsize=13)
        ax_top.set_xlabel("ns (at σ = 5 ns)", fontsize=14)

        ax.set_yticks([y + 0.5 for y in range(n_tools)])
        ax.set_title(panel_label, pad=20, fontsize=15)

        if panel_idx == 0:
            tool_labels = [_format_tool_label_with_threshold(t, tacet_threshold_ns) for t in tools_present]
            ax.set_yticklabels(tool_labels, fontsize=13)
            ax.set_ylabel("Tool", fontsize=14)

        ax.invert_yaxis()

    # Legend to the right
    legend_elements = [
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["found"], edgecolor=COLORS["border"], label="Effect found"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["not_found"], edgecolor=COLORS["border"], label="Effect not found"),
        plt.Rectangle((0, 0), 1, 1, facecolor=VERDICT_COLORS["uncertain"], edgecolor=COLORS["border"], label="Inconclusive"),
    ]
    fig.legend(handles=legend_elements, loc="upper left", bbox_to_anchor=(1.02, 0.95), fontsize=13)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def plot_power_heatmap_combined(
    raw_df: pd.DataFrame,
    noise_model: str = "ar1-0.6",
    tacet_threshold_ns: float = 0.4,
    ref_sigma_ns: float = 5.0,
    effect_sizes: Optional[list[float]] = None,
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (10.5, 6.5),
) -> plt.Figure:
    """Combined power heatmap: tools on y-axis with sub-rows per effect pattern.

    Replaces the three-panel layout (shift | tail | bimodal) with a single grid
    where each tool has three sub-rows. This uses ~1/3 the horizontal space.

    Caption should note: "Sub-rows per tool: S = shift, T = tail (upper 5%),
    B = bimodal. All tools achieve 100% detection at ≥20σ (omitted)."
    """
    setup_paper_style()

    if effect_sizes is None:
        # Drop 20σ (all tools at 100%); keep 10σ as convergence reference
        effect_sizes = [0, 0.1, 0.4, 1, 2, 10]

    df = raw_df[raw_df["noise_model"] == noise_model].copy()
    df = _filter_by_threshold(df, tacet_threshold_ns)

    tools_present = [t for t in PRIMARY_TOOLS if t in df["tool"].unique()]
    effects_present = [e for e in effect_sizes if e in df["effect_sigma_mult"].unique()]

    patterns = ["shift", "tail", "bimodal"]
    pattern_abbrev = {"shift": "shift", "tail": "tail", "bimodal": "bimodal"}

    n_tools = len(tools_present)
    n_effects = len(effects_present)
    n_patterns = len(patterns)
    group_gap = 0.4  # visual gap between tool groups

    def row_y(tool_idx: int, pattern_idx: int) -> float:
        return tool_idx * (n_patterns + group_gap) + pattern_idx

    total_height = n_tools * n_patterns + (n_tools - 1) * group_gap

    fig, ax = plt.subplots(figsize=figsize)

    # Show all spines for the grid border
    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_linewidth(0.5)
        spine.set_color(COLORS["border"])

    # Aggregate all data
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

    tacet_idx = tools_present.index("tacet") if "tacet" in tools_present else None

    # Draw cells (no per-cell borders; group borders drawn separately)
    for i, tool in enumerate(tools_present):
        for p, pattern in enumerate(patterns):
            y = row_y(i, p)
            for j, effect in enumerate(effects_present):
                rect = plt.Rectangle(
                    (j, y), 1, 1,
                    facecolor="white",
                    edgecolor="none",
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

    # Single horizontal lines between tool groups (in the gap)
    for i in range(1, n_tools):
        sep_y = row_y(i, 0) - group_gap / 2
        ax.axhline(y=sep_y, color=COLORS["border"], linewidth=0.6, zorder=5)

    # Axes limits (inverted so first tool is at top)
    ax.set_xlim(0, n_effects)
    ax.set_ylim(-0.2, total_height + 0.2)
    ax.invert_yaxis()

    # X-axis: effect sizes (σ)
    ax.set_xticks([x + 0.5 for x in range(n_effects)])
    ax.set_xticklabels(
        [EFFECT_NAMES.get(e, str(e)) for e in effects_present], fontsize=11
    )
    ax.set_xlabel("Effect size (σ)", fontsize=12)

    # Secondary x-axis: nanoseconds
    ax_top = ax.twiny()
    ax_top.set_xlim(0, n_effects)
    ax_top.set_xticks([x + 0.5 for x in range(n_effects)])
    ns_labels = [_format_ns_label(e, ref_sigma_ns) for e in effects_present]
    ax_top.set_xticklabels(ns_labels, fontsize=11)
    ax_top.set_xlabel("Effect size (ns, σ = 5 ns)", fontsize=12)
    # Style the top spine to match
    ax_top.spines["top"].set_visible(True)
    ax_top.spines["top"].set_linewidth(0.5)
    ax_top.spines["top"].set_color(COLORS["border"])

    # Y-axis: tool names centered on their 3-row groups
    tool_centers = [row_y(i, 0) + (n_patterns - 1) / 2 for i in range(n_tools)]
    ax.set_yticks(tool_centers)
    # Place tool names manually so we can bold Tacet reliably
    ax.set_yticks(tool_centers)
    ax.set_yticklabels([""] * n_tools)  # blank tick labels
    ax.tick_params(axis="y", length=0)

    from matplotlib.transforms import blended_transform_factory
    label_trans = blended_transform_factory(ax.transAxes, ax.transData)
    for i, tool in enumerate(tools_present):
        is_tacet = tool == "tacet"
        if is_tacet:
            # mathtext bold so it renders regardless of system font
            threshold_str = f"{tacet_threshold_ns:.1f}" if tacet_threshold_ns < 1 else f"{tacet_threshold_ns:.0f}"
            label = r"$\mathbf{Tacet}$" + f" (θ={threshold_str}ns)"
        else:
            label = _format_tool_label_with_threshold(tool, tacet_threshold_ns)
        ax.text(
            -0.10, tool_centers[i], label,
            ha="right", va="center",
            fontsize=11,
            transform=label_trans,
        )

    # Pattern sub-labels (S/T/B) between tool names and grid
    from matplotlib.transforms import blended_transform_factory
    trans = blended_transform_factory(ax.transAxes, ax.transData)
    for i in range(n_tools):
        for p, pattern in enumerate(patterns):
            y_pos = row_y(i, p) + 0.5
            label = pattern_abbrev[pattern]
            is_tacet = tools_present[i] == "tacet"
            ax.text(
                -0.01, y_pos, label,
                ha="right", va="center", fontsize=9,
                color=COLORS["text"] if is_tacet else COLORS["text_secondary"],
                fontweight="bold" if is_tacet else "normal",
                transform=trans,
            )

    # Legend below with breathing room
    legend_elements = [
        plt.Rectangle(
            (0, 0), 1, 1, facecolor=VERDICT_COLORS["found"],
            edgecolor=COLORS["border"], label="Effect found",
        ),
        plt.Rectangle(
            (0, 0), 1, 1, facecolor=VERDICT_COLORS["not_found"],
            edgecolor=COLORS["border"], label="Effect not found",
        ),
        plt.Rectangle(
            (0, 0), 1, 1, facecolor=VERDICT_COLORS["uncertain"],
            edgecolor=COLORS["border"], label="Inconclusive",
        ),
    ]
    ax.legend(
        handles=legend_elements,
        loc="upper left",
        bbox_to_anchor=(1.02, 1.0),
        ncol=1,
        frameon=False,
        fontsize=10,
    )

    plt.tight_layout()

    if output_path:
        fig.savefig(
            output_path, dpi=300, bbox_inches="tight",
            facecolor=COLORS["background"],
        )
        print(f"Saved: {output_path}")

    return fig


def plot_tail_power_curve_v3(
    summary_df: pd.DataFrame,
    tacet_threshold_ns: float = 0.4,
    ref_sigma_ns: float = 5.0,
    noise_model: str = "iid",  # Add noise model parameter
    output_path: Optional[Path] = None,
    figsize: tuple[float, float] = (6, 5),
) -> plt.Figure:
    """Tail power curve with fixed x-axis and nanosecond labels."""
    setup_paper_style()

    df = summary_df[
        (summary_df["effect_pattern"] == "tail")
        & (summary_df["noise_model"] == noise_model)  # Filter to specific noise model
    ].copy()
    df = _filter_by_threshold(df, tacet_threshold_ns)
    df = df[df["tool"] == "tacet"].sort_values("effect_sigma_mult")

    if len(df) == 0:
        fig, ax = plt.subplots(figsize=figsize)
        ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        return fig

    fig, ax = plt.subplots(figsize=figsize)

    x = df["effect_sigma_mult"].values
    y = df["detection_rate"].values * 100
    ci_low = df["ci_low"].values * 100
    ci_high = df["ci_high"].values * 100

    tacet_label = _format_tool_label_with_threshold("tacet", tacet_threshold_ns)
    ax.plot(x, y, "o-", linewidth=1.4, markersize=4,
            color=PRIMARY_TOOL_COLORS["tacet"], label=tacet_label)
    ax.fill_between(x, ci_low, ci_high, alpha=0.15, color=PRIMARY_TOOL_COLORS["tacet"])

    # Reference lines
    ax.axhline(95, color="#888888", linestyle=":", linewidth=0.8, alpha=0.7,
               label="Fail threshold (95%)")
    ax.axhline(5, color=COLORS["fail"], linestyle="--", linewidth=0.6, alpha=0.5,
               label="α = 5%")

    ax.set_xlabel("Effect size (σ)", fontsize=14)
    ax.set_ylabel("Detection rate (%)", fontsize=14)

    ax.grid(True, alpha=0.3, linestyle="--", linewidth=0.4)
    ax.set_ylim(-5, 105)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_yticklabels([0, 25, 50, 75, 100], fontsize=13)

    ax.set_xscale("symlog", linthresh=0.3, linscale=0.5)
    max_x = max(x) if len(x) > 0 else 20
    ax.set_xlim(-0.02, max_x + 1)

    tick_vals = sorted(set(x))
    ax.set_xticks(tick_vals)
    ax.set_xticklabels([EFFECT_NAMES.get(e, f"{e}σ") for e in tick_vals], fontsize=13)

    # Secondary ns axis
    ax_top = ax.twiny()
    ax_top.set_xscale("symlog", linthresh=0.3, linscale=0.5)
    ax_top.set_xlim(ax.get_xlim())
    ax_top.set_xticks(tick_vals)
    ns_labels = [_format_ns_label(e, ref_sigma_ns) for e in tick_vals]
    ax_top.set_xticklabels(ns_labels, fontsize=13)
    ax_top.set_xlabel("ns (at σ = 5 ns)", fontsize=14)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=300, bbox_inches="tight", facecolor=COLORS["background"])
        print(f"Saved: {output_path}")

    return fig


def print_ablation_summary() -> None:
    """Print key ablation comparison numbers for paper verification.

    Loads the v6 (per-quantile) and v7 (W₁) summary CSVs, plus
    bootstrap ablation CSVs if available, and prints comparison tables.
    """
    import pandas as pd
    from .utils import PROJECT_ROOT

    results_root = PROJECT_ROOT.parent.parent / "results"

    # --- Part A: W₁ vs 9-quantile ---
    pq_path = results_root / "medium-perquantile" / "benchmark_summary.csv"
    w1_path = results_root / "medium-w1-distance" / "benchmark_summary.csv"

    print("\n" + "=" * 60)
    print("ABLATION: W₁ vs 9-Quantile Test Statistic")
    print("=" * 60)

    if pq_path.exists() and w1_path.exists():
        pq = pd.read_csv(pq_path)
        w1 = pd.read_csv(w1_path)

        pq_t = pq[(pq["tool"] == "tacet") & (pq["attacker_threshold_ns"] == 0.4)]
        w1_t = w1[(w1["tool"] == "tacet") & (w1["attacker_threshold_ns"] == 0.4)]

        for pattern in ["tail", "shift"]:
            print(f"\n  {pattern.upper()} effects (θ=0.4ns):")
            for noise in ["iid", "ar1-0.8"]:
                print(f"    {noise}:")
                for sigma in [0.2, 1, 2, 4, 20]:
                    pq_row = pq_t[
                        (pq_t["effect_pattern"] == pattern)
                        & (pq_t["effect_sigma_mult"] == sigma)
                        & (pq_t["noise_model"] == noise)
                    ]
                    w1_row = w1_t[
                        (w1_t["effect_pattern"] == pattern)
                        & (w1_t["effect_sigma_mult"] == sigma)
                        & (w1_t["noise_model"] == noise)
                    ]
                    pq_rate = pq_row["detection_rate"].values[0] if len(pq_row) > 0 else "N/A"
                    w1_rate = w1_row["detection_rate"].values[0] if len(w1_row) > 0 else "N/A"
                    print(f"      {sigma:5.1f}σ: PQ={pq_rate}  W₁={w1_rate}")

        print("\n  FPR (effect=0σ):")
        for noise in ["iid", "ar1-0.3", "ar1-0.6", "ar1-0.8"]:
            pq_null = pq_t[(pq_t["effect_sigma_mult"] == 0) & (pq_t["noise_model"] == noise)]
            w1_null = w1_t[(w1_t["effect_sigma_mult"] == 0) & (w1_t["noise_model"] == noise)]
            pq_rate = pq_null["detection_rate"].values[0] if len(pq_null) > 0 else "N/A"
            w1_rate = w1_null["detection_rate"].values[0] if len(w1_null) > 0 else "N/A"
            print(f"    {noise:10s}: PQ={pq_rate}  W₁={w1_rate}")
    else:
        print("  Data not found. Skipping.")

    # --- Part B: Joint vs Stratified Bootstrap ---
    joint_path = results_root / "ablation-bootstrap-joint" / "benchmark_summary.csv"
    strat_path = results_root / "ablation-bootstrap-stratified" / "benchmark_summary.csv"

    print("\n" + "=" * 60)
    print("ABLATION: Joint vs Stratified Bootstrap")
    print("=" * 60)

    if joint_path.exists() and strat_path.exists():
        joint = pd.read_csv(joint_path)
        strat = pd.read_csv(strat_path)

        joint_t = joint[(joint["tool"] == "tacet") & (joint["attacker_threshold_ns"] == 0.4)]
        strat_t = strat[(strat["tool"] == "tacet") & (strat["attacker_threshold_ns"] == 0.4)]

        print("\n  FPR (effect=0σ):")
        for noise in ["iid", "ar1-0.3", "ar1-0.6", "ar1-0.8"]:
            j_null = joint_t[(joint_t["effect_sigma_mult"] == 0) & (joint_t["noise_model"] == noise)]
            s_null = strat_t[(strat_t["effect_sigma_mult"] == 0) & (strat_t["noise_model"] == noise)]
            j_rate = j_null["detection_rate"].values[0] if len(j_null) > 0 else "N/A"
            s_rate = s_null["detection_rate"].values[0] if len(s_null) > 0 else "N/A"
            print(f"    {noise:10s}: Joint={j_rate}  Stratified={s_rate}")

        for pattern in ["shift", "tail"]:
            print(f"\n  {pattern.upper()} detection power:")
            for noise in ["iid", "ar1-0.8"]:
                print(f"    {noise}:")
                for sigma in [1, 2, 20]:
                    j_row = joint_t[
                        (joint_t["effect_pattern"] == pattern)
                        & (joint_t["effect_sigma_mult"] == sigma)
                        & (joint_t["noise_model"] == noise)
                    ]
                    s_row = strat_t[
                        (strat_t["effect_pattern"] == pattern)
                        & (strat_t["effect_sigma_mult"] == sigma)
                        & (strat_t["noise_model"] == noise)
                    ]
                    j_rate = j_row["detection_rate"].values[0] if len(j_row) > 0 else "N/A"
                    s_rate = s_row["detection_rate"].values[0] if len(s_row) > 0 else "N/A"
                    print(f"      {sigma:5.1f}σ: Joint={j_rate}  Stratified={s_rate}")
    else:
        print("  Data not found. Run ablation benchmarks first.")
