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
    FIGURES_DIR,
    NOISE_NAMES,
    NOISE_ORDER,
    TOOL_NAMES,
    TOOL_ORDER,
    setup_paper_style,
)


# Distinctive but neutral color scheme
VERDICT_COLORS = {
    "found": "#14b8a6",       # Teal - detection occurred
    "not_found": "#d6ccc2",   # Warm taupe - no detection
    "uncertain": "#f97316",   # Coral - couldn't determine
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


def _highlight_tacet_row(ax: plt.Axes, tool_labels: list[str]) -> None:
    """Add visual distinction for Tacet row(s) - just bold text, no separator."""
    tacet_indices = [i for i, label in enumerate(tool_labels) if "Tacet" in str(label)]
    if tacet_indices:
        # Just make Tacet labels bold - clean and simple
        labels = ax.get_yticklabels()
        for i in tacet_indices:
            if i < len(labels):
                labels[i].set_fontweight("bold")
        ax.set_yticklabels(labels)


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
    tools_present = [t for t in TOOL_ORDER if t in agg["tool"].unique()]
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
    tool_labels = [TOOL_NAMES.get(t, t) for t in tools_present]
    ax.set_yticklabels(tool_labels)
    ax.invert_yaxis()

    ax.set_xlabel("Effect Size (σ)")
    ax.set_ylabel("Tool")
    ax.set_title(
        f"Detection Power by Effect Size\n"
        f"(noise: {NOISE_NAMES[noise_model]}, pattern: {effect_pattern})",
        pad=10,
    )

    # Highlight Tacet row
    _highlight_tacet_row(ax, tool_labels)

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
    tools_present = [t for t in TOOL_ORDER if t in agg["tool"].unique()]
    noise_present = [n for n in NOISE_ORDER if n in agg["noise_model"].unique()]

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
    tool_labels = [TOOL_NAMES.get(t, t) for t in tools_present]
    ax.set_yticklabels(tool_labels)
    ax.invert_yaxis()

    ax.set_xlabel("Autocorrelation Structure")
    ax.set_ylabel("Tool")
    ax.set_title(
        f"False Positive Rate by Autocorrelation\n"
        f"(null effect, pattern: {effect_pattern}, nominal α=5%)",
        pad=10,
    )

    # Highlight Tacet row
    _highlight_tacet_row(ax, tool_labels)

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
    for tool in TOOL_ORDER:
        tool_df = df[df["tool"] == tool].sort_values("effect_sigma_mult")
        if len(tool_df) == 0:
            continue

        x = tool_df["effect_sigma_mult"]
        y = tool_df["detection_rate"]
        ci_low = tool_df["ci_low"]
        ci_high = tool_df["ci_high"]

        color = tool_colors.get(tool, "#ffffff")
        label = TOOL_NAMES.get(tool, tool)

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
        tools_present = [t for t in TOOL_ORDER if t in pivot.index]
        effects_present = [e for e in EFFECT_ORDER if e in pivot.columns]
        pivot = pivot.reindex(index=tools_present, columns=effects_present)

        # Rename for display
        pivot.index = pivot.index.map(TOOL_NAMES)
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

    # Main paper figures
    print("\nGenerating main paper figures...")

    # Use 0.4ns threshold (SharedHardware) to showcase Inconclusive verdicts
    figures["power_heatmap"] = plot_power_heatmap(
        raw_df,
        noise_model="ar1-0.6",
        effect_pattern="shift",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "heatmap_power.png",
    )

    figures["fpr_heatmap"] = plot_fpr_heatmap(
        raw_df,
        effect_pattern="shift",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "heatmap_fpr.png",
    )

    figures["verdict_distribution"] = plot_verdict_distribution(
        raw_df,
        effect_sigma_mult=0.2,
        effect_pattern="shift",
        output_path=output_dir / "verdict_distribution.png",
    )

    # Supplementary figures
    print("\nGenerating supplementary figures...")

    figures["power_curves_iid"] = plot_power_curves(
        summary_df,
        noise_model="iid",
        effect_pattern="shift",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "power_curves_iid.png",
    )

    figures["power_curves_ar1"] = plot_power_curves(
        summary_df,
        noise_model="ar1-0.6",
        effect_pattern="shift",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "power_curves_ar1.png",
    )

    figures["shift_vs_tail"] = plot_shift_vs_tail(
        summary_df,
        noise_model="iid",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "shift_vs_tail.png",
    )

    # Tail pattern specific
    figures["power_heatmap_tail"] = plot_power_heatmap(
        raw_df,
        noise_model="iid",
        effect_pattern="tail",
        tacet_threshold_ns=0.4,
        output_path=output_dir / "heatmap_power_tail.png",
    )

    print(f"\nAll figures saved to {output_dir}")

    return figures
