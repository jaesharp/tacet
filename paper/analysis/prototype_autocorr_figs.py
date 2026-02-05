#!/usr/bin/env python3
"""Prototype alternative autocorrelation visualizations."""

from pathlib import Path
from tacet_analysis.data import load_thorough_data
from tacet_analysis.charts import (
    plot_fpr_line_with_ci,
    plot_fpr_slope_graph,
    plot_fpr_small_multiples,
    plot_fpr_grouped_bars_stages,
)
from tacet_analysis.utils import OUTPUT_DIR

# Load data
print("Loading thorough dataset...")
thorough_raw = load_thorough_data()

figures_dir = OUTPUT_DIR / "figures"
figures_dir.mkdir(parents=True, exist_ok=True)

print("\nGenerating Option 1: Line plot with confidence bands...")
plot_fpr_line_with_ci(
    thorough_raw,
    output_path=figures_dir / "prototype_option1_line_with_ci.png",
)

print("\nGenerating Option 2: Slope graph...")
plot_fpr_slope_graph(
    thorough_raw,
    output_path=figures_dir / "prototype_option2_slope_graph.png",
)

print("\nGenerating Option 3: Small multiples (sparkline grid)...")
plot_fpr_small_multiples(
    thorough_raw,
    output_path=figures_dir / "prototype_option3_small_multiples.png",
)

print("\nGenerating Option 4: Grouped bar chart (3 stages)...")
plot_fpr_grouped_bars_stages(
    thorough_raw,
    output_path=figures_dir / "prototype_option4_grouped_bars.png",
)

print("\nDone! Check outputs/figures/ for prototype_option*.png")
