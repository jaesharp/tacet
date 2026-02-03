"""Tacet benchmark data analysis for USENIX Security 2026 paper."""

from tacet_analysis.data import load_benchmark_data, load_summary_data
from tacet_analysis.robustness import run_all_checks
from tacet_analysis.charts import (
    plot_power_heatmap,
    plot_fpr_heatmap,
    plot_verdict_distribution,
    generate_all_figures,
)

__all__ = [
    "load_benchmark_data",
    "load_summary_data",
    "run_all_checks",
    "plot_power_heatmap",
    "plot_fpr_heatmap",
    "plot_verdict_distribution",
    "generate_all_figures",
]
