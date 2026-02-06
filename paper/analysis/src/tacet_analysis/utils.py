"""Shared utilities for tacet analysis."""

from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
DATA_DIR = PROJECT_ROOT.parent.parent / "results" / "thorough-final-merged"
OUTPUT_DIR = PROJECT_ROOT / "outputs"
FIGURES_DIR = OUTPUT_DIR / "figures"

# Ensure output directories exist
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# Color scheme for paper figures (adapted from tacet design system)
COLORS = {
    "pass": "#2ecc71",         # Green
    "fail": "#e74c3c",         # Red
    "inconclusive": "#f39c12", # Amber
    "error": "#95a5a6",        # Gray
    "background": "#ffffff",   # White
    "text": "#1a1a1a",         # Near black (high contrast)
    "text_secondary": "#6B6B6B",  # Muted text
    "grid": "#e8e8e8",         # Light gray
    "border": "#d4d4d4",       # Medium gray for borders
    "accent": "#FF6060",       # Tacet brand accent (coral)
}

# Tool display names (for prettier plots)
TOOL_NAMES = {
    "ad-test": "AD Test",
    "dudect": "dudect",
    "ks-test": "KS Test",
    "mona": "MONA",
    "rtlf": "RTLF",           # R-based reference implementation
    "rtlf-native": "RTLF",    # Native Rust implementation (alias)
    "silent": "SILENT",
    "tacet": "Tacet",
    "timing-tvla": "TVLA",
    "tlsfuzzer": "tlsfuzzer",
}

# Noise model display names (ordered by autocorrelation strength)
# Medium preset uses: ar1-n0.6, ar1-n0.3, iid, ar1-0.3, ar1-0.6, ar1-0.8
# Thorough preset uses finer steps: ar1-n0.6, ar1-n0.4, ar1-n0.2, iid, ar1-0.2, ar1-0.4, ar1-0.6, ar1-0.8
NOISE_ORDER_MEDIUM = ["ar1-n0.6", "ar1-n0.3", "iid", "ar1-0.3", "ar1-0.6", "ar1-0.8"]
NOISE_ORDER_THOROUGH = ["ar1-n0.6", "ar1-n0.4", "ar1-n0.2", "iid", "ar1-0.2", "ar1-0.4", "ar1-0.6", "ar1-0.8"]
NOISE_ORDER = NOISE_ORDER_MEDIUM  # Default for backwards compatibility

NOISE_NAMES = {
    "ar1-n0.6": "AR(1) ρ=-0.6",
    "ar1-n0.4": "AR(1) ρ=-0.4",
    "ar1-n0.3": "AR(1) ρ=-0.3",
    "ar1-n0.2": "AR(1) ρ=-0.2",
    "iid": "i.i.d.",
    "ar1-0.2": "AR(1) ρ=0.2",
    "ar1-0.3": "AR(1) ρ=0.3",
    "ar1-0.4": "AR(1) ρ=0.4",
    "ar1-0.6": "AR(1) ρ=0.6",
    "ar1-0.8": "AR(1) ρ=0.8",
}

# Noise amplitude (σ) display names for Heatmap 3
# Updated to realistic PMU-calibrated values (σ ≈ 2ns measured on ARM64 Linux)
SIGMA_ORDER = [2, 5, 10, 20, 50]
SIGMA_NAMES = {
    2: "2ns",
    5: "5ns",
    10: "10ns",
    20: "20ns",
    50: "50ns",
}

# Effect size display
# Medium preset: [0, 0.2, 1, 2, 4, 20]
# Thorough preset: [0, 0.1, 0.2, 0.4, 1, 2, 4, 10, 20]
# Paper figures preset: [0, 0.1, 0.4, 1, 2, 10, 20] - reduced granularity for clarity
EFFECT_ORDER_MEDIUM = [0, 0.2, 1, 2, 4, 20]
EFFECT_ORDER_THOROUGH = [0, 0.1, 0.2, 0.4, 1, 2, 4, 10, 20]
EFFECT_ORDER_PAPER = [0, 0.1, 0.4, 1, 2, 10, 20]  # Remove 0.2σ and 4σ for cleaner viz
EFFECT_ORDER = EFFECT_ORDER_MEDIUM  # Default for backwards compatibility

EFFECT_NAMES = {
    0: "0σ",
    0.1: "0.1σ",
    0.2: "0.2σ",
    0.4: "0.4σ",
    1: "1σ",
    2: "2σ",
    4: "4σ",
    10: "10σ",
    20: "20σ",
}

# Tools to include (ordered for display)
TOOL_ORDER = [
    "tacet",
    "silent",
    "rtlf-native",
    "tlsfuzzer",
    "dudect",
    "timing-tvla",
    "ad-test",
    "ks-test",
    "mona",
]

# Primary tools for paper figures (6 tools from post-fix thorough run)
PRIMARY_TOOLS = ["tacet", "silent", "rtlf-native", "dudect", "timing-tvla", "tlsfuzzer"]

# Distinctive color palette for 7 primary tools
PRIMARY_TOOL_COLORS = {
    "tacet": "#FF6060",        # Coral red (Tacet brand accent)
    "silent": "#8b5cf6",       # Purple
    "rtlf-native": "#3b82f6",  # Blue
    "dudect": "#f59e0b",       # Amber
    "timing-tvla": "#10b981",  # Emerald
    "tlsfuzzer": "#6b7280",    # Gray
}

# Thorough dataset path (higher trial count, more effect sizes)
# Lives under paper/analysis/results/ (not repo-root results/)
THOROUGH_DATA_DIR = PROJECT_ROOT.parent.parent / "results" / "thorough-final-merged"

# Target figure widths matching the LaTeX layout:
#   USENIX textwidth = 7.0", figure* uses width=0.85\textwidth, figure uses ~columnwidth
FIGSIZE_FULL = 5.95    # 0.85 * 7.0" — for figure* (2-column spanning)
FIGSIZE_SINGLE = 3.36  # ~columnwidth — for figure (single column)


def setup_paper_style():
    """Configure matplotlib for paper figures.

    Minimal style: sans-serif font for clarity, clean axes, otherwise defaults.
    """
    import matplotlib.pyplot as plt

    plt.style.use("default")

    plt.rcParams.update({
        # Colors
        "figure.facecolor": COLORS["background"],
        "axes.facecolor": COLORS["background"],
        "axes.edgecolor": COLORS["border"],
        "axes.labelcolor": COLORS["text"],
        "text.color": COLORS["text"],
        "xtick.color": COLORS["text"],
        "ytick.color": COLORS["text"],

        # Typography — just sans-serif, keep default sizes
        "font.family": "sans-serif",
        "font.sans-serif": ["Helvetica", "DejaVu Sans", "Arial", "sans-serif"],

        # Cleaner axes
        "axes.spines.top": False,
        "axes.spines.right": False,

        # Legend
        "legend.frameon": False,

        # Figure
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
    })
