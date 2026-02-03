"""Shared utilities for tacet analysis."""

from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
DATA_DIR = PROJECT_ROOT.parent.parent / "aws-results" / "local" / "medium"
OUTPUT_DIR = PROJECT_ROOT / "outputs"
FIGURES_DIR = OUTPUT_DIR / "figures"

# Ensure output directories exist
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# Color scheme from tacet brand guidelines
COLORS = {
    "pass": "#2ecc71",      # Green
    "fail": "#e74c3c",      # Red
    "inconclusive": "#f39c12",  # Amber
    "error": "#95a5a6",     # Gray
    "background": "#1a1a1a",
    "text": "#ffffff",
    "grid": "#333333",
}

# Tool display names (for prettier plots)
TOOL_NAMES = {
    "ad-test": "AD Test",
    "dudect": "dudect",
    "ks-test": "KS Test",
    "mona": "MONA",
    "rtlf-native": "RTLF",
    "silent-native": "SILENT",
    "tacet": "Tacet",
    "timing-tvla": "TVLA",
}

# Noise model display names (ordered by autocorrelation strength)
NOISE_ORDER = ["ar1-n0.6", "ar1-n0.3", "iid", "ar1-0.3", "ar1-0.6"]
NOISE_NAMES = {
    "ar1-n0.6": "AR(1) ρ=-0.6",
    "ar1-n0.3": "AR(1) ρ=-0.3",
    "iid": "i.i.d.",
    "ar1-0.3": "AR(1) ρ=0.3",
    "ar1-0.6": "AR(1) ρ=0.6",
}

# Effect size display
EFFECT_ORDER = [0, 0.2, 1, 2, 4, 20]
EFFECT_NAMES = {
    0: "0σ",
    0.2: "0.2σ",
    1: "1σ",
    2: "2σ",
    4: "4σ",
    20: "20σ",
}

# Tools to include (ordered for display)
TOOL_ORDER = [
    "tacet",
    "silent-native",
    "rtlf-native",
    "dudect",
    "timing-tvla",
    "ad-test",
    "ks-test",
    "mona",
]


def setup_dark_style():
    """Configure matplotlib for dark theme consistent with tacet branding."""
    import matplotlib.pyplot as plt

    plt.style.use("dark_background")
    plt.rcParams.update({
        "figure.facecolor": COLORS["background"],
        "axes.facecolor": COLORS["background"],
        "axes.edgecolor": COLORS["grid"],
        "axes.labelcolor": COLORS["text"],
        "text.color": COLORS["text"],
        "xtick.color": COLORS["text"],
        "ytick.color": COLORS["text"],
        "grid.color": COLORS["grid"],
        "font.family": "sans-serif",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
    })
