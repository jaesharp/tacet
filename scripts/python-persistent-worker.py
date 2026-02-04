#!/usr/bin/env python3
"""
Persistent Python worker for tlsfuzzer timing analysis.

This script maintains a persistent Python session to avoid interpreter startup
overhead on each analysis call. The expensive part (importing tlsfuzzer and
numpy/scipy/pandas) happens once at startup.

Protocol:
    Request:  {"id": N, "method": "tlsfuzzer", "params": {...}}
    Response: {"id": N, "result": {...}} or {"id": N, "error": {...}}

Usage:
    python3 python-persistent-worker.py
"""

import sys
import json
import os
import tempfile
import shutil
from pathlib import Path

# Import heavy libraries once at startup
import numpy as np
import pandas as pd

# Import tlsfuzzer analysis module - REQUIRED
try:
    from tlsfuzzer.analysis import Analysis
except ImportError as e:
    print(f"FATAL: tlsfuzzer not installed: {e}", file=sys.stderr)
    print("Install with: pip install tlsfuzzer", file=sys.stderr)
    sys.exit(1)

print("tlsfuzzer loaded successfully", file=sys.stderr)


def run_tlsfuzzer(params: dict) -> dict:
    """Run tlsfuzzer timing analysis on in-memory data."""
    baseline = np.array(params["baseline"], dtype=np.float64)
    test = np.array(params["test"], dtype=np.float64)
    alpha = params.get("alpha", 0.05)

    temp_dir = tempfile.mkdtemp()
    old_cwd = os.getcwd()

    try:
        # tlsfuzzer expects timing data in a specific CSV format:
        # Column per class, rows are observations
        timing_path = Path(temp_dir) / "timing.csv"

        # Pad shorter array with NaN
        max_len = max(len(baseline), len(test))
        baseline_padded = np.full(max_len, np.nan)
        test_padded = np.full(max_len, np.nan)
        baseline_padded[:len(baseline)] = baseline
        test_padded[:len(test)] = test

        df = pd.DataFrame({
            "baseline": baseline_padded,
            "sample": test_padded,
        })
        df.to_csv(timing_path, index=False)

        # Change to temp dir for tlsfuzzer's relative path handling
        os.chdir(temp_dir)

        # Create Analysis object and run analysis
        analysis = Analysis(
            output=str(temp_dir),
            draw_ecdf_plot=False,
            draw_scatter_plot=False,
            draw_conf_interval_plot=False,
            multithreaded_graph=False,
        )

        # Load the timing data (reads from timing.csv in output directory)
        analysis.load_data()

        # Run the statistical tests that tlsfuzzer provides
        # Test methods return dict[TestPair, float] where TestPair is (index1, index2)
        # For two classes, there's one pair (0, 1) with its p-value
        results = {}

        def extract_pvalue(test_dict):
            """Extract p-value from test result dictionary."""
            if test_dict is None or len(test_dict) == 0:
                return None
            # Get the first (and typically only for 2-class) p-value
            return float(list(test_dict.values())[0])

        # Box test (returns formatted strings for display, not numeric p-values)
        # We skip it for numeric analysis and rely on sign_test/wilcoxon_test
        try:
            box_result = analysis.box_test()
            if box_result is not None:
                # box_test returns strings like "<0.05" for display
                # Just record that it ran without extracting p-value
                results["box_test"] = {"status": "ran", "note": "returns display strings, not numeric p-values"}
        except Exception as e:
            results["box_test"] = {"error": str(e)}

        # Sign test
        try:
            sign_result = analysis.sign_test()
            p_value = extract_pvalue(sign_result)
            if p_value is not None:
                results["sign_test"] = {"p_value": p_value}
        except Exception as e:
            results["sign_test"] = {"error": str(e)}

        # Wilcoxon signed-rank test
        try:
            wilcox_result = analysis.wilcoxon_test()
            p_value = extract_pvalue(wilcox_result)
            if p_value is not None:
                results["wilcoxon_test"] = {"p_value": p_value}
        except Exception as e:
            results["wilcoxon_test"] = {"error": str(e)}

        # Find minimum p-value across all successful tests
        min_p = 1.0
        min_test = "none"
        for test_name, test_result in results.items():
            if "p_value" in test_result and test_result["p_value"] is not None:
                if test_result["p_value"] < min_p:
                    min_p = test_result["p_value"]
                    min_test = test_name

        if min_test == "none":
            raise RuntimeError(f"All tlsfuzzer tests failed: {results}")

        detected = min_p < alpha

        return {
            "detected": detected,
            "p_value": min_p,
            "test_name": min_test,
            "status": "vulnerable" if detected else "pass",
            "all_tests": results,
        }

    finally:
        os.chdir(old_cwd)
        shutil.rmtree(temp_dir, ignore_errors=True)


def handle_request(request: dict) -> dict:
    """Dispatch request to appropriate handler."""
    method = request.get("method", "")

    if method == "tlsfuzzer":
        return run_tlsfuzzer(request.get("params", {}))
    else:
        raise ValueError(f"Unknown method: {method}")


def main():
    """Main loop: read JSON requests, dispatch, write responses."""
    print("Python persistent worker ready", file=sys.stderr)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
            request_id = request.get("id", 0)

            result = handle_request(request)
            response = {"id": request_id, "result": result}

        except json.JSONDecodeError as e:
            response = {
                "id": 0,
                "error": {"code": -32700, "message": f"Parse error: {e}"}
            }
        except Exception as e:
            response = {
                "id": request.get("id", 0) if "request" in dir() else 0,
                "error": {"code": -32603, "message": str(e)}
            }

        print(json.dumps(response), flush=True)

    print("Python persistent worker shutting down", file=sys.stderr)


if __name__ == "__main__":
    main()
