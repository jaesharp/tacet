#!/usr/bin/env Rscript
# Persistent R worker for SILENT and RTLF analysis.
#
# This script maintains a persistent R session to avoid interpreter startup
# overhead on each analysis call. The expensive part (loading R packages and
# sourcing scripts) happens once at startup. Each analysis call only needs
# to run the core algorithm.
#
# Protocol:
#   Request:  {"id": N, "method": "silent"|"rtlf", "params": {...}}
#   Response: {"id": N, "result": {...}} or {"id": N, "error": {...}}
#
# Usage:
#   Rscript --vanilla r-persistent-worker.R [--silent-path PATH] [--rtlf-path PATH]

suppressPackageStartupMessages({
  library(jsonlite)
  library(tidyverse)
  library(optparse)
})

# Parse command line arguments
option_list <- list(
  make_option(c("--silent-path"), type = "character", default = NULL,
              help = "Path to SILENT.R script (or its parent directory)"),
  make_option(c("--rtlf-path"), type = "character", default = NULL,
              help = "Path to rtlf.R script")
)

parser <- OptionParser(option_list = option_list)
args <- parse_args(parser)

# Track which tools are loaded
SILENT_LOADED <- FALSE
RTLF_LOADED <- FALSE

# Source external scripts if provided
if (!is.null(args$`silent-path`)) {
  silent_path <- args$`silent-path`

  # Find the functions.R file (the actual algorithm implementation)
  if (file.exists(silent_path)) {
    silent_dir <- if (dir.exists(silent_path)) {
      silent_path
    } else {
      dirname(silent_path)
    }

    functions_path <- file.path(silent_dir, "functions.R")

    if (file.exists(functions_path)) {
      # Load required packages for SILENT
      suppressPackageStartupMessages({
        library(np)
        library(robcp)
        library(Qtools)
      })

      # Source the SILENT algorithm functions
      source(functions_path)
      SILENT_LOADED <- TRUE
      message("Loaded SILENT functions from: ", functions_path)
    } else {
      message("Warning: Could not find functions.R at: ", functions_path)
    }
  } else {
    message("Warning: SILENT path does not exist: ", silent_path)
  }
}

# Note: We don't source rtlf.R directly because it has its own argument parsing
# and main loop that would conflict with our worker. Instead, we implement the
# RTLF algorithm directly in run_rtlf() below.
if (!is.null(args$`rtlf-path`) && file.exists(args$`rtlf-path`)) {
  # Just verify the path exists - we use our own implementation
  RTLF_LOADED <- TRUE
  message("RTLF implementation enabled (using built-in algorithm)")
}

# Run SILENT analysis on in-memory data
run_silent <- function(params) {
  if (!SILENT_LOADED) {
    stop("SILENT not loaded - provide --silent-path pointing to SILENT's scripts directory")
  }

  baseline <- as.numeric(params$baseline)
  test_data <- as.numeric(params$test)
  alpha <- params$alpha %||% 0.1
  delta <- params$delta %||% 1.0
  bootstrap_samples <- params$bootstrap_samples %||% 1000

  # SILENT parameters
  quant_start <- 0.05
  quant_end <- 0.95
  quant_step <- 0.01
  quantiles <- seq(quant_start, quant_end, by = quant_step)

  n <- min(length(baseline), length(test_data))
  if (n < 100) {
    stop("SILENT requires at least 100 samples per class")
  }

  tryCatch({
    # Use the SILENT algorithm function from functions.R
    result <- algorithm(
      data1 = baseline[1:n],
      data2 = test_data[1:n],
      n = n,
      B = bootstrap_samples,
      alpha = alpha,
      quant = quantiles,
      Delta = delta
    )

    # Parse the result
    test_result <- result$test_result
    test_stat <- test_result$test_stat
    threshold <- test_result$threshold
    adjusted <- test_result$test_adjusted

    # Debug: log what we got from the algorithm
    message("SILENT result: test_stat=", test_stat, " threshold=", threshold, " adjusted=", adjusted)

    # Handle NA values - if adjusted is NA, check test_stat vs threshold directly
    if (is.null(adjusted) || is.na(adjusted)) {
      if (is.null(test_stat) || is.na(test_stat) || is.null(threshold) || is.na(threshold)) {
        stop("SILENT algorithm returned NA for test_stat or threshold")
      }
      # Fallback: compare test_stat to threshold
      detected <- isTRUE(test_stat > threshold)
      adjusted <- test_stat - threshold
    } else {
      # Decision: reject if adjusted test stat > 0 (i.e., test_stat > threshold)
      detected <- isTRUE(adjusted > 0)
    }

    list(
      detected = detected,
      statistic = test_stat,
      threshold = as.numeric(threshold),
      adjusted = adjusted,
      block_size = result$block_size,
      status = if (detected) "Rejected null hypothesis" else "Failed to reject"
    )
  }, error = function(e) {
    stop(paste("SILENT analysis failed:", e$message))
  })
}

# Run RTLF analysis on in-memory data
run_rtlf <- function(params) {
  baseline <- as.numeric(params$baseline)
  test_data <- as.numeric(params$test)
  alpha <- params$alpha %||% 0.09

  n <- min(length(baseline), length(test_data))
  if (n < 100) {
    stop("RTLF requires at least 100 samples per class")
  }

  g1 <- baseline[1:n]
  g2 <- test_data[1:n]

  tryCatch({
    # If RTLF is loaded, try to use its autotest function
    if (RTLF_LOADED && exists("autotest")) {
      result <- autotest(g1, g2, alpha = alpha)
      detected <- isTRUE(result$significant) || isTRUE(result$detected)
      p_value <- result$p_value %||% (if (detected) 0.0 else 1.0)

      if (!detected && !is.null(result$significant_deciles)) {
        detected <- length(result$significant_deciles) > 0
      }

      return(list(
        detected = detected,
        p_value = p_value,
        significant_deciles = if (!is.null(result$significant_deciles)) as.list(result$significant_deciles) else list(),
        status = if (detected) "Difference detected" else "No significant difference"
      ))
    }

    # Fallback: implement RTLF's bootstrap quantile test
    # RTLF tests 9 deciles (10%, 20%, ..., 90%) with Bonferroni correction

    # Decile probabilities
    decile_probs <- seq(0.1, 0.9, by = 0.1)
    n_deciles <- length(decile_probs)

    # Observed quantile differences
    q1 <- quantile(g1, probs = decile_probs, na.rm = TRUE)
    q2 <- quantile(g2, probs = decile_probs, na.rm = TRUE)
    observed_diffs <- q2 - q1

    # Bootstrap (within-group resampling as per RTLF paper)
    B <- 10000
    n1 <- length(g1)
    n2 <- length(g2)

    # Count exceedances for each decile
    exceedance_counts <- rep(0, n_deciles)

    for (b in 1:B) {
      # Resample within each group (paired bootstrap)
      b1a <- sample(g1, n1, replace = TRUE)
      b1b <- sample(g1, n1, replace = TRUE)
      b2a <- sample(g2, n2, replace = TRUE)
      b2b <- sample(g2, n2, replace = TRUE)

      # Compute quantile differences for bootstrap samples
      bq1 <- quantile(b1a, probs = decile_probs, na.rm = TRUE) -
             quantile(b1b, probs = decile_probs, na.rm = TRUE)
      bq2 <- quantile(b2a, probs = decile_probs, na.rm = TRUE) -
             quantile(b2b, probs = decile_probs, na.rm = TRUE)

      # Check if observed difference exceeds bootstrap null
      for (d in 1:n_deciles) {
        if (abs(observed_diffs[d]) > max(abs(bq1[d]), abs(bq2[d]))) {
          exceedance_counts[d] <- exceedance_counts[d] + 1
        }
      }
    }

    # Bonferroni-corrected threshold
    bonferroni_alpha <- alpha / n_deciles
    threshold_count <- B * (1 - bonferroni_alpha)

    # Check which deciles are significant
    significant_deciles <- decile_probs[exceedance_counts > threshold_count] * 100

    detected <- length(significant_deciles) > 0
    p_value <- if (detected) 0.0 else 1.0

    list(
      detected = detected,
      p_value = p_value,
      significant_deciles = as.list(significant_deciles),
      status = if (detected) "Difference detected" else "No significant difference"
    )
  }, error = function(e) {
    stop(paste("RTLF analysis failed:", e$message))
  })
}

# Main loop: read JSON requests, dispatch, write responses
main <- function() {
  message("R persistent worker ready")
  message("  SILENT loaded: ", SILENT_LOADED)
  message("  RTLF loaded: ", RTLF_LOADED)

  con <- file("stdin", "r")
  on.exit(close(con))

  while (TRUE) {
    line <- readLines(con, n = 1)

    if (length(line) == 0) {
      # EOF - stdin closed
      break
    }

    if (nchar(trimws(line)) == 0) {
      next
    }

    response <- tryCatch({
      request <- fromJSON(line)
      id <- request$id

      result <- switch(request$method,
        "silent" = run_silent(request$params),
        "rtlf" = run_rtlf(request$params),
        stop(paste("Unknown method:", request$method))
      )

      list(id = id, result = result)
    }, error = function(e) {
      list(
        id = if (exists("id")) id else 0,
        error = list(code = -32603, message = e$message)
      )
    })

    cat(toJSON(response, auto_unbox = TRUE), "\n")
    flush(stdout())
  }

  message("R persistent worker shutting down")
}

# Run main loop
main()
