/**
 * Shared utilities for noble-crypto timing tests.
 *
 * Provides helper functions for DudeCT two-class testing pattern:
 * - Baseline: Fixed input (all zeros or constant)
 * - Sample: Random input (crypto.getRandomValues)
 */

/**
 * Generate a baseline input (all zeros).
 *
 * @param size Number of bytes
 * @returns Uint8Array filled with zeros
 */
export function baselineBytes(size: number): Uint8Array {
  return new Uint8Array(size);
}

/**
 * Generate a sample input (random bytes).
 *
 * @param size Number of bytes
 * @returns Uint8Array filled with random bytes
 */
export function sampleBytes(size: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(size));
}

/**
 * Log test result for paper analysis.
 *
 * Formats result consistently across all noble tests.
 *
 * @param testName Test identifier (e.g., "secp256k1_sign")
 * @param result Timing test result
 */
export function logResult(testName: string, result: any): void {
  const outcome = result.outcome;
  const leakProb = (result.leakProbability * 100).toFixed(1);
  const effectNs = result.effectNs?.toFixed(1) ?? "N/A";
  const exploitability = result.exploitability ?? "N/A";
  const samples = result.samplesUsed ?? "N/A";

  console.log(
    `${testName}: ${outcome}, P(leak)=${leakProb}%, effect=${effectNs}ns, ` +
      `exploitability=${exploitability}, samples=${samples}`
  );
}

/**
 * Standard attacker models for crypto operations.
 */
export const ATTACKER_MODELS = {
  /** Post-quantum crypto (2ns threshold, ~10 cycles @ 5 GHz) */
  POST_QUANTUM: "PostQuantum" as const,
  /** Adjacent network attacker (100ns threshold) */
  ADJACENT_NETWORK: "AdjacentNetwork" as const,
  /** Shared hardware attacker (0.4ns threshold, ~2 cycles @ 5 GHz) */
  SHARED_HARDWARE: "SharedHardware" as const,
};

/**
 * Standard time budgets for tests.
 */
export const TIME_BUDGETS = {
  /** Quick test (30 seconds) */
  QUICK: 30_000,
  /** Thorough test (60 seconds) */
  THOROUGH: 60_000,
  /** Extended test (120 seconds) */
  EXTENDED: 120_000,
};
