/**
 * Noble ciphers (@noble/ciphers) timing tests.
 *
 * Tests symmetric cipher operations for constant-time properties using
 * the DudeCT two-class pattern (baseline: all zeros, sample: random).
 *
 * Coverage:
 * - ChaCha20: encryption with random plaintext, different keys, nonce independence
 * - Salsa20: encryption with random plaintext, different keys
 * - XSalsa20: encryption with random plaintext (extended nonce variant)
 * - AES-256-CTR: encryption with random plaintext, different keys
 */

import { test, expect } from "bun:test";
import { TimingOracle, initializeWasm, AttackerModelValues } from "../../dist/index.js";
import { baselineBytes, sampleBytes, logResult, ATTACKER_MODELS, TIME_BUDGETS } from "./helpers.js";

// ============================================================================
// ChaCha20 Tests (3 tests)
// ============================================================================

test("ChaCha20: encrypt with random plaintext", async () => {
  await initializeWasm();
  const { chacha20 } = await import("@noble/ciphers/chacha");

  // Pre-generate key and nonce outside timing region
  const key = sampleBytes(32);
  const nonce = sampleBytes(12);

  const result = await TimingOracle.forAttacker(AttackerModelValues.AdjacentNetwork)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(64),
        sample: () => sampleBytes(64),
      },
      (plaintext) => {
        // Noble-ciphers API: chacha20(key, nonce, data) returns ciphertext
        chacha20(key, nonce, plaintext);
      }
    );

  logResult("chacha20_encrypt_random_plaintext", result);
  expect(result.outcome).toBeDefined();
});

test("ChaCha20: encrypt with different keys", async () => {
  await initializeWasm();
  const { chacha20 } = await import("@noble/ciphers/chacha");

  const plaintext = new Uint8Array(64).fill(0x42);
  const nonce = sampleBytes(12);

  const result = await TimingOracle.forAttacker(AttackerModelValues.AdjacentNetwork)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(32),
        sample: () => sampleBytes(32),
      },
      (key) => {
        chacha20(key, nonce, plaintext);
      }
    );

  logResult("chacha20_encrypt_different_keys", result);
  expect(result.outcome).toBeDefined();
});

test("ChaCha20: nonce independence", async () => {
  await initializeWasm();
  const { chacha20 } = await import("@noble/ciphers/chacha");

  const key = sampleBytes(32);
  const plaintext = new Uint8Array(64).fill(0x42);

  const result = await TimingOracle.forAttacker(AttackerModelValues.AdjacentNetwork)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(12),
        sample: () => sampleBytes(12),
      },
      (nonce) => {
        chacha20(key, nonce, plaintext);
      }
    );

  logResult("chacha20_nonce_independence", result);
  expect(result.outcome).toBeDefined();
});

// ============================================================================
// Salsa20 Tests (2 tests)
// ============================================================================

test("Salsa20: encrypt with random plaintext", async () => {
  await initializeWasm();
  const { salsa20 } = await import("@noble/ciphers/salsa");

  const key = sampleBytes(32);
  const nonce = sampleBytes(8);

  const result = await TimingOracle.forAttacker(AttackerModelValues.AdjacentNetwork)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(64),
        sample: () => sampleBytes(64),
      },
      (plaintext) => {
        salsa20(key, nonce, plaintext);
      }
    );

  logResult("salsa20_encrypt_random_plaintext", result);
  expect(result.outcome).toBeDefined();
});

test("Salsa20: encrypt with different keys", async () => {
  await initializeWasm();
  const { salsa20 } = await import("@noble/ciphers/salsa");

  const plaintext = new Uint8Array(64).fill(0x42);
  const nonce = sampleBytes(8);

  const result = await TimingOracle.forAttacker(AttackerModelValues.AdjacentNetwork)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(32),
        sample: () => sampleBytes(32),
      },
      (key) => {
        salsa20(key, nonce, plaintext);
      }
    );

  logResult("salsa20_encrypt_different_keys", result);
  expect(result.outcome).toBeDefined();
});

// ============================================================================
// XSalsa20 Tests (1 test)
// ============================================================================

test("XSalsa20: encrypt with random plaintext", async () => {
  await initializeWasm();
  const { xsalsa20 } = await import("@noble/ciphers/salsa");

  const key = sampleBytes(32);
  const nonce = sampleBytes(24); // XSalsa20 uses 192-bit nonce

  const result = await TimingOracle.forAttacker(AttackerModelValues.AdjacentNetwork)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(64),
        sample: () => sampleBytes(64),
      },
      (plaintext) => {
        xsalsa20(key, nonce, plaintext);
      }
    );

  logResult("xsalsa20_encrypt_random_plaintext", result);
  expect(result.outcome).toBeDefined();
});

// ============================================================================
// AES-256-CTR Tests (2 tests)
// ============================================================================

test("AES-256-CTR: encrypt with random plaintext", async () => {
  await initializeWasm();
  const { ctr } = await import("@noble/ciphers/aes");

  const key = sampleBytes(32); // AES-256
  const iv = sampleBytes(16);

  const result = await TimingOracle.forAttacker(AttackerModelValues.AdjacentNetwork)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(64),
        sample: () => sampleBytes(64),
      },
      (plaintext) => {
        const cipher = ctr(key, iv);
        cipher.encrypt(plaintext);
      }
    );

  logResult("aes256_ctr_encrypt_random_plaintext", result);
  expect(result.outcome).toBeDefined();
});

test("AES-256-CTR: encrypt with different keys (SHOULD detect leak)", async () => {
  await initializeWasm();
  const { ctr } = await import("@noble/ciphers/aes");

  const plaintext = new Uint8Array(64).fill(0x42);
  const iv = sampleBytes(16);

  const result = await TimingOracle.forAttacker(AttackerModelValues.AdjacentNetwork)
    .timeBudget(TIME_BUDGETS.THOROUGH)
    .maxSamples(200_000)
    .testAsync(
      {
        baseline: () => baselineBytes(32),
        sample: () => sampleBytes(32),
      },
      (key) => {
        const cipher = ctr(key, iv);
        cipher.encrypt(plaintext);
      }
    );

  logResult("aes256_ctr_encrypt_different_keys", result);

  // This test SHOULD detect a timing leak due to T-table cache timing in key expansion.
  // Noble-ciphers explicitly documents that AES uses T-tables which leak access timings.
  // See: https://github.com/paulmillr/noble-ciphers#constant-timeness
  expect(result.isFail() || result.leakProbability > 0.9).toBe(true);
});
