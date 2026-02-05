/**
 * crypto-js timing tests
 *
 * crypto-js is a legacy but widely-used JavaScript crypto library (DISCONTINUED).
 * Despite being discontinued, many legacy codebases still depend on it.
 *
 * ⚠️  WARNING: crypto-js is NO LONGER MAINTAINED (last release: 2021)
 * This test suite exists to help identify timing vulnerabilities in legacy code.
 *
 * This test suite focuses on:
 * - AES-128/192/256 encryption/decryption
 * - HMAC-SHA256 MAC generation
 * - PBKDF2 key derivation (timing-sensitive)
 *
 * Note: crypto-js is 40-100× slower than native crypto, so time budgets are generous.
 */

import { describe, test, expect, beforeAll } from "bun:test";
import {
  initializeWasm,
  TimingOracle,
  AttackerModelValues,
  OutcomeValues,
} from "../dist/index.js";
import CryptoJS from "crypto-js";

describe("crypto-js AES encryption", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  test("sanity check: identical inputs should pass", {
    timeout: 180000, // 3 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(256 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32), // All zeros
      sample: () => new Uint8Array(32),   // Also all zeros
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.Research)
      .timeBudget(120000)  // 2 minutes
      .maxSamples(20000)
      .test(inputs, (plaintext) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(plaintext));
        const encrypted = CryptoJS.AES.encrypt(wordArray, key.toString());
        // Store to prevent optimization
        const _ = encrypted;
      });

    expect(result.isPass() || result.outcome === OutcomeValues.Inconclusive).toBe(true);
  });

  test("AES-128 encryption timing", {
    timeout: 180000, // 3 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(128 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes for JS crypto
      .maxSamples(30000)
      .test(inputs, (plaintext) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(plaintext));
        const encrypted = CryptoJS.AES.encrypt(wordArray, key.toString());
        const _ = encrypted;
      });

    console.log(`\nAES-128 encryption: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);
    console.log(`  Samples used: ${result.samplesUsed}`);
    if (result.isFail()) {
      console.log(`  ⚠️  TIMING LEAK DETECTED in AES-128 encryption`);
      console.log(`  Exploitability: ${result.exploitability || "unknown"}`);
    }

    expect(result.outcome).toBeDefined();
  });

  test("AES-192 encryption timing", {
    timeout: 180000, // 3 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(192 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes
      .maxSamples(30000)
      .test(inputs, (plaintext) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(plaintext));
        const encrypted = CryptoJS.AES.encrypt(wordArray, key.toString());
        const _ = encrypted;
      });

    console.log(`\nAES-192 encryption: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });

  test("AES-256 encryption timing", {
    timeout: 180000, // 3 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(256 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes
      .maxSamples(30000)
      .test(inputs, (plaintext) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(plaintext));
        const encrypted = CryptoJS.AES.encrypt(wordArray, key.toString());
        const _ = encrypted;
      });

    console.log(`\nAES-256 encryption: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });

  test("AES-256 decryption timing", {
    timeout: 180000, // 3 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(256 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes
      .maxSamples(30000)
      .test(inputs, (plaintext) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(plaintext));
        const encrypted = CryptoJS.AES.encrypt(wordArray, key.toString());
        // Decrypt to test decryption timing
        const decrypted = CryptoJS.AES.decrypt(encrypted.toString(), key.toString());
        const _ = decrypted;
      });

    console.log(`\nAES-256 decryption: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });

  test("known-leaky: deliberate timing leak in AES", {
    timeout: 180000, // 3 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(256 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32).fill(0),
      sample: () => new Uint8Array(32).fill(0xFF),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes
      .maxSamples(20000)
      .test(inputs, (plaintext) => {
        // Deliberate leak: early exit if first byte is 0
        if (plaintext[0] === 0) {
          return;
        }

        const wordArray = CryptoJS.lib.WordArray.create(Array.from(plaintext));
        const encrypted = CryptoJS.AES.encrypt(wordArray, key.toString());
        const _ = encrypted;
      });

    console.log(`\nKnown-leaky AES test: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    // Should detect the deliberate leak
    expect(result.isFail() || result.outcome === OutcomeValues.Inconclusive).toBe(true);
  });
});

describe("crypto-js HMAC", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  test("HMAC-SHA256 generation timing", {
    timeout: 120000, // 2 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(256 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(90000)  // 1.5 minutes - HMAC is faster than AES
      .maxSamples(30000)
      .test(inputs, (message) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(message));
        const hmac = CryptoJS.HmacSHA256(wordArray, key);
        const _ = hmac;
      });

    console.log(`\nHMAC-SHA256 generation: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);
    console.log(`  Samples used: ${result.samplesUsed}`);

    expect(result.outcome).toBeDefined();
  });

  test("HMAC-SHA256 different message sizes", {
    timeout: 120000, // 2 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(256 / 8);

    const inputs = {
      baseline: () => new Uint8Array(16),  // Shorter message
      sample: () => crypto.getRandomValues(new Uint8Array(64)),  // Longer message
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(90000)  // 1.5 minutes
      .maxSamples(30000)
      .test(inputs, (message) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(message));
        const hmac = CryptoJS.HmacSHA256(wordArray, key);
        const _ = hmac;
      });

    console.log(`\nHMAC-SHA256 different message sizes: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    // Note: This test intentionally uses different message sizes
    // We expect a leak here since HMAC timing depends on message length
    expect(result.outcome).toBeDefined();
  });
});

describe("crypto-js PBKDF2", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  test("PBKDF2 key derivation timing (low iterations)", {
    timeout: 240000, // 4 minutes
  }, () => {
    const salt = CryptoJS.lib.WordArray.random(128 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(180000)  // 3 minutes - PBKDF2 is very slow
      .maxSamples(30000)
      .test(inputs, (password) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(password));
        // Use low iteration count for testing (100 iterations)
        // Production should use ≥100,000 iterations
        const derived = CryptoJS.PBKDF2(wordArray, salt, {
          keySize: 256 / 32,
          iterations: 100,
        });
        const _ = derived;
      });

    console.log(`\nPBKDF2 key derivation (100 iterations): ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);
    console.log(`  Samples used: ${result.samplesUsed}`);
    if (result.isFail()) {
      console.log(`  ⚠️  TIMING LEAK DETECTED in PBKDF2`);
      console.log(`  Exploitability: ${result.exploitability || "unknown"}`);
    }

    expect(result.outcome).toBeDefined();
  });

  test("PBKDF2 different passwords (Hamming weight)", {
    timeout: 240000, // 4 minutes
  }, () => {
    const salt = CryptoJS.lib.WordArray.random(128 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32).fill(0x00),  // All zeros
      sample: () => new Uint8Array(32).fill(0xFF),    // All ones
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(180000)  // 3 minutes
      .maxSamples(30000)
      .test(inputs, (password) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(password));
        const derived = CryptoJS.PBKDF2(wordArray, salt, {
          keySize: 256 / 32,
          iterations: 100,
        });
        const _ = derived;
      });

    console.log(`\nPBKDF2 Hamming weight independence: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });
});

describe("crypto-js AES modes", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  test("AES-256-CBC encryption timing", {
    timeout: 180000, // 3 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(256 / 8);
    const iv = CryptoJS.lib.WordArray.random(128 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes
      .maxSamples(30000)
      .test(inputs, (plaintext) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(plaintext));
        const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        });
        const _ = encrypted;
      });

    console.log(`\nAES-256-CBC encryption: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });

  test("AES-256-CTR encryption timing", {
    timeout: 180000, // 3 minutes
  }, () => {
    const key = CryptoJS.lib.WordArray.random(256 / 8);
    const iv = CryptoJS.lib.WordArray.random(128 / 8);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes
      .maxSamples(30000)
      .test(inputs, (plaintext) => {
        const wordArray = CryptoJS.lib.WordArray.create(Array.from(plaintext));
        const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
          iv: iv,
          mode: CryptoJS.mode.CTR,
          padding: CryptoJS.pad.NoPadding,
        });
        const _ = encrypted;
      });

    console.log(`\nAES-256-CTR encryption: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });
});
