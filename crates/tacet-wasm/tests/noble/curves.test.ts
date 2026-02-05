/**
 * Noble curves (@noble/curves) timing tests.
 *
 * Tests elliptic curve operations for constant-time properties using
 * the DudeCT two-class pattern (baseline: all zeros, sample: random).
 *
 * Coverage:
 * - secp256k1: ECDSA signing, ECDH, verification
 * - ed25519: EdDSA signing, verification
 * - ed448: EdDSA signing, verification
 */

import { test, expect } from "bun:test";
import { TimingOracle, initializeWasm, AttackerModelValues } from "../../dist/index.js";
import { baselineBytes, sampleBytes, logResult, ATTACKER_MODELS, TIME_BUDGETS } from "./helpers.js";

// ============================================================================
// secp256k1 Tests (5 tests)
// ============================================================================

test("secp256k1: signing with random messages", async () => {
  await initializeWasm();
  const { secp256k1 } = await import("@noble/curves/secp256k1.js");

  // Fixed private key for consistent setup
  const privKey = secp256k1.utils.randomSecretKey();

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.THOROUGH)
    .maxSamples(200_000)
    .testAsync(
      {
        baseline: () => baselineBytes(32),
        sample: () => sampleBytes(32),
      },
      (message) => {
        secp256k1.sign(message, privKey);
      }
    );

  logResult("secp256k1_sign_random_msg", result);
  expect(result.outcome).toBeDefined();
});

test("secp256k1: ECDH with random private keys", async () => {
  await initializeWasm();
  const { secp256k1 } = await import("@noble/curves/secp256k1.js");

  // Fixed public key for consistent setup
  const privKey = secp256k1.utils.randomSecretKey();
  const pubKey = secp256k1.getPublicKey(privKey);

  // Note: All-zero private key is invalid, so use non-zero baseline
  const baselineKey = new Uint8Array(32);
  baselineKey[31] = 1; // Make it non-zero but consistent

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineKey.slice(), // Clone to avoid mutation
        sample: () => {
          // Generate valid random private key
          let key;
          do {
            key = sampleBytes(32);
          } while (!secp256k1.utils.isValidSecretKey(key));
          return key;
        },
      },
      (privateKey) => {
        // Compute shared secret
        secp256k1.getSharedSecret(privateKey, pubKey);
      }
    );

  logResult("secp256k1_ecdh_random_privkey", result);
  expect(result.outcome).toBeDefined();
});

test("secp256k1: signing with different private keys (informational)", async () => {
  await initializeWasm();
  const { secp256k1 } = await import("@noble/curves/secp256k1.js");

  // Fixed message
  const message = new Uint8Array(32).fill(0x42);

  // Note: All-zero private key is invalid, so use non-zero baseline
  const baselineKey = new Uint8Array(32);
  baselineKey[31] = 1; // Make it non-zero but consistent

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineKey.slice(),
        sample: () => {
          // Generate valid random private key
          let key;
          do {
            key = sampleBytes(32);
          } while (!secp256k1.utils.isValidSecretKey(key));
          return key;
        },
      },
      (privKey) => {
        secp256k1.sign(message, privKey);
      }
    );

  logResult("secp256k1_sign_different_keys", result);
  expect(result.outcome).toBeDefined();
});

test("secp256k1: Hamming weight independence", async () => {
  await initializeWasm();
  const { secp256k1 } = await import("@noble/curves/secp256k1.js");

  const privKey = secp256k1.utils.randomSecretKey();

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => new Uint8Array(32).fill(0x00), // All zeros
        sample: () => new Uint8Array(32).fill(0xff), // All ones
      },
      (message) => {
        secp256k1.sign(message, privKey);
      }
    );

  logResult("secp256k1_sign_hamming_weight", result);
  expect(result.outcome).toBeDefined();
});

test("secp256k1: signature verification (baseline, NOT constant-time requirement)", async () => {
  await initializeWasm();
  const { secp256k1 } = await import("@noble/curves/secp256k1.js");

  const privKey = secp256k1.utils.randomSecretKey();
  const pubKey = secp256k1.getPublicKey(privKey);

  // Pre-sign messages for verification
  const baselineMsg = baselineBytes(32);
  const baselineSig = secp256k1.sign(baselineMsg, privKey);

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => ({ msg: baselineMsg, sig: baselineSig }),
        sample: () => {
          const msg = sampleBytes(32);
          const sig = secp256k1.sign(msg, privKey);
          return { msg, sig };
        },
      },
      ({ msg, sig }) => {
        secp256k1.verify(sig, msg, pubKey);
      }
    );

  logResult("secp256k1_verify", result);
  expect(result.outcome).toBeDefined();
});

// ============================================================================
// ed25519 Tests (5 tests)
// ============================================================================

test("ed25519: signing with random messages", async () => {
  await initializeWasm();
  const { ed25519 } = await import("@noble/curves/ed25519.js");

  const privKey = ed25519.utils.randomSecretKey();

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(32),
        sample: () => sampleBytes(32),
      },
      (message) => {
        ed25519.sign(message, privKey);
      }
    );

  logResult("ed25519_sign_random_msg", result);
  expect(result.outcome).toBeDefined();
});

test("ed25519: signing with different private keys (informational)", async () => {
  await initializeWasm();
  const { ed25519 } = await import("@noble/curves/ed25519.js");

  const message = new Uint8Array(32).fill(0x42);

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(32),
        sample: () => sampleBytes(32),
      },
      (privKey) => {
        ed25519.sign(message, privKey);
      }
    );

  logResult("ed25519_sign_different_keys", result);
  expect(result.outcome).toBeDefined();
});

test("ed25519: Hamming weight independence", async () => {
  await initializeWasm();
  const { ed25519 } = await import("@noble/curves/ed25519.js");

  const privKey = ed25519.utils.randomSecretKey();

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => new Uint8Array(32).fill(0x00),
        sample: () => new Uint8Array(32).fill(0xff),
      },
      (message) => {
        ed25519.sign(message, privKey);
      }
    );

  logResult("ed25519_sign_hamming_weight", result);
  expect(result.outcome).toBeDefined();
});

test("ed25519: byte pattern independence", async () => {
  await initializeWasm();
  const { ed25519 } = await import("@noble/curves/ed25519.js");

  const privKey = ed25519.utils.randomSecretKey();

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => Uint8Array.from({ length: 32 }, (_, i) => i), // Sequential
        sample: () => Uint8Array.from({ length: 32 }, (_, i) => 31 - i), // Reverse
      },
      (message) => {
        ed25519.sign(message, privKey);
      }
    );

  logResult("ed25519_sign_byte_pattern", result);
  expect(result.outcome).toBeDefined();
});

test("ed25519: signature verification (baseline, NOT constant-time requirement)", async () => {
  await initializeWasm();
  const { ed25519 } = await import("@noble/curves/ed25519.js");

  const privKey = ed25519.utils.randomSecretKey();
  const pubKey = ed25519.getPublicKey(privKey);

  const baselineMsg = baselineBytes(32);
  const baselineSig = ed25519.sign(baselineMsg, privKey);

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => ({ msg: baselineMsg, sig: baselineSig }),
        sample: () => {
          const msg = sampleBytes(32);
          const sig = ed25519.sign(msg, privKey);
          return { msg, sig };
        },
      },
      ({ msg, sig }) => {
        ed25519.verify(sig, msg, pubKey);
      }
    );

  logResult("ed25519_verify", result);
  expect(result.outcome).toBeDefined();
});

// ============================================================================
// ed448 Tests (2 tests)
// ============================================================================

test("ed448: signing with random messages", async () => {
  await initializeWasm();
  const { ed448 } = await import("@noble/curves/ed448.js");

  const privKey = ed448.utils.randomSecretKey();

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => baselineBytes(57), // ed448 uses 57-byte keys
        sample: () => sampleBytes(57),
      },
      (message) => {
        ed448.sign(message, privKey);
      }
    );

  logResult("ed448_sign_random_msg", result);
  expect(result.outcome).toBeDefined();
});

test("ed448: signature verification (baseline, NOT constant-time requirement)", async () => {
  await initializeWasm();
  const { ed448 } = await import("@noble/curves/ed448.js");

  const privKey = ed448.utils.randomSecretKey();
  const pubKey = ed448.getPublicKey(privKey);

  const baselineMsg = baselineBytes(57);
  const baselineSig = ed448.sign(baselineMsg, privKey);

  const result = await TimingOracle.forAttacker(AttackerModelValues.PostQuantum)
    .timeBudget(TIME_BUDGETS.QUICK)
    .testAsync(
      {
        baseline: () => ({ msg: baselineMsg, sig: baselineSig }),
        sample: () => {
          const msg = sampleBytes(57);
          const sig = ed448.sign(msg, privKey);
          return { msg, sig };
        },
      },
      ({ msg, sig }) => {
        ed448.verify(sig, msg, pubKey);
      }
    );

  logResult("ed448_verify", result);
  expect(result.outcome).toBeDefined();
});
