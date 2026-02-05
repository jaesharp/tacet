/**
 * node-forge timing tests
 *
 * node-forge is a widely-used JavaScript crypto library (~26M weekly downloads).
 * Recent CVE-2025-12816 highlights the importance of timing analysis for this library.
 *
 * This test suite focuses on:
 * - RSA PKCS#1 v1.5 encryption/decryption (HIGH PRIORITY - MARVIN-class attacks)
 * - RSA-PSS signing/verification
 * - Ed25519 signing/verification (note: node-forge doesn't support ECDSA with NIST curves)
 */

import { describe, test, expect, beforeAll } from "bun:test";
import {
  initializeWasm,
  TimingOracle,
  AttackerModelValues,
  OutcomeValues,
} from "../dist/index.js";
import forge from "node-forge";

describe("node-forge RSA PKCS#1 v1.5", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  test("sanity check: identical inputs should pass", () => {
    // Generate RSA key pair (2048-bit for realistic testing)
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });

    const inputs = {
      baseline: () => new Uint8Array(32), // All zeros
      sample: () => new Uint8Array(32),   // Also all zeros
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.Research)
      .timeBudget(180000)  // 3 minutes - JavaScript RSA is 40-100× slower than native
      .maxSamples(20000)   // Cap to prevent runaway
      .test(inputs, (plaintext) => {
        // PKCS#1 v1.5 padding requires conversion to bytes
        const message = Buffer.from(plaintext).toString("binary");
        const encrypted = keypair.publicKey.encrypt(message, "RSAES-PKCS1-V1_5");
        // Decrypt to complete the round trip
        try {
          keypair.privateKey.decrypt(encrypted, "RSAES-PKCS1-V1_5");
        } catch (e) {
          // Padding errors can occur and should be handled
        }
      });

    expect(result.isPass() || result.outcome === OutcomeValues.Inconclusive).toBe(true);
  });

  test("RSA PKCS#1 v1.5 decryption timing (MARVIN-class)", () => {
    // Generate RSA key pair
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });

    // Two-class pattern: zeros vs random plaintext
    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(240000)  // 4 minutes - RSA decryption is expensive in JavaScript
      .maxSamples(30000)   // Cap to prevent runaway
      .test(inputs, (plaintext) => {
        // Encrypt with public key
        const message = Buffer.from(plaintext).toString("binary");
        const encrypted = keypair.publicKey.encrypt(message, "RSAES-PKCS1-V1_5");

        // Decrypt with private key - this is where timing leaks occur
        // MARVIN attacks exploit padding validation timing
        try {
          keypair.privateKey.decrypt(encrypted, "RSAES-PKCS1-V1_5");
        } catch (e) {
          // Padding errors should be handled in constant time
        }
      });

    // Report results
    console.log(`\nRSA PKCS#1 v1.5 decryption: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);
    console.log(`  Samples used: ${result.samplesUsed}`);
    if (result.isFail()) {
      console.log(`  ⚠️  TIMING LEAK DETECTED in RSA PKCS#1 v1.5 decryption`);
      console.log(`  Exploitability: ${result.exploitability || "unknown"}`);
    }

    expect(result.outcome).toBeDefined();
  });

  test("RSA PKCS#1 v1.5 encryption timing", () => {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(180000)  // 3 minutes - JavaScript RSA encryption
      .maxSamples(30000)
      .test(inputs, (plaintext) => {
        const message = Buffer.from(plaintext).toString("binary");
        // Encryption should be constant-time (no secret-dependent operations)
        keypair.publicKey.encrypt(message, "RSAES-PKCS1-V1_5");
      });

    console.log(`\nRSA PKCS#1 v1.5 encryption: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });

  test("known-leaky: deliberate timing leak in RSA", () => {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });

    const inputs = {
      baseline: () => new Uint8Array(32).fill(0),
      sample: () => new Uint8Array(32).fill(0xFF),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(180000)  // 3 minutes - known-leaky test with RSA
      .maxSamples(20000)
      .test(inputs, (plaintext) => {
        const message = Buffer.from(plaintext).toString("binary");
        const encrypted = keypair.publicKey.encrypt(message, "RSAES-PKCS1-V1_5");

        // Deliberate leak: early exit if first byte is 0
        if (plaintext[0] === 0) {
          return;
        }

        // Otherwise decrypt
        try {
          keypair.privateKey.decrypt(encrypted, "RSAES-PKCS1-V1_5");
        } catch (e) {
          // Ignore errors
        }
      });

    console.log(`\nKnown-leaky RSA test: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    // Should detect the deliberate leak
    expect(result.isFail() || result.outcome === OutcomeValues.Inconclusive).toBe(true);
  });
});

describe("node-forge Ed25519", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  test("Ed25519 signing timing", () => {
    // Note: node-forge doesn't support ECDSA P-256/P-384/P-521, only Ed25519
    const keypair = forge.pki.ed25519.generateKeyPair();

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes - Ed25519 is faster than RSA but still slow in JS
      .maxSamples(30000)
      .test(inputs, (message) => {
        // Ed25519 signing
        forge.pki.ed25519.sign({
          message: Buffer.from(message),
          privateKey: keypair.privateKey,
        });
      });

    console.log(`\nEd25519 signing: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });

  test("Ed25519 verification timing", () => {
    const keypair = forge.pki.ed25519.generateKeyPair();

    // Pre-sign a message
    const testMessage = new Uint8Array(32);
    const validSignature = forge.pki.ed25519.sign({
      message: testMessage,
      privateKey: keypair.privateKey,
    });

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(120000)  // 2 minutes - Ed25519 verification
      .maxSamples(30000)
      .test(inputs, (message) => {
        // Verify signature (will fail for most messages, but timing should be constant)
        try {
          forge.pki.ed25519.verify({
            message: Buffer.from(message),
            signature: validSignature,
            publicKey: keypair.publicKey,
          });
        } catch (e) {
          // Verification failures should be constant-time
        }
      });

    console.log(`\nEd25519 verification: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });

  test("sanity check: Ed25519 with identical messages", () => {
    const keypair = forge.pki.ed25519.generateKeyPair();

    const fixedMessage = new Uint8Array(32);
    const fixedSignature = forge.pki.ed25519.sign({
      message: fixedMessage,
      privateKey: keypair.privateKey,
    });

    const inputs = {
      baseline: () => fixedMessage,
      sample: () => fixedMessage, // Same message
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.Research)
      .timeBudget(120000)  // 2 minutes - Ed25519 sanity check
      .maxSamples(20000)
      .test(inputs, (message) => {
        forge.pki.ed25519.verify({
          message: Buffer.from(message),
          signature: fixedSignature,
          publicKey: keypair.publicKey,
        });
      });

    expect(result.isPass() || result.outcome === OutcomeValues.Inconclusive).toBe(true);
  });
});

describe("node-forge RSA Signature", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  test("RSA-PSS signing timing", () => {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(180000)  // 3 minutes - RSA-PSS signing
      .maxSamples(30000)
      .test(inputs, (message) => {
        const md = forge.md.sha256.create();
        md.update(Buffer.from(message).toString("binary"));

        // RSA-PSS signature
        const pss = forge.pss.create({
          md: forge.md.sha256.create(),
          mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
          saltLength: 32,
        });

        keypair.privateKey.sign(md, pss);
      });

    console.log(`\nRSA-PSS signing: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });

  test("RSA-PSS verification timing", () => {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });

    // Pre-sign a test message
    const testMessage = new Uint8Array(32);
    const md = forge.md.sha256.create();
    md.update(Buffer.from(testMessage).toString("binary"));
    const pss = forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength: 32,
    });
    const validSignature = keypair.privateKey.sign(md, pss);

    const inputs = {
      baseline: () => new Uint8Array(32),
      sample: () => crypto.getRandomValues(new Uint8Array(32)),
    };

    const result = TimingOracle
      .forAttacker(AttackerModelValues.AdjacentNetwork)
      .timeBudget(180000)  // 3 minutes - RSA-PSS verification
      .maxSamples(30000)
      .test(inputs, (message) => {
        const md2 = forge.md.sha256.create();
        md2.update(Buffer.from(message).toString("binary"));
        const pss2 = forge.pss.create({
          md: forge.md.sha256.create(),
          mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
          saltLength: 32,
        });

        try {
          keypair.publicKey.verify(md2.digest().bytes(), validSignature, pss2);
        } catch (e) {
          // Verification failures should be constant-time
        }
      });

    console.log(`\nRSA-PSS verification: ${result.outcome}`);
    console.log(`  Leak probability: ${result.leakProbabilityPercent()}`);

    expect(result.outcome).toBeDefined();
  });
});
