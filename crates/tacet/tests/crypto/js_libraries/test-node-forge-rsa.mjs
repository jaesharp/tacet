#!/usr/bin/env node
/**
 * node-forge RSA PKCS#1 v1.5 timing tests
 *
 * Tests node-forge RSA implementation for timing side channels.
 * HIGH PRIORITY: node-forge has CVE-2025-12816 (timing vulnerability in RSA PKCS#1 v1.5)
 *
 * NOTE: This script requires @tacet/js to be built and available.
 * Run from the tacet-napi directory: bun run build
 */

import forge from 'node-forge';

// Import tacet from the parent tacet-napi package
// We'll use a workaround since the link might not work
// For now, create a version that outputs JSON results that Rust can parse

// Generate RSA key pair (1024-bit for speed)
console.error('Generating RSA-1024 key pair...');
const keyPair = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
const publicKey = keyPair.publicKey;
const privateKey = keyPair.privateKey;

/**
 * Test RSA encryption timing (zeros vs random messages)
 */
function testRSAEncryption() {
    console.error('\\nTesting RSA PKCS#1 v1.5 encryption...');

    const baselineMessage = Buffer.alloc(32, 0); // All zeros

    // Warmup
    for (let i = 0; i < 100; i++) {
        publicKey.encrypt(baselineMessage.toString('binary'), 'RSAES-PKCS1-V1_5');
    }

    // Measure baseline (zeros) - collect many samples
    const baselineTimes = [];
    for (let i = 0; i < 1000; i++) {
        const start = process.hrtime.bigint();
        publicKey.encrypt(baselineMessage.toString('binary'), 'RSAES-PKCS1-V1_5');
        const end = process.hrtime.bigint();
        baselineTimes.push(Number(end - start));
    }

    // Measure sample (random) - collect many samples
    const sampleTimes = [];
    for (let i = 0; i < 1000; i++) {
        const randomMessage = Buffer.allocUnsafe(32);
        for (let j = 0; j < 32; j++) {
            randomMessage[j] = Math.floor(Math.random() * 256);
        }
        const start = process.hrtime.bigint();
        publicKey.encrypt(randomMessage.toString('binary'), 'RSAES-PKCS1-V1_5');
        const end = process.hrtime.bigint();
        sampleTimes.push(Number(end - start));
    }

    // Calculate statistics
    const baselineMean = baselineTimes.reduce((a, b) => a + b, 0) / baselineTimes.length;
    const sampleMean = sampleTimes.reduce((a, b) => a + b, 0) / sampleTimes.length;
    const difference = Math.abs(sampleMean - baselineMean);

    console.error(`Baseline mean: ${(baselineMean / 1000).toFixed(2)} µs`);
    console.error(`Sample mean: ${(sampleMean / 1000).toFixed(2)} µs`);
    console.error(`Difference: ${(difference / 1000).toFixed(2)} µs`);

    return {
        operation: 'rsa_encrypt',
        baseline_mean_ns: baselineMean,
        sample_mean_ns: sampleMean,
        difference_ns: difference,
    };
}

/**
 * Test RSA decryption timing (different ciphertexts)
 */
function testRSADecryption() {
    console.error('\\nTesting RSA PKCS#1 v1.5 decryption...');

    // Pre-generate ciphertexts
    const baselineCiphertexts = [];
    const sampleCiphertexts = [];

    for (let i = 0; i < 1000; i++) {
        const msg1 = Buffer.alloc(32, 0);
        const msg2 = Buffer.allocUnsafe(32);
        for (let j = 0; j < 32; j++) {
            msg2[j] = Math.floor(Math.random() * 256);
        }
        baselineCiphertexts.push(publicKey.encrypt(msg1.toString('binary'), 'RSAES-PKCS1-V1_5'));
        sampleCiphertexts.push(publicKey.encrypt(msg2.toString('binary'), 'RSAES-PKCS1-V1_5'));
    }

    // Warmup
    for (let i = 0; i < 100; i++) {
        privateKey.decrypt(baselineCiphertexts[i % baselineCiphertexts.length], 'RSAES-PKCS1-V1_5');
    }

    // Measure baseline
    const baselineTimes = [];
    for (let i = 0; i < baselineCiphertexts.length; i++) {
        const start = process.hrtime.bigint();
        privateKey.decrypt(baselineCiphertexts[i], 'RSAES-PKCS1-V1_5');
        const end = process.hrtime.bigint();
        baselineTimes.push(Number(end - start));
    }

    // Measure sample
    const sampleTimes = [];
    for (let i = 0; i < sampleCiphertexts.length; i++) {
        const start = process.hrtime.bigint();
        privateKey.decrypt(sampleCiphertexts[i], 'RSAES-PKCS1-V1_5');
        const end = process.hrtime.bigint();
        sampleTimes.push(Number(end - start));
    }

    // Calculate statistics
    const baselineMean = baselineTimes.reduce((a, b) => a + b, 0) / baselineTimes.length;
    const sampleMean = sampleTimes.reduce((a, b) => a + b, 0) / sampleTimes.length;
    const difference = Math.abs(sampleMean - baselineMean);

    console.error(`Baseline mean: ${(baselineMean / 1000).toFixed(2)} µs`);
    console.error(`Sample mean: ${(sampleMean / 1000).toFixed(2)} µs`);
    console.error(`Difference: ${(difference / 1000).toFixed(2)} µs`);

    return {
        operation: 'rsa_decrypt',
        baseline_mean_ns: baselineMean,
        sample_mean_ns: sampleMean,
        difference_ns: difference,
    };
}

// Run tests and output JSON
const results = {
    library: 'node-forge',
    version: '1.3.x',
    cve: 'CVE-2025-12816',
    tests: [
        testRSAEncryption(),
        testRSADecryption(),
    ],
};

console.log(JSON.stringify(results, null, 2));
