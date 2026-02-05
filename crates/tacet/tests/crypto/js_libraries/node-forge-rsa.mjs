#!/usr/bin/env node
/**
 * node-forge RSA PKCS#1 v1.5 operations
 *
 * This script provides RSA operations using node-forge for timing analysis.
 * HIGH PRIORITY: node-forge has CVE-2025-12816 (timing vulnerability in RSA PKCS#1 v1.5)
 */

import forge from 'node-forge';

// Pre-generate RSA key pair (1024-bit for speed, same constant-time properties as 2048)
const keyPair = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
const publicKey = keyPair.publicKey;
const privateKey = keyPair.privateKey;

/**
 * RSA PKCS#1 v1.5 encryption
 * @param {Buffer} message - Message to encrypt (as Buffer)
 * @returns {Buffer} - Ciphertext
 */
export function rsaEncrypt(message) {
    const encrypted = publicKey.encrypt(message.toString('binary'), 'RSAES-PKCS1-V1_5');
    return Buffer.from(encrypted, 'binary');
}

/**
 * RSA PKCS#1 v1.5 decryption
 * @param {Buffer} ciphertext - Ciphertext to decrypt (as Buffer)
 * @returns {Buffer} - Plaintext
 */
export function rsaDecrypt(ciphertext) {
    const decrypted = privateKey.decrypt(ciphertext.toString('binary'), 'RSAES-PKCS1-V1_5');
    return Buffer.from(decrypted, 'binary');
}

/**
 * Pre-generate ciphertexts for decryption tests
 * @param {number} count - Number of ciphertexts to generate
 * @returns {Array<Buffer>} - Array of ciphertexts
 */
export function generateCiphertexts(count) {
    const ciphertexts = [];
    for (let i = 0; i < count; i++) {
        // Generate random 32-byte messages
        const message = Buffer.allocUnsafe(32);
        for (let j = 0; j < 32; j++) {
            message[j] = Math.floor(Math.random() * 256);
        }
        const encrypted = rsaEncrypt(message);
        ciphertexts.push(encrypted);
    }
    return ciphertexts;
}

// If run directly, perform a test
if (import.meta.url === `file://${process.argv[1]}`) {
    console.log('Testing node-forge RSA PKCS#1 v1.5...');
    const message = Buffer.from('Hello, World!');
    const encrypted = rsaEncrypt(message);
    const decrypted = rsaDecrypt(encrypted);
    console.log('Original:', message.toString());
    console.log('Decrypted:', decrypted.toString());
    console.log('Match:', message.equals(decrypted));
}
