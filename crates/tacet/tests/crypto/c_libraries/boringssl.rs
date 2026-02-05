//! BoringSSL timing tests
//!
//! Tests cryptographic implementations from BoringSSL (Google's OpenSSL fork) via Rust bindings.
//! Uses DudeCT's two-class pattern:
//! - Baseline: All zeros or fixed values
//! - Sample: Random values
//!
//! CRITICAL: FFI harness verification is essential. Always run sanity checks first.
//!
//! **NOTE**: These tests use the `boring` crate which builds and bundles BoringSSL.
//! No separate installation required.
//!
//! **Why BoringSSL**: Google's OpenSSL fork used in Chrome, Android, gRPC (billions of devices).
//! Real-world validation at massive scale.
//!
//! Operations tested:
//! - RSA-2048 PKCS#1 v1.5 decryption (Bleichenbacher-class attacks like MARVIN)
//! - RSA-2048 OAEP decryption
//! - RSA-2048 PSS signing
//! - ECDSA P-256 signing (private key operation)
//! - AES-256-GCM encryption/decryption
//!
//! Note: ChaCha20-Poly1305 is not tested because BoringSSL uses a different API
//! (EVP_AEAD) than the standard OpenSSL cipher interface.

use boring::ec::{EcGroup, EcKey};
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::rsa::{Padding, Rsa};
use boring::sign::Signer;
use boring::hash::MessageDigest;
use boring::symm::{Cipher, encrypt_aead, decrypt_aead};
use std::time::Duration;
use tacet::helpers::InputPair;
use tacet::{skip_if_unreliable, AttackerModel, Outcome, TimingOracle};

fn rand_bytes_32() -> [u8; 32] {
    let mut arr = [0u8; 32];
    for byte in &mut arr {
        *byte = rand::random();
    }
    arr
}

fn rand_bytes_64() -> [u8; 64] {
    let mut arr = [0u8; 64];
    for byte in &mut arr {
        *byte = rand::random();
    }
    arr
}

// ============================================================================
// RSA PKCS#1 v1.5 Tests (Bleichenbacher-class, MARVIN)
// ============================================================================

/// BoringSSL RSA PKCS#1 v1.5 decryption should be constant-time
///
/// Tests for timing side channels in PKCS#1 v1.5 padding validation.
/// Historical vulnerabilities: Bleichenbacher (1998), ROBOT (2017), MARVIN (2023)
///
/// Uses pool-based pattern to avoid caching artifacts.
#[test]
fn boringssl_rsa_2048_pkcs1v15_decrypt_constant_time() {
    const POOL_SIZE: usize = 100;

    // Generate RSA-2048 key pair
    let rsa = Rsa::generate(2048).expect("failed to generate RSA key");
    let private_key = PKey::from_rsa(rsa.clone()).expect("failed to create private key");
    let public_key = PKey::from_rsa(rsa).expect("failed to create public key");

    // Pre-generate two pools of ciphertexts
    let pool_baseline: Vec<Vec<u8>> = (0..POOL_SIZE)
        .map(|_| {
            let msg = rand_bytes_32();
            let mut encrypted = vec![0u8; 256]; // RSA-2048 = 256 bytes
            let rsa = public_key.rsa().unwrap();
            let len = rsa
                .public_encrypt(&msg, &mut encrypted, Padding::PKCS1)
                .unwrap();
            encrypted.truncate(len);
            encrypted
        })
        .collect();

    let pool_sample: Vec<Vec<u8>> = (0..POOL_SIZE)
        .map(|_| {
            let msg = rand_bytes_32();
            let mut encrypted = vec![0u8; 256];
            let rsa = public_key.rsa().unwrap();
            let len = rsa
                .public_encrypt(&msg, &mut encrypted, Padding::PKCS1)
                .unwrap();
            encrypted.truncate(len);
            encrypted
        })
        .collect();

    let idx_baseline = std::cell::Cell::new(0usize);
    let idx_sample = std::cell::Cell::new(0usize);

    let inputs = InputPair::new(
        move || {
            let i = idx_baseline.get();
            idx_baseline.set((i + 1) % POOL_SIZE);
            pool_baseline[i].clone()
        },
        move || {
            let i = idx_sample.get();
            idx_sample.set((i + 1) % POOL_SIZE);
            pool_sample[i].clone()
        },
    );

    let outcome = TimingOracle::for_attacker(AttackerModel::AdjacentNetwork)
        .pass_threshold(0.15)
        .fail_threshold(0.99)
        .time_budget(Duration::from_secs(60))
        .warmup(100)
        .calibration_samples(2000)
        .test(inputs, |ciphertext| {
            let rsa = private_key.rsa().unwrap();
            let mut decrypted = vec![0u8; 256];
            // PKCS#1 v1.5 padding - historical source of timing leaks
            let result = rsa.private_decrypt(ciphertext, &mut decrypted, Padding::PKCS1);
            std::hint::black_box(result);
        });

    eprintln!("\n[boringssl_rsa_2048_pkcs1v15_decrypt_constant_time]");
    eprintln!("{}", tacet::output::format_outcome(&outcome));

    let outcome = skip_if_unreliable!(outcome, "boringssl_rsa_2048_pkcs1v15_decrypt_constant_time");

    match &outcome {
        Outcome::Pass {
            leak_probability,
            quality,
            ..
        } => {
            eprintln!(
                "Test passed: P(leak)={:.1}%, quality={:?}",
                leak_probability * 100.0,
                quality
            );
        }
        Outcome::Fail {
            leak_probability,
            exploitability,
            effect,
            ..
        } => {
            eprintln!(
                "⚠️  TIMING LEAK DETECTED in BoringSSL RSA PKCS#1 v1.5 decryption"
            );
            eprintln!(
                "   P(leak)={:.1}%, exploitability={:?}, effect={:.1}ns",
                leak_probability * 100.0,
                exploitability,
                effect.max_effect_ns
            );
            eprintln!("   This may be a variant of MARVIN (CVE-2023-50782) or similar timing leak");
            panic!("RSA PKCS#1 v1.5 decryption timing leak - potential security vulnerability");
        }
        Outcome::Inconclusive { reason, .. } => {
            eprintln!("Inconclusive: {:?}", reason);
        }
        Outcome::Unmeasurable { recommendation, .. } => {
            eprintln!("Unmeasurable: {}", recommendation);
        }
        Outcome::Research(_) => {}
    }
}

// ============================================================================
// RSA OAEP Tests
// ============================================================================

/// BoringSSL RSA OAEP decryption should be constant-time
///
/// OAEP is more robust than PKCS#1 v1.5 but still requires constant-time implementation.
#[test]
fn boringssl_rsa_2048_oaep_decrypt_constant_time() {
    const POOL_SIZE: usize = 100;

    let rsa = Rsa::generate(2048).expect("failed to generate RSA key");
    let private_key = PKey::from_rsa(rsa.clone()).expect("failed to create private key");
    let public_key = PKey::from_rsa(rsa).expect("failed to create public key");

    // Pre-generate two pools of ciphertexts with OAEP padding
    let pool_baseline: Vec<Vec<u8>> = (0..POOL_SIZE)
        .map(|_| {
            let msg = rand_bytes_32();
            let mut encrypted = vec![0u8; 256];
            let rsa = public_key.rsa().unwrap();
            let len = rsa
                .public_encrypt(&msg, &mut encrypted, Padding::PKCS1_OAEP)
                .unwrap();
            encrypted.truncate(len);
            encrypted
        })
        .collect();

    let pool_sample: Vec<Vec<u8>> = (0..POOL_SIZE)
        .map(|_| {
            let msg = rand_bytes_32();
            let mut encrypted = vec![0u8; 256];
            let rsa = public_key.rsa().unwrap();
            let len = rsa
                .public_encrypt(&msg, &mut encrypted, Padding::PKCS1_OAEP)
                .unwrap();
            encrypted.truncate(len);
            encrypted
        })
        .collect();

    let idx_baseline = std::cell::Cell::new(0usize);
    let idx_sample = std::cell::Cell::new(0usize);

    let inputs = InputPair::new(
        move || {
            let i = idx_baseline.get();
            idx_baseline.set((i + 1) % POOL_SIZE);
            pool_baseline[i].clone()
        },
        move || {
            let i = idx_sample.get();
            idx_sample.set((i + 1) % POOL_SIZE);
            pool_sample[i].clone()
        },
    );

    let outcome = TimingOracle::for_attacker(AttackerModel::AdjacentNetwork)
        .pass_threshold(0.15)
        .fail_threshold(0.99)
        .time_budget(Duration::from_secs(60))
        .warmup(100)
        .calibration_samples(2000)
        .test(inputs, |ciphertext| {
            let rsa = private_key.rsa().unwrap();
            let mut decrypted = vec![0u8; 256];
            let result = rsa.private_decrypt(ciphertext, &mut decrypted, Padding::PKCS1_OAEP);
            std::hint::black_box(result);
        });

    eprintln!("\n[boringssl_rsa_2048_oaep_decrypt_constant_time]");
    eprintln!("{}", tacet::output::format_outcome(&outcome));

    let outcome = skip_if_unreliable!(outcome, "boringssl_rsa_2048_oaep_decrypt_constant_time");

    match &outcome {
        Outcome::Pass {
            leak_probability,
            quality,
            ..
        } => {
            eprintln!(
                "Test passed: P(leak)={:.1}%, quality={:?}",
                leak_probability * 100.0,
                quality
            );
        }
        Outcome::Fail {
            leak_probability,
            exploitability,
            effect,
            ..
        } => {
            eprintln!("⚠️  TIMING LEAK DETECTED in BoringSSL RSA OAEP decryption");
            eprintln!(
                "   P(leak)={:.1}%, exploitability={:?}, effect={:.1}ns",
                leak_probability * 100.0,
                exploitability,
                effect.max_effect_ns
            );
            panic!("RSA OAEP decryption timing leak");
        }
        Outcome::Inconclusive { reason, .. } => {
            eprintln!("Inconclusive: {:?}", reason);
        }
        Outcome::Unmeasurable { recommendation, .. } => {
            eprintln!("Unmeasurable: {}", recommendation);
        }
        Outcome::Research(_) => {}
    }
}

// ============================================================================
// RSA PSS Tests
// ============================================================================

/// BoringSSL RSA PSS signing should be constant-time
///
/// PSS (Probabilistic Signature Scheme) is the modern RSA signature scheme.
/// Tests for timing leaks in signing operation (private key operation).
#[test]
fn boringssl_rsa_2048_pss_sign_constant_time() {
    // Generate RSA-2048 key pair
    let rsa = Rsa::generate(2048).expect("failed to generate RSA key");
    let private_key = PKey::from_rsa(rsa).expect("failed to create private key");

    // Use zeros vs random pattern for message
    let inputs = InputPair::new(|| [0u8; 32], rand_bytes_32);

    let outcome = TimingOracle::for_attacker(AttackerModel::AdjacentNetwork)
        .pass_threshold(0.15)
        .fail_threshold(0.99)
        .time_budget(Duration::from_secs(60))
        .warmup(100)
        .test(inputs, |message| {
            let mut signer = Signer::new(MessageDigest::sha256(), &private_key)
                .expect("failed to create signer");
            signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            signer.set_rsa_pss_saltlen(boring::sign::RsaPssSaltlen::DIGEST_LENGTH).unwrap();
            signer.update(message).unwrap();
            let signature = signer.sign_to_vec().unwrap();
            std::hint::black_box(signature[0]);
        });

    eprintln!("\n[boringssl_rsa_2048_pss_sign_constant_time]");
    eprintln!("{}", tacet::output::format_outcome(&outcome));

    let outcome = skip_if_unreliable!(outcome, "boringssl_rsa_2048_pss_sign_constant_time");

    match &outcome {
        Outcome::Pass {
            leak_probability,
            quality,
            ..
        } => {
            eprintln!(
                "Test passed: P(leak)={:.1}%, quality={:?}",
                leak_probability * 100.0,
                quality
            );
        }
        Outcome::Fail {
            leak_probability,
            exploitability,
            effect,
            ..
        } => {
            eprintln!("⚠️  TIMING LEAK DETECTED in BoringSSL RSA PSS signing");
            eprintln!(
                "   P(leak)={:.1}%, exploitability={:?}, effect={:.1}ns",
                leak_probability * 100.0,
                exploitability,
                effect.max_effect_ns
            );
            panic!("RSA PSS signing timing leak");
        }
        Outcome::Inconclusive { reason, .. } => {
            eprintln!("Inconclusive: {:?}", reason);
        }
        Outcome::Unmeasurable { recommendation, .. } => {
            eprintln!("Unmeasurable: {}", recommendation);
        }
        Outcome::Research(_) => {}
    }
}

// ============================================================================
// ECDSA P-256 Tests (Multiple 2024 CVEs in other implementations)
// ============================================================================

/// BoringSSL ECDSA P-256 signing should be constant-time
///
/// ECDSA is particularly sensitive to timing attacks - nonce generation and
/// modular inversion can leak the private key. Multiple CVEs in 2024.
#[test]
fn boringssl_ecdsa_p256_sign_constant_time() {
    // Generate P-256 key pair
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("failed to create EC group");
    let ec_key = EcKey::generate(&group).expect("failed to generate EC key");
    let private_key = PKey::from_ec_key(ec_key).expect("failed to create private key");

    // Use zeros vs random pattern for message
    let inputs = InputPair::new(|| [0u8; 32], rand_bytes_32);

    let outcome = TimingOracle::for_attacker(AttackerModel::SharedHardware)
        .pass_threshold(0.15)
        .fail_threshold(0.99)
        .time_budget(Duration::from_secs(60))
        .warmup(100)
        .test(inputs, |message| {
            let mut signer = Signer::new(MessageDigest::sha256(), &private_key)
                .expect("failed to create signer");
            signer.update(message).unwrap();
            let signature = signer.sign_to_vec().unwrap();
            std::hint::black_box(signature[0]);
        });

    eprintln!("\n[boringssl_ecdsa_p256_sign_constant_time]");
    eprintln!("{}", tacet::output::format_outcome(&outcome));

    let outcome = skip_if_unreliable!(outcome, "boringssl_ecdsa_p256_sign_constant_time");

    match &outcome {
        Outcome::Pass {
            leak_probability,
            quality,
            ..
        } => {
            eprintln!(
                "Test passed: P(leak)={:.1}%, quality={:?}",
                leak_probability * 100.0,
                quality
            );
        }
        Outcome::Fail {
            leak_probability,
            exploitability,
            effect,
            ..
        } => {
            eprintln!("⚠️  TIMING LEAK DETECTED in BoringSSL ECDSA P-256 signing");
            eprintln!(
                "   P(leak)={:.1}%, exploitability={:?}, effect={:.1}ns",
                leak_probability * 100.0,
                exploitability,
                effect.max_effect_ns
            );
            eprintln!("   Similar to CVEs in other ECDSA implementations (2024)");
            panic!("ECDSA P-256 signing timing leak - can reveal private key");
        }
        Outcome::Inconclusive { reason, .. } => {
            eprintln!("Inconclusive: {:?}", reason);
        }
        Outcome::Unmeasurable { recommendation, .. } => {
            eprintln!("Unmeasurable: {}", recommendation);
        }
        Outcome::Research(_) => {}
    }
}

// ============================================================================
// AES-256-GCM Tests
// ============================================================================

/// BoringSSL AES-256-GCM encryption should be constant-time
///
/// Tests for data-dependent timing in AES-GCM encryption.
#[test]
fn boringssl_aes_256_gcm_encrypt_constant_time() {
    let key = rand_bytes_32();
    let cipher = Cipher::aes_256_gcm();

    let nonce_counter = std::sync::atomic::AtomicU64::new(0);
    let inputs = InputPair::new(|| [0u8; 64], rand_bytes_64);

    let outcome = TimingOracle::for_attacker(AttackerModel::AdjacentNetwork)
        .pass_threshold(0.15)
        .fail_threshold(0.99)
        .time_budget(Duration::from_secs(30))
        .test(inputs, |plaintext| {
            // Generate unique nonce for each encryption
            let n = nonce_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&n.to_le_bytes());

            let mut tag = vec![0u8; 16];
            let ciphertext = encrypt_aead(cipher, &key, Some(&nonce), &[], plaintext, &mut tag)
                .expect("encryption failed");
            std::hint::black_box(ciphertext[0]);
            std::hint::black_box(tag[0]);
        });

    eprintln!("\n[boringssl_aes_256_gcm_encrypt_constant_time]");
    eprintln!("{}", tacet::output::format_outcome(&outcome));

    let outcome = skip_if_unreliable!(outcome, "boringssl_aes_256_gcm_encrypt_constant_time");

    match &outcome {
        Outcome::Pass {
            leak_probability,
            quality,
            ..
        } => {
            eprintln!(
                "Test passed: P(leak)={:.1}%, quality={:?}",
                leak_probability * 100.0,
                quality
            );
        }
        Outcome::Fail {
            leak_probability,
            exploitability,
            effect,
            ..
        } => {
            eprintln!("⚠️  TIMING LEAK DETECTED in BoringSSL AES-256-GCM encryption");
            eprintln!(
                "   P(leak)={:.1}%, exploitability={:?}, effect={:.1}ns",
                leak_probability * 100.0,
                exploitability,
                effect.max_effect_ns
            );
            panic!("AES-256-GCM encryption timing leak");
        }
        Outcome::Inconclusive { reason, .. } => {
            eprintln!("Inconclusive: {:?}", reason);
        }
        Outcome::Unmeasurable { recommendation, .. } => {
            eprintln!("Unmeasurable: {}", recommendation);
        }
        Outcome::Research(_) => {}
    }
}

/// BoringSSL AES-256-GCM decryption should be constant-time
///
/// Tests for data-dependent timing in AES-GCM decryption, including MAC verification.
#[test]
fn boringssl_aes_256_gcm_decrypt_constant_time() {
    const POOL_SIZE: usize = 100;

    let key = rand_bytes_32();
    let cipher = Cipher::aes_256_gcm();

    // Pre-generate two pools of ciphertext/tag pairs
    let mut pool_baseline: Vec<(Vec<u8>, Vec<u8>, [u8; 12])> = Vec::with_capacity(POOL_SIZE);
    let mut pool_sample: Vec<(Vec<u8>, Vec<u8>, [u8; 12])> = Vec::with_capacity(POOL_SIZE);

    for i in 0..POOL_SIZE {
        // Baseline: all zeros
        let plaintext = [0u8; 64];
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let mut tag = vec![0u8; 16];
        let ciphertext = encrypt_aead(cipher, &key, Some(&nonce), &[], &plaintext, &mut tag)
            .expect("encryption failed");
        pool_baseline.push((ciphertext, tag, nonce));

        // Sample: random
        let plaintext = rand_bytes_64();
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&((i + POOL_SIZE) as u64).to_le_bytes());
        let mut tag = vec![0u8; 16];
        let ciphertext = encrypt_aead(cipher, &key, Some(&nonce), &[], &plaintext, &mut tag)
            .expect("encryption failed");
        pool_sample.push((ciphertext, tag, nonce));
    }

    let idx_baseline = std::cell::Cell::new(0usize);
    let idx_sample = std::cell::Cell::new(0usize);

    let inputs = InputPair::new(
        move || {
            let i = idx_baseline.get();
            idx_baseline.set((i + 1) % POOL_SIZE);
            i
        },
        move || {
            let i = idx_sample.get();
            idx_sample.set((i + 1) % POOL_SIZE);
            i + POOL_SIZE
        },
    );

    let all_pairs: Vec<_> = pool_baseline.into_iter().chain(pool_sample).collect();

    let outcome = TimingOracle::for_attacker(AttackerModel::AdjacentNetwork)
        .pass_threshold(0.15)
        .fail_threshold(0.99)
        .time_budget(Duration::from_secs(30))
        .test(inputs, |idx| {
            let (ciphertext, tag, nonce) = &all_pairs[*idx];
            let plaintext = decrypt_aead(cipher, &key, Some(nonce), &[], ciphertext, tag);
            std::hint::black_box(plaintext);
        });

    eprintln!("\n[boringssl_aes_256_gcm_decrypt_constant_time]");
    eprintln!("{}", tacet::output::format_outcome(&outcome));

    let outcome = skip_if_unreliable!(outcome, "boringssl_aes_256_gcm_decrypt_constant_time");

    match &outcome {
        Outcome::Pass {
            leak_probability,
            quality,
            ..
        } => {
            eprintln!(
                "Test passed: P(leak)={:.1}%, quality={:?}",
                leak_probability * 100.0,
                quality
            );
        }
        Outcome::Fail {
            leak_probability,
            exploitability,
            effect,
            ..
        } => {
            eprintln!("⚠️  TIMING LEAK DETECTED in BoringSSL AES-256-GCM decryption");
            eprintln!(
                "   P(leak)={:.1}%, exploitability={:?}, effect={:.1}ns",
                leak_probability * 100.0,
                exploitability,
                effect.max_effect_ns
            );
            panic!("AES-256-GCM decryption timing leak");
        }
        Outcome::Inconclusive { reason, .. } => {
            eprintln!("Inconclusive: {:?}", reason);
        }
        Outcome::Unmeasurable { recommendation, .. } => {
            eprintln!("Unmeasurable: {}", recommendation);
        }
        Outcome::Research(_) => {}
    }
}

// ============================================================================
// Harness Verification Tests
// ============================================================================

/// Sanity check: identical inputs should pass
///
/// FFI overhead can introduce noise - verify harness is working correctly
#[test]
fn boringssl_harness_sanity_check() {
    let rsa = Rsa::generate(2048).expect("failed to generate RSA key");
    let private_key = PKey::from_rsa(rsa.clone()).expect("failed to create private key");
    let public_key = PKey::from_rsa(rsa).expect("failed to create public key");

    // Pre-generate a single ciphertext
    let msg = rand_bytes_32();
    let mut encrypted = vec![0u8; 256];
    let rsa = public_key.rsa().unwrap();
    let len = rsa
        .public_encrypt(&msg, &mut encrypted, Padding::PKCS1)
        .unwrap();
    encrypted.truncate(len);

    // Both classes return the same ciphertext
    let inputs = InputPair::new(|| encrypted.clone(), || encrypted.clone());

    let outcome = TimingOracle::for_attacker(AttackerModel::Research)
        .time_budget(Duration::from_secs(10))
        .test(inputs, |ciphertext| {
            let rsa = private_key.rsa().unwrap();
            let mut decrypted = vec![0u8; 256];
            let result = rsa.private_decrypt(ciphertext, &mut decrypted, Padding::PKCS1);
            std::hint::black_box(result);
        });

    eprintln!("\n[boringssl_harness_sanity_check]");
    eprintln!("{}", tacet::output::format_outcome(&outcome));

    match &outcome {
        Outcome::Pass { .. } => {
            eprintln!("Sanity check passed - harness is working correctly");
        }
        Outcome::Fail { .. } => {
            panic!("Sanity check failed - identical inputs should not show timing difference");
        }
        _ => {}
    }
}
