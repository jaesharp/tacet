package tacet_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agucova/tacet/crates/tacet-go"
)

// =============================================================================
// Go stdlib crypto timing tests
//
// These tests validate the Go team's recent security fixes, particularly:
// - CVE-2025-22866: ECDSA timing leak on ppc64 (scalar multiplication timing)
// - General RSA PKCS#1 v1.5 constant-time properties
// - AES-GCM AEAD constant-time properties
//
// Test pattern (DudeCT two-class):
// - Baseline class: all-zero data
// - Sample class: random data
//
// IMPORTANT: Run with `sudo -E go test -run TestGoStdlib` to use macOS PMU timers
// for higher precision measurements.
// =============================================================================

// =============================================================================
// crypto/ecdsa Tests (HIGH PRIORITY - CVE-2025-22866)
// =============================================================================

// TestGoStdlibECDSA_P256_SignZerosVsRandom tests ECDSA P-256 signing timing.
// CVE-2025-22866 involved scalar multiplication timing on ppc64.
// This test uses zeros vs random for the message digest to detect any
// data-dependent timing in the signing process.
func TestGoStdlibECDSA_P256_SignZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	// Generate a fixed ECDSA P-256 key for all measurements
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(digest []byte) {
			// Sign the digest (32 bytes for SHA-256)
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
			if err != nil {
				t.Logf("ECDSA signing failed: %v", err)
				return
			}
			_ = r
			_ = s
		}),
		32, // SHA-256 digest size
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("ECDSA P-256 Sign Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)
	t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)
	t.Logf("  Samples: %d", result.SamplesUsed)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/ecdsa P-256 Sign")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  Exploitability: %s", result.Exploitability)
		t.Logf("  This may be related to CVE-2025-22866 (scalar multiplication timing)")
	}
}

// TestGoStdlibECDSA_P384_SignZerosVsRandom tests ECDSA P-384 signing timing.
func TestGoStdlibECDSA_P384_SignZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(digest []byte) {
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
			if err != nil {
				t.Logf("ECDSA signing failed: %v", err)
				return
			}
			_ = r
			_ = s
		}),
		48, // SHA-384 digest size
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("ECDSA P-384 Sign Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)
	t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/ecdsa P-384 Sign")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  Exploitability: %s", result.Exploitability)
	}
}

// TestGoStdlibECDSA_P256_VerifyZerosVsRandom tests ECDSA P-256 verification timing.
func TestGoStdlibECDSA_P256_VerifyZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Pre-generate a valid signature for a zero digest
	zeroDigest := make([]byte, 32)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, zeroDigest)
	if err != nil {
		t.Fatalf("Failed to generate test signature: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(digest []byte) {
			// Verify using the pre-generated signature
			// This will fail for random digests, but we're measuring timing not correctness
			_ = ecdsa.Verify(&privateKey.PublicKey, digest, r, s)
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("ECDSA P-256 Verify Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/ecdsa P-256 Verify")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// TestGoStdlibECDSA_P256_SharedHardware tests ECDSA with SharedHardware threshold.
// This is more sensitive and targets the ~2 cycle threshold mentioned in CVE-2025-22866.
func TestGoStdlibECDSA_P256_SharedHardware(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping thorough stdlib crypto test in short mode")
	}

	// Mark as thorough test - requires stable timing environment
	t.Skip("Requires stable timing environment and PMU timers for cycle-level precision")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(digest []byte) {
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
			if err != nil {
				return
			}
			_ = r
			_ = s
		}),
		32,
		tacet.WithAttacker(tacet.SharedHardware), // ~2 cycles @ 5GHz
		tacet.WithTimeBudget(60*time.Second),
		tacet.WithMaxSamples(100_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("ECDSA P-256 SharedHardware Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/ecdsa P-256 at SharedHardware threshold")
		t.Logf("  This indicates a cycle-level timing leak (CVE-2025-22866 class)")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// =============================================================================
// crypto/rsa Tests
// =============================================================================

// TestGoStdlibRSA_PKCS1v15_EncryptZerosVsRandom tests RSA PKCS#1 v1.5 encryption.
func TestGoStdlibRSA_PKCS1v15_EncryptZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	// Generate RSA-2048 key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(plaintext []byte) {
			// Encrypt using PKCS#1 v1.5
			// Use a fixed prefix to ensure proper message size
			msg := make([]byte, 32)
			copy(msg, plaintext)
			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, msg)
			if err != nil {
				t.Logf("RSA encryption failed: %v", err)
				return
			}
			_ = ciphertext
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("RSA PKCS#1 v1.5 Encrypt Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/rsa PKCS#1 v1.5 Encrypt")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// TestGoStdlibRSA_PKCS1v15_DecryptZerosVsRandom tests RSA PKCS#1 v1.5 decryption.
// This is critical as PKCS#1 v1.5 decryption is vulnerable to Bleichenbacher attacks.
func TestGoStdlibRSA_PKCS1v15_DecryptZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Pre-encrypt a zero message to get a valid ciphertext
	zeroMsg := make([]byte, 32)
	zeroCiphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, zeroMsg)
	if err != nil {
		t.Fatalf("Failed to generate test ciphertext: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			// Create a ciphertext-sized buffer
			// For baseline (zeros), use the valid ciphertext
			// For sample (random), use modified ciphertext
			ciphertext := make([]byte, len(zeroCiphertext))
			if input[0] == 0 {
				// Baseline: use valid ciphertext
				copy(ciphertext, zeroCiphertext)
			} else {
				// Sample: use modified ciphertext (will likely fail padding check)
				copy(ciphertext, zeroCiphertext)
				// XOR with input to make it different
				for i := range input {
					if i < len(ciphertext) {
						ciphertext[i] ^= input[i]
					}
				}
			}

			// Decrypt - timing should be constant regardless of padding validity
			plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
			_ = err        // Ignore errors - we're measuring timing not correctness
			_ = plaintext
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("RSA PKCS#1 v1.5 Decrypt Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/rsa PKCS#1 v1.5 Decrypt")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  This could enable Bleichenbacher-class attacks")
	}
}

// TestGoStdlibRSA_PKCS1v15_KnownLimitation_AssertLeak validates that tacet
// detects the known RSA PKCS#1 v1.5 timing limitation documented in Go's
// crypto/rsa package.
//
// Go's documentation explicitly warns that PKCS#1 v1.5 encryption is
// "almost impossible to use safely" and recommends RSA-OAEP instead.
// This test validates that tacet can detect timing differences in the
// padding validation code path.
//
// Expected: FAIL - This is a KNOWN limitation, not a bug.
// Reference: https://pkg.go.dev/crypto/rsa#DecryptPKCS1v15
//
// CI Configuration:
// - pass_threshold(0.01): Very hard to falsely pass (we expect leak)
// - fail_threshold(0.85): Quick to detect leak
// - time_budget(30s): Generous ceiling
func TestGoStdlibRSA_PKCS1v15_KnownLimitation_AssertLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Pre-encrypt a zero message to get a valid ciphertext
	zeroMsg := make([]byte, 32)
	zeroCiphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, zeroMsg)
	if err != nil {
		t.Fatalf("Failed to generate test ciphertext: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			// Create a ciphertext-sized buffer
			// For baseline (zeros), use the valid ciphertext
			// For sample (random), use modified ciphertext
			ciphertext := make([]byte, len(zeroCiphertext))
			if input[0] == 0 {
				// Baseline: use valid ciphertext
				copy(ciphertext, zeroCiphertext)
			} else {
				// Sample: use modified ciphertext (will likely fail padding check)
				copy(ciphertext, zeroCiphertext)
				// XOR with input to make it different
				for i := range input {
					if i < len(ciphertext) {
						ciphertext[i] ^= input[i]
					}
				}
			}

			// Decrypt - timing should be constant regardless of padding validity
			// (but Go's implementation has known timing variation)
			plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
			_ = err       // Ignore errors - we're measuring timing not correctness
			_ = plaintext
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithPassThreshold(0.01),   // Stricter thresholds for validation test
		tacet.WithFailThreshold(0.85),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[TestGoStdlibRSA_PKCS1v15_KnownLimitation_AssertLeak]")
	t.Logf("RSA PKCS#1 v1.5 Known Limitation: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	// Skip ONLY if unmeasurable (operation too fast for this platform)
	if result.Outcome == tacet.Unmeasurable {
		t.Skipf("SKIPPED: Operation too fast to measure - %s", result.Recommendation)
		return
	}

	// For known leaky code, we EXPECT Fail - this validates tacet's detection capability
	if result.Outcome != tacet.Fail {
		t.Errorf("Expected FAIL outcome for RSA PKCS#1 v1.5 known limitation, got: %s", result.Outcome)
		t.Logf("  This is a KNOWN timing limitation per Go docs (\"almost impossible to use safely\")")
		t.Logf("  If tacet cannot detect this leak, it indicates a detection failure")
		t.Logf("  Current P(leak): %.2f%%", result.LeakProbability*100)
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	} else {
		// Expected outcome - leak detected
		t.Logf("  ✓ LEAK DETECTED as expected (known limitation)")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  This validates tacet's ability to detect Bleichenbacher-class attacks")
	}
}

// TestGoStdlibRSA_OAEP_EncryptZerosVsRandom tests RSA OAEP encryption.
func TestGoStdlibRSA_OAEP_EncryptZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(plaintext []byte) {
			msg := make([]byte, 32)
			copy(msg, plaintext)
			// Use sha256.New() for OAEP (required, not nil)
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, msg, nil)
			if err != nil {
				t.Logf("RSA OAEP encryption failed: %v", err)
				return
			}
			_ = ciphertext
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("RSA OAEP Encrypt Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/rsa OAEP Encrypt")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// =============================================================================
// crypto/aes AES-GCM Tests
// =============================================================================

// TestGoStdlibAES_GCM_EncryptZerosVsRandom tests AES-256-GCM encryption.
// Uses atomic counter for unique nonces as required by AEAD pattern.
func TestGoStdlibAES_GCM_EncryptZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	// Fixed AES-256 key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}

	var nonceCounter uint64

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(plaintext []byte) {
			// Generate unique nonce using atomic counter
			n := atomic.AddUint64(&nonceCounter, 1)
			nonce := make([]byte, gcm.NonceSize())
			for i := 0; i < 8 && i < len(nonce); i++ {
				nonce[i] = byte(n >> (i * 8))
			}

			// Encrypt
			ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
			_ = ciphertext
		}),
		64, // plaintext size
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("AES-256-GCM Encrypt Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/aes GCM Encrypt")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// TestGoStdlibAES_GCM_DecryptZerosVsRandom tests AES-256-GCM decryption.
func TestGoStdlibAES_GCM_DecryptZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}

	var nonceCounter uint64

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(plaintext []byte) {
			// Generate unique nonce
			n := atomic.AddUint64(&nonceCounter, 1)
			nonce := make([]byte, gcm.NonceSize())
			for i := 0; i < 8 && i < len(nonce); i++ {
				nonce[i] = byte(n >> (i * 8))
			}

			// First encrypt to get valid ciphertext
			ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

			// Then decrypt it - timing should be constant regardless of plaintext
			decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
			_ = err
			_ = decrypted
		}),
		64,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("AES-256-GCM Decrypt Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/aes GCM Decrypt")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// =============================================================================
// Hamming Weight Independence Tests
// =============================================================================

// TestGoStdlibECDSA_P256_HammingWeight tests ECDSA P-256 with Hamming weight variation.
// Compares all-zeros vs all-ones to detect Hamming-weight-dependent timing.
func TestGoStdlibECDSA_P256_HammingWeight(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Custom generator: zeros vs ones
	gen := &hammingWeightGenerator{}

	result, err := tacet.Test(
		gen,
		tacet.FuncOperation(func(digest []byte) {
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
			if err != nil {
				return
			}
			_ = r
			_ = s
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("ECDSA P-256 Hamming Weight Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/ecdsa P-256 (Hamming weight dependent)")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// TestGoStdlibRSA_HammingWeight tests RSA with Hamming weight variation.
func TestGoStdlibRSA_HammingWeight(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	gen := &hammingWeightGenerator{}

	result, err := tacet.Test(
		gen,
		tacet.FuncOperation(func(plaintext []byte) {
			msg := make([]byte, 32)
			copy(msg, plaintext)
			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, msg)
			if err != nil {
				return
			}
			_ = ciphertext
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("RSA Hamming Weight Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/rsa (Hamming weight dependent)")
	}
}

// =============================================================================
// Harness Verification Tests
// =============================================================================

// TestGoStdlibHarness_SanityCheck verifies the test harness with identical inputs.
// Both baseline and sample are zeros - should always PASS.
func TestGoStdlibHarness_SanityCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping harness verification in short mode")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Custom generator that returns zeros for both classes
	gen := &identicalGenerator{}

	result, err := tacet.Test(
		gen,
		tacet.FuncOperation(func(digest []byte) {
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
			_ = r
			_ = s
			_ = err
		}),
		32,
		tacet.WithAttacker(tacet.Research), // Most sensitive threshold
		tacet.WithTimeBudget(10*time.Second),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("Harness Sanity Check Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)

	if result.Outcome == tacet.Fail {
		t.Errorf("HARNESS ERROR: Identical inputs should not fail")
		t.Logf("  This indicates a problem with the test setup, not the crypto")
	}
}

// TestGoStdlibHarness_KnownLeaky verifies the harness can detect obvious leaks.
func TestGoStdlibHarness_KnownLeaky(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping harness verification in short mode")
	}

	// Artificial leaky operation: early-exit comparison
	secret := make([]byte, 512)

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			// Early-exit comparison - KNOWN LEAKY
			for i := range input {
				if i >= len(secret) {
					break
				}
				if input[i] != secret[i] {
					return // Early exit on mismatch
				}
			}
		}),
		512,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(15*time.Second),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("Harness Known Leaky Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)

	if result.Outcome != tacet.Fail {
		t.Errorf("HARNESS ERROR: Known leaky operation should fail")
		t.Logf("  This indicates the harness cannot detect obvious timing leaks")
	}
}

// =============================================================================
// Helper Generators
// =============================================================================

// hammingWeightGenerator generates zeros (baseline) vs ones (sample) for Hamming weight tests.
type hammingWeightGenerator struct{}

func (g *hammingWeightGenerator) Generate(isBaseline bool, buf []byte) {
	if isBaseline {
		// All zeros - Hamming weight = 0
		for i := range buf {
			buf[i] = 0x00
		}
	} else {
		// All ones - Hamming weight = len*8
		for i := range buf {
			buf[i] = 0xFF
		}
	}
}

// identicalGenerator returns zeros for both classes (for sanity checks).
type identicalGenerator struct{}

func (g *identicalGenerator) Generate(isBaseline bool, buf []byte) {
	for i := range buf {
		buf[i] = 0x00
	}
}

// =============================================================================
// Additional RSA Tests
// =============================================================================

// TestGoStdlibRSA_SignPKCS1v15_ZerosVsRandom tests RSA PKCS#1 v1.5 signing.
func TestGoStdlibRSA_SignPKCS1v15_ZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(digest []byte) {
			// Sign digest with PKCS#1 v1.5
			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, digest)
			if err != nil {
				return
			}
			_ = signature
		}),
		32, // SHA-256 digest size
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("RSA PKCS#1 v1.5 Sign Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/rsa PKCS#1 v1.5 Sign")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// TestGoStdlibRSA_VerifyPKCS1v15_ZerosVsRandom tests RSA PKCS#1 v1.5 verification.
func TestGoStdlibRSA_VerifyPKCS1v15_ZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Pre-generate a valid signature for zero digest
	zeroDigest := make([]byte, 32)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, zeroDigest)
	if err != nil {
		t.Fatalf("Failed to generate test signature: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(digest []byte) {
			// Verify using pre-generated signature
			// Will fail for random digests, but we're measuring timing
			_ = rsa.VerifyPKCS1v15(&privateKey.PublicKey, 0, digest, signature)
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("RSA PKCS#1 v1.5 Verify Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/rsa PKCS#1 v1.5 Verify")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// TestGoStdlibRSA_DecryptOAEP_ZerosVsRandom tests RSA OAEP decryption.
func TestGoStdlibRSA_DecryptOAEP_ZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Pre-encrypt a zero message
	zeroMsg := make([]byte, 32)
	zeroCiphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, zeroMsg, nil)
	if err != nil {
		t.Fatalf("Failed to generate test ciphertext: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			ciphertext := make([]byte, len(zeroCiphertext))
			if input[0] == 0 {
				copy(ciphertext, zeroCiphertext)
			} else {
				// Modified ciphertext
				copy(ciphertext, zeroCiphertext)
				for i := range input {
					if i < len(ciphertext) {
						ciphertext[i] ^= input[i]
					}
				}
			}

			plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
			_ = err
			_ = plaintext
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("RSA OAEP Decrypt Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in crypto/rsa OAEP Decrypt")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// =============================================================================
// Scalar Arithmetic Tests
// =============================================================================

// TestGoStdlibBigInt_ModExp_ZerosVsRandom tests big.Int modular exponentiation.
// This is the underlying primitive used by RSA and may have timing leaks.
func TestGoStdlibBigInt_ModExp_ZerosVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stdlib crypto test in short mode")
	}

	// Fixed base, modulus
	base := big.NewInt(3)
	modulus, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16) // P-256 prime

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(exponent []byte) {
			// Convert exponent bytes to big.Int
			exp := new(big.Int).SetBytes(exponent)

			// Modular exponentiation: base^exp mod modulus
			result := new(big.Int).Exp(base, exp, modulus)
			_ = result
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(30*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("math/big ModExp Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in math/big ModExp")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  This affects RSA and other cryptographic primitives")
	}
}
