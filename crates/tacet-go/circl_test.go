package tacet_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/agucova/tacet/crates/tacet-go"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/sign/ed25519"
)

// =============================================================================
// Cloudflare circl Post-Quantum Cryptography Timing Tests
//
// These tests validate timing side-channel properties of Cloudflare's circl
// library, focusing on post-quantum algorithms used in production at scale.
//
// Test pattern (DudeCT two-class):
// - Baseline class: all-zero data
// - Sample class: random data
//
// CRITICAL SCOPE:
// - Test ONLY private key operations (decapsulation, signing)
// - Public key operations (encapsulation, verification) are NOT constant-time requirements
//
// Cross-validation:
// - Compare results with Rust pqcrypto tests (crates/tacet/tests/crypto/pqcrypto/)
// - Findings documented in CIRCL_INVESTIGATION_REPORT.md
//
// IMPORTANT: Run with `sudo -E go test -run TestCircl -v` to use macOS PMU
// timers for higher precision measurements (~cycle-level).
// =============================================================================

// =============================================================================
// Kyber512 (ML-KEM) Tests
// =============================================================================

// TestCircl_Kyber512_Decapsulation tests Kyber512 decapsulation timing.
// This is the CRITICAL private key operation that must be constant-time.
func TestCircl_Kyber512_Decapsulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	scheme := kyber512.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber512 key pair: %v", err)
	}

	// Pre-generate a valid ciphertext
	baseCiphertext, _, err := scheme.Encapsulate(publicKey)
	if err != nil {
		t.Fatalf("Failed to encapsulate: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			// Modify ciphertext based on input (zeros vs random)
			// For baseline (zeros): use unmodified ciphertext
			// For sample (random): XOR ciphertext with input
			ct := make([]byte, len(baseCiphertext))
			copy(ct, baseCiphertext)

			// Only modify if we have random input (sample class)
			if input[0] != 0 {
				for i := range input {
					if i < len(ct) {
						ct[i] ^= input[i]
					}
				}
			}

			// Decapsulate - timing should be constant regardless of ciphertext validity
			sharedSecret, err := scheme.Decapsulate(privateKey, ct)
			_ = sharedSecret
			_ = err // Ignore errors - we're measuring timing, not correctness
		}),
		32, // Input size for XOR modification
		tacet.WithAttacker(tacet.PostQuantum), // ~10 cycles @ 5 GHz
		tacet.WithTimeBudget(60*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[Kyber512 Decapsulation]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)
	t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)
	t.Logf("  Samples: %d", result.SamplesUsed)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in Kyber512 Decapsulation")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  Exploitability: %s", result.Exploitability)
		t.Logf("  This is CRITICAL: Kyber decapsulation must be constant-time (KyberSlash-class vulnerability)")
	}
}

// TestCircl_Kyber512_Encapsulation tests Kyber512 encapsulation timing.
// This is a PUBLIC KEY operation - timing leaks are less critical but still undesirable.
func TestCircl_Kyber512_Encapsulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	scheme := kyber512.Scheme()
	publicKey, _, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber512 key pair: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			// Encapsulation with same public key
			// Input is ignored - we're measuring encapsulation consistency
			ciphertext, sharedSecret, err := scheme.Encapsulate(publicKey)
			_ = ciphertext
			_ = sharedSecret
			_ = err
		}),
		32,
		tacet.WithAttacker(tacet.PostQuantum),
		tacet.WithTimeBudget(45*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[Kyber512 Encapsulation]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)
	t.Logf("  Note: This is a PUBLIC KEY operation - timing leaks less critical")

	if result.Outcome == tacet.Fail {
		t.Logf("Timing difference detected in Kyber512 Encapsulation")
		t.Logf("  Effect: %.2f ns (public key operation)", result.Effect.MaxEffectNs)
	}
}

// =============================================================================
// Kyber768 (ML-KEM) Tests
// =============================================================================

// TestCircl_Kyber768_Decapsulation tests Kyber768 decapsulation timing.
// Kyber768 is the NIST Level 3 parameter set (most commonly deployed).
func TestCircl_Kyber768_Decapsulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	scheme := kyber768.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber768 key pair: %v", err)
	}

	baseCiphertext, _, err := scheme.Encapsulate(publicKey)
	if err != nil {
		t.Fatalf("Failed to encapsulate: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			ct := make([]byte, len(baseCiphertext))
			copy(ct, baseCiphertext)

			if input[0] != 0 {
				for i := range input {
					if i < len(ct) {
						ct[i] ^= input[i]
					}
				}
			}

			sharedSecret, err := scheme.Decapsulate(privateKey, ct)
			_ = sharedSecret
			_ = err
		}),
		32,
		tacet.WithAttacker(tacet.PostQuantum),
		tacet.WithTimeBudget(60*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[Kyber768 Decapsulation]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)
	t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in Kyber768 Decapsulation")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  Exploitability: %s", result.Exploitability)
	}
}

// =============================================================================
// Kyber1024 (ML-KEM) Tests
// =============================================================================

// TestCircl_Kyber1024_Decapsulation tests Kyber1024 decapsulation timing.
// Kyber1024 is the NIST Level 5 parameter set (highest security).
func TestCircl_Kyber1024_Decapsulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	scheme := kyber1024.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber1024 key pair: %v", err)
	}

	baseCiphertext, _, err := scheme.Encapsulate(publicKey)
	if err != nil {
		t.Fatalf("Failed to encapsulate: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			ct := make([]byte, len(baseCiphertext))
			copy(ct, baseCiphertext)

			if input[0] != 0 {
				for i := range input {
					if i < len(ct) {
						ct[i] ^= input[i]
					}
				}
			}

			sharedSecret, err := scheme.Decapsulate(privateKey, ct)
			_ = sharedSecret
			_ = err
		}),
		32,
		tacet.WithAttacker(tacet.PostQuantum),
		tacet.WithTimeBudget(60*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[Kyber1024 Decapsulation]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in Kyber1024 Decapsulation")
		t.Logf("  Effect size: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// =============================================================================
// Dilithium Mode2 (ML-DSA) Tests
// =============================================================================

// TestCircl_Dilithium2_Signing tests Dilithium Mode2 signing timing.
// NOTE: Dilithium uses rejection sampling which causes INTENTIONAL timing variation
// based on the message. This is NOT a vulnerability because:
// 1. The message is public in signature schemes
// 2. The rejection probability is independent of the secret key
func TestCircl_Dilithium2_Signing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	_, privateKey, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium2 key pair: %v", err)
	}

	// Test with same message for both classes to isolate measurement noise
	// from message-dependent rejection sampling
	fixedMessage := make([]byte, 64)
	for i := range fixedMessage {
		fixedMessage[i] = 0x42
	}

	result, err := tacet.Test(
		&fixedMessageGenerator{message: fixedMessage},
		tacet.FuncOperation(func(msg []byte) {
			signature := make([]byte, mode2.SignatureSize)
			mode2.SignTo(privateKey, msg, signature)
			_ = signature
		}),
		64,
		tacet.WithAttacker(tacet.PostQuantum),
		tacet.WithTimeBudget(60*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[Dilithium Mode2 Signing]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)
	t.Logf("  Note: Same message used for both classes (testing timing consistency)")

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in Dilithium2 Signing (same message)")
		t.Logf("  This suggests implementation issue, not rejection sampling")
		t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// TestCircl_Dilithium2_MessageHamming tests Dilithium Mode2 with different messages.
// This is INFORMATIONAL - Dilithium timing varies based on message content due to
// rejection sampling. This is expected behavior, not a vulnerability.
func TestCircl_Dilithium2_MessageHamming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	_, privateKey, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium2 key pair: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(msg []byte) {
			signature := make([]byte, mode2.SignatureSize)
			mode2.SignTo(privateKey, msg, signature)
			_ = signature
		}),
		64,
		tacet.WithAttacker(tacet.PostQuantum),
		tacet.WithTimeBudget(60*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[Dilithium Mode2 Message Hamming]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)
	t.Logf("  Note: Dilithium uses rejection sampling - message-dependent timing is EXPECTED")
	t.Logf("        This is NOT a vulnerability (message is public, rejection independent of secret)")

	// Don't fail on timing difference - this is informational
	if result.Outcome == tacet.Fail {
		t.Logf("Timing difference detected (expected for Dilithium): %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  This is EXPECTED behavior, not a vulnerability")
	}
}

// =============================================================================
// Dilithium Mode3 (ML-DSA) Tests
// =============================================================================

// TestCircl_Dilithium3_Signing tests Dilithium Mode3 signing timing.
// Mode3 is the NIST Level 3 parameter set (most commonly deployed).
func TestCircl_Dilithium3_Signing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	_, privateKey, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium3 key pair: %v", err)
	}

	fixedMessage := make([]byte, 64)
	for i := range fixedMessage {
		fixedMessage[i] = 0x42
	}

	result, err := tacet.Test(
		&fixedMessageGenerator{message: fixedMessage},
		tacet.FuncOperation(func(msg []byte) {
			signature := make([]byte, mode3.SignatureSize)
			mode3.SignTo(privateKey, msg, signature)
			_ = signature
		}),
		64,
		tacet.WithAttacker(tacet.PostQuantum),
		tacet.WithTimeBudget(60*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[Dilithium Mode3 Signing]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in Dilithium3 Signing (same message)")
		t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// =============================================================================
// Dilithium Mode5 (ML-DSA) Tests
// =============================================================================

// TestCircl_Dilithium5_Signing tests Dilithium Mode5 signing timing.
// Mode5 is the NIST Level 5 parameter set (highest security).
func TestCircl_Dilithium5_Signing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	_, privateKey, err := mode5.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium5 key pair: %v", err)
	}

	fixedMessage := make([]byte, 64)
	for i := range fixedMessage {
		fixedMessage[i] = 0x42
	}

	result, err := tacet.Test(
		&fixedMessageGenerator{message: fixedMessage},
		tacet.FuncOperation(func(msg []byte) {
			signature := make([]byte, mode5.SignatureSize)
			mode5.SignTo(privateKey, msg, signature)
			_ = signature
		}),
		64,
		tacet.WithAttacker(tacet.PostQuantum),
		tacet.WithTimeBudget(60*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[Dilithium Mode5 Signing]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in Dilithium5 Signing (same message)")
		t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)
	}
}

// =============================================================================
// X25519 Tests (Classical ECC for comparison)
// =============================================================================

// TestCircl_X25519_ScalarMult tests X25519 scalar multiplication timing.
// This serves as a comparison with golang.org/x/crypto/curve25519.
func TestCircl_X25519_ScalarMult(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	// Generate a fixed base point
	var basepoint x25519.Key
	rand.Read(basepoint[:])

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(scalar []byte) {
			// Ensure scalar is 32 bytes
			var scalarKey x25519.Key
			copy(scalarKey[:], scalar)

			// Perform scalar multiplication
			var output x25519.Key
			x25519.KeyGen(&output, &scalarKey)
			_ = output
		}),
		32,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(45*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[circl X25519 Scalar Multiplication]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in circl X25519")
		t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  Compare with golang.org/x/crypto/curve25519 results")
	}
}

// =============================================================================
// Ed25519 Tests (Classical EdDSA for comparison)
// =============================================================================

// TestCircl_Ed25519_Signing tests Ed25519 signing timing.
// This serves as a comparison with stdlib crypto/ed25519.
func TestCircl_Ed25519_Signing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(message []byte) {
			signature := ed25519.Sign(privateKey, message)
			_ = signature
		}),
		64,
		tacet.WithAttacker(tacet.AdjacentNetwork),
		tacet.WithTimeBudget(45*time.Second),
		tacet.WithMaxSamples(50_000),
	)
	if err != nil {
		t.Fatalf("Test failed with error: %v", err)
	}

	t.Logf("\n[circl Ed25519 Signing]")
	t.Logf("Result: %s", result)
	t.Logf("  Outcome: %s", result.Outcome)
	t.Logf("  P(leak): %.2f%%", result.LeakProbability*100)

	if result.Outcome == tacet.Fail {
		t.Errorf("TIMING LEAK DETECTED in circl Ed25519")
		t.Logf("  Effect: %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  Compare with crypto/ed25519 results")
	}

	// Also report public key to suppress unused variable warning
	_ = publicKey
}

// =============================================================================
// Helper Generators
// =============================================================================

// fixedMessageGenerator returns the same message for both baseline and sample classes.
// Used for testing Dilithium signing with identical messages to isolate
// measurement noise from message-dependent rejection sampling.
type fixedMessageGenerator struct {
	message []byte
}

func (g *fixedMessageGenerator) Generate(isBaseline bool, buf []byte) {
	copy(buf, g.message)
}
