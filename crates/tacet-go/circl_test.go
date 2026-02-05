package tacet_test

import (
	"crypto/rand"
	mathrand "math/rand/v2"
	"testing"
	"time"

	"github.com/agucova/tacet/crates/tacet-go"
	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
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
// Kyber Decapsulation Pool Helpers
//
// To avoid measurement artifacts, Kyber decapsulation tests pre-generate a
// flat pool of ciphertexts outside the timed closure:
//
//   pool[0..poolHalf-1]       = valid ciphertexts   (baseline class)
//   pool[poolHalf..poolSize-1] = corrupted ciphertexts (sample class)
//
// The generator encodes a pool index into the input buffer. Baseline indices
// point to the first half; sample indices point to the second half. The timed
// closure performs a single array lookup and calls Decapsulate -- no branches,
// no allocations, no XOR inside the measurement region.
// =============================================================================

const kyberPoolHalf = 256
const kyberPoolTotal = kyberPoolHalf * 2

// kyberFlatPool is a single flat array where the first half holds valid
// ciphertexts (baseline) and the second half holds corrupted ciphertexts
// (sample). The timed closure indexes into this array with no branches.
type kyberFlatPool struct {
	entries [kyberPoolTotal][]byte
}

// newKyberFlatPool builds a flat ciphertext pool for artifact-free DudeCT
// testing. The first kyberPoolHalf entries are valid ciphertexts; the second
// kyberPoolHalf entries are copies with random corruption applied.
func newKyberFlatPool(scheme kem.Scheme, publicKey kem.PublicKey) (*kyberFlatPool, error) {
	pool := &kyberFlatPool{}
	rng := mathrand.New(mathrand.NewPCG(12345, 67890))

	for i := 0; i < kyberPoolHalf; i++ {
		// Generate a fresh valid ciphertext for each pair to avoid
		// cache-line sharing artifacts between entries.
		ct, _, err := scheme.Encapsulate(publicKey)
		if err != nil {
			return nil, err
		}

		// Baseline half: unmodified valid ciphertext
		pool.entries[i] = make([]byte, len(ct))
		copy(pool.entries[i], ct)

		// Sample half: corrupt the ciphertext with random XOR data
		corrupted := make([]byte, len(ct))
		copy(corrupted, ct)
		for j := 0; j < 32 && j < len(ct); j++ {
			corrupted[j] ^= byte(rng.UintN(256))
		}
		// Ensure at least one byte differs
		if corrupted[0] == ct[0] {
			corrupted[0] ^= 0x01
		}
		pool.entries[kyberPoolHalf+i] = corrupted
	}
	return pool, nil
}

// kyberPoolIndexGenerator encodes a rotating pool index into the input buffer.
// Baseline invocations get indices in [0, kyberPoolHalf), pointing to valid
// ciphertexts. Sample invocations get indices in [kyberPoolHalf, kyberPoolTotal),
// pointing to corrupted ciphertexts.
type kyberPoolIndexGenerator struct {
	baselineCounter uint64
	sampleCounter   uint64
}

func (g *kyberPoolIndexGenerator) Generate(isBaseline bool, buf []byte) {
	// Store a 16-bit index in buf[0:2] (little-endian). The rest of the
	// buffer is zeroed to avoid spurious entropy.
	for i := range buf {
		buf[i] = 0
	}

	var idx uint16
	if isBaseline {
		idx = uint16(g.baselineCounter % kyberPoolHalf)
		g.baselineCounter++
	} else {
		idx = uint16(kyberPoolHalf + (g.sampleCounter % kyberPoolHalf))
		g.sampleCounter++
	}
	buf[0] = byte(idx)
	buf[1] = byte(idx >> 8)
}

// =============================================================================
// Kyber512 (ML-KEM) Tests
// =============================================================================

// TestCircl_Kyber512_Decapsulation tests Kyber512 decapsulation timing.
// This is the CRITICAL private key operation that must be constant-time.
//
// Harness design: A flat pool of ciphertexts is pre-generated outside the
// timed region. The generator encodes a pool index into the input buffer.
// The operation closure reads the index, looks up the pre-generated
// ciphertext, and calls Decapsulate -- no branches on class identity,
// no heap allocations, no data manipulation inside the timed region.
func TestCircl_Kyber512_Decapsulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	scheme := kyber512.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber512 key pair: %v", err)
	}

	pool, err := newKyberFlatPool(scheme, publicKey)
	if err != nil {
		t.Fatalf("Failed to build ciphertext pool: %v", err)
	}

	result, err := tacet.Test(
		&kyberPoolIndexGenerator{},
		tacet.FuncOperation(func(input []byte) {
			// Decode the pool index from the input buffer (little-endian u16).
			// Both classes execute identical code; only the index differs.
			idx := int(input[0]) | int(input[1])<<8
			ct := pool.entries[idx]
			sharedSecret, err := scheme.Decapsulate(privateKey, ct)
			_ = sharedSecret
			_ = err
		}),
		32,
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
// This is a PUBLIC KEY operation -- timing leaks are less critical but still
// undesirable.
//
// Harness design: Uses EncapsulateDeterministically with a seed that varies
// between classes (all-zero seed for baseline, random seed for sample). This
// tests whether encapsulation timing depends on the randomness input.
func TestCircl_Kyber512_Encapsulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	scheme := kyber512.Scheme()
	publicKey, _, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber512 key pair: %v", err)
	}

	seedSize := scheme.EncapsulationSeedSize()

	// Pre-allocate seed buffer outside the timed closure.
	seed := make([]byte, seedSize)

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(input []byte) {
			// Copy generator output into the seed buffer.
			// Baseline: seed is all zeros. Sample: seed is random bytes.
			copy(seed, input)
			// Zero-pad if input is shorter than seedSize.
			for i := len(input); i < seedSize; i++ {
				seed[i] = 0
			}
			ct, ss, err := scheme.EncapsulateDeterministically(publicKey, seed)
			_ = ct
			_ = ss
			_ = err
		}),
		seedSize,
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
//
// Harness design: Same pre-generated flat pool approach as Kyber512 -- see
// TestCircl_Kyber512_Decapsulation for details.
func TestCircl_Kyber768_Decapsulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	scheme := kyber768.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber768 key pair: %v", err)
	}

	pool, err := newKyberFlatPool(scheme, publicKey)
	if err != nil {
		t.Fatalf("Failed to build ciphertext pool: %v", err)
	}

	result, err := tacet.Test(
		&kyberPoolIndexGenerator{},
		tacet.FuncOperation(func(input []byte) {
			idx := int(input[0]) | int(input[1])<<8
			ct := pool.entries[idx]
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
//
// Harness design: Same pre-generated flat pool approach as Kyber512 -- see
// TestCircl_Kyber512_Decapsulation for details.
func TestCircl_Kyber1024_Decapsulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	scheme := kyber1024.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Kyber1024 key pair: %v", err)
	}

	pool, err := newKyberFlatPool(scheme, publicKey)
	if err != nil {
		t.Fatalf("Failed to build ciphertext pool: %v", err)
	}

	result, err := tacet.Test(
		&kyberPoolIndexGenerator{},
		tacet.FuncOperation(func(input []byte) {
			idx := int(input[0]) | int(input[1])<<8
			ct := pool.entries[idx]
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

// TestCircl_Dilithium2_Signing tests Dilithium Mode2 signing timing with
// zeros-vs-random messages (the standard DudeCT two-class pattern).
//
// NOTE: Dilithium uses rejection sampling, so signing time depends on the
// message content. This is EXPECTED behavior, not a vulnerability, because:
//  1. The message is public in signature schemes.
//  2. The rejection probability is independent of the secret key.
//
// This test is therefore INFORMATIONAL: a timing difference indicates the
// expected rejection-sampling effect, not a secret-key-dependent leak.
// The Go test passes regardless of tacet's verdict.
func TestCircl_Dilithium2_Signing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	_, privateKey, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium2 key pair: %v", err)
	}

	// Pre-allocate signature buffer outside the timed closure to avoid
	// heap allocation artifacts inside the measurement region.
	signature := make([]byte, mode2.SignatureSize)

	result, err := tacet.Test(
		// Zeros-vs-random pattern: baseline gets all-zero messages,
		// sample gets random messages.
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(msg []byte) {
			mode2.SignTo(privateKey, msg, signature)
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
	t.Logf("  Note: Dilithium uses rejection sampling - message-dependent timing is EXPECTED")
	t.Logf("        This is NOT a vulnerability (message is public, rejection independent of secret)")

	// Informational only: do not fail the Go test on timing differences.
	// Rejection sampling causes expected message-dependent variation.
	if result.Outcome == tacet.Fail {
		t.Logf("Timing difference detected (expected for Dilithium): %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  This is EXPECTED behavior due to rejection sampling, not a vulnerability")
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

	// Pre-allocate signature buffer outside the timed closure.
	signature := make([]byte, mode2.SignatureSize)

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(msg []byte) {
			mode2.SignTo(privateKey, msg, signature)
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
//
// See TestCircl_Dilithium2_Signing for harness design rationale. This test
// is INFORMATIONAL: message-dependent timing from rejection sampling is
// expected and not a vulnerability.
func TestCircl_Dilithium3_Signing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	_, privateKey, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium3 key pair: %v", err)
	}

	// Pre-allocate signature buffer outside the timed closure.
	signature := make([]byte, mode3.SignatureSize)

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(msg []byte) {
			mode3.SignTo(privateKey, msg, signature)
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
	t.Logf("  Note: Dilithium uses rejection sampling - message-dependent timing is EXPECTED")

	// Informational only: do not fail the Go test on timing differences.
	if result.Outcome == tacet.Fail {
		t.Logf("Timing difference detected (expected for Dilithium): %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  This is EXPECTED behavior due to rejection sampling, not a vulnerability")
	}
}

// =============================================================================
// Dilithium Mode5 (ML-DSA) Tests
// =============================================================================

// TestCircl_Dilithium5_Signing tests Dilithium Mode5 signing timing.
// Mode5 is the NIST Level 5 parameter set (highest security).
//
// See TestCircl_Dilithium2_Signing for harness design rationale. This test
// is INFORMATIONAL: message-dependent timing from rejection sampling is
// expected and not a vulnerability.
func TestCircl_Dilithium5_Signing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping circl test in short mode")
	}

	_, privateKey, err := mode5.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium5 key pair: %v", err)
	}

	// Pre-allocate signature buffer outside the timed closure.
	signature := make([]byte, mode5.SignatureSize)

	result, err := tacet.Test(
		tacet.NewZeroGenerator(42),
		tacet.FuncOperation(func(msg []byte) {
			mode5.SignTo(privateKey, msg, signature)
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
	t.Logf("  Note: Dilithium uses rejection sampling - message-dependent timing is EXPECTED")

	// Informational only: do not fail the Go test on timing differences.
	if result.Outcome == tacet.Fail {
		t.Logf("Timing difference detected (expected for Dilithium): %.2f ns", result.Effect.MaxEffectNs)
		t.Logf("  This is EXPECTED behavior due to rejection sampling, not a vulnerability")
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
