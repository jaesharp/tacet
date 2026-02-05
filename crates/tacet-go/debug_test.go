package tacet

import (
	"testing"
	"unsafe"
	
	"github.com/agucova/tacet/crates/tacet-go/internal/ffi"
)

func TestDebugFFI(t *testing.T) {
	// Create some dummy timing data
	baseline := make([]uint64, 5000)
	sample := make([]uint64, 5000)
	
	for i := 0; i < 5000; i++ {
		baseline[i] = 1000 + uint64(i%10)
		sample[i] = 1000 + uint64(i%10)
	}
	
	cfg := &ffi.Config{
		AttackerModel:    ffi.AdjacentNetwork,
		MaxSamples:       100000,
		TimeBudgetSecs:   30.0,
		PassThreshold:    0.05,
		FailThreshold:    0.95,
		Seed:             42,
		TimerFrequencyHz: 1000000000, // 1 GHz
	}
	
	t.Logf("Calling Calibrate...")
	cal, err := ffi.Calibrate(baseline, sample, cfg)
	if err != nil {
		t.Fatalf("Calibrate error: %v", err)
	}
	defer cal.Free()
	
	t.Logf("Calibration successful")
	
	state := ffi.NewState()
	if state == nil {
		t.Fatal("Failed to create state")
	}
	defer state.Free()
	
	t.Logf("State created")
	
	// Try one step
	t.Logf("Calling Step...")
	stepResult, err := ffi.Step(cal, state, baseline[:1000], sample[:1000], cfg, 0.1)
	if err != nil {
		t.Fatalf("Step error: %v", err)
	}
	
	t.Logf("Step result:")
	t.Logf("  HasDecision: %v", stepResult.HasDecision)
	t.Logf("  LeakProbability: %f", stepResult.LeakProbability)
	t.Logf("  SamplesUsed: %d", stepResult.SamplesUsed)
	t.Logf("  ElapsedSecs: %f", stepResult.ElapsedSecs)
	
	if stepResult.HasDecision {
		r := &stepResult.Result
		t.Logf("  Result:")
		t.Logf("    Outcome: %v", r.Outcome)
		t.Logf("    SamplesUsed: %d", r.SamplesUsed)
		t.Logf("    ElapsedTime: %f", r.ElapsedTime)
		t.Logf("    MaxEffectNs: %f", r.Effect.MaxEffectNs)
		
		// Print raw bytes
		t.Logf("\n  Raw bytes at SamplesUsed offset:")
		ptr := unsafe.Pointer(r)
		// SamplesUsed is at offset 48
		samplesPtr := (*uint64)(unsafe.Pointer(uintptr(ptr) + 48))
		t.Logf("    Value: %d (0x%x)", *samplesPtr, *samplesPtr)
	}
}
