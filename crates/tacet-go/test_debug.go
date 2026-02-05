package tacet

import (
	"fmt"
	"testing"
	"time"
	
	"github.com/agucova/tacet/crates/tacet-go/internal/ffi"
)

func TestDebugCalibration(t *testing.T) {
	// Create config
	config := &ffi.Config{
		AttackerModel:     ffi.SharedHardware,
		CustomThresholdNs: 0,
		MaxSamples:        100000,
		TimeBudgetSecs:    30.0,
		PassThreshold:     0.05,
		FailThreshold:     0.95,
		Seed:              0,
		TimerFrequencyHz:  0, // Let C code detect
	}
	
	fmt.Printf("Config before calibration:\n")
	fmt.Printf("  AttackerModel: %d\n", config.AttackerModel)
	fmt.Printf("  MaxSamples: %d\n", config.MaxSamples)
	fmt.Printf("  TimeBudgetSecs: %.1f\n", config.TimeBudgetSecs)
	fmt.Printf("  TimerFrequencyHz: %d\n", config.TimerFrequencyHz)
	
	// Collect 5000 calibration samples
	const calibrationSize = 5000
	baseline := make([]uint64, calibrationSize)
	sample := make([]uint64, calibrationSize)
	
	fmt.Printf("\nCollecting %d calibration samples...\n", calibrationSize)
	start := time.Now()
	for i := 0; i < calibrationSize; i++ {
		// Simulate timing measurements (constant time operation)
		// Use time.Now() to get real timing measurements
		t0 := time.Now()
		_ = 42 * 42  // dummy operation
		baseline[i] = uint64(time.Since(t0).Nanoseconds())
		
		t1 := time.Now()
		_ = 42 * 42  // same operation
		sample[i] = uint64(time.Since(t1).Nanoseconds())
	}
	collectTime := time.Since(start)
	fmt.Printf("Collection took: %v\n", collectTime)
	
	// Print first few samples
	fmt.Printf("\nFirst 5 baseline samples: %v\n", baseline[:5])
	fmt.Printf("First 5 sample samples: %v\n", sample[:5])
	
	// Call calibration
	fmt.Printf("\nCalling ffi.Calibrate...\n")
	calibration, err := ffi.Calibrate(baseline, sample, config)
	if err != nil {
		t.Fatalf("Calibration failed: %v", err)
	}
	defer calibration.Free()
	
	fmt.Printf("SUCCESS: Calibration completed\n")
	
	// Now try one step
	state := ffi.NewState()
	if state == nil {
		t.Fatalf("Failed to create state")
	}
	defer state.Free()
	
	// Collect a batch
	batchSize := 1000
	batchBaseline := make([]uint64, batchSize)
	batchSample := make([]uint64, batchSize)
	
	fmt.Printf("\nCollecting batch of %d samples...\n", batchSize)
	for i := 0; i < batchSize; i++ {
		t0 := time.Now()
		_ = 42 * 42
		batchBaseline[i] = uint64(time.Since(t0).Nanoseconds())
		
		t1 := time.Now()
		_ = 42 * 42
		batchSample[i] = uint64(time.Since(t1).Nanoseconds())
	}
	
	// Run one step
	fmt.Printf("Calling ffi.Step...\n")
	stepResult, err := ffi.Step(calibration, state, batchBaseline, batchSample, config, collectTime.Seconds())
	if err != nil {
		t.Fatalf("Step failed: %v", err)
	}
	
	fmt.Printf("\nStep result:\n")
	fmt.Printf("  HasDecision: %v\n", stepResult.HasDecision)
	fmt.Printf("  LeakProbability: %.4f\n", stepResult.LeakProbability)
	fmt.Printf("  SamplesUsed: %d\n", stepResult.SamplesUsed)
	fmt.Printf("  ElapsedSecs: %.2f\n", stepResult.ElapsedSecs)
	
	if stepResult.HasDecision {
		r := stepResult.Result
		fmt.Printf("\nFinal result:\n")
		fmt.Printf("  Outcome: %d\n", r.Outcome)
		fmt.Printf("  LeakProbability: %.4f\n", r.LeakProbability)
		fmt.Printf("  SamplesUsed: %d\n", r.SamplesUsed)
		fmt.Printf("  MaxEffectNs: %.2f\n", r.Effect.MaxEffectNs)
		fmt.Printf("  Quality: %d\n", r.Quality)
		fmt.Printf("  MDENs: %.2f\n", r.MDENs)
		fmt.Printf("  TimerResolutionNs: %.2f\n", r.TimerResolutionNs)
	}
}
