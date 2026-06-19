package policyserver

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupCanaryTest(t *testing.T) (*RolloutManager, *CanaryAnalyzer) {
	t.Helper()
	store := NewStore()
	rm := NewRolloutManager(store)

	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "policy.wasm")
	if err := os.WriteFile(wasmPath, []byte("test-wasm"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePolicy(&Policy{
		ID:       "canary-policy",
		Name:     "Canary Policy",
		Selector: map[string]string{"app": "web"},
		Priority: 10,
	}, wasmPath); err != nil {
		t.Fatal(err)
	}

	ca := NewCanaryAnalyzer(rm)
	return rm, ca
}

func TestCanaryHealthy(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, err := rm.CreateRollout(RolloutConfig{
		ID:            "canary-1",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})
	if err != nil {
		t.Fatal(err)
	}

	ca.Configure("canary-1", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0, // immediate for testing
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	// Baseline: 10% deny rate
	for i := range 100 {
		ca.RecordDecision("canary-1", false, i < 10)
	}
	// Canary: 11% deny rate (within 5% threshold)
	for i := range 100 {
		ca.RecordDecision("canary-1", true, i < 11)
	}

	metrics, rolled := ca.Evaluate("canary-1")
	if rolled {
		t.Error("should not rollback for minor difference")
	}
	if metrics.Verdict != "healthy" {
		t.Errorf("expected healthy, got %s", metrics.Verdict)
	}
}

func TestCanaryRollback(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, err := rm.CreateRollout(RolloutConfig{
		ID:            "canary-2",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})
	if err != nil {
		t.Fatal(err)
	}

	ca.Configure("canary-2", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	// Baseline: 5% deny rate
	for i := range 100 {
		ca.RecordDecision("canary-2", false, i < 5)
	}
	// Canary: 20% deny rate (15% delta, exceeds 5% threshold)
	for i := range 100 {
		ca.RecordDecision("canary-2", true, i < 20)
	}

	metrics, rolled := ca.Evaluate("canary-2")
	if !rolled {
		t.Error("expected rollback for high deny rate delta")
	}
	if metrics.Verdict != "rolled-back" {
		t.Errorf("expected rolled-back, got %s", metrics.Verdict)
	}

	// Verify the rollout was actually aborted
	state, ok := rm.GetRollout("canary-2")
	if !ok {
		t.Fatal("rollout not found")
	}
	if state.Status != "aborted" {
		t.Errorf("expected rollout status=aborted, got %s", state.Status)
	}
}

func TestCanaryDegradedNoAutoRollback(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-3",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-3", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      false, // no auto-rollback
	})

	for i := range 100 {
		ca.RecordDecision("canary-3", false, i < 5)
	}
	for i := range 100 {
		ca.RecordDecision("canary-3", true, i < 20)
	}

	metrics, rolled := ca.Evaluate("canary-3")
	if rolled {
		t.Error("should not auto-rollback when disabled")
	}
	if metrics.Verdict != "degraded" {
		t.Errorf("expected degraded, got %s", metrics.Verdict)
	}

	// Rollout should still be active
	state, _ := rm.GetRollout("canary-3")
	if state.Status != "active" {
		t.Errorf("expected rollout still active, got %s", state.Status)
	}
}

func TestCanaryPendingInsufficientSamples(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-4",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-4", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     100,
		AutoRollback:      true,
	})

	// Only 5 samples each (below MinSampleSize=100)
	for range 5 {
		ca.RecordDecision("canary-4", false, true)
		ca.RecordDecision("canary-4", true, true)
	}

	metrics, rolled := ca.Evaluate("canary-4")
	if rolled {
		t.Error("should not rollback with insufficient samples")
	}
	if metrics.Verdict != "pending" {
		t.Errorf("expected pending, got %s", metrics.Verdict)
	}
}

func TestCanaryPendingObservationWindow(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	// Use a fixed clock for testing
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ca.clock = func() time.Time { return now }

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-5",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-5", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 5 * time.Minute,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	// Record enough samples
	for i := range 100 {
		ca.RecordDecision("canary-5", false, i < 5)
		ca.RecordDecision("canary-5", true, i < 50)
	}

	// Still within observation window
	metrics, rolled := ca.Evaluate("canary-5")
	if rolled {
		t.Error("should not rollback before observation window completes")
	}
	if metrics.Verdict != "pending" {
		t.Errorf("expected pending, got %s", metrics.Verdict)
	}

	// Advance time past observation window
	now = now.Add(6 * time.Minute)
	metrics, rolled = ca.Evaluate("canary-5")
	if !rolled {
		t.Error("expected rollback after observation window")
	}
	if metrics.Verdict != "rolled-back" {
		t.Errorf("expected rolled-back, got %s", metrics.Verdict)
	}
}

func TestCanaryReset(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-6",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-6", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	for range 50 {
		ca.RecordDecision("canary-6", false, false)
		ca.RecordDecision("canary-6", true, true)
	}

	ca.Reset("canary-6")

	metrics, _ := ca.Evaluate("canary-6")
	if metrics.Verdict != "pending" {
		t.Errorf("expected pending after reset, got %s", metrics.Verdict)
	}
}

func TestCanaryMetricsAccuracy(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-7",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-7", CanaryConfig{
		MaxDenyRateDelta:  0.50,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	// 20 baseline events, 5 denied = 25% deny rate
	for i := range 20 {
		ca.RecordDecision("canary-7", false, i < 5)
	}
	// 40 canary events, 12 denied = 30% deny rate
	for i := range 40 {
		ca.RecordDecision("canary-7", true, i < 12)
	}

	metrics := ca.Metrics("canary-7")
	if metrics.BaselineSamples != 20 {
		t.Errorf("expected 20 baseline samples, got %d", metrics.BaselineSamples)
	}
	if metrics.CanarySamples != 40 {
		t.Errorf("expected 40 canary samples, got %d", metrics.CanarySamples)
	}
	if metrics.BaselineDenyRate != 0.25 {
		t.Errorf("expected 0.25 baseline deny rate, got %f", metrics.BaselineDenyRate)
	}
	if metrics.CanaryDenyRate != 0.30 {
		t.Errorf("expected 0.30 canary deny rate, got %f", metrics.CanaryDenyRate)
	}
}

func TestCanaryIdempotentAfterRollback(t *testing.T) {
	rm, ca := setupCanaryTest(t)

	_, _ = rm.CreateRollout(RolloutConfig{
		ID:            "canary-8",
		PolicyID:      "canary-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	ca.Configure("canary-8", CanaryConfig{
		MaxDenyRateDelta:  0.05,
		ObservationWindow: 0,
		MinSampleSize:     10,
		AutoRollback:      true,
	})

	for i := range 100 {
		ca.RecordDecision("canary-8", false, i < 5)
		ca.RecordDecision("canary-8", true, i < 30)
	}

	_, rolled1 := ca.Evaluate("canary-8")
	if !rolled1 {
		t.Fatal("expected first rollback")
	}

	// Second evaluate should not trigger another rollback
	_, rolled2 := ca.Evaluate("canary-8")
	if rolled2 {
		t.Error("second evaluate should not trigger rollback again")
	}
}
