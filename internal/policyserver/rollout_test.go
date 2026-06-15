package policyserver

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func setupRolloutTest(t *testing.T) (*Store, *RolloutManager, string) {
	t.Helper()
	store := NewStore()
	rm := NewRolloutManager(store)

	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "policy.wasm")
	os.WriteFile(wasmPath, []byte("test-wasm"), 0644)

	store.CreatePolicy(&Policy{
		ID:       "web-policy",
		Name:     "Web Policy",
		Selector: map[string]string{"tier": "web"},
		Priority: 10,
	}, wasmPath)

	return store, rm, wasmPath
}

func TestRolloutCreation(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	state, err := rm.CreateRollout(RolloutConfig{
		ID:            "rollout-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "active" {
		t.Errorf("expected status=active, got %s", state.Status)
	}
	if state.Percentage != 10 {
		t.Errorf("expected percentage=10, got %d", state.Percentage)
	}
}

func TestRolloutPercentageUpdate(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	rm.CreateRollout(RolloutConfig{
		ID:            "rollout-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    10,
	})

	if err := rm.UpdatePercentage("rollout-1", 50); err != nil {
		t.Fatal(err)
	}

	state, ok := rm.GetRollout("rollout-1")
	if !ok {
		t.Fatal("rollout not found")
	}
	if state.Percentage != 50 {
		t.Errorf("expected 50%%, got %d%%", state.Percentage)
	}

	// Complete at 100%
	if err := rm.UpdatePercentage("rollout-1", 100); err != nil {
		t.Fatal(err)
	}
	state, _ = rm.GetRollout("rollout-1")
	if state.Status != "completed" {
		t.Errorf("expected status=completed, got %s", state.Status)
	}
}

func TestRolloutAbort(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	rm.CreateRollout(RolloutConfig{
		ID:            "rollout-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    25,
	})

	if err := rm.AbortRollout("rollout-1"); err != nil {
		t.Fatal(err)
	}

	state, _ := rm.GetRollout("rollout-1")
	if state.Status != "aborted" {
		t.Errorf("expected status=aborted, got %s", state.Status)
	}
}

func TestConsistentBucketing(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	rm.CreateRollout(RolloutConfig{
		ID:            "rollout-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    50,
	})

	// Same agent should always get the same decision
	first := rm.ShouldUseNewVersion("rollout-1", "agent-xyz")
	for i := 0; i < 100; i++ {
		if rm.ShouldUseNewVersion("rollout-1", "agent-xyz") != first {
			t.Fatal("inconsistent bucketing for same agent")
		}
	}
}

func TestRolloutDistribution(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	rm.CreateRollout(RolloutConfig{
		ID:            "rollout-dist",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    50,
	})

	// With 1000 agents and 50% rollout, distribution should be roughly even
	newCount := 0
	total := 1000
	for i := 0; i < total; i++ {
		agentID := fmt.Sprintf("agent-%d", i)
		if rm.ShouldUseNewVersion("rollout-dist", agentID) {
			newCount++
		}
	}

	ratio := float64(newCount) / float64(total)
	if ratio < 0.40 || ratio > 0.60 {
		t.Errorf("expected ~50%% distribution, got %.1f%% (%d/%d)", ratio*100, newCount, total)
	}
}

func TestResolvePolicyWithRollout(t *testing.T) {
	store, rm, wasmPath := setupRolloutTest(t)

	// Update policy to version 2
	store.UpdatePolicy("web-policy", wasmPath)

	rm.CreateRollout(RolloutConfig{
		ID:            "canary-1",
		PolicyID:      "web-policy",
		TargetVersion: 2,
		Percentage:    100, // 100% means all agents get the new version
	})

	labels := map[string]string{"tier": "web"}
	assignment := rm.ResolvePolicy("any-agent", labels)
	if assignment == nil {
		t.Fatal("expected assignment")
	}
	if assignment.Version != 2 {
		t.Errorf("expected version=2, got %d", assignment.Version)
	}
}

func TestResolvePolicyNoRollout(t *testing.T) {
	_, rm, _ := setupRolloutTest(t)

	labels := map[string]string{"tier": "web"}
	assignment := rm.ResolvePolicy("agent-1", labels)
	if assignment == nil {
		t.Fatal("expected assignment")
	}
	if assignment.Version != 1 {
		t.Errorf("expected version=1 (base), got %d", assignment.Version)
	}
}
