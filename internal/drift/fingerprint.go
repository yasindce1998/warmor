package drift

import (
	"sync"
	"time"
)

// BehaviorFingerprint represents the behavioral profile of a container instance.
type BehaviorFingerprint struct {
	AgentID   string             `json:"agent_id"`
	ImageHash string             `json:"image_hash"`
	Window    time.Duration      `json:"window"`
	Vectors   map[string]float64 `json:"vectors"`
	Timestamp time.Time          `json:"timestamp"`
}

// FingerprintCollector tracks events per agent and computes rate vectors.
type FingerprintCollector struct {
	mu       sync.Mutex
	counters map[string]*agentCounters // agent ID → counters
	window   time.Duration
}

type agentCounters struct {
	imageHash string
	counts    map[string]int
	startedAt time.Time
}

// NewFingerprintCollector creates a collector with the given observation window.
func NewFingerprintCollector(window time.Duration) *FingerprintCollector {
	return &FingerprintCollector{
		counters: make(map[string]*agentCounters),
		window:   window,
	}
}

// Record adds an event observation to the agent's running counters.
// The pattern is typically "event_type:target" (e.g. "exec:/usr/bin/curl").
func (fc *FingerprintCollector) Record(agentID, imageHash, pattern string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	ac, ok := fc.counters[agentID]
	if !ok {
		ac = &agentCounters{
			imageHash: imageHash,
			counts:    make(map[string]int),
			startedAt: time.Now(),
		}
		fc.counters[agentID] = ac
	}
	ac.counts[pattern]++
}

// Snapshot returns the current fingerprint for an agent (rates per minute).
func (fc *FingerprintCollector) Snapshot(agentID string) *BehaviorFingerprint {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	ac, ok := fc.counters[agentID]
	if !ok {
		return nil
	}

	elapsed := max(time.Since(ac.startedAt), time.Second)
	minutes := elapsed.Minutes()

	vectors := make(map[string]float64, len(ac.counts))
	for pattern, count := range ac.counts {
		vectors[pattern] = float64(count) / minutes
	}

	return &BehaviorFingerprint{
		AgentID:   agentID,
		ImageHash: ac.imageHash,
		Window:    elapsed,
		Vectors:   vectors,
		Timestamp: time.Now(),
	}
}

// Reset clears the counters for an agent.
func (fc *FingerprintCollector) Reset(agentID string) {
	fc.mu.Lock()
	delete(fc.counters, agentID)
	fc.mu.Unlock()
}
