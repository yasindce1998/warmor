package policyserver

import (
	"sync"
	"time"
)

// CanaryConfig controls automatic rollback behavior during a canary rollout.
type CanaryConfig struct {
	MaxDenyRateDelta  float64       `json:"max_deny_rate_delta"`
	ObservationWindow time.Duration `json:"observation_window"`
	MinSampleSize     int           `json:"min_sample_size"`
	AutoRollback      bool          `json:"auto_rollback"`
}

// CanaryMetrics contains current canary health measurements.
type CanaryMetrics struct {
	BaselineDenyRate float64 `json:"baseline_deny_rate"`
	CanaryDenyRate   float64 `json:"canary_deny_rate"`
	BaselineSamples  int     `json:"baseline_samples"`
	CanarySamples    int     `json:"canary_samples"`
	ObservedFor      time.Duration `json:"observed_for"`
	Verdict          string  `json:"verdict"` // "pending", "healthy", "degraded", "rolled-back"
}

// CanaryAnalyzer monitors canary vs baseline deny rates and triggers rollback.
type CanaryAnalyzer struct {
	mu       sync.Mutex
	configs  map[string]*CanaryConfig // rollout ID → config
	counters map[string]*canaryCounters
	rollouts *RolloutManager
	clock    func() time.Time
}

type canaryCounters struct {
	baselineTotal int
	baselineDeny  int
	canaryTotal   int
	canaryDeny    int
	startedAt     time.Time
	rolledBack    bool
}

// NewCanaryAnalyzer creates a canary analyzer attached to the given rollout manager.
func NewCanaryAnalyzer(rm *RolloutManager) *CanaryAnalyzer {
	return &CanaryAnalyzer{
		configs:  make(map[string]*CanaryConfig),
		counters: make(map[string]*canaryCounters),
		rollouts: rm,
		clock:    time.Now,
	}
}

// Configure sets canary config for a rollout.
func (ca *CanaryAnalyzer) Configure(rolloutID string, cfg CanaryConfig) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.configs[rolloutID] = &cfg
	if _, ok := ca.counters[rolloutID]; !ok {
		ca.counters[rolloutID] = &canaryCounters{startedAt: ca.clock()}
	}
}

// RecordDecision records a policy decision for canary analysis.
// isCanary indicates whether the agent was in the canary (new policy) cohort.
// denied indicates whether the decision was a deny.
func (ca *CanaryAnalyzer) RecordDecision(rolloutID string, isCanary bool, denied bool) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	c, ok := ca.counters[rolloutID]
	if !ok {
		c = &canaryCounters{startedAt: ca.clock()}
		ca.counters[rolloutID] = c
	}

	if isCanary {
		c.canaryTotal++
		if denied {
			c.canaryDeny++
		}
	} else {
		c.baselineTotal++
		if denied {
			c.baselineDeny++
		}
	}
}

// Evaluate checks canary health and triggers rollback if needed.
// Returns the current metrics and whether a rollback was triggered this call.
func (ca *CanaryAnalyzer) Evaluate(rolloutID string) (CanaryMetrics, bool) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	cfg, hasCfg := ca.configs[rolloutID]
	c, hasCounters := ca.counters[rolloutID]

	if !hasCfg || !hasCounters {
		return CanaryMetrics{Verdict: "pending"}, false
	}

	if c.rolledBack {
		return ca.buildMetrics(c, "rolled-back"), false
	}

	observed := ca.clock().Sub(c.startedAt)

	// Not enough data yet
	if c.canaryTotal < cfg.MinSampleSize || c.baselineTotal < cfg.MinSampleSize {
		return ca.buildMetrics(c, "pending"), false
	}

	// Haven't observed long enough
	if observed < cfg.ObservationWindow {
		return ca.buildMetrics(c, "pending"), false
	}

	baselineRate := float64(c.baselineDeny) / float64(c.baselineTotal)
	canaryRate := float64(c.canaryDeny) / float64(c.canaryTotal)
	delta := canaryRate - baselineRate

	if delta > cfg.MaxDenyRateDelta {
		if cfg.AutoRollback {
			c.rolledBack = true
			_ = ca.rollouts.AbortRollout(rolloutID)
			return ca.buildMetrics(c, "rolled-back"), true
		}
		return ca.buildMetrics(c, "degraded"), false
	}

	return ca.buildMetrics(c, "healthy"), false
}

// Metrics returns current canary metrics without triggering evaluation.
func (ca *CanaryAnalyzer) Metrics(rolloutID string) CanaryMetrics {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	c, ok := ca.counters[rolloutID]
	if !ok {
		return CanaryMetrics{Verdict: "pending"}
	}

	if c.rolledBack {
		return ca.buildMetrics(c, "rolled-back")
	}
	return ca.buildMetrics(c, "pending")
}

// Reset clears canary state for a rollout.
func (ca *CanaryAnalyzer) Reset(rolloutID string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	delete(ca.configs, rolloutID)
	delete(ca.counters, rolloutID)
}

func (ca *CanaryAnalyzer) buildMetrics(c *canaryCounters, verdict string) CanaryMetrics {
	m := CanaryMetrics{
		BaselineSamples: c.baselineTotal,
		CanarySamples:   c.canaryTotal,
		ObservedFor:     ca.clock().Sub(c.startedAt),
		Verdict:         verdict,
	}
	if c.baselineTotal > 0 {
		m.BaselineDenyRate = float64(c.baselineDeny) / float64(c.baselineTotal)
	}
	if c.canaryTotal > 0 {
		m.CanaryDenyRate = float64(c.canaryDeny) / float64(c.canaryTotal)
	}
	return m
}
