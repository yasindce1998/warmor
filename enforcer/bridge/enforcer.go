package bridge

import (
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/yasindce1998/warmor/enforcer/policy"
)

// Decision represents a policy enforcement decision
type Decision struct {
	Action    policy.ActionType
	Rule      *policy.PolicyRule
	Timestamp time.Time
	Duration  time.Duration
}

// String returns a string representation of the decision
func (d *Decision) String() string {
	if d.Rule != nil {
		return fmt.Sprintf("%s (reason: %s)", d.Action, d.Rule.Reason)
	}
	return d.Action.String()
}

// ExecEvent represents a process execution event from eBPF
type ExecEvent struct {
	PID         int
	UID         int
	ProcessPath string
	Timestamp   time.Time
}

// Enforcer manages policy enforcement
type Enforcer struct {
	policies     *policy.PolicyConfig
	policyPath   string
	logger       zerolog.Logger
	statsEnabled bool
	stats        *Stats
}

// Stats tracks enforcement statistics
type Stats struct {
	TotalEvaluations int64
	AllowedActions   int64
	DeniedActions    int64
	LoggedActions    int64
	TotalDuration    time.Duration
	AverageDuration  time.Duration
}

// NewEnforcer creates a new policy enforcer
func NewEnforcer(policyPath string, policyConfig *policy.PolicyConfig) (*Enforcer, error) {
	logger := zerolog.New(os.Stdout).
		With().
		Timestamp().
		Str("component", "enforcer").
		Logger()

	enforcer := &Enforcer{
		policies:     policyConfig,
		policyPath:   policyPath,
		logger:       logger,
		statsEnabled: true,
		stats:        &Stats{},
	}

	enforcer.logger.Info().
		Str("policy_path", policyPath).
		Int("policy_count", policyConfig.Count()).
		Msg("Enforcer initialized")

	return enforcer, nil
}

// Close releases resources
func (e *Enforcer) Close() {
	e.logger.Info().Msg("Enforcer closed")
}

// Evaluate evaluates a policy for the given event
func (e *Enforcer) Evaluate(event *ExecEvent) (*Decision, error) {
	startTime := time.Now()

	// Log the event
	e.logger.Debug().
		Str("event_type", "ebpf").
		Int("pid", event.PID).
		Int("uid", event.UID).
		Str("process", event.ProcessPath).
		Msg("eBPF event received")

	// Evaluate using Go policy engine
	action, rule := e.policies.Evaluate(event.UID, event.ProcessPath)

	decision := &Decision{
		Action:    action,
		Rule:      rule,
		Timestamp: event.Timestamp,
		Duration:  time.Since(startTime),
	}

	// Update statistics
	if e.statsEnabled {
		e.updateStats(decision)
	}

	// Log the decision
	e.logDecision(event, decision)

	return decision, nil
}

// updateStats updates enforcement statistics
func (e *Enforcer) updateStats(decision *Decision) {
	e.stats.TotalEvaluations++
	e.stats.TotalDuration += decision.Duration

	switch decision.Action {
	case policy.ActionAllow:
		e.stats.AllowedActions++
	case policy.ActionDeny:
		e.stats.DeniedActions++
	case policy.ActionLog:
		e.stats.LoggedActions++
	}

	if e.stats.TotalEvaluations > 0 {
		e.stats.AverageDuration = time.Duration(
			int64(e.stats.TotalDuration) / e.stats.TotalEvaluations,
		)
	}
}

// logDecision logs the enforcement decision
func (e *Enforcer) logDecision(event *ExecEvent, decision *Decision) {
	reason := "no matching rule"
	if decision.Rule != nil {
		reason = decision.Rule.Reason
	}

	// Log policy enforcement event
	e.logger.Info().
		Str("event_type", "policy_enforcement").
		Str("action", decision.Action.String()).
		Int("uid", event.UID).
		Str("process", event.ProcessPath).
		Str("decision", decision.Action.String()).
		Str("reason", reason).
		Msg("Policy enforcement decision")

	// Log at appropriate level based on action
	switch decision.Action {
	case policy.ActionDeny:
		e.logger.Warn().
			Int("pid", event.PID).
			Int("uid", event.UID).
			Str("process", event.ProcessPath).
			Str("decision", "DENIED").
			Str("reason", reason).
			Dur("duration", decision.Duration).
			Msg("Policy enforcement: DENIED")
	case policy.ActionAllow:
		e.logger.Debug().
			Int("pid", event.PID).
			Int("uid", event.UID).
			Str("process", event.ProcessPath).
			Str("decision", "ALLOWED").
			Dur("duration", decision.Duration).
			Msg("Policy enforcement: ALLOWED")
	case policy.ActionLog:
		e.logger.Info().
			Int("pid", event.PID).
			Int("uid", event.UID).
			Str("process", event.ProcessPath).
			Str("decision", "LOGGED").
			Str("reason", reason).
			Dur("duration", decision.Duration).
			Msg("Policy enforcement: LOGGED")
	}
}

// GetStats returns current enforcement statistics
func (e *Enforcer) GetStats() *Stats {
	return e.stats
}

// ResetStats resets enforcement statistics
func (e *Enforcer) ResetStats() {
	e.stats = &Stats{}
	e.logger.Info().Msg("Statistics reset")
}

// ReloadPolicies reloads policies from the configuration file
func (e *Enforcer) ReloadPolicies() error {
	newConfig, err := policy.LoadPolicies(e.policyPath)
	if err != nil {
		return fmt.Errorf("failed to reload policies: %w", err)
	}

	e.policies = newConfig
	e.logger.Info().
		Int("policy_count", newConfig.Count()).
		Msg("Policies reloaded")

	return nil
}

// GetPolicyCount returns the number of loaded policies
func (e *Enforcer) GetPolicyCount() int {
	return e.policies.Count()
}

// GetPolicies returns the current policy configuration
func (e *Enforcer) GetPolicies() *policy.PolicyConfig {
	return e.policies
}

// Made with Bob
