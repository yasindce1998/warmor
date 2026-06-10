package wasm

import (
	"context"
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// PolicyEvaluator handles policy evaluation with context
type PolicyEvaluator struct {
	policy   *Policy
	hostname string
}

// NewPolicyEvaluator creates a new policy evaluator
func NewPolicyEvaluator(policy *Policy, hostname string) *PolicyEvaluator {
	return &PolicyEvaluator{
		policy:   policy,
		hostname: hostname,
	}
}

// Evaluate runs policy evaluation with full context
func (e *PolicyEvaluator) Evaluate(ctx context.Context, event *api.Event) (*api.ActionResult, error) {
	start := time.Now()

	// Call policy
	action, err := e.policy.Evaluate(ctx, event)
	if err != nil {
		return nil, err
	}

	// Build result
	result := &api.ActionResult{
		Action:    action,
		Reason:    e.buildReason(action, event),
		Timestamp: start,
		Cached:    false,
		Latency:   time.Since(start),
	}

	return result, nil
}

func (e *PolicyEvaluator) buildReason(action api.Action, event *api.Event) string {
	switch action {
	case api.ActionAllow:
		return "Policy allows execution"
	case api.ActionDeny:
		return fmt.Sprintf("Policy denies: %s by UID %d", event.Filename, event.UID)
	case api.ActionLog:
		return "Policy requires logging"
	default:
		return "Unknown action"
	}
}

// Close closes the underlying policy
func (e *PolicyEvaluator) Close(ctx context.Context) error {
	return e.policy.Close(ctx)
}
