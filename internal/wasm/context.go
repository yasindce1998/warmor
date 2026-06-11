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

// ActionAuditDeny is the WASM ABI value for per-rule audit mode denials
const ActionAuditDeny api.Action = 3

// Evaluate runs policy evaluation with full context
func (e *PolicyEvaluator) Evaluate(ctx context.Context, event *api.Event) (*api.ActionResult, error) {
	start := time.Now()

	// Call policy
	action, err := e.policy.Evaluate(ctx, event)
	if err != nil {
		return nil, err
	}

	// Map AUDIT_DENY from WASM to ActionDeny + Audit flag
	audit := false
	if action == ActionAuditDeny {
		action = api.ActionDeny
		audit = true
	}

	// Build result
	result := &api.ActionResult{
		Action:    action,
		Reason:    e.buildReason(action, event),
		Timestamp: start,
		Cached:    false,
		Latency:   time.Since(start),
		Audit:     audit,
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
