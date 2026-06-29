package wasm

import (
	"context"
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// PolicyEvaluator handles policy evaluation with an instance pool.
type PolicyEvaluator struct {
	pool     *Pool
	hostname string
}

// NewPolicyEvaluator creates a new pool-backed policy evaluator.
func NewPolicyEvaluator(pool *Pool, hostname string) *PolicyEvaluator {
	return &PolicyEvaluator{
		pool:     pool,
		hostname: hostname,
	}
}

// ActionAuditDeny is the WASM ABI value for per-rule audit mode denials.
const ActionAuditDeny api.Action = 3

// Evaluate runs policy evaluation using an instance from the pool.
func (e *PolicyEvaluator) Evaluate(ctx context.Context, event *api.Event) (*api.ActionResult, error) {
	start := time.Now()

	policy, err := e.pool.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("get policy from pool: %w", err)
	}
	defer e.pool.Put(policy)

	action, err := policy.Evaluate(ctx, event)
	if err != nil {
		return nil, err
	}

	// Map AUDIT_DENY from WASM to ActionDeny + Audit flag
	audit := false
	if action == ActionAuditDeny {
		action = api.ActionDeny
		audit = true
	}

	// Extract matched rule reason from WASM if available
	reason := policy.GetMatchedRule(ctx)
	if reason == "" {
		reason = e.buildReason(action, event)
	}

	result := &api.ActionResult{
		Action:    action,
		Reason:    reason,
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

// Close closes the underlying pool.
func (e *PolicyEvaluator) Close(ctx context.Context) error {
	return e.pool.Close(ctx)
}
