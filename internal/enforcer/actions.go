package enforcer

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/yasindce1998/warmor/pkg/api"
)

// ActionHandler handles policy decisions
type ActionHandler struct {
	allowed uint64
	denied  uint64
	logged  uint64
}

// NewActionHandler creates a new action handler
func NewActionHandler() *ActionHandler {
	return &ActionHandler{}
}

// Enforce executes the policy decision
func (h *ActionHandler) Enforce(ctx context.Context, event *api.Event, result *api.ActionResult) error {
	switch result.Action {
	case api.ActionAllow:
		atomic.AddUint64(&h.allowed, 1)
		return h.handleAllow(event, result)

	case api.ActionDeny:
		atomic.AddUint64(&h.denied, 1)
		return h.handleDeny(event, result)

	case api.ActionLog:
		atomic.AddUint64(&h.logged, 1)
		return h.handleLog(event, result)

	default:
		return fmt.Errorf("unknown action: %v", result.Action)
	}
}

func (h *ActionHandler) handleAllow(event *api.Event, result *api.ActionResult) error {
	// For Phase 2, we're monitoring only (no actual blocking)
	// Phase 3 will add kernel-level enforcement
	return nil
}

func (h *ActionHandler) handleDeny(event *api.Event, result *api.ActionResult) error {
	// Log the denial
	fmt.Printf("[DENY] PID=%d UID=%d COMM=%s FILE=%s REASON=%s\n",
		event.PID, event.UID, event.Comm, event.Filename, result.Reason)

	// In Phase 2, we simulate enforcement
	// Phase 3 will add actual process termination via eBPF
	return nil
}

func (h *ActionHandler) handleLog(event *api.Event, result *api.ActionResult) error {
	fmt.Printf("[LOG] PID=%d UID=%d COMM=%s FILE=%s REASON=%s\n",
		event.PID, event.UID, event.Comm, event.Filename, result.Reason)
	return nil
}

// GetStats returns current enforcement statistics
func (h *ActionHandler) GetStats() api.EnforcementStats {
	return api.EnforcementStats{
		Allowed: atomic.LoadUint64(&h.allowed),
		Denied:  atomic.LoadUint64(&h.denied),
		Logged:  atomic.LoadUint64(&h.logged),
	}
}

// Made with Bob
