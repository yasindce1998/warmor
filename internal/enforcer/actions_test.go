package enforcer

import (
	"context"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestActionHandler_AuditMode_DowngradesDeny(t *testing.T) {
	handler := NewActionHandler(true)

	event := &api.Event{
		PID:       1234,
		UID:       1000,
		GID:       1000,
		Comm:      "test",
		Filename:  "/tmp/malicious",
		Timestamp: time.Now(),
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "execution from temp dir",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if !result.Audit {
		t.Error("expected result.Audit to be true in audit mode")
	}

	stats := handler.GetStats()
	if stats.AuditDenied != 1 {
		t.Errorf("expected AuditDenied=1, got %d", stats.AuditDenied)
	}
	if stats.Denied != 0 {
		t.Errorf("expected Denied=0 in audit mode, got %d", stats.Denied)
	}
}

func TestActionHandler_AuditMode_AllowPassesThrough(t *testing.T) {
	handler := NewActionHandler(true)

	event := &api.Event{
		PID:  1234,
		UID:  0,
		Comm: "systemd",
	}

	result := &api.ActionResult{
		Action:    api.ActionAllow,
		Reason:    "allowed",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if result.Audit {
		t.Error("expected result.Audit to be false for allow actions")
	}

	stats := handler.GetStats()
	if stats.Allowed != 1 {
		t.Errorf("expected Allowed=1, got %d", stats.Allowed)
	}
}

func TestActionHandler_NoAudit_DenyNotDowngraded(t *testing.T) {
	handler := NewActionHandler(false)

	event := &api.Event{
		PID:      1234,
		UID:      1000,
		Comm:     "nc",
		Filename: "/usr/bin/nc",
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "blocked network tool",
		Timestamp: time.Now(),
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if result.Audit {
		t.Error("expected result.Audit to be false when audit mode is off")
	}

	stats := handler.GetStats()
	if stats.Denied != 1 {
		t.Errorf("expected Denied=1, got %d", stats.Denied)
	}
	if stats.AuditDenied != 0 {
		t.Errorf("expected AuditDenied=0, got %d", stats.AuditDenied)
	}
}

func TestActionHandler_PerRuleAudit(t *testing.T) {
	handler := NewActionHandler(false)

	event := &api.Event{
		PID:      1234,
		UID:      1000,
		Comm:     "test",
		Filename: "/tmp/script.sh",
	}

	result := &api.ActionResult{
		Action:    api.ActionDeny,
		Reason:    "temp dir execution",
		Timestamp: time.Now(),
		Audit:     true, // per-rule audit set by WASM evaluator
	}

	err := handler.Enforce(context.Background(), event, result)
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if !result.Audit {
		t.Error("expected result.Audit to remain true for per-rule audit")
	}

	stats := handler.GetStats()
	if stats.AuditDenied != 1 {
		t.Errorf("expected AuditDenied=1, got %d", stats.AuditDenied)
	}
	if stats.Denied != 0 {
		t.Errorf("expected Denied=0 for audit deny, got %d", stats.Denied)
	}
}
