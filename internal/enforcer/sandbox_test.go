package enforcer

import (
	"testing"
)

func TestSandboxProfileRegistration(t *testing.T) {
	sm := NewSandboxManager()

	sm.RegisterProfile(&SandboxProfile{
		Name:        "test-profile",
		DenyNetwork: true,
		ReadOnlyFS:  true,
	})

	p, ok := sm.GetProfile("test-profile")
	if !ok {
		t.Fatal("profile not found")
	}
	if !p.DenyNetwork {
		t.Error("expected DenyNetwork=true")
	}
	if !p.ReadOnlyFS {
		t.Error("expected ReadOnlyFS=true")
	}
}

func TestSandboxApplyAndCheck(t *testing.T) {
	sm := NewSandboxManager(DefaultProfiles()...)

	if err := sm.ApplySandbox(1234, "strict"); err != nil {
		t.Fatal(err)
	}

	p, ok := sm.IsSandboxed(1234)
	if !ok {
		t.Fatal("expected process to be sandboxed")
	}
	if p.Name != "strict" {
		t.Errorf("expected profile=strict, got %s", p.Name)
	}
	if sm.SandboxedCount() != 1 {
		t.Errorf("expected 1 sandboxed process, got %d", sm.SandboxedCount())
	}
}

func TestSandboxApplyUnknownProfile(t *testing.T) {
	sm := NewSandboxManager()
	if err := sm.ApplySandbox(1234, "nonexistent"); err == nil {
		t.Error("expected error for unknown profile")
	}
}

func TestSandboxRelease(t *testing.T) {
	sm := NewSandboxManager(DefaultProfiles()...)
	sm.ApplySandbox(1234, "strict")
	sm.ReleaseSandbox(1234)

	_, ok := sm.IsSandboxed(1234)
	if ok {
		t.Error("expected process to no longer be sandboxed")
	}
}

func TestSandboxViolationNetwork(t *testing.T) {
	sm := NewSandboxManager(DefaultProfiles()...)
	sm.ApplySandbox(1234, "network-deny")

	reason := sm.CheckViolation(1234, "network")
	if reason == "" {
		t.Error("expected violation for network access")
	}

	reason = sm.CheckViolation(1234, "write")
	if reason != "" {
		t.Errorf("unexpected violation for write: %s", reason)
	}
}

func TestSandboxViolationReadOnly(t *testing.T) {
	sm := NewSandboxManager(DefaultProfiles()...)
	sm.ApplySandbox(1234, "readonly")

	reason := sm.CheckViolation(1234, "write")
	if reason == "" {
		t.Error("expected violation for write on read-only profile")
	}

	reason = sm.CheckViolation(1234, "network")
	if reason != "" {
		t.Errorf("unexpected violation for network: %s", reason)
	}
}

func TestSandboxViolationBlockedSyscall(t *testing.T) {
	sm := NewSandboxManager(DefaultProfiles()...)
	sm.ApplySandbox(1234, "limited")

	reason := sm.CheckViolation(1234, "ptrace")
	if reason == "" {
		t.Error("expected violation for ptrace syscall")
	}

	reason = sm.CheckViolation(1234, "read")
	if reason != "" {
		t.Errorf("unexpected violation for read: %s", reason)
	}
}

func TestSandboxViolationNotSandboxed(t *testing.T) {
	sm := NewSandboxManager()
	reason := sm.CheckViolation(9999, "network")
	if reason != "" {
		t.Errorf("expected no violation for non-sandboxed process, got: %s", reason)
	}
}

func TestDefaultProfiles(t *testing.T) {
	profiles := DefaultProfiles()
	if len(profiles) != 4 {
		t.Fatalf("expected 4 default profiles, got %d", len(profiles))
	}

	names := make(map[string]bool)
	for _, p := range profiles {
		names[p.Name] = true
	}
	for _, expected := range []string{"strict", "network-deny", "readonly", "limited"} {
		if !names[expected] {
			t.Errorf("missing default profile: %s", expected)
		}
	}
}

func TestSandboxListProfiles(t *testing.T) {
	sm := NewSandboxManager(DefaultProfiles()...)
	profiles := sm.ListProfiles()
	if len(profiles) != 4 {
		t.Errorf("expected 4 profiles, got %d", len(profiles))
	}
}
