package enforcer

import (
	"fmt"
	"slices"
	"sync"
)

// SandboxProfile defines the restrictions applied to a process when it
// violates policy or matches a sandboxing rule. On Linux, these translate
// to seccomp profiles and namespace restrictions. The profile is evaluated
// by the action handler when a deny decision is made with sandbox escalation.
type SandboxProfile struct {
	Name string `json:"name" yaml:"name"`

	// Network isolation — drop all network access
	DenyNetwork bool `json:"deny_network" yaml:"deny_network"`

	// Filesystem isolation — restrict to read-only
	ReadOnlyFS bool `json:"read_only_fs" yaml:"read_only_fs"`

	// Allowed syscalls whitelist (seccomp-style). If non-empty, only these
	// syscalls are permitted. An empty list means "no restriction".
	AllowedSyscalls []string `json:"allowed_syscalls,omitempty" yaml:"allowed_syscalls,omitempty"`

	// Blocked syscalls blacklist. Overrides AllowedSyscalls when both are set.
	BlockedSyscalls []string `json:"blocked_syscalls,omitempty" yaml:"blocked_syscalls,omitempty"`

	// Resource limits
	MaxOpenFiles int `json:"max_open_files,omitempty" yaml:"max_open_files,omitempty"`
	MaxProcesses int `json:"max_processes,omitempty" yaml:"max_processes,omitempty"`
	MaxMemoryMB  int `json:"max_memory_mb,omitempty" yaml:"max_memory_mb,omitempty"`

	// PID namespace isolation — gives process its own PID namespace
	IsolatePID bool `json:"isolate_pid" yaml:"isolate_pid"`

	// Drop capabilities
	DropCaps []string `json:"drop_caps,omitempty" yaml:"drop_caps,omitempty"`
}

// SandboxManager manages sandbox profiles and tracks which processes are sandboxed.
type SandboxManager struct {
	mu       sync.RWMutex
	profiles map[string]*SandboxProfile
	applied  map[uint32]*SandboxProfile // pid → active profile
}

// NewSandboxManager creates a sandbox manager with optional pre-registered profiles.
func NewSandboxManager(profiles ...*SandboxProfile) *SandboxManager {
	sm := &SandboxManager{
		profiles: make(map[string]*SandboxProfile),
		applied:  make(map[uint32]*SandboxProfile),
	}
	for _, p := range profiles {
		sm.profiles[p.Name] = p
	}
	return sm
}

// RegisterProfile adds or updates a sandbox profile.
func (sm *SandboxManager) RegisterProfile(p *SandboxProfile) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.profiles[p.Name] = p
}

// GetProfile retrieves a named profile.
func (sm *SandboxManager) GetProfile(name string) (*SandboxProfile, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	p, ok := sm.profiles[name]
	return p, ok
}

// ListProfiles returns all registered profile names.
func (sm *SandboxManager) ListProfiles() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	names := make([]string, 0, len(sm.profiles))
	for name := range sm.profiles {
		names = append(names, name)
	}
	return names
}

// ApplySandbox records that a process is now running under a sandbox profile.
// In a real deployment this would invoke seccomp/namespace syscalls; here it
// tracks state for the decision pipeline to query.
func (sm *SandboxManager) ApplySandbox(pid uint32, profileName string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	p, ok := sm.profiles[profileName]
	if !ok {
		return fmt.Errorf("sandbox profile %q not found", profileName)
	}
	sm.applied[pid] = p
	return nil
}

// IsSandboxed returns whether a process is currently sandboxed and its profile.
func (sm *SandboxManager) IsSandboxed(pid uint32) (*SandboxProfile, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	p, ok := sm.applied[pid]
	return p, ok
}

// ReleaseSandbox removes sandbox tracking for a process (e.g., on exit).
func (sm *SandboxManager) ReleaseSandbox(pid uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.applied, pid)
}

// SandboxedCount returns the number of currently sandboxed processes.
func (sm *SandboxManager) SandboxedCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.applied)
}

// CheckViolation evaluates if a sandboxed process is attempting something its
// profile disallows. Returns an enforcement reason if violated, empty string otherwise.
func (sm *SandboxManager) CheckViolation(pid uint32, action string) string {
	sm.mu.RLock()
	profile, ok := sm.applied[pid]
	sm.mu.RUnlock()
	if !ok {
		return ""
	}

	switch action {
	case "network":
		if profile.DenyNetwork {
			return fmt.Sprintf("sandbox %q: network access denied", profile.Name)
		}
	case "write":
		if profile.ReadOnlyFS {
			return fmt.Sprintf("sandbox %q: filesystem is read-only", profile.Name)
		}
	}

	if slices.Contains(profile.BlockedSyscalls, action) {
		return fmt.Sprintf("sandbox %q: syscall %s blocked", profile.Name, action)
	}

	return ""
}

// DefaultProfiles returns commonly used sandbox profiles.
func DefaultProfiles() []*SandboxProfile {
	return []*SandboxProfile{
		{
			Name:        "strict",
			DenyNetwork: true,
			ReadOnlyFS:  true,
			IsolatePID:  true,
			DropCaps:    []string{"ALL"},
		},
		{
			Name:        "network-deny",
			DenyNetwork: true,
		},
		{
			Name:       "readonly",
			ReadOnlyFS: true,
		},
		{
			Name:            "limited",
			MaxOpenFiles:    64,
			MaxProcesses:    16,
			MaxMemoryMB:     256,
			BlockedSyscalls: []string{"ptrace", "mount", "reboot", "kexec_load"},
		},
	}
}
