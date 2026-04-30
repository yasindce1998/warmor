package testing

import (
	"context"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// PolicyTest represents a single policy test case
type PolicyTest struct {
	Name     string
	Event    *api.Event
	Expected api.Action
}

// TestPolicy runs a series of tests against a policy
func TestPolicy(t *testing.T, policyPath string, tests []PolicyTest) {
	ctx := context.Background()

	// Load policy
	runtime, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	defer runtime.Close(ctx)

	if err := runtime.LoadPolicy(ctx, policyPath); err != nil {
		t.Fatalf("load policy: %v", err)
	}

	policy, err := wasm.NewPolicy(ctx, runtime)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	defer policy.Close(ctx)

	// Run tests
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			action, err := policy.Evaluate(ctx, test.Event)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			if action != test.Expected {
				t.Errorf("expected %v, got %v", test.Expected, action)
			}
		})
	}
}

// BenchmarkPolicy benchmarks policy evaluation performance
func BenchmarkPolicy(b *testing.B, policyPath string, event *api.Event) {
	ctx := context.Background()

	runtime, err := wasm.NewRuntime(ctx)
	if err != nil {
		b.Fatalf("create runtime: %v", err)
	}
	defer runtime.Close(ctx)

	if err := runtime.LoadPolicy(ctx, policyPath); err != nil {
		b.Fatalf("load policy: %v", err)
	}

	policy, err := wasm.NewPolicy(ctx, runtime)
	if err != nil {
		b.Fatalf("create policy: %v", err)
	}
	defer policy.Close(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := policy.Evaluate(ctx, event)
		if err != nil {
			b.Fatalf("evaluate: %v", err)
		}
	}
}

// TestSuite represents a collection of policy tests
type TestSuite struct {
	Name       string
	PolicyPath string
	Tests      []PolicyTest
}

// Run executes all tests in the suite
func (s *TestSuite) Run(t *testing.T) {
	t.Run(s.Name, func(t *testing.T) {
		TestPolicy(t, s.PolicyPath, s.Tests)
	})
}

// Helper functions for creating test events

// NewProcessEvent creates a process event for testing
func NewProcessEvent(uid uint32, filename string) *api.Event {
	return &api.Event{
		PID:       1234,
		UID:       uid,
		GID:       uid,
		Comm:      "test",
		Filename:  filename,
		Timestamp: time.Now(),
		Type:      api.EventTypeProcess,
	}
}

// NewFileEvent creates a file event for testing
func NewFileEvent(uid uint32, path string, operation string) *api.Event {
	return &api.Event{
		UID:       uid,
		Timestamp: time.Now(),
		Type:      api.EventTypeFile,
		File: &api.FileEvent{
			BaseEvent: api.BaseEvent{
				Type:      api.EventTypeFile,
				PID:       1234,
				UID:       uid,
				GID:       uid,
				Comm:      "test",
				Timestamp: time.Now(),
			},
			Operation: operation,
			Path:      path,
			Flags:     0,
		},
	}
}

// NewNetworkEvent creates a network event for testing
func NewNetworkEvent(uid uint32, remoteAddr string, remotePort uint16) *api.Event {
	return &api.Event{
		UID:       uid,
		Timestamp: time.Now(),
		Type:      api.EventTypeNetwork,
		Network: &api.NetworkEvent{
			BaseEvent: api.BaseEvent{
				Type:      api.EventTypeNetwork,
				PID:       1234,
				UID:       uid,
				GID:       uid,
				Comm:      "test",
				Timestamp: time.Now(),
			},
			Operation:  "connect",
			Protocol:   "tcp",
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
		},
	}
}

// Made with Bob
