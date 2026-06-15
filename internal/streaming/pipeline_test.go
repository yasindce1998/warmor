package streaming

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

type mockSink struct {
	mu     sync.Mutex
	events []*SecurityEvent
}

func (m *mockSink) Write(_ context.Context, event *SecurityEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}
func (m *mockSink) Flush(_ context.Context) error { return nil }
func (m *mockSink) Close() error                  { return nil }
func (m *mockSink) Name() string                  { return "mock" }

func (m *mockSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestPipelineEmit(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{
		Sinks: []Sink{sink},
	})
	defer p.Close()

	ev := &api.Event{
		PID:       1234,
		Comm:      "test-bin",
		Filename:  "/usr/bin/test",
		Timestamp: time.Now(),
		Type:      api.EventTypeProcess,
		Process: &api.ProcessEvent{
			BaseEvent: api.BaseEvent{Type: api.EventTypeProcess, PID: 1234, Comm: "test-bin"},
			Filename:  "/usr/bin/test",
		},
	}
	result := &api.ActionResult{
		Action:  api.ActionDeny,
		Reason:  "blocked by policy",
		Latency: 150 * time.Microsecond,
	}

	p.Emit(ev, result)

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)

	if sink.count() != 1 {
		t.Fatalf("expected 1 event in sink, got %d", sink.count())
	}

	got := sink.events[0]
	if got.EventType != "exec" {
		t.Errorf("expected event_type=exec, got %s", got.EventType)
	}
	if got.Decision != "deny" {
		t.Errorf("expected decision=deny, got %s", got.Decision)
	}
	if got.PID != 1234 {
		t.Errorf("expected pid=1234, got %d", got.PID)
	}
	if got.Filename != "/usr/bin/test" {
		t.Errorf("expected filename=/usr/bin/test, got %s", got.Filename)
	}
	if !got.Enforced {
		t.Error("expected enforced=true for deny without audit")
	}
	if got.LatencyUS != 150 {
		t.Errorf("expected latency_us=150, got %d", got.LatencyUS)
	}

	stats := p.Stats()
	if stats.EventsReceived != 1 {
		t.Errorf("expected EventsReceived=1, got %d", stats.EventsReceived)
	}
	if stats.EventsEmitted != 1 {
		t.Errorf("expected EventsEmitted=1, got %d", stats.EventsEmitted)
	}
}

func TestPipelineDropsWhenFull(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{
		BufferSize: 1,
		Sinks:      []Sink{sink},
	})
	defer p.Close()

	// Flood the buffer
	for i := 0; i < 100; i++ {
		p.Emit(&api.Event{PID: uint32(i), Comm: "flood"}, &api.ActionResult{Action: api.ActionAllow})
	}

	time.Sleep(100 * time.Millisecond)

	stats := p.Stats()
	if stats.EventsDropped == 0 {
		t.Error("expected some events to be dropped")
	}
	if stats.EventsReceived != 100 {
		t.Errorf("expected EventsReceived=100, got %d", stats.EventsReceived)
	}
}

func TestPipelineNetworkEvent(t *testing.T) {
	sink := &mockSink{}
	p := NewPipeline(PipelineConfig{
		Sinks:  []Sink{sink},
		Labels: map[string]string{"env": "test"},
	})
	defer p.Close()

	ev := &api.Event{
		PID:  5678,
		Comm: "curl",
		Type: api.EventTypeNetwork,
		Network: &api.NetworkEvent{
			BaseEvent:  api.BaseEvent{Type: api.EventTypeNetwork, PID: 5678, Comm: "curl"},
			RemoteAddr: "10.0.0.1",
			RemotePort: 443,
			Protocol:   "tcp",
		},
	}
	p.Emit(ev, &api.ActionResult{Action: api.ActionAllow, Cached: true})

	time.Sleep(50 * time.Millisecond)

	if sink.count() != 1 {
		t.Fatalf("expected 1 event, got %d", sink.count())
	}
	got := sink.events[0]
	if got.EventType != "network" {
		t.Errorf("expected event_type=network, got %s", got.EventType)
	}
	if got.RemoteAddr != "10.0.0.1" {
		t.Errorf("expected remote_addr=10.0.0.1, got %s", got.RemoteAddr)
	}
	if got.Labels["env"] != "test" {
		t.Errorf("expected label env=test, got %v", got.Labels)
	}
}
