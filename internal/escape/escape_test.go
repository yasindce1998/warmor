package escape

import (
	"context"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

func makeEvent(eventType, comm, filename string, cgroupID uint64) *streaming.SecurityEvent {
	return &streaming.SecurityEvent{
		EventType: eventType,
		Comm:      comm,
		Filename:  filename,
		CgroupID:  cgroupID,
		PID:       1000,
		PPID:      1,
		UID:       0,
	}
}

func TestDetectNsenter(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 100)
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for nsenter")
	}
	if result.Action != api.ActionDeny {
		t.Errorf("expected ActionDeny, got %d", result.Action)
	}

	alerts := d.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].TechniqueID != TechNsenter {
		t.Errorf("expected TechNsenter, got %s", alerts[0].TechniqueID)
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("expected Critical severity, got %d", alerts[0].Severity)
	}
}

func TestDetectHostMount(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("mount", "mount", "/", 200)
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for host mount")
	}
	alerts := d.Alerts()
	if alerts[0].TechniqueID != TechHostMount {
		t.Errorf("expected TechHostMount, got %s", alerts[0].TechniqueID)
	}
}

func TestDetectPtraceCross(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := &streaming.SecurityEvent{
		EventType:  "ptrace",
		Comm:       "gdb",
		PtraceComm: "target",
		CgroupID:   300,
		PID:        1001,
	}
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for cross-cgroup ptrace")
	}
	alerts := d.Alerts()
	if alerts[0].TechniqueID != TechPtraceCross {
		t.Errorf("expected TechPtraceCross, got %s", alerts[0].TechniqueID)
	}
}

func TestDetectProcNSAccess(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("file", "cat", "/proc/1/ns/mnt", 400)
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for /proc/*/ns/* access")
	}
	alerts := d.Alerts()
	if alerts[0].TechniqueID != TechProcNS {
		t.Errorf("expected TechProcNS, got %s", alerts[0].TechniqueID)
	}
}

func TestDetectDockerSocket(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("file", "curl", "/var/run/docker.sock", 500)
	result := d.CheckEvent(context.Background(), ev)

	if result == nil {
		t.Fatal("expected deny for docker socket access")
	}
	alerts := d.Alerts()
	if alerts[0].TechniqueID != TechDockerSocket {
		t.Errorf("expected TechDockerSocket, got %s", alerts[0].TechniqueID)
	}
}

func TestDetectSensitiveExec(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	tools := []string{"runc", "ctr", "crictl", "kubectl", "mount", "chroot", "capsh"}
	for _, tool := range tools {
		d.ClearAlerts()
		ev := makeEvent("exec", tool, "/usr/bin/"+tool, 600)
		result := d.CheckEvent(context.Background(), ev)

		if result == nil {
			t.Errorf("expected deny for sensitive exec: %s", tool)
		}
	}
}

func TestDetectUnshareSetnsMultiStep(t *testing.T) {
	// Use DenyOnDetect: false so all patterns are evaluated (procNS single-step
	// also matches the second event but doesn't short-circuit).
	d := NewDetector(DetectorConfig{DenyOnDetect: false})

	// Step 1: unshare exec
	ev1 := makeEvent("exec", "unshare", "/usr/bin/unshare", 700)
	result := d.CheckEvent(context.Background(), ev1)
	if result != nil {
		t.Fatal("unshare alone should not trigger (first step only)")
	}

	// Step 2: ns file access within window
	ev2 := makeEvent("file", "bash", "/proc/1/ns/mnt", 700)
	result = d.CheckEvent(context.Background(), ev2)
	if result != nil {
		t.Fatal("deny_on_detect=false should always return nil")
	}

	alerts := d.Alerts()
	found := false
	for _, a := range alerts {
		if a.TechniqueID == TechUnshareSetns {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TechUnshareSetns alert for unshare + ns access sequence")
	}
}

func TestMultiStepOutsideWindow(t *testing.T) {
	// Use a custom pattern with a very short window
	shortPattern := &Pattern{
		ID:       TechUnshareSetns,
		Name:     "test short window",
		Severity: SeverityCritical,
		Window:   1 * time.Millisecond,
		Steps: []StepMatcher{
			{
				EventType: "exec",
				Match:     func(ev *EventView) bool { return ev.Comm == "unshare" },
			},
			{
				EventType: "file",
				Match:     func(ev *EventView) bool { return containsNS(ev.Filename) },
			},
		},
	}

	d := NewDetector(DetectorConfig{
		Patterns:     []*Pattern{shortPattern},
		DenyOnDetect: true,
	})

	ev1 := makeEvent("exec", "unshare", "/usr/bin/unshare", 800)
	d.CheckEvent(context.Background(), ev1)

	// Wait longer than window
	time.Sleep(5 * time.Millisecond)

	ev2 := makeEvent("file", "bash", "/proc/1/ns/mnt", 800)
	result := d.CheckEvent(context.Background(), ev2)

	if result != nil {
		t.Error("should not match when events are outside the time window")
	}
}

func TestNoMatchForBenignEvents(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	benign := []*streaming.SecurityEvent{
		makeEvent("exec", "nginx", "/usr/bin/nginx", 100),
		makeEvent("file", "cat", "/etc/passwd", 100),
		makeEvent("exec", "ls", "/usr/bin/ls", 100),
		makeEvent("file", "app", "/tmp/data.json", 100),
	}

	for _, ev := range benign {
		result := d.CheckEvent(context.Background(), ev)
		if result != nil {
			t.Errorf("unexpected deny for benign event: %s %s", ev.Comm, ev.Filename)
		}
	}

	if len(d.Alerts()) != 0 {
		t.Errorf("expected 0 alerts for benign events, got %d", len(d.Alerts()))
	}
}

func TestZeroCgroupIgnored(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 0)
	result := d.CheckEvent(context.Background(), ev)

	if result != nil {
		t.Error("events with cgroup_id=0 should be ignored")
	}
}

func TestDenyOnDetectFalse(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: false})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 100)
	result := d.CheckEvent(context.Background(), ev)

	if result != nil {
		t.Error("deny_on_detect=false should return nil even on detection")
	}

	if len(d.Alerts()) != 1 {
		t.Error("alert should still be recorded when deny is off")
	}
}

func TestAlertCallback(t *testing.T) {
	var received *Alert
	d := NewDetector(DetectorConfig{
		DenyOnDetect: true,
		AlertCallback: func(a *Alert) {
			received = a
		},
	})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 100)
	d.CheckEvent(context.Background(), ev)

	if received == nil {
		t.Fatal("alert callback was not called")
	}
	if received.TechniqueID != TechNsenter {
		t.Errorf("callback received wrong technique: %s", received.TechniqueID)
	}
}

func TestClearAlerts(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	ev := makeEvent("exec", "nsenter", "/usr/bin/nsenter", 100)
	d.CheckEvent(context.Background(), ev)

	if len(d.Alerts()) != 1 {
		t.Fatal("expected 1 alert before clear")
	}

	d.ClearAlerts()
	if len(d.Alerts()) != 0 {
		t.Error("expected 0 alerts after clear")
	}
}

func TestClearWindow(t *testing.T) {
	d := NewDetector(DetectorConfig{DenyOnDetect: true})

	// Record some benign events to populate window
	ev := makeEvent("exec", "ls", "/usr/bin/ls", 900)
	d.CheckEvent(context.Background(), ev)

	d.ClearWindow(900)

	// Multi-step pattern should not find prior events
	ev2 := makeEvent("file", "bash", "/proc/1/ns/mnt", 900)
	d.CheckEvent(context.Background(), ev2)

	// Only procNS single-step should trigger, not unshare+setns
	for _, a := range d.Alerts() {
		if a.TechniqueID == TechUnshareSetns {
			t.Error("should not match unshare+setns after window clear")
		}
	}
}

func TestEnrichLabelsEscape(t *testing.T) {
	d := NewDetector(DetectorConfig{})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nsenter",
		Filename:  "/usr/bin/nsenter",
		CgroupID:  100,
		PID:       1000,
	}

	d.Enrich(ev)

	if ev.Labels == nil {
		t.Fatal("expected labels to be set")
	}
	if ev.Labels["escape_technique"] != string(TechNsenter) {
		t.Errorf("expected escape_technique=%s, got %s", TechNsenter, ev.Labels["escape_technique"])
	}
	if ev.Labels["escape_name"] != "nsenter from container" {
		t.Errorf("unexpected escape_name: %s", ev.Labels["escape_name"])
	}
}

func TestEnrichNoLabelForBenign(t *testing.T) {
	d := NewDetector(DetectorConfig{})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nginx",
		Filename:  "/usr/bin/nginx",
		CgroupID:  100,
		PID:       1000,
	}

	d.Enrich(ev)

	if ev.Labels != nil {
		t.Error("benign event should not get escape labels")
	}
}

func TestEnrichZeroCgroupIgnored(t *testing.T) {
	d := NewDetector(DetectorConfig{})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nsenter",
		Filename:  "/usr/bin/nsenter",
		CgroupID:  0,
		PID:       1000,
	}

	d.Enrich(ev)

	if ev.Labels != nil {
		t.Error("cgroup_id=0 events should not be enriched")
	}
}

func TestDefaultPatternsCount(t *testing.T) {
	patterns := DefaultPatterns()
	if len(patterns) != 7 {
		t.Errorf("expected 7 default patterns, got %d", len(patterns))
	}
}

func TestContainsNS(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/proc/1/ns/mnt", true},
		{"/proc/123/ns/pid", true},
		{"/proc/1/ns/net", true},
		{"/proc/1/status", false},
		{"/proc/1/n", false},
		{"/etc/passwd", false},
		{"short", false},
	}

	for _, tt := range tests {
		got := containsNS(tt.path)
		if got != tt.want {
			t.Errorf("containsNS(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
