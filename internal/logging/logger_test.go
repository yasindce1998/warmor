package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestNewLogger_ValidLevel(t *testing.T) {
	l := NewLogger("debug")
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNewLogger_InvalidLevel(t *testing.T) {
	l := NewLogger("bogus")
	if l == nil {
		t.Fatal("expected non-nil logger with fallback to info level")
	}
}

func TestNewLoggerWithWriter_OutputsJSON(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("info", &buf)

	l.LogInfo("hello world")

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, buf.String())
	}
	if m["service"] != "warmor" {
		t.Errorf("service = %v, want warmor", m["service"])
	}
	if m["message"] != "hello world" {
		t.Errorf("message = %v, want 'hello world'", m["message"])
	}
	if _, ok := m["time"]; !ok {
		t.Error("expected 'time' field in JSON output")
	}
}

func TestNewLoggerWithWriter_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("warn", &buf)

	l.LogInfo("this should be filtered")

	if buf.Len() != 0 {
		t.Errorf("expected no output at info level when logger is set to warn, got: %s", buf.String())
	}
}

func TestLogEvent(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("info", &buf)

	event := &api.Event{
		PID:      1234,
		UID:      1000,
		GID:      1000,
		Comm:     "cat",
		Filename: "/usr/bin/cat",
	}
	result := &api.ActionResult{
		Action:  api.ActionAllow,
		Reason:  "whitelisted",
		Cached:  true,
		Latency: 50 * time.Microsecond,
	}

	l.LogEvent(event, result)

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["message"] != "policy_evaluation" {
		t.Errorf("message = %v, want policy_evaluation", m["message"])
	}
	if m["pid"] != float64(1234) {
		t.Errorf("pid = %v, want 1234", m["pid"])
	}
	if m["action"] != "ALLOW" {
		t.Errorf("action = %v, want ALLOW", m["action"])
	}
	if m["cached"] != true {
		t.Errorf("cached = %v, want true", m["cached"])
	}
}

func TestLogDenial(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("info", &buf)

	event := &api.Event{
		PID:      5678,
		UID:      0,
		Comm:     "rm",
		Filename: "/bin/rm",
	}
	result := &api.ActionResult{
		Action: api.ActionDeny,
		Reason: "blocked by policy",
	}

	l.LogDenial(event, result)

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)

	if m["message"] != "action_denied" {
		t.Errorf("message = %v, want action_denied", m["message"])
	}
	if m["level"] != "warn" {
		t.Errorf("level = %v, want warn", m["level"])
	}
	if m["reason"] != "blocked by policy" {
		t.Errorf("reason = %v, want 'blocked by policy'", m["reason"])
	}
}

func TestLogDenial_AuditMode(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("info", &buf)

	event := &api.Event{PID: 100, Comm: "test"}
	result := &api.ActionResult{
		Action: api.ActionDeny,
		Reason: "would deny",
		Audit:  true,
	}

	l.LogDenial(event, result)

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)

	if m["audit"] != true {
		t.Errorf("audit = %v, want true", m["audit"])
	}
}

func TestLogError(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("info", &buf)

	l.LogError(errors.New("connection refused"), "failed to connect")

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)

	if m["level"] != "error" {
		t.Errorf("level = %v, want error", m["level"])
	}
	if m["message"] != "failed to connect" {
		t.Errorf("message = %v, want 'failed to connect'", m["message"])
	}
	if m["error"] != "connection refused" {
		t.Errorf("error = %v, want 'connection refused'", m["error"])
	}
}

func TestLogStats(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("info", &buf)

	stats := &api.EnforcementStats{
		Allowed:      100,
		Denied:       5,
		Logged:       10,
		AuditDenied:  2,
		CacheHits:    80,
		CacheMisses:  35,
		TotalLatency: 115 * time.Millisecond,
	}

	l.LogStats(stats)

	var m map[string]any
	json.Unmarshal(buf.Bytes(), &m)

	if m["message"] != "enforcement_stats" {
		t.Errorf("message = %v, want enforcement_stats", m["message"])
	}
	if m["allowed"] != float64(100) {
		t.Errorf("allowed = %v, want 100", m["allowed"])
	}
	if m["denied"] != float64(5) {
		t.Errorf("denied = %v, want 5", m["denied"])
	}
}

func TestLogStartup(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("info", &buf)

	l.LogStartup("/etc/warmor/policy.wasm")

	output := buf.String()
	if !strings.Contains(output, "warmor_starting") {
		t.Errorf("expected 'warmor_starting' in output, got: %s", output)
	}
	if !strings.Contains(output, "/etc/warmor/policy.wasm") {
		t.Errorf("expected policy path in output, got: %s", output)
	}
}

func TestLogShutdown(t *testing.T) {
	var buf bytes.Buffer
	l := NewLoggerWithWriter("info", &buf)

	l.LogShutdown()

	output := buf.String()
	if !strings.Contains(output, "warmor_shutting_down") {
		t.Errorf("expected 'warmor_shutting_down' in output, got: %s", output)
	}
}
