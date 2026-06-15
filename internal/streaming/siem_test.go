package streaming

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestToCEF_DenyEvent(t *testing.T) {
	event := &SecurityEvent{
		EventType: "file_open",
		Decision:  "deny",
		Hostname:  "node-1",
		PID:       4321,
		UID:       1000,
		Comm:      "malware",
		Filename:  "/etc/shadow",
		Reason:    "policy violation",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	cef := ToCEF(event)

	if !strings.HasPrefix(cef, "CEF:0|Warmor|warmor-agent|1.0|") {
		t.Errorf("bad CEF prefix: %s", cef)
	}
	if !strings.Contains(cef, "|file_open|file_open_deny|8|") {
		t.Errorf("expected signatureID, name, severity=8: %s", cef)
	}
	if !strings.Contains(cef, "src=node-1") {
		t.Error("missing src field")
	}
	if !strings.Contains(cef, "dvcpid=4321") {
		t.Error("missing dvcpid field")
	}
	if !strings.Contains(cef, "filePath=/etc/shadow") {
		t.Error("missing filePath field")
	}
	if !strings.Contains(cef, "msg=policy violation") {
		t.Error("missing msg field")
	}
}

func TestToCEF_AllowEvent(t *testing.T) {
	event := &SecurityEvent{
		EventType: "socket_connect",
		Decision:  "allow",
		Hostname:  "node-2",
		PID:       100,
		UID:       0,
		Comm:      "curl",
		Timestamp: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	cef := ToCEF(event)
	if !strings.Contains(cef, "|1|") {
		t.Errorf("expected severity=1 for allow: %s", cef)
	}
}

func TestToCEF_NetworkEvent(t *testing.T) {
	event := &SecurityEvent{
		EventType:  "socket_connect",
		Decision:   "log",
		Hostname:   "node-3",
		PID:        555,
		UID:        1000,
		Comm:       "wget",
		RemoteAddr: "93.184.216.34",
		RemotePort: 443,
		LocalPort:  54321,
		Protocol:   "tcp",
		Timestamp:  time.Date(2024, 3, 20, 12, 0, 0, 0, time.UTC),
	}

	cef := ToCEF(event)
	if !strings.Contains(cef, "dst=93.184.216.34") {
		t.Error("missing dst field")
	}
	if !strings.Contains(cef, "dpt=443") {
		t.Error("missing dpt field")
	}
	if !strings.Contains(cef, "spt=54321") {
		t.Error("missing spt field")
	}
	if !strings.Contains(cef, "proto=tcp") {
		t.Error("missing proto field")
	}
}

func TestCEFEscape(t *testing.T) {
	event := &SecurityEvent{
		EventType: "file_open",
		Decision:  "deny",
		Hostname:  "h",
		Comm:      "cat",
		Filename:  `/path/with|pipe\and=equals`,
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	cef := ToCEF(event)
	if strings.Contains(cef, `/path/with|pipe\and=equals`) {
		t.Error("CEF special chars should be escaped")
	}
	if !strings.Contains(cef, `\\|`) || !strings.Contains(cef, `\\=`) {
		t.Logf("CEF: %s", cef)
	}
}

func TestCEFSeverity(t *testing.T) {
	tests := []struct {
		decision string
		expected int
	}{
		{"deny", 8},
		{"log", 4},
		{"allow", 1},
		{"", 0},
		{"unknown", 0},
	}
	for _, tc := range tests {
		if got := CEFSeverity(tc.decision); got != tc.expected {
			t.Errorf("CEFSeverity(%q) = %d, want %d", tc.decision, got, tc.expected)
		}
	}
}

func TestCEFSink(t *testing.T) {
	var mu sync.Mutex
	var messages []string

	sink := NewCEFSink("test", func(msg string) error {
		mu.Lock()
		messages = append(messages, msg)
		mu.Unlock()
		return nil
	})

	event := &SecurityEvent{
		EventType: "exec",
		Decision:  "deny",
		Hostname:  "test-host",
		PID:       1,
		Comm:      "bash",
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	if !strings.HasPrefix(messages[0], "CEF:0|") {
		t.Errorf("message not CEF: %s", messages[0])
	}
	if sink.Name() != "cef:test" {
		t.Errorf("unexpected name: %s", sink.Name())
	}
}

func TestSyslogSink_Integration(t *testing.T) {
	// Start a UDP listener to act as a syslog server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	sink, err := NewSyslogSink(SyslogConfig{
		Network: "udp",
		Addr:    pc.LocalAddr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	event := &SecurityEvent{
		EventType: "exec",
		Decision:  "deny",
		Hostname:  "test-host",
		PID:       42,
		UID:       0,
		Comm:      "exploit",
		Filename:  "/tmp/payload",
		Reason:    "blocked",
		Timestamp: time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC),
	}

	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	msg := string(buf[:n])
	if !strings.Contains(msg, "CEF:0|Warmor|") {
		t.Errorf("syslog message missing CEF: %s", msg)
	}
	if !strings.Contains(msg, "warmor:") {
		t.Errorf("syslog message missing app tag: %s", msg)
	}
	if !strings.Contains(msg, "dvcpid=42") {
		t.Errorf("syslog message missing PID: %s", msg)
	}
	if sink.Name() != "syslog:udp://"+pc.LocalAddr().String() {
		t.Errorf("unexpected sink name: %s", sink.Name())
	}
}
