package learner

import (
	"context"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestRecorderFiltersOnCgroup(t *testing.T) {
	r := NewRecorder([]uint64{100})

	ctx := context.Background()
	_ = r.Write(ctx, &streaming.SecurityEvent{CgroupID: 100, EventType: "exec", Filename: "/bin/sh"})
	_ = r.Write(ctx, &streaming.SecurityEvent{CgroupID: 200, EventType: "exec", Filename: "/bin/bash"})

	profiles := r.Profiles()
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if _, ok := profiles[100]; !ok {
		t.Fatal("expected profile for cgroup 100")
	}
}

func TestRecorderRecordsAllWhenNoFilter(t *testing.T) {
	r := NewRecorder(nil)

	ctx := context.Background()
	_ = r.Write(ctx, &streaming.SecurityEvent{CgroupID: 100, EventType: "exec", Filename: "/bin/sh"})
	_ = r.Write(ctx, &streaming.SecurityEvent{CgroupID: 200, EventType: "exec", Filename: "/bin/bash"})

	profiles := r.Profiles()
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
}

func TestRecorderAllEventTypes(t *testing.T) {
	r := NewRecorder(nil)
	ctx := context.Background()

	events := []*streaming.SecurityEvent{
		{CgroupID: 1, EventType: "exec", Filename: "/usr/bin/nginx"},
		{CgroupID: 1, EventType: "file", Filename: "/etc/nginx/nginx.conf"},
		{CgroupID: 1, EventType: "network", Protocol: "tcp", RemoteAddr: "10.0.0.1", RemotePort: 443},
		{CgroupID: 1, EventType: "bind", Protocol: "tcp", LocalPort: 80},
		{CgroupID: 1, EventType: "listen", Protocol: "tcp", LocalPort: 80},
		{CgroupID: 1, EventType: "mount", MountType: "tmpfs"},
		{CgroupID: 1, EventType: "ptrace", PtraceComm: "strace"},
	}

	for _, e := range events {
		if err := r.Write(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	p := r.Profiles()[1]
	if len(p.Execs) != 1 {
		t.Errorf("execs: got %d, want 1", len(p.Execs))
	}
	if len(p.Files) != 1 {
		t.Errorf("files: got %d, want 1", len(p.Files))
	}
	if len(p.Networks) != 1 {
		t.Errorf("networks: got %d, want 1", len(p.Networks))
	}
	if len(p.Binds) != 1 {
		t.Errorf("binds: got %d, want 1", len(p.Binds))
	}
	if len(p.Listens) != 1 {
		t.Errorf("listens: got %d, want 1", len(p.Listens))
	}
	if len(p.Mounts) != 1 {
		t.Errorf("mounts: got %d, want 1", len(p.Mounts))
	}
	if len(p.Ptrace) != 1 {
		t.Errorf("ptrace: got %d, want 1", len(p.Ptrace))
	}
}

func TestRecorderStopsAfterClose(t *testing.T) {
	r := NewRecorder(nil)
	ctx := context.Background()

	_ = r.Write(ctx, &streaming.SecurityEvent{CgroupID: 1, EventType: "exec", Filename: "/bin/sh"})
	_ = r.Close()
	_ = r.Write(ctx, &streaming.SecurityEvent{CgroupID: 1, EventType: "exec", Filename: "/bin/bash"})

	p := r.Profiles()[1]
	if len(p.Execs) != 1 {
		t.Errorf("expected 1 exec after close, got %d", len(p.Execs))
	}
}

func TestSynthesizeProducesValidPolicy(t *testing.T) {
	profile := &ContainerProfile{
		CgroupID: 42,
		Execs:    map[string]int{"/usr/bin/nginx": 5, "/usr/sbin/nginx": 2},
		Files:    map[string]int{"/etc/nginx/nginx.conf": 10},
		Networks: map[string]int{"tcp:10.0.0.1:443": 3},
		Binds:    map[string]int{"tcp:80": 1},
		Listens:  map[string]int{"tcp:80": 1},
		Mounts:   map[string]int{},
		Ptrace:   map[string]int{},
	}

	policy := Synthesize(profile, "test-policy")

	if policy.Name != "test-policy" {
		t.Errorf("name: got %q, want %q", policy.Name, "test-policy")
	}
	if policy.DefaultAction != "deny" {
		t.Errorf("default_action: got %q, want %q", policy.DefaultAction, "deny")
	}
	if len(policy.Rules) != 6 {
		t.Errorf("rules: got %d, want 6", len(policy.Rules))
	}

	for _, rule := range policy.Rules {
		if rule.Action != "allow" {
			t.Errorf("rule %q: action=%q, want allow", rule.Name, rule.Action)
		}
		if rule.Event == "" {
			t.Errorf("rule %q: empty event", rule.Name)
		}
	}
}

func TestSynthesizeAllMergesProfiles(t *testing.T) {
	profiles := map[uint64]*ContainerProfile{
		1: {CgroupID: 1, Execs: map[string]int{"/bin/sh": 1}, Files: make(map[string]int), Networks: make(map[string]int), Binds: make(map[string]int), Listens: make(map[string]int), Mounts: make(map[string]int), Ptrace: make(map[string]int)},
		2: {CgroupID: 2, Execs: map[string]int{"/bin/bash": 1}, Files: make(map[string]int), Networks: make(map[string]int), Binds: make(map[string]int), Listens: make(map[string]int), Mounts: make(map[string]int), Ptrace: make(map[string]int)},
	}

	policy := SynthesizeAll(profiles, "merged")
	if len(policy.Rules) != 2 {
		t.Errorf("rules: got %d, want 2", len(policy.Rules))
	}
}

func TestSessionRunExpires(t *testing.T) {
	sess := NewSession(Config{Duration: 50 * time.Millisecond})
	start := time.Now()
	err := sess.Run(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("returned too early: %v", elapsed)
	}
}

func TestSessionRunCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sess := NewSession(Config{Duration: 10 * time.Second})

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := sess.Run(ctx)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/usr/bin/nginx", "usr-bin-nginx"},
		{"tcp:10.0.0.1:443", "tcp-10-0-0-1-443"},
		{"short", "short"},
	}
	for _, tc := range cases {
		got := sanitizeName(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
