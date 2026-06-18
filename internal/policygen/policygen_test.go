package policygen

import (
	"strings"
	"testing"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestReadEvents(t *testing.T) {
	input := `{"event_type":"exec","comm":"nginx","filename":"/usr/sbin/nginx","pid":100,"uid":0,"gid":0,"decision":"allow","cached":false,"enforced":false,"latency_us":50}
{"event_type":"file","comm":"nginx","filename":"/etc/nginx/nginx.conf","pid":100,"uid":0,"gid":0,"decision":"allow","cached":false,"enforced":false,"latency_us":20}
{"event_type":"network","comm":"nginx","protocol":"tcp","remote_addr":"10.0.1.5","remote_port":443,"pid":100,"uid":0,"gid":0,"decision":"allow","cached":false,"enforced":false,"latency_us":30}
`
	events, err := ReadEvents(strings.NewReader(input), ReadOptions{})
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].EventType != "exec" {
		t.Errorf("events[0].EventType = %q, want exec", events[0].EventType)
	}
	if events[1].Filename != "/etc/nginx/nginx.conf" {
		t.Errorf("events[1].Filename = %q, want /etc/nginx/nginx.conf", events[1].Filename)
	}
}

func TestReadEventsWithFilter(t *testing.T) {
	input := `{"event_type":"exec","comm":"nginx","filename":"/usr/sbin/nginx","pid":100,"uid":0,"gid":0,"decision":"allow","cached":false,"enforced":false,"latency_us":50}
{"event_type":"exec","comm":"python3","filename":"/usr/bin/python3","pid":200,"uid":1000,"gid":1000,"decision":"allow","cached":false,"enforced":false,"latency_us":50}
{"event_type":"file","comm":"nginx","filename":"/etc/nginx/nginx.conf","pid":100,"uid":0,"gid":0,"decision":"allow","cached":false,"enforced":false,"latency_us":20}
`
	events, err := ReadEvents(strings.NewReader(input), ReadOptions{
		CommFilter: []string{"nginx"},
	})
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events (filtered to nginx), got %d", len(events))
	}
}

func TestReadEventsEventTypeFilter(t *testing.T) {
	input := `{"event_type":"exec","comm":"nginx","filename":"/usr/sbin/nginx","pid":100,"uid":0,"gid":0,"decision":"allow","cached":false,"enforced":false,"latency_us":50}
{"event_type":"file","comm":"nginx","filename":"/etc/nginx/nginx.conf","pid":100,"uid":0,"gid":0,"decision":"allow","cached":false,"enforced":false,"latency_us":20}
{"event_type":"network","comm":"nginx","protocol":"tcp","remote_addr":"10.0.1.5","remote_port":443,"pid":100,"uid":0,"gid":0,"decision":"allow","cached":false,"enforced":false,"latency_us":30}
`
	events, err := ReadEvents(strings.NewReader(input), ReadOptions{
		EventTypes: []string{"exec", "network"},
	})
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events (exec+network), got %d", len(events))
	}
}

func TestAggregateExec(t *testing.T) {
	events := []streaming.SecurityEvent{
		{EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx"},
		{EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx"},
		{EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx"},
		{EventType: "exec", Comm: "sh", Filename: "/bin/sh"},
		{EventType: "exec", Comm: "sh", Filename: "/bin/sh"},
	}

	result := Aggregate(events, AggregateOptions{MinCount: 2, CollapsePaths: false, NetworkGroup: "subnet"})

	if len(result.Behaviors) != 2 {
		t.Fatalf("expected 2 behaviors, got %d", len(result.Behaviors))
	}
	if result.TotalEvents != 5 {
		t.Errorf("TotalEvents = %d, want 5", result.TotalEvents)
	}

	found := false
	for _, b := range result.Behaviors {
		if b.Comm == "nginx" && b.Count == 3 {
			found = true
		}
	}
	if !found {
		t.Error("expected nginx behavior with count=3")
	}
}

func TestAggregateMinCount(t *testing.T) {
	events := []streaming.SecurityEvent{
		{EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx"},
		{EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx"},
		{EventType: "exec", Comm: "rare", Filename: "/tmp/rare"},
	}

	result := Aggregate(events, AggregateOptions{MinCount: 2, CollapsePaths: false, NetworkGroup: "subnet"})

	if len(result.Behaviors) != 1 {
		t.Fatalf("expected 1 behavior (rare filtered out), got %d", len(result.Behaviors))
	}
	if result.Behaviors[0].Comm != "nginx" {
		t.Errorf("expected nginx, got %s", result.Behaviors[0].Comm)
	}
}

func TestAggregateNetworkSubnet(t *testing.T) {
	events := []streaming.SecurityEvent{
		{EventType: "network", Comm: "curl", Protocol: "tcp", RemoteAddr: "10.0.1.5", RemotePort: 443},
		{EventType: "network", Comm: "curl", Protocol: "tcp", RemoteAddr: "10.0.1.10", RemotePort: 443},
		{EventType: "network", Comm: "curl", Protocol: "tcp", RemoteAddr: "10.0.1.20", RemotePort: 443},
	}

	result := Aggregate(events, AggregateOptions{MinCount: 1, CollapsePaths: false, NetworkGroup: "subnet"})

	if len(result.Behaviors) != 1 {
		t.Fatalf("expected 1 behavior (same subnet), got %d", len(result.Behaviors))
	}
	if result.Behaviors[0].Count != 3 {
		t.Errorf("count = %d, want 3", result.Behaviors[0].Count)
	}
}

func TestAggregateNetworkExact(t *testing.T) {
	events := []streaming.SecurityEvent{
		{EventType: "network", Comm: "curl", Protocol: "tcp", RemoteAddr: "10.0.1.5", RemotePort: 443},
		{EventType: "network", Comm: "curl", Protocol: "tcp", RemoteAddr: "10.0.1.10", RemotePort: 443},
	}

	result := Aggregate(events, AggregateOptions{MinCount: 1, CollapsePaths: false, NetworkGroup: "exact"})

	if len(result.Behaviors) != 2 {
		t.Fatalf("expected 2 behaviors (exact mode), got %d", len(result.Behaviors))
	}
}

func TestCollapsePaths(t *testing.T) {
	paths := []string{
		"/var/log/app-001.log",
		"/var/log/app-002.log",
		"/var/log/app-003.log",
	}

	result := collapsePaths(paths)
	switch v := result.(type) {
	case string:
		if !strings.Contains(v, "*") {
			t.Errorf("expected glob pattern, got %q", v)
		}
	case []string:
		if len(v) != 1 || !strings.Contains(v[0], "*") {
			t.Errorf("expected single glob pattern, got %v", v)
		}
	default:
		t.Errorf("unexpected type %T", result)
	}
}

func TestGenerateBasic(t *testing.T) {
	events := []streaming.SecurityEvent{
		{EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx"},
		{EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx"},
		{EventType: "exec", Comm: "nginx", Filename: "/usr/sbin/nginx"},
	}

	result := Aggregate(events, AggregateOptions{MinCount: 2, CollapsePaths: false, NetworkGroup: "subnet"})

	yamlBytes, err := Generate(result, GenerateOptions{PolicyName: "test-policy"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	yaml := string(yamlBytes)
	if !strings.Contains(yaml, "name: test-policy") {
		t.Error("missing policy name")
	}
	if !strings.Contains(yaml, "default_action: deny") {
		t.Error("missing default_action: deny")
	}
	if !strings.Contains(yaml, "allow-nginx-exec") {
		t.Error("missing allow-nginx-exec rule")
	}
	if !strings.Contains(yaml, "/usr/sbin/nginx") {
		t.Error("missing nginx path")
	}
}

func TestGenerateMultiplePaths(t *testing.T) {
	events := []streaming.SecurityEvent{
		{EventType: "exec", Comm: "app", Filename: "/usr/bin/python3"},
		{EventType: "exec", Comm: "app", Filename: "/usr/bin/python3"},
		{EventType: "exec", Comm: "app", Filename: "/usr/local/bin/gunicorn"},
		{EventType: "exec", Comm: "app", Filename: "/usr/local/bin/gunicorn"},
	}

	result := Aggregate(events, AggregateOptions{MinCount: 2, CollapsePaths: false, NetworkGroup: "subnet"})

	yamlBytes, err := Generate(result, GenerateOptions{PolicyName: "multi-path"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	yaml := string(yamlBytes)
	if !strings.Contains(yaml, "any_of") {
		t.Error("expected any_of for multiple paths")
	}
	if !strings.Contains(yaml, "app-binaries") {
		t.Error("expected variable name app-binaries")
	}
}

func TestGenerateNetwork(t *testing.T) {
	events := []streaming.SecurityEvent{
		{EventType: "network", Comm: "curl", Protocol: "tcp", RemoteAddr: "10.0.1.5", RemotePort: 443},
		{EventType: "network", Comm: "curl", Protocol: "tcp", RemoteAddr: "10.0.1.5", RemotePort: 443},
		{EventType: "network", Comm: "curl", Protocol: "tcp", RemoteAddr: "10.0.1.5", RemotePort: 443},
	}

	result := Aggregate(events, AggregateOptions{MinCount: 2, CollapsePaths: false, NetworkGroup: "subnet"})

	yamlBytes, err := Generate(result, GenerateOptions{PolicyName: "net-policy"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	yaml := string(yamlBytes)
	if !strings.Contains(yaml, "network") {
		t.Error("missing network event type")
	}
	if !strings.Contains(yaml, "tcp") {
		t.Error("missing tcp protocol")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"allow-nginx-exec", "allow-nginx-exec"},
		{"allow nginx/exec", "allow-nginx-exec"},
		{"ALLOW--NGINX", "allow-nginx"},
		{"a/b/c/d/e/f", "a-b-c-d-e-f"},
	}
	for _, tc := range cases {
		got := sanitizeName(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
