package attackgraph

import (
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestTacticIndex(t *testing.T) {
	if TacticIndex(TacticReconnaissance) != 0 {
		t.Error("reconnaissance should be index 0")
	}
	if TacticIndex(TacticImpact) != 10 {
		t.Error("impact should be index 10")
	}
	if TacticIndex("nonexistent") != -1 {
		t.Error("unknown tactic should return -1")
	}
}

func TestTechniqueDBContents(t *testing.T) {
	if len(TechniqueDB) < 20 {
		t.Errorf("expected at least 20 techniques, got %d", len(TechniqueDB))
	}

	tech := TechniqueDB["T1611"]
	if tech == nil {
		t.Fatal("T1611 not found")
	}
	if tech.Tactic != TacticPrivilegeEscalation {
		t.Errorf("T1611 tactic should be privilege_escalation, got %s", tech.Tactic)
	}
}

func TestCorrelatorExecShell(t *testing.T) {
	c := NewCorrelator()

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "bash",
		CgroupID:  100,
	}

	techniques := c.Correlate(ev)
	if len(techniques) == 0 {
		t.Fatal("expected techniques for bash exec")
	}
	found := false
	for _, tid := range techniques {
		if tid == "T1059.004" {
			found = true
		}
	}
	if !found {
		t.Error("expected T1059.004 (Unix Shell) for bash exec")
	}
}

func TestCorrelatorToolTransfer(t *testing.T) {
	c := NewCorrelator()

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "curl",
		CgroupID:  100,
	}

	techniques := c.Correlate(ev)
	found := false
	for _, tid := range techniques {
		if tid == "T1105" {
			found = true
		}
	}
	if !found {
		t.Error("expected T1105 (Ingress Tool Transfer) for curl exec")
	}
}

func TestCorrelatorFileCredentials(t *testing.T) {
	c := NewCorrelator()

	ev := &streaming.SecurityEvent{
		EventType: "file",
		Filename:  "/home/user/.ssh/id_rsa",
		CgroupID:  100,
	}

	techniques := c.Correlate(ev)
	found := false
	for _, tid := range techniques {
		if tid == "T1552.001" {
			found = true
		}
	}
	if !found {
		t.Error("expected T1552.001 (Credentials in Files) for .ssh/id_rsa access")
	}
}

func TestCorrelatorNoMatch(t *testing.T) {
	c := NewCorrelator()

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nginx",
		CgroupID:  100,
	}

	techniques := c.Correlate(ev)
	if len(techniques) != 0 {
		t.Errorf("expected no techniques for nginx exec, got %v", techniques)
	}
}

func TestCorrelatorEnrich(t *testing.T) {
	c := NewCorrelator()

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "wget",
		CgroupID:  100,
	}

	c.Enrich(ev)

	if ev.Labels == nil {
		t.Fatal("expected labels after enrichment")
	}
	if ev.Labels["mitre_techniques"] == "" {
		t.Error("expected mitre_techniques label")
	}
	if ev.Labels["mitre_tactic"] == "" {
		t.Error("expected mitre_tactic label")
	}
}

func TestCorrelatorEnrichNoMatch(t *testing.T) {
	c := NewCorrelator()

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "myapp",
		CgroupID:  100,
	}

	c.Enrich(ev)

	if ev.Labels != nil {
		t.Error("expected no labels for non-matching event")
	}
}

func TestCorrelatorNoDuplicates(t *testing.T) {
	rules := []MatchRule{
		{TechniqueID: "T1059.004", EventType: "exec", CommMatch: "bash"},
		{TechniqueID: "T1059.004", EventType: "exec", CommMatch: "bash"},
	}
	c := NewCorrelatorWithRules(rules)

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "bash",
		CgroupID:  100,
	}

	techniques := c.Correlate(ev)
	if len(techniques) != 1 {
		t.Errorf("expected 1 unique technique, got %d", len(techniques))
	}
}

func TestGraphIngest(t *testing.T) {
	c := NewCorrelator()
	g := NewGraph(c)

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "curl",
		CgroupID:  100,
		Timestamp: now,
	})

	cg := g.GetContainer(100)
	if cg == nil {
		t.Fatal("expected container graph for cgroup 100")
	}
	if len(cg.Nodes) == 0 {
		t.Fatal("expected at least one node")
	}
	if cg.Nodes["T1105"] == nil {
		t.Error("expected T1105 node for curl")
	}
}

func TestGraphIngestZeroCgroup(t *testing.T) {
	c := NewCorrelator()
	g := NewGraph(c)

	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "curl",
		CgroupID:  0,
		Timestamp: time.Now(),
	})

	if len(g.Containers()) != 0 {
		t.Error("should not track cgroup 0")
	}
}

func TestGraphKillChainEdges(t *testing.T) {
	c := NewCorrelator()
	g := NewGraph(c)

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Discovery phase: run ps
	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "ps",
		CgroupID:  100,
		Timestamp: now,
	})

	// Privilege escalation: nsenter
	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nsenter",
		CgroupID:  100,
		Timestamp: now.Add(time.Second),
	})

	cg := g.GetContainer(100)
	if cg == nil {
		t.Fatal("expected container graph")
	}

	if len(cg.Edges) == 0 {
		t.Fatal("expected kill-chain edges between discovery and privilege escalation")
	}

	foundEdge := false
	for _, edge := range cg.Edges {
		fromTech := TechniqueDB[edge.From]
		toTech := TechniqueDB[edge.To]
		if fromTech != nil && toTech != nil {
			fromIdx := TacticIndex(fromTech.Tactic)
			toIdx := TacticIndex(toTech.Tactic)
			if fromIdx < toIdx {
				foundEdge = true
			}
		}
	}
	if !foundEdge {
		t.Error("expected at least one edge from earlier to later tactic")
	}
}

func TestGraphMultipleContainers(t *testing.T) {
	c := NewCorrelator()
	g := NewGraph(c)

	now := time.Now()

	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "curl",
		CgroupID:  100,
		Timestamp: now,
	})
	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "wget",
		CgroupID:  200,
		Timestamp: now,
	})

	containers := g.Containers()
	if len(containers) != 2 {
		t.Errorf("expected 2 containers, got %d", len(containers))
	}
}

func TestGraphRemove(t *testing.T) {
	c := NewCorrelator()
	g := NewGraph(c)

	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "curl",
		CgroupID:  100,
		Timestamp: time.Now(),
	})

	g.Remove(100)

	if g.GetContainer(100) != nil {
		t.Error("expected nil after remove")
	}
}

func TestGraphSummary(t *testing.T) {
	c := NewCorrelator()
	g := NewGraph(c)

	now := time.Now()

	// Container 1: discovery + execution
	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "ps",
		CgroupID:  100,
		Timestamp: now,
	})
	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "curl",
		CgroupID:  100,
		Timestamp: now,
	})

	// Container 2: privilege escalation
	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nsenter",
		CgroupID:  200,
		Timestamp: now,
	})

	summary := g.Summary()
	if summary.ContainerCount != 2 {
		t.Errorf("expected 2 containers, got %d", summary.ContainerCount)
	}
	if summary.TechniqueCount < 3 {
		t.Errorf("expected at least 3 techniques, got %d", summary.TechniqueCount)
	}
	if summary.HighestProgression < TacticIndex(TacticDiscovery) {
		t.Error("expected highest progression at least at discovery level")
	}
}

func TestGraphNodeCountIncrement(t *testing.T) {
	c := NewCorrelator()
	g := NewGraph(c)

	now := time.Now()

	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "curl",
		CgroupID:  100,
		Timestamp: now,
	})
	g.Ingest(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "curl",
		CgroupID:  100,
		Timestamp: now.Add(time.Second),
	})

	cg := g.GetContainer(100)
	if cg == nil {
		t.Fatal("expected container graph")
	}
	node := cg.Nodes["T1105"]
	if node == nil {
		t.Fatal("expected T1105 node")
	}
	if node.Count != 2 {
		t.Errorf("expected count 2, got %d", node.Count)
	}
}

func TestCorrelatorPtraceEvent(t *testing.T) {
	c := NewCorrelator()

	ev := &streaming.SecurityEvent{
		EventType: "ptrace",
		CgroupID:  100,
		Comm:      "gdb",
	}

	techniques := c.Correlate(ev)
	found := false
	for _, tid := range techniques {
		if tid == "T1055" {
			found = true
		}
	}
	if !found {
		t.Error("expected T1055 (Process Injection) for ptrace event")
	}
}
