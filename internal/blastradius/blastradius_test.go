package blastradius

import (
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

func TestGraphAddNode(t *testing.T) {
	g := NewGraph()

	now := time.Now()
	g.AddNode(&ContainerNode{
		CgroupID:  100,
		Image:     "nginx:latest",
		Name:      "web",
		FirstSeen: now,
		LastSeen:  now,
	})

	if g.NodeCount() != 1 {
		t.Fatalf("expected 1 node, got %d", g.NodeCount())
	}

	node := g.GetNode(100)
	if node == nil {
		t.Fatal("expected node for cgroup 100")
	}
	if node.Image != "nginx:latest" {
		t.Errorf("expected image nginx:latest, got %s", node.Image)
	}
	if node.Name != "web" {
		t.Errorf("expected name web, got %s", node.Name)
	}
}

func TestGraphAddNodeUpdate(t *testing.T) {
	g := NewGraph()

	t1 := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)

	g.AddNode(&ContainerNode{
		CgroupID:  100,
		Image:     "nginx:latest",
		Name:      "web",
		FirstSeen: t1,
		LastSeen:  t1,
	})

	g.AddNode(&ContainerNode{
		CgroupID:  100,
		Image:     "nginx:1.25",
		Name:      "",
		FirstSeen: t2,
		LastSeen:  t2,
	})

	if g.NodeCount() != 1 {
		t.Fatalf("expected 1 node after update, got %d", g.NodeCount())
	}

	node := g.GetNode(100)
	if node.Image != "nginx:1.25" {
		t.Errorf("expected updated image, got %s", node.Image)
	}
	if node.Name != "web" {
		t.Error("expected name preserved when update is empty")
	}
	if !node.LastSeen.Equal(t2) {
		t.Error("expected LastSeen updated")
	}
}

func TestGraphRemoveNode(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 100, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 200, FirstSeen: now, LastSeen: now})
	g.AddEdge(100, 200, EdgeNetwork, "tcp:80", now)

	g.RemoveNode(100)

	if g.NodeCount() != 1 {
		t.Errorf("expected 1 node after removal, got %d", g.NodeCount())
	}
	if g.GetNode(100) != nil {
		t.Error("expected nil for removed node")
	}
	if g.EdgeCount() != 0 {
		t.Errorf("expected 0 edges after removal, got %d", g.EdgeCount())
	}
}

func TestGraphAddEdge(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 100, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 200, FirstSeen: now, LastSeen: now})

	g.AddEdge(100, 200, EdgeNetwork, "tcp:80", now)

	if g.EdgeCount() != 1 {
		t.Fatalf("expected 1 edge, got %d", g.EdgeCount())
	}

	edges := g.EdgesFrom(100)
	if len(edges) != 1 {
		t.Fatalf("expected 1 outgoing edge, got %d", len(edges))
	}
	if edges[0].To != 200 {
		t.Errorf("expected edge to 200, got %d", edges[0].To)
	}
	if edges[0].Type != EdgeNetwork {
		t.Errorf("expected network edge, got %s", edges[0].Type)
	}
	if edges[0].Count != 1 {
		t.Errorf("expected count 1, got %d", edges[0].Count)
	}
}

func TestGraphAddEdgeUpdatesExisting(t *testing.T) {
	g := NewGraph()
	t1 := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)

	g.AddNode(&ContainerNode{CgroupID: 100, FirstSeen: t1, LastSeen: t1})
	g.AddNode(&ContainerNode{CgroupID: 200, FirstSeen: t1, LastSeen: t1})

	g.AddEdge(100, 200, EdgeNetwork, "tcp:80", t1)
	g.AddEdge(100, 200, EdgeNetwork, "tcp:443", t2)

	if g.EdgeCount() != 1 {
		t.Fatalf("expected 1 edge (deduplicated), got %d", g.EdgeCount())
	}

	edges := g.EdgesFrom(100)
	if edges[0].Count != 2 {
		t.Errorf("expected count 2, got %d", edges[0].Count)
	}
	if edges[0].Details != "tcp:443" {
		t.Errorf("expected updated details, got %s", edges[0].Details)
	}
	if !edges[0].LastSeen.Equal(t2) {
		t.Error("expected LastSeen updated")
	}
}

func TestGraphEdgesTo(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 100, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 200, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 300, FirstSeen: now, LastSeen: now})

	g.AddEdge(100, 200, EdgeNetwork, "tcp:80", now)
	g.AddEdge(300, 200, EdgeSharedVolume, "/data", now)

	incoming := g.EdgesTo(200)
	if len(incoming) != 2 {
		t.Fatalf("expected 2 incoming edges, got %d", len(incoming))
	}
}

func TestGraphNodes(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 100, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 200, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 300, FirstSeen: now, LastSeen: now})

	nodes := g.Nodes()
	if len(nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodes))
	}
}

func TestAnalyzerReachUndirected(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 1, Name: "a", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 2, Name: "b", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 3, Name: "c", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 4, Name: "d", FirstSeen: now, LastSeen: now})

	// a -> b -> c, d is isolated
	g.AddEdge(1, 2, EdgeNetwork, "tcp:80", now)
	g.AddEdge(2, 3, EdgeSharedVolume, "/data", now)

	analyzer := NewAnalyzer(g)
	result := analyzer.Reach(1, 0)

	if result.Source != 1 {
		t.Errorf("expected source 1, got %d", result.Source)
	}
	if len(result.Reachable) != 2 {
		t.Fatalf("expected 2 reachable nodes, got %d", len(result.Reachable))
	}

	found := map[uint64]bool{}
	for _, r := range result.Reachable {
		found[r.CgroupID] = true
	}
	if !found[2] || !found[3] {
		t.Error("expected nodes 2 and 3 reachable from 1")
	}
	if found[4] {
		t.Error("node 4 should not be reachable")
	}
}

func TestAnalyzerReachMaxHops(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 1, Name: "a", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 2, Name: "b", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 3, Name: "c", FirstSeen: now, LastSeen: now})

	g.AddEdge(1, 2, EdgeNetwork, "tcp:80", now)
	g.AddEdge(2, 3, EdgeNetwork, "tcp:80", now)

	analyzer := NewAnalyzer(g)
	result := analyzer.Reach(1, 1)

	if len(result.Reachable) != 1 {
		t.Fatalf("expected 1 reachable node with maxHops=1, got %d", len(result.Reachable))
	}
	if result.Reachable[0].CgroupID != 2 {
		t.Errorf("expected node 2 at hop 1, got %d", result.Reachable[0].CgroupID)
	}
}

func TestAnalyzerReachDirected(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 1, Name: "a", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 2, Name: "b", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 3, Name: "c", FirstSeen: now, LastSeen: now})

	// a -> b, c -> b (b has no outgoing)
	g.AddEdge(1, 2, EdgeNetwork, "tcp:80", now)
	g.AddEdge(3, 2, EdgeNetwork, "tcp:80", now)

	analyzer := NewAnalyzer(g)

	// From node 1, directed: can reach 2 (via outgoing edge)
	result := analyzer.ReachDirected(1, 0)
	if len(result.Reachable) != 1 {
		t.Fatalf("expected 1 reachable (directed) from 1, got %d", len(result.Reachable))
	}
	if result.Reachable[0].CgroupID != 2 {
		t.Errorf("expected node 2, got %d", result.Reachable[0].CgroupID)
	}

	// From node 2, directed: can reach nothing (no outgoing edges)
	result = analyzer.ReachDirected(2, 0)
	if len(result.Reachable) != 0 {
		t.Errorf("expected 0 reachable (directed) from 2, got %d", len(result.Reachable))
	}
}

func TestAnalyzerReachUnknownNode(t *testing.T) {
	g := NewGraph()
	analyzer := NewAnalyzer(g)

	result := analyzer.Reach(999, 0)
	if len(result.Reachable) != 0 {
		t.Errorf("expected 0 reachable for unknown node, got %d", len(result.Reachable))
	}
}

func TestAnalyzerPathTracking(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 1, Name: "a", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 2, Name: "b", FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 3, Name: "c", FirstSeen: now, LastSeen: now})

	g.AddEdge(1, 2, EdgeNetwork, "tcp:80", now)
	g.AddEdge(2, 3, EdgeSharedVolume, "/shared", now)

	analyzer := NewAnalyzer(g)
	result := analyzer.Reach(1, 0)

	var nodeC *ReachableNode
	for i := range result.Reachable {
		if result.Reachable[i].CgroupID == 3 {
			nodeC = &result.Reachable[i]
		}
	}
	if nodeC == nil {
		t.Fatal("expected node 3 in reachable set")
	}
	if nodeC.Hops != 2 {
		t.Errorf("expected 2 hops to node 3, got %d", nodeC.Hops)
	}
	if len(nodeC.Path) != 2 {
		t.Fatalf("expected path length 2, got %d", len(nodeC.Path))
	}
	if nodeC.Path[0].From != 1 || nodeC.Path[0].To != 2 {
		t.Error("expected first path edge 1->2")
	}
	if nodeC.Path[1].From != 2 || nodeC.Path[1].To != 3 {
		t.Error("expected second path edge 2->3")
	}
	if nodeC.Path[0].Type != EdgeNetwork {
		t.Error("expected first hop to be network edge")
	}
	if nodeC.Path[1].Type != EdgeSharedVolume {
		t.Error("expected second hop to be shared_volume edge")
	}
}

func TestAnalyzerImpactScore(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 1, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 2, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 3, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 4, FirstSeen: now, LastSeen: now})

	// 1 connects to 2 and 3 (2 out of 3 other nodes reachable)
	g.AddEdge(1, 2, EdgeNetwork, "tcp:80", now)
	g.AddEdge(1, 3, EdgeNetwork, "tcp:80", now)

	analyzer := NewAnalyzer(g)
	score := analyzer.ImpactScore(1)

	expected := 2.0 / 3.0
	if score < expected-0.01 || score > expected+0.01 {
		t.Errorf("expected impact score ~%.3f, got %.3f", expected, score)
	}

	// Node 4 is isolated
	score4 := analyzer.ImpactScore(4)
	if score4 != 0 {
		t.Errorf("expected impact score 0 for isolated node, got %.3f", score4)
	}
}

func TestAnalyzerImpactScoreSingleNode(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 1, FirstSeen: now, LastSeen: now})

	analyzer := NewAnalyzer(g)
	score := analyzer.ImpactScore(1)
	if score != 0 {
		t.Errorf("expected 0 for single node graph, got %.3f", score)
	}
}

func TestAnalyzerMostConnected(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 1, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 2, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 3, FirstSeen: now, LastSeen: now})

	// Node 2 is most connected (2 edges touching it)
	g.AddEdge(1, 2, EdgeNetwork, "tcp:80", now)
	g.AddEdge(3, 2, EdgeSharedVolume, "/data", now)

	analyzer := NewAnalyzer(g)
	id, count := analyzer.MostConnected()

	if id != 2 {
		t.Errorf("expected most connected node 2, got %d", id)
	}
	if count != 2 {
		t.Errorf("expected connection count 2, got %d", count)
	}
}

func TestAnalyzerMostConnectedEmpty(t *testing.T) {
	g := NewGraph()
	analyzer := NewAnalyzer(g)

	id, count := analyzer.MostConnected()
	if id != 0 || count != 0 {
		t.Errorf("expected (0,0) for empty graph, got (%d,%d)", id, count)
	}
}

func TestCollectorProcessEvent(t *testing.T) {
	g := NewGraph()
	c := NewCollector(g)

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	c.ProcessEvent(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nginx",
		CgroupID:  100,
		Timestamp: now,
	})

	if g.NodeCount() != 1 {
		t.Fatalf("expected 1 node, got %d", g.NodeCount())
	}

	node := g.GetNode(100)
	if node == nil {
		t.Fatal("expected node for cgroup 100")
	}
	if node.Name != "nginx" {
		t.Errorf("expected name nginx, got %s", node.Name)
	}
}

func TestCollectorSkipsZeroCgroup(t *testing.T) {
	g := NewGraph()
	c := NewCollector(g)

	c.ProcessEvent(&streaming.SecurityEvent{
		EventType: "exec",
		Comm:      "nginx",
		CgroupID:  0,
		Timestamp: time.Now(),
	})

	if g.NodeCount() != 0 {
		t.Error("should not add nodes for cgroup 0")
	}
}

func TestCollectorRegisterSharedNamespace(t *testing.T) {
	g := NewGraph()
	c := NewCollector(g)
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 100, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 200, FirstSeen: now, LastSeen: now})

	c.RegisterSharedNamespace(100, 200, EdgeSharedPID, now)

	if g.EdgeCount() != 2 {
		t.Fatalf("expected 2 edges (bidirectional), got %d", g.EdgeCount())
	}

	from100 := g.EdgesFrom(100)
	if len(from100) != 1 {
		t.Fatalf("expected 1 edge from 100, got %d", len(from100))
	}
	if from100[0].Type != EdgeSharedPID {
		t.Errorf("expected shared_pid_ns edge, got %s", from100[0].Type)
	}

	from200 := g.EdgesFrom(200)
	if len(from200) != 1 {
		t.Fatalf("expected 1 edge from 200, got %d", len(from200))
	}
}

func TestRemoveNodeCleansEdges(t *testing.T) {
	g := NewGraph()
	now := time.Now()

	g.AddNode(&ContainerNode{CgroupID: 1, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 2, FirstSeen: now, LastSeen: now})
	g.AddNode(&ContainerNode{CgroupID: 3, FirstSeen: now, LastSeen: now})

	g.AddEdge(1, 2, EdgeNetwork, "tcp:80", now)
	g.AddEdge(3, 2, EdgeSharedVolume, "/data", now)
	g.AddEdge(1, 3, EdgeSharedIPC, "ipc", now)

	g.RemoveNode(2)

	if g.EdgeCount() != 1 {
		t.Errorf("expected 1 edge remaining after removing node 2, got %d", g.EdgeCount())
	}

	edges := g.EdgesFrom(1)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge from node 1, got %d", len(edges))
	}
	if edges[0].To != 3 {
		t.Errorf("expected remaining edge to node 3, got %d", edges[0].To)
	}
}

func TestPortStr(t *testing.T) {
	tests := []struct {
		port uint16
		want string
	}{
		{0, "0"},
		{80, "80"},
		{443, "443"},
		{8080, "8080"},
		{65535, "65535"},
	}

	for _, tt := range tests {
		got := portStr(tt.port)
		if got != tt.want {
			t.Errorf("portStr(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}
