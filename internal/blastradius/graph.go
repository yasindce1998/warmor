package blastradius

import (
	"sync"
	"time"
)

// EdgeType describes the type of relationship between containers.
type EdgeType string

const (
	EdgeNetwork      EdgeType = "network"
	EdgeSharedVolume EdgeType = "shared_volume"
	EdgeSharedPID    EdgeType = "shared_pid_ns"
	EdgeSharedIPC    EdgeType = "shared_ipc_ns"
)

// ContainerNode represents a container in the blast radius graph.
type ContainerNode struct {
	CgroupID  uint64            `json:"cgroup_id"`
	Image     string            `json:"image"`
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels,omitempty"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

// ContainerEdge represents a directional relationship between containers.
type ContainerEdge struct {
	From     uint64   `json:"from"`
	To       uint64   `json:"to"`
	Type     EdgeType `json:"type"`
	Details  string   `json:"details"`
	LastSeen time.Time `json:"last_seen"`
	Count    int      `json:"count"`
}

// Graph maintains the container relationship graph for blast radius analysis.
type Graph struct {
	mu    sync.RWMutex
	nodes map[uint64]*ContainerNode
	edges []*ContainerEdge
}

// NewGraph creates a new blast radius graph.
func NewGraph() *Graph {
	return &Graph{
		nodes: make(map[uint64]*ContainerNode),
	}
}

// AddNode registers or updates a container node.
func (g *Graph) AddNode(node *ContainerNode) {
	g.mu.Lock()
	defer g.mu.Unlock()

	existing, ok := g.nodes[node.CgroupID]
	if ok {
		existing.LastSeen = node.LastSeen
		if node.Image != "" {
			existing.Image = node.Image
		}
		if node.Name != "" {
			existing.Name = node.Name
		}
		return
	}
	g.nodes[node.CgroupID] = node
}

// RemoveNode removes a container and all its edges.
func (g *Graph) RemoveNode(cgroupID uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	delete(g.nodes, cgroupID)

	filtered := g.edges[:0]
	for _, e := range g.edges {
		if e.From != cgroupID && e.To != cgroupID {
			filtered = append(filtered, e)
		}
	}
	g.edges = filtered
}

// AddEdge records a relationship between two containers.
func (g *Graph) AddEdge(from, to uint64, edgeType EdgeType, details string, timestamp time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, e := range g.edges {
		if e.From == from && e.To == to && e.Type == edgeType {
			e.Count++
			e.LastSeen = timestamp
			if details != "" {
				e.Details = details
			}
			return
		}
	}

	g.edges = append(g.edges, &ContainerEdge{
		From:     from,
		To:       to,
		Type:     edgeType,
		Details:  details,
		LastSeen: timestamp,
		Count:    1,
	})
}

// NodeCount returns the number of tracked containers.
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// EdgeCount returns the number of tracked edges.
func (g *Graph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.edges)
}

// GetNode returns a container node by cgroup ID.
func (g *Graph) GetNode(cgroupID uint64) *ContainerNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[cgroupID]
}

// Nodes returns all container nodes.
func (g *Graph) Nodes() []*ContainerNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*ContainerNode, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// EdgesFrom returns all outgoing edges from a container.
func (g *Graph) EdgesFrom(cgroupID uint64) []*ContainerEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []*ContainerEdge
	for _, e := range g.edges {
		if e.From == cgroupID {
			result = append(result, e)
		}
	}
	return result
}

// EdgesTo returns all incoming edges to a container.
func (g *Graph) EdgesTo(cgroupID uint64) []*ContainerEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []*ContainerEdge
	for _, e := range g.edges {
		if e.To == cgroupID {
			result = append(result, e)
		}
	}
	return result
}
