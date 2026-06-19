package attackgraph

import (
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// Node represents an observed ATT&CK technique instance in the graph.
type Node struct {
	TechniqueID string    `json:"technique_id"`
	Name        string    `json:"name"`
	Tactic      Tactic    `json:"tactic"`
	Count       int       `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// Edge represents a kill-chain progression between two technique nodes.
type Edge struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Weight    int       `json:"weight"`
	LastSeen  time.Time `json:"last_seen"`
}

// ContainerGraph holds the attack graph for a specific container.
type ContainerGraph struct {
	CgroupID uint64           `json:"cgroup_id"`
	Nodes    map[string]*Node `json:"nodes"`
	Edges    []*Edge          `json:"edges"`
	LastSeen time.Time        `json:"last_seen"`
}

// Graph maintains per-container attack graphs.
type Graph struct {
	mu         sync.RWMutex
	containers map[uint64]*ContainerGraph
	correlator *Correlator
}

// NewGraph creates a new attack graph with the given correlator.
func NewGraph(correlator *Correlator) *Graph {
	return &Graph{
		containers: make(map[uint64]*ContainerGraph),
		correlator: correlator,
	}
}

// Ingest processes a security event and updates the attack graph.
func (g *Graph) Ingest(event *streaming.SecurityEvent) {
	if event.CgroupID == 0 {
		return
	}

	techniques := g.correlator.Correlate(event)
	if len(techniques) == 0 {
		return
	}

	now := event.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	cg := g.containers[event.CgroupID]
	if cg == nil {
		cg = &ContainerGraph{
			CgroupID: event.CgroupID,
			Nodes:    make(map[string]*Node),
		}
		g.containers[event.CgroupID] = cg
	}
	cg.LastSeen = now

	for _, techID := range techniques {
		tech, ok := TechniqueDB[techID]
		if !ok {
			continue
		}

		node := cg.Nodes[techID]
		if node == nil {
			node = &Node{
				TechniqueID: techID,
				Name:        tech.Name,
				Tactic:      tech.Tactic,
				FirstSeen:   now,
			}
			cg.Nodes[techID] = node
		}
		node.Count++
		node.LastSeen = now

		g.addKillChainEdges(cg, techID, now)
	}
}

// GetContainer returns the attack graph for a specific container.
func (g *Graph) GetContainer(cgroupID uint64) *ContainerGraph {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.containers[cgroupID]
}

// Containers returns all tracked container cgroup IDs.
func (g *Graph) Containers() []uint64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	ids := make([]uint64, 0, len(g.containers))
	for id := range g.containers {
		ids = append(ids, id)
	}
	return ids
}

// Summary returns a global summary across all containers.
type GraphSummary struct {
	ContainerCount   int            `json:"container_count"`
	TechniqueCount   int            `json:"technique_count"`
	TacticCoverage   map[Tactic]int `json:"tactic_coverage"`
	HighestProgression int          `json:"highest_progression"`
}

func (g *Graph) Summary() *GraphSummary {
	g.mu.RLock()
	defer g.mu.RUnlock()

	allTechniques := make(map[string]bool)
	tacticCoverage := make(map[Tactic]int)
	highestProg := 0

	for _, cg := range g.containers {
		maxIdx := 0
		for _, node := range cg.Nodes {
			allTechniques[node.TechniqueID] = true
			tacticCoverage[node.Tactic]++
			idx := TacticIndex(node.Tactic)
			if idx > maxIdx {
				maxIdx = idx
			}
		}
		if maxIdx > highestProg {
			highestProg = maxIdx
		}
	}

	return &GraphSummary{
		ContainerCount:     len(g.containers),
		TechniqueCount:     len(allTechniques),
		TacticCoverage:     tacticCoverage,
		HighestProgression: highestProg,
	}
}

// Remove deletes a container's attack graph.
func (g *Graph) Remove(cgroupID uint64) {
	g.mu.Lock()
	delete(g.containers, cgroupID)
	g.mu.Unlock()
}

func (g *Graph) addKillChainEdges(cg *ContainerGraph, newTechID string, now time.Time) {
	newTech, ok := TechniqueDB[newTechID]
	if !ok {
		return
	}
	newIdx := TacticIndex(newTech.Tactic)

	for techID, node := range cg.Nodes {
		if techID == newTechID {
			continue
		}
		existingIdx := TacticIndex(node.Tactic)

		if existingIdx < newIdx {
			g.addOrUpdateEdge(cg, techID, newTechID, now)
		} else if existingIdx > newIdx {
			g.addOrUpdateEdge(cg, newTechID, techID, now)
		}
	}
}

func (g *Graph) addOrUpdateEdge(cg *ContainerGraph, from, to string, now time.Time) {
	for _, edge := range cg.Edges {
		if edge.From == from && edge.To == to {
			edge.Weight++
			edge.LastSeen = now
			return
		}
	}
	cg.Edges = append(cg.Edges, &Edge{
		From:     from,
		To:       to,
		Weight:   1,
		LastSeen: now,
	})
}
