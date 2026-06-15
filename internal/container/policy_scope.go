package container

import (
	"strings"
	"sync"
)

type PolicyBinding struct {
	PolicyID    string `json:"policy_id"`
	ContainerID string `json:"container_id"`
	Namespace   string `json:"namespace"`
	Image       string `json:"image"`
}

type PolicyScope struct {
	mu       sync.RWMutex
	bindings map[string]*PolicyBinding // container ID -> binding
}

func NewPolicyScope() *PolicyScope {
	return &PolicyScope{
		bindings: make(map[string]*PolicyBinding),
	}
}

func (ps *PolicyScope) Bind(containerID, policyID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.bindings[containerID] = &PolicyBinding{
		PolicyID:    policyID,
		ContainerID: containerID,
	}
}

func (ps *PolicyScope) BindWithInfo(info *ContainerInfo, policyID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.bindings[info.ID] = &PolicyBinding{
		PolicyID:    policyID,
		ContainerID: info.ID,
		Namespace:   info.Namespace,
		Image:       info.Image,
	}
}

func (ps *PolicyScope) Unbind(containerID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.bindings, containerID)
}

func (ps *PolicyScope) Lookup(containerID string) (string, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	b, ok := ps.bindings[containerID]
	if !ok {
		return "", false
	}
	return b.PolicyID, true
}

func (ps *PolicyScope) LookupByImage(image string) (string, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for _, b := range ps.bindings {
		if b.Image == image || matchImagePrefix(b.Image, image) {
			return b.PolicyID, true
		}
	}
	return "", false
}

func (ps *PolicyScope) LookupByNamespace(ns string) (string, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for _, b := range ps.bindings {
		if b.Namespace == ns {
			return b.PolicyID, true
		}
	}
	return "", false
}

func (ps *PolicyScope) All() []*PolicyBinding {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	out := make([]*PolicyBinding, 0, len(ps.bindings))
	for _, b := range ps.bindings {
		out = append(out, b)
	}
	return out
}

func matchImagePrefix(pattern, image string) bool {
	if prefix, ok := strings.CutSuffix(pattern, ":*"); ok {
		return strings.HasPrefix(image, prefix+":")
	}
	return false
}
