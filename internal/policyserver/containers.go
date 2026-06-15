package policyserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

type ContainerBinding struct {
	ContainerID string            `json:"container_id"`
	PID         int               `json:"pid"`
	PolicyID    string            `json:"policy_id"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type containerStore struct {
	mu       sync.RWMutex
	bindings map[string]*ContainerBinding
}

var containers = &containerStore{
	bindings: make(map[string]*ContainerBinding),
}

func (s *Server) handleContainerBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var binding ContainerBinding
	if err := json.NewDecoder(r.Body).Decode(&binding); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if binding.ContainerID == "" || binding.PolicyID == "" {
		http.Error(w, "container_id and policy_id required", http.StatusBadRequest)
		return
	}

	containers.mu.Lock()
	containers.bindings[binding.ContainerID] = &binding
	containers.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"status":       "bound",
		"container_id": binding.ContainerID,
		"policy_id":    binding.PolicyID,
	})
}

func (s *Server) handleContainerDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/containers/")
	if id == "" {
		http.Error(w, "container_id required", http.StatusBadRequest)
		return
	}

	containers.mu.Lock()
	delete(containers.bindings, id)
	containers.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func GetContainerPolicy(containerID string) (string, bool) {
	containers.mu.RLock()
	defer containers.mu.RUnlock()
	b, ok := containers.bindings[containerID]
	if !ok {
		return "", false
	}
	return b.PolicyID, true
}

func ListContainerBindings() []*ContainerBinding {
	containers.mu.RLock()
	defer containers.mu.RUnlock()
	out := make([]*ContainerBinding, 0, len(containers.bindings))
	for _, b := range containers.bindings {
		out = append(out, b)
	}
	return out
}
