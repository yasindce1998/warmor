package policyserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Server is the central policy management HTTP server.
type Server struct {
	store      *Store
	rollouts   *RolloutManager
	httpServer *http.Server
	addr       string
	staleCheck time.Duration
}

// ServerConfig configures the policy management server.
type ServerConfig struct {
	Addr           string
	StaleThreshold time.Duration
}

// NewServer creates a policy management server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}
	if cfg.StaleThreshold <= 0 {
		cfg.StaleThreshold = 90 * time.Second
	}

	store := NewStore()
	s := &Server{
		store:      store,
		rollouts:   NewRolloutManager(store),
		addr:       cfg.Addr,
		staleCheck: cfg.StaleThreshold,
	}

	mux := http.NewServeMux()

	// Agent-facing endpoints
	mux.HandleFunc("/api/v1/register", s.handleRegister)
	mux.HandleFunc("/api/v1/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/v1/policy", s.handleGetPolicy)
	mux.HandleFunc("/api/v1/policy/wasm", s.handleGetWASM)

	// Admin endpoints
	mux.HandleFunc("/api/v1/admin/policies", s.handleAdminPolicies)
	mux.HandleFunc("/api/v1/admin/policies/", s.handleAdminPolicy)
	mux.HandleFunc("/api/v1/admin/agents", s.handleAdminAgents)
	mux.HandleFunc("/api/v1/admin/rollouts", s.handleAdminRollouts)
	mux.HandleFunc("/api/v1/admin/rollouts/", s.handleAdminRollout)

	s.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Store returns the underlying store for direct manipulation in tests.
func (s *Server) Store() *Store {
	return s.store
}

// Rollouts returns the rollout manager.
func (s *Server) Rollouts() *RolloutManager {
	return s.rollouts
}

// Start begins listening and serving. Blocks until shutdown.
func (s *Server) Start() error {
	go s.staleLoop()
	log.Printf("policy server listening on %s", s.addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) staleLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.store.MarkStaleAgents(s.staleCheck)
	}
}

// --- Agent endpoints ---

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	agent := s.store.RegisterAgent(&req)
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.store.Heartbeat(req.AgentID, req.PolicyVersion); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Return the agent's current policy assignment via rollout-aware resolution
	agent, _ := s.store.GetAgent(req.AgentID)
	assignment := s.rollouts.ResolvePolicy(req.AgentID, agent.Labels)
	if assignment == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "policy": "none"})
		return
	}
	writeJSON(w, http.StatusOK, assignment)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}

	agent, ok := s.store.GetAgent(agentID)
	if !ok {
		http.Error(w, "agent not registered", http.StatusNotFound)
		return
	}

	assignment := s.rollouts.ResolvePolicy(agentID, agent.Labels)
	if assignment == nil {
		http.Error(w, "no matching policy", http.StatusNotFound)
		return
	}

	// Version-based long-poll: if agent already has this version, return 304
	ifVersion := r.URL.Query().Get("if_version")
	if ifVersion != "" {
		var v int64
		fmt.Sscanf(ifVersion, "%d", &v)
		if v >= assignment.Version {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	writeJSON(w, http.StatusOK, assignment)
}

func (s *Server) handleGetWASM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	policyID := r.URL.Query().Get("policy_id")
	if policyID == "" {
		http.Error(w, "policy_id required", http.StatusBadRequest)
		return
	}

	data, ok := s.store.GetWASM(policyID)
	if !ok {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/wasm")
	w.Write(data)
}

// --- Admin endpoints ---

func (s *Server) handleAdminPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policies := s.store.ListPolicies()
		writeJSON(w, http.StatusOK, policies)

	case http.MethodPost:
		var p Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if p.ID == "" || p.WASMPath == "" {
			http.Error(w, "id and wasm_path required", http.StatusBadRequest)
			return
		}
		if err := s.store.CreatePolicy(&p, p.WASMPath); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusCreated, &p)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminPolicy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/policies/")
	if id == "" {
		http.Error(w, "policy id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, ok := s.store.GetPolicy(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, p)

	case http.MethodPut:
		var req struct {
			WASMPath string `json:"wasm_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.store.UpdatePolicy(id, req.WASMPath); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		p, _ := s.store.GetPolicy(id)
		writeJSON(w, http.StatusOK, p)

	case http.MethodDelete:
		if err := s.store.DeletePolicy(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agents := s.store.ListAgents()
	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) handleAdminRollouts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rollouts := s.rollouts.ListRollouts()
		writeJSON(w, http.StatusOK, rollouts)

	case http.MethodPost:
		var cfg RolloutConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if cfg.ID == "" || cfg.PolicyID == "" {
			http.Error(w, "id and policy_id required", http.StatusBadRequest)
			return
		}
		state, err := s.rollouts.CreateRollout(cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusCreated, state)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminRollout(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/rollouts/")
	if id == "" {
		http.Error(w, "rollout id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		state, ok := s.rollouts.GetRollout(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, state)

	case http.MethodPut:
		var req struct {
			Percentage int `json:"percentage"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.rollouts.UpdatePercentage(id, req.Percentage); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		state, _ := s.rollouts.GetRollout(id)
		writeJSON(w, http.StatusOK, state)

	case http.MethodDelete:
		if err := s.rollouts.AbortRollout(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
