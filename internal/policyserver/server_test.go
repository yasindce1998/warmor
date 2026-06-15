package policyserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func setupTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := NewServer(ServerConfig{Addr: ":0"})
	ts := httptest.NewServer(srv.httpServer.Handler)
	return srv, ts
}

func TestRegisterAndHeartbeat(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Register agent
	body, _ := json.Marshal(RegisterRequest{
		ID:       "agent-1",
		Hostname: "node-1",
		Labels:   map[string]string{"env": "prod", "region": "us-east"},
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: status %d", resp.StatusCode)
	}

	// Verify agent exists
	agent, ok := srv.store.GetAgent("agent-1")
	if !ok {
		t.Fatal("agent not found after register")
	}
	if agent.Hostname != "node-1" {
		t.Errorf("expected hostname=node-1, got %s", agent.Hostname)
	}
	if agent.Status != AgentStatusActive {
		t.Errorf("expected status=active, got %s", agent.Status)
	}

	// Heartbeat
	hb, _ := json.Marshal(HeartbeatRequest{AgentID: "agent-1", PolicyVersion: 1})
	resp, err = http.Post(ts.URL+"/api/v1/heartbeat", "application/json", bytes.NewReader(hb))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: status %d", resp.StatusCode)
	}
}

func TestPolicyCRUD(t *testing.T) {
	_, ts := setupTestServer(t)
	defer ts.Close()

	// Create a temp WASM file
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "test.wasm")
	os.WriteFile(wasmPath, []byte("fake-wasm-binary"), 0644)

	// Create policy
	p := Policy{
		ID:       "default-deny",
		Name:     "Default Deny",
		WASMPath: wasmPath,
		Selector: map[string]string{"env": "prod"},
		Priority: 10,
	}
	body, _ := json.Marshal(p)
	resp, err := http.Post(ts.URL+"/api/v1/admin/policies", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create policy: status %d", resp.StatusCode)
	}

	// List policies
	resp, err = http.Get(ts.URL + "/api/v1/admin/policies")
	if err != nil {
		t.Fatal(err)
	}
	var policies []*Policy
	json.NewDecoder(resp.Body).Decode(&policies)
	resp.Body.Close()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Version != 1 {
		t.Errorf("expected version=1, got %d", policies[0].Version)
	}
	if policies[0].WASMHash == "" {
		t.Error("expected non-empty wasm hash")
	}

	// Get specific policy
	resp, err = http.Get(ts.URL + "/api/v1/admin/policies/default-deny")
	if err != nil {
		t.Fatal(err)
	}
	var got Policy
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.ID != "default-deny" {
		t.Errorf("expected id=default-deny, got %s", got.ID)
	}

	// Delete policy
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/policies/default-deny", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d", resp.StatusCode)
	}

	// Verify gone
	resp, _ = http.Get(ts.URL + "/api/v1/admin/policies/default-deny")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestPolicyMatching(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	// Create WASM file
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "policy.wasm")
	os.WriteFile(wasmPath, []byte("wasm-bytes"), 0644)

	// Create a policy targeting env=prod
	srv.store.CreatePolicy(&Policy{
		ID:       "prod-policy",
		Name:     "Prod Policy",
		Selector: map[string]string{"env": "prod"},
		Priority: 10,
	}, wasmPath)

	// Register an agent with matching labels
	body, _ := json.Marshal(RegisterRequest{
		ID:       "agent-prod",
		Hostname: "prod-node",
		Labels:   map[string]string{"env": "prod", "tier": "web"},
	})
	http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))

	// Get policy for agent
	resp, err := http.Get(ts.URL + "/api/v1/policy?agent_id=agent-prod")
	if err != nil {
		t.Fatal(err)
	}
	var assignment PolicyAssignment
	json.NewDecoder(resp.Body).Decode(&assignment)
	resp.Body.Close()

	if assignment.PolicyID != "prod-policy" {
		t.Errorf("expected policy=prod-policy, got %s", assignment.PolicyID)
	}
	if assignment.Version != 1 {
		t.Errorf("expected version=1, got %d", assignment.Version)
	}

	// Version-based long-poll: should return 304 if agent already has version 1
	resp, err = http.Get(ts.URL + "/api/v1/policy?agent_id=agent-prod&if_version=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", resp.StatusCode)
	}

	// No matching policy for non-prod agent
	body, _ = json.Marshal(RegisterRequest{
		ID:       "agent-dev",
		Hostname: "dev-node",
		Labels:   map[string]string{"env": "dev"},
	})
	http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))

	resp, _ = http.Get(ts.URL + "/api/v1/policy?agent_id=agent-dev")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for non-matching agent, got %d", resp.StatusCode)
	}
}

func TestWASMDownload(t *testing.T) {
	srv, ts := setupTestServer(t)
	defer ts.Close()

	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "test.wasm")
	wasmContent := []byte{0x00, 0x61, 0x73, 0x6d} // WASM magic bytes
	os.WriteFile(wasmPath, wasmContent, 0644)

	srv.store.CreatePolicy(&Policy{
		ID:   "my-policy",
		Name: "Test",
	}, wasmPath)

	resp, err := http.Get(ts.URL + "/api/v1/policy/wasm?policy_id=my-policy")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/wasm" {
		t.Errorf("expected content-type=application/wasm, got %s", resp.Header.Get("Content-Type"))
	}

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if !bytes.Equal(buf.Bytes(), wasmContent) {
		t.Error("wasm content mismatch")
	}
}
