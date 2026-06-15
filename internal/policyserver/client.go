package policyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client connects to the policy management server for policy distribution.
type Client struct {
	baseURL       string
	agentID       string
	hostname      string
	labels        map[string]string
	httpClient    *http.Client
	policyVersion int64
	mu            sync.Mutex
	onUpdate      func(assignment *PolicyAssignment, wasmData []byte)
}

// ClientConfig configures the policy server client.
type ClientConfig struct {
	ServerURL string
	AgentID   string
	Hostname  string
	Labels    map[string]string
	OnUpdate  func(assignment *PolicyAssignment, wasmData []byte)
}

// NewClient creates a policy server client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL:    cfg.ServerURL,
		agentID:    cfg.AgentID,
		hostname:   cfg.Hostname,
		labels:     cfg.Labels,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		onUpdate:   cfg.OnUpdate,
	}
}

// Register sends a registration request to the server.
func (c *Client) Register(ctx context.Context) error {
	req := RegisterRequest{
		ID:       c.agentID,
		Hostname: c.hostname,
		Labels:   c.labels,
	}

	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register: status %d", resp.StatusCode)
	}
	return nil
}

// PollLoop starts polling the server for policy updates. Blocks until ctx is cancelled.
func (c *Client) PollLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.poll(ctx)
		}
	}
}

func (c *Client) poll(ctx context.Context) {
	c.mu.Lock()
	version := c.policyVersion
	c.mu.Unlock()

	url := fmt.Sprintf("%s/api/v1/policy?agent_id=%s&if_version=%d", c.baseURL, c.agentID, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return
	}

	var assignment PolicyAssignment
	if err := json.NewDecoder(resp.Body).Decode(&assignment); err != nil {
		return
	}

	if assignment.Version <= version {
		return
	}

	// Fetch WASM binary
	wasmData, err := c.fetchWASM(ctx, assignment.PolicyID)
	if err != nil {
		return
	}

	c.mu.Lock()
	c.policyVersion = assignment.Version
	c.mu.Unlock()

	if c.onUpdate != nil {
		c.onUpdate(&assignment, wasmData)
	}
}

func (c *Client) fetchWASM(ctx context.Context, policyID string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/policy/wasm?policy_id=%s", c.baseURL, policyID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch wasm: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch wasm: status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// SendHeartbeat sends a heartbeat to the server.
func (c *Client) SendHeartbeat(ctx context.Context) error {
	c.mu.Lock()
	version := c.policyVersion
	c.mu.Unlock()

	req := HeartbeatRequest{
		AgentID:       c.agentID,
		PolicyVersion: version,
	}

	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// HeartbeatLoop sends periodic heartbeats. Blocks until ctx is cancelled.
func (c *Client) HeartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.SendHeartbeat(ctx)
		}
	}
}
