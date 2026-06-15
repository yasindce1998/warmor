package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newAPIClient(baseURL, token string) *apiClient {
	return &apiClient{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *apiClient) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

type agentInfo struct {
	ID            string            `json:"id"`
	Hostname      string            `json:"hostname"`
	Labels        map[string]string `json:"labels"`
	Status        string            `json:"status"`
	PolicyVersion int64             `json:"policy_version"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	RegisteredAt  time.Time         `json:"registered_at"`
}

type policyInfo struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

type rolloutInfo struct {
	ID         string `json:"id"`
	PolicyID   string `json:"policy_id"`
	Status     string `json:"status"`
	Percentage int    `json:"percentage"`
}
