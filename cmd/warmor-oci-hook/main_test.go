package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInferPolicy(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  string
	}{
		{"full registry with tag", "docker.io/library/nginx:1.25", "nginx-default"},
		{"gcr with latest", "gcr.io/project/app:latest", "app-default"},
		{"simple image no tag", "nginx", "nginx-default"},
		{"registry with org", "myregistry.io/team/service", "service-default"},
		{"no tag colon at position 0", "a:tag", "a-default"},
		{"deep path", "us-docker.pkg.dev/project/repo/image:v2", "image-default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferPolicy(tt.image)
			if got != tt.want {
				t.Errorf("inferPolicy(%q) = %q, want %q", tt.image, got, tt.want)
			}
		})
	}
}

func TestHandleStart_BindsPolicy(t *testing.T) {
	var receivedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/containers/bind" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	state := ociState{
		ID:     "container-123",
		PID:    4567,
		Status: "running",
		Annotations: map[string]string{
			"io.warmor/policy": "strict-web",
		},
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handleStart(state, srv.URL, logger)

	if receivedBody == nil {
		t.Fatal("expected server to receive bind request")
	}
	if receivedBody["policy_id"] != "strict-web" {
		t.Errorf("expected policy_id=strict-web, got %v", receivedBody["policy_id"])
	}
	if receivedBody["container_id"] != "container-123" {
		t.Errorf("expected container_id=container-123, got %v", receivedBody["container_id"])
	}
}

func TestHandleStart_InfersFromImage(t *testing.T) {
	var receivedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	state := ociState{
		ID:     "container-456",
		PID:    789,
		Status: "running",
		Annotations: map[string]string{
			"io.kubernetes.container.image": "docker.io/library/redis:7",
		},
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handleStart(state, srv.URL, logger)

	if receivedBody == nil {
		t.Fatal("expected server to receive bind request")
	}
	if receivedBody["policy_id"] != "redis-default" {
		t.Errorf("expected policy_id=redis-default, got %v", receivedBody["policy_id"])
	}
}

func TestHandleStart_NoPolicyNoRequest(t *testing.T) {
	requestReceived := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	state := ociState{
		ID:          "container-789",
		PID:         100,
		Annotations: map[string]string{},
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handleStart(state, srv.URL, logger)

	if requestReceived {
		t.Error("expected no request when no policy annotation present")
	}
}

func TestHandleStart_AnnotationPriority(t *testing.T) {
	var receivedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	state := ociState{
		ID:  "container-abc",
		PID: 200,
		Annotations: map[string]string{
			"io.warmor/policy":              "explicit-policy",
			"io.kubernetes.container.image": "docker.io/library/nginx:latest",
		},
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handleStart(state, srv.URL, logger)

	if receivedBody["policy_id"] != "explicit-policy" {
		t.Errorf("io.warmor/policy should take priority, got %v", receivedBody["policy_id"])
	}
}

func TestHandleStop(t *testing.T) {
	var receivedMethod, receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	state := ociState{ID: "container-stop-test"}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handleStop(state, srv.URL, logger)

	if receivedMethod != http.MethodDelete {
		t.Errorf("expected DELETE, got %s", receivedMethod)
	}
	if receivedPath != "/api/v1/containers/container-stop-test" {
		t.Errorf("unexpected path: %s", receivedPath)
	}
}
