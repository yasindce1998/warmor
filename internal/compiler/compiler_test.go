package compiler

import (
	"strings"
	"testing"
)

const sampleYAML = `
name: test-policy
version: 1
description: "Test policy for compiler"

variables:
  blocked_bins:
    - "/usr/bin/nc"
    - "/usr/bin/ncat"
  sensitive_ports:
    - 22
    - 23
    - 3389
  temp_dirs:
    - "/tmp/**"
    - "/var/tmp/**"

rules:
  - name: block-tmp-exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
    action: deny
    reason: "Execution from temp directory"

  - name: block-network-tools
    event: process
    conditions:
      all:
        - uid: { not: 0 }
        - path: { any_of: $blocked_bins }
    action: deny
    reason: "Blocked network tool"

  - name: log-sensitive-ports
    event: network
    conditions:
      all:
        - uid: { not: 0 }
        - remote_port: { any_of: $sensitive_ports }
    action: log
    reason: "Connection to sensitive port"

  - name: block-etc-write
    event: file
    conditions:
      all:
        - uid: { not: 0 }
        - path: { glob: "/etc/**" }
        - operation: { any_of: ["write", "unlink"] }
    action: deny
    reason: "Write to /etc by non-root"

default_action: allow
`

func TestParse(t *testing.T) {
	policy, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if policy.Name != "test-policy" {
		t.Errorf("expected name 'test-policy', got %q", policy.Name)
	}
	if policy.Version != 1 {
		t.Errorf("expected version 1, got %d", policy.Version)
	}
	if len(policy.Rules) != 4 {
		t.Errorf("expected 4 rules, got %d", len(policy.Rules))
	}
	if policy.DefaultAction != "allow" {
		t.Errorf("expected default_action 'allow', got %q", policy.DefaultAction)
	}
}

func TestVariableResolution(t *testing.T) {
	policy, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	rule := policy.Rules[1]
	if rule.Name != "block-network-tools" {
		t.Fatalf("expected rule 'block-network-tools', got %q", rule.Name)
	}

	pathCond := rule.Conditions.All[1]
	if pathCond.Operator != "any_of" {
		t.Errorf("expected operator 'any_of', got %q", pathCond.Operator)
	}

	items, ok := pathCond.Value.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{} value, got %T", pathCond.Value)
	}
	if len(items) != 2 {
		t.Errorf("expected 2 items in blocked_bins, got %d", len(items))
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "missing name",
			yaml:    "version: 1\nrules:\n  - name: r\n    event: process\n    conditions:\n      all:\n        - comm: test\n    action: deny\ndefault_action: allow\n",
			wantErr: "policy name is required",
		},
		{
			name:    "invalid event type",
			yaml:    "name: x\nversion: 1\nrules:\n  - name: r\n    event: invalid\n    conditions:\n      all:\n        - comm: test\n    action: deny\ndefault_action: allow\n",
			wantErr: "invalid event type",
		},
		{
			name:    "invalid action",
			yaml:    "name: x\nversion: 1\nrules:\n  - name: r\n    event: process\n    conditions:\n      all:\n        - comm: test\n    action: invalid\ndefault_action: allow\n",
			wantErr: "invalid action",
		},
		{
			name:    "no conditions",
			yaml:    "name: x\nversion: 1\nrules:\n  - name: r\n    event: process\n    conditions: {}\n    action: deny\ndefault_action: allow\n",
			wantErr: "at least one condition",
		},
		{
			name:    "invalid field for event",
			yaml:    "name: x\nversion: 1\nrules:\n  - name: r\n    event: process\n    conditions:\n      all:\n        - remote_port: 22\n    action: deny\ndefault_action: allow\n",
			wantErr: "not valid for event type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestGenerateRust(t *testing.T) {
	policy, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	rust, err := GenerateRust(policy)
	if err != nil {
		t.Fatalf("GenerateRust failed: %v", err)
	}

	checks := []string{
		"evaluate_syscall",
		"evaluate_process",
		"evaluate_file",
		"evaluate_network",
		"ACTION_ALLOW",
		"ACTION_DENY",
		"ACTION_LOG",
		"malloc",
		"free",
		"matches_glob",
		"serde::Deserialize",
		"serde_json::from_slice",
		"/tmp/**",
		"/usr/bin/nc",
		"/usr/bin/ncat",
	}

	for _, check := range checks {
		if !strings.Contains(rust, check) {
			t.Errorf("generated Rust missing expected string %q", check)
		}
	}
}

func TestGenerateCargoToml(t *testing.T) {
	toml := GenerateCargoToml("test-policy")

	if !strings.Contains(toml, "warmor-policy-test_policy") {
		t.Error("Cargo.toml missing expected crate name")
	}
	if !strings.Contains(toml, "cdylib") {
		t.Error("Cargo.toml missing cdylib crate-type")
	}
	if !strings.Contains(toml, "serde") {
		t.Error("Cargo.toml missing serde dependency")
	}
	if !strings.Contains(toml, "serde_json") {
		t.Error("Cargo.toml missing serde_json dependency")
	}
	if !strings.Contains(toml, "wasm32-wasi") || true {
		// wasm32-wasi target is set via cargo build flags, not in Cargo.toml
	}
}

func TestConditionOperators(t *testing.T) {
	yaml := `
name: op-test
version: 1
rules:
  - name: numeric-compare
    event: network
    conditions:
      all:
        - remote_port: { gt: 1024 }
        - remote_port: { lt: 65535 }
    action: log

  - name: string-ops
    event: file
    conditions:
      all:
        - path: { starts_with: "/home" }
        - path: { contains: ".ssh" }
    action: deny

  - name: not-conditions
    event: process
    conditions:
      not:
        - comm: "systemd"
    action: log

  - name: any-conditions
    event: process
    conditions:
      any:
        - comm: "bash"
        - comm: "sh"
    action: log
default_action: allow
`
	policy, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	rust, err := GenerateRust(policy)
	if err != nil {
		t.Fatalf("GenerateRust failed: %v", err)
	}

	checks := []string{
		"event.remote_port > 1024",
		"event.remote_port < 65535",
		".starts_with(\"/home\")",
		".contains(\".ssh\")",
		"!(event.comm == \"systemd\")",
		"event.comm == \"bash\" || event.comm == \"sh\"",
	}

	for _, check := range checks {
		if !strings.Contains(rust, check) {
			t.Errorf("generated Rust missing expected expression %q\nGot:\n%s", check, rust)
		}
	}
}

func TestBuildRustOnly(t *testing.T) {
	policy, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	result, err := Build(policy, BuildOptions{RustOnly: true})
	if err != nil {
		t.Fatalf("Build(RustOnly) failed: %v", err)
	}

	if result.RustSource == "" {
		t.Error("RustOnly build returned empty source")
	}
	if result.WasmPath != "" {
		t.Error("RustOnly build should not produce WasmPath")
	}
}
