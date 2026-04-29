package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		want    ActionType
		wantErr bool
	}{
		{"deny lowercase", "deny", ActionDeny, false},
		{"allow lowercase", "allow", ActionAllow, false},
		{"log lowercase", "log", ActionLog, false},
		{"deny uppercase", "DENY", ActionDeny, false},
		{"allow mixed case", "Allow", ActionAllow, false},
		{"invalid action", "invalid", ActionDeny, true},
		{"empty action", "", ActionDeny, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAction(tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    PolicyRule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: PolicyRule{
				UID:     1000,
				Process: "/bin/bash",
				Action:  "deny",
				Reason:  "Test reason",
			},
			wantErr: false,
		},
		{
			name: "valid rule with root UID",
			rule: PolicyRule{
				UID:     0,
				Process: "/bin/bash",
				Action:  "deny",
				Reason:  "Root access",
			},
			wantErr: false,
		},
		{
			name: "negative UID",
			rule: PolicyRule{
				UID:     -1,
				Process: "/bin/bash",
				Action:  "deny",
			},
			wantErr: true,
		},
		{
			name: "empty process",
			rule: PolicyRule{
				UID:    1000,
				Action: "deny",
			},
			wantErr: true,
		},
		{
			name: "invalid action",
			rule: PolicyRule{
				UID:     1000,
				Process: "/bin/bash",
				Action:  "invalid",
			},
			wantErr: true,
		},
		{
			name: "missing reason (should be valid)",
			rule: PolicyRule{
				UID:     1000,
				Process: "/bin/bash",
				Action:  "allow",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("PolicyRule.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicyRule_MatchesProcess(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		processPath string
		want        bool
	}{
		{"exact match", "/bin/bash", "/bin/bash", true},
		{"no match", "/bin/bash", "/bin/sh", false},
		{"prefix wildcard", "/tmp/go-build*", "/tmp/go-build123", true},
		{"prefix wildcard no match", "/tmp/go-build*", "/tmp/other", false},
		{"suffix wildcard", "*/bash", "/usr/bin/bash", true},
		{"suffix wildcard no match", "*/bash", "/usr/bin/sh", false},
		{"contains wildcard", "*local*", "/usr/local/bin/node", true},
		{"contains wildcard no match", "*local*", "/usr/bin/node", false},
		{"prefix wildcard exact", "/tmp/go-build*", "/tmp/go-build", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := PolicyRule{Process: tt.pattern}
			if got := rule.MatchesProcess(tt.processPath); got != tt.want {
				t.Errorf("PolicyRule.MatchesProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyRule_MatchesUID(t *testing.T) {
	rule := PolicyRule{UID: 1000}

	if !rule.MatchesUID(1000) {
		t.Error("Expected UID 1000 to match")
	}

	if rule.MatchesUID(1001) {
		t.Error("Expected UID 1001 not to match")
	}
}

func TestPolicyConfig_Evaluate(t *testing.T) {
	config := &PolicyConfig{
		Policies: []PolicyRule{
			{UID: 0, Process: "/bin/bash", Action: "deny"},
			{UID: 1000, Process: "/usr/bin/python3", Action: "deny"},
			{UID: 1001, Process: "/usr/bin/node", Action: "allow"},
			{UID: 1000, Process: "/tmp/go-build*", Action: "deny"},
		},
	}

	tests := []struct {
		name        string
		uid         int
		processPath string
		wantAction  ActionType
		wantRule    bool
	}{
		{"root bash denied", 0, "/bin/bash", ActionDeny, true},
		{"user 1000 python denied", 1000, "/usr/bin/python3", ActionDeny, true},
		{"user 1001 node allowed", 1001, "/usr/bin/node", ActionAllow, true},
		{"user 1000 go-build denied", 1000, "/tmp/go-build123", ActionDeny, true},
		{"no match defaults to allow", 2000, "/bin/ls", ActionAllow, false},
		{"UID matches but process doesn't", 1000, "/bin/bash", ActionAllow, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, rule := config.Evaluate(tt.uid, tt.processPath)
			if action != tt.wantAction {
				t.Errorf("Evaluate() action = %v, want %v", action, tt.wantAction)
			}
			if (rule != nil) != tt.wantRule {
				t.Errorf("Evaluate() rule = %v, wantRule %v", rule != nil, tt.wantRule)
			}
		})
	}
}

func TestLoadPolicies(t *testing.T) {
	// Create a temporary policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-policy.yaml")

	validPolicy := `policies:
  - uid: 0
    process: "/bin/bash"
    action: "deny"
    reason: "Test policy"
  - uid: 1000
    process: "/usr/bin/python3"
    action: "allow"
    reason: "Allow python"
`

	if err := os.WriteFile(policyFile, []byte(validPolicy), 0644); err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}

	// Test loading valid policy
	config, err := LoadPolicies(policyFile)
	if err != nil {
		t.Errorf("LoadPolicies() error = %v", err)
	}
	if config == nil {
		t.Fatal("LoadPolicies() returned nil config")
	}
	if len(config.Policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(config.Policies))
	}

	// Test loading non-existent file
	_, err = LoadPolicies("/nonexistent/policy.yaml")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Test loading invalid YAML
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte("invalid: yaml: content:"), 0644); err != nil {
		t.Fatalf("Failed to create invalid policy file: %v", err)
	}
	_, err = LoadPolicies(invalidFile)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}

	// Test loading empty policies
	emptyFile := filepath.Join(tmpDir, "empty.yaml")
	if err := os.WriteFile(emptyFile, []byte("policies: []"), 0644); err != nil {
		t.Fatalf("Failed to create empty policy file: %v", err)
	}
	_, err = LoadPolicies(emptyFile)
	if err == nil {
		t.Error("Expected error for empty policies")
	}
}

func TestPolicyConfig_GetPoliciesByUID(t *testing.T) {
	config := &PolicyConfig{
		Policies: []PolicyRule{
			{UID: 1000, Process: "/bin/bash", Action: "deny"},
			{UID: 1000, Process: "/usr/bin/python3", Action: "deny"},
			{UID: 1001, Process: "/usr/bin/node", Action: "allow"},
		},
	}

	policies := config.GetPoliciesByUID(1000)
	if len(policies) != 2 {
		t.Errorf("Expected 2 policies for UID 1000, got %d", len(policies))
	}

	policies = config.GetPoliciesByUID(1001)
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy for UID 1001, got %d", len(policies))
	}

	policies = config.GetPoliciesByUID(9999)
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies for UID 9999, got %d", len(policies))
	}
}

func TestPolicyConfig_GetPoliciesByAction(t *testing.T) {
	config := &PolicyConfig{
		Policies: []PolicyRule{
			{UID: 1000, Process: "/bin/bash", Action: "deny"},
			{UID: 1000, Process: "/usr/bin/python3", Action: "deny"},
			{UID: 1001, Process: "/usr/bin/node", Action: "allow"},
			{UID: 1002, Process: "/usr/bin/gcc", Action: "log"},
		},
	}

	denyPolicies := config.GetPoliciesByAction(ActionDeny)
	if len(denyPolicies) != 2 {
		t.Errorf("Expected 2 deny policies, got %d", len(denyPolicies))
	}

	allowPolicies := config.GetPoliciesByAction(ActionAllow)
	if len(allowPolicies) != 1 {
		t.Errorf("Expected 1 allow policy, got %d", len(allowPolicies))
	}

	logPolicies := config.GetPoliciesByAction(ActionLog)
	if len(logPolicies) != 1 {
		t.Errorf("Expected 1 log policy, got %d", len(logPolicies))
	}
}

func TestPolicyConfig_Count(t *testing.T) {
	config := &PolicyConfig{
		Policies: []PolicyRule{
			{UID: 1000, Process: "/bin/bash", Action: "deny"},
			{UID: 1001, Process: "/usr/bin/node", Action: "allow"},
		},
	}

	if config.Count() != 2 {
		t.Errorf("Expected count 2, got %d", config.Count())
	}

	emptyConfig := &PolicyConfig{}
	if emptyConfig.Count() != 0 {
		t.Errorf("Expected count 0 for empty config, got %d", emptyConfig.Count())
	}
}

// Made with Bob
