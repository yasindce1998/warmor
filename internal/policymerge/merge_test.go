package policymerge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeUnionNoOverlap(t *testing.T) {
	a := &PolicyYAML{
		Name:          "sbom-policy",
		Version:       1,
		DefaultAction: "deny",
		Variables:     map[string]any{"sbom-binaries": []any{"/usr/sbin/nginx", "/usr/bin/curl"}},
		Rules: []RuleYAML{{
			Name:  "allow-sbom-binaries",
			Event: "process",
			Conditions: ConditionsYAML{
				All: []map[string]any{{"path": map[string]any{"any_of": "$sbom-binaries"}}},
			},
			Action: "allow",
		}},
	}

	b := &PolicyYAML{
		Name:          "audit-policy",
		Version:       1,
		DefaultAction: "deny",
		Variables:     map[string]any{"nginx_files": []any{"/etc/nginx/nginx.conf", "/var/log/nginx/access.log"}},
		Rules: []RuleYAML{{
			Name:  "allow-nginx-file-access",
			Event: "file",
			Conditions: ConditionsYAML{
				All: []map[string]any{
					{"comm": map[string]any{"eq": "nginx"}},
					{"path": map[string]any{"any_of": "$nginx_files"}},
				},
			},
			Action: "allow",
		}},
	}

	result, err := Merge([]*PolicyYAML{a, b}, []string{"sbom.yaml", "audit.yaml"}, MergeOptions{
		Strategy: "union",
		Annotate: true,
		Dedup:    true,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if result.Sources != 2 {
		t.Errorf("sources = %d, want 2", result.Sources)
	}
	if result.TotalRules != 2 {
		t.Errorf("total rules = %d, want 2", result.TotalRules)
	}
	if len(result.Policy.Rules) != 2 {
		t.Fatalf("merged rules = %d, want 2", len(result.Policy.Rules))
	}
	if result.Policy.Variables["sbom-binaries"] == nil {
		t.Error("missing sbom-binaries variable")
	}
	if result.Policy.Variables["nginx_files"] == nil {
		t.Error("missing nginx_files variable")
	}
	if result.Policy.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want deny", result.Policy.DefaultAction)
	}
}

func TestMergeUnionDedupIdenticalRules(t *testing.T) {
	rule := RuleYAML{
		Name:  "allow-nginx-exec",
		Event: "process",
		Conditions: ConditionsYAML{
			All: []map[string]any{
				{"comm": map[string]any{"eq": "nginx"}},
				{"path": map[string]any{"eq": "/usr/sbin/nginx"}},
			},
		},
		Action: "allow",
	}

	a := &PolicyYAML{Name: "a", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{rule}}
	b := &PolicyYAML{Name: "b", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{rule}}

	result, err := Merge([]*PolicyYAML{a, b}, []string{"a.yaml", "b.yaml"}, MergeOptions{
		Strategy: "union",
		Dedup:    true,
		Annotate: true,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if len(result.Policy.Rules) != 1 {
		t.Errorf("merged rules = %d, want 1 (deduped)", len(result.Policy.Rules))
	}
	if result.DedupedRules != 1 {
		t.Errorf("deduped = %d, want 1", result.DedupedRules)
	}
}

func TestMergeVariablesMerged(t *testing.T) {
	a := &PolicyYAML{
		Name:          "a",
		Version:       1,
		DefaultAction: "deny",
		Variables:     map[string]any{"bins": []any{"/usr/bin/a", "/usr/bin/b"}},
		Rules: []RuleYAML{{
			Name: "r1", Event: "process",
			Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/a"}}}},
			Action:     "allow",
		}},
	}
	b := &PolicyYAML{
		Name:          "b",
		Version:       1,
		DefaultAction: "deny",
		Variables:     map[string]any{"bins": []any{"/usr/bin/b", "/usr/bin/c"}},
		Rules: []RuleYAML{{
			Name: "r2", Event: "file",
			Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/b"}}}},
			Action:     "allow",
		}},
	}

	result, err := Merge([]*PolicyYAML{a, b}, nil, MergeOptions{Strategy: "union", Dedup: true})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	bins, ok := result.Policy.Variables["bins"].([]string)
	if !ok {
		t.Fatalf("bins variable type = %T, want []string", result.Policy.Variables["bins"])
	}
	if len(bins) != 3 {
		t.Errorf("bins = %v, want 3 unique entries", bins)
	}
}

func TestMergeIntersection(t *testing.T) {
	shared := RuleYAML{
		Name:  "shared-rule",
		Event: "process",
		Conditions: ConditionsYAML{
			All: []map[string]any{{"path": map[string]any{"eq": "/usr/sbin/nginx"}}},
		},
		Action: "allow",
	}
	unique := RuleYAML{
		Name:  "only-in-a",
		Event: "file",
		Conditions: ConditionsYAML{
			All: []map[string]any{{"path": map[string]any{"eq": "/tmp/foo"}}},
		},
		Action: "allow",
	}

	a := &PolicyYAML{Name: "a", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{shared, unique}}
	b := &PolicyYAML{Name: "b", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{shared}}

	result, err := Merge([]*PolicyYAML{a, b}, []string{"a.yaml", "b.yaml"}, MergeOptions{
		Strategy: "intersection",
		Annotate: true,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if len(result.Policy.Rules) != 1 {
		t.Fatalf("intersection rules = %d, want 1", len(result.Policy.Rules))
	}
	if result.Policy.Rules[0].Event != "process" {
		t.Errorf("kept rule event = %q, want process", result.Policy.Rules[0].Event)
	}
}

func TestMergeDenyWins(t *testing.T) {
	rule := RuleYAML{
		Name:  "nginx-exec",
		Event: "process",
		Conditions: ConditionsYAML{
			All: []map[string]any{{"path": map[string]any{"eq": "/usr/sbin/nginx"}}},
		},
		Action: "allow",
	}
	denyRule := rule
	denyRule.Action = "deny"

	a := &PolicyYAML{Name: "a", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{rule}}
	b := &PolicyYAML{Name: "b", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{denyRule}}

	result, err := Merge([]*PolicyYAML{a, b}, []string{"a.yaml", "b.yaml"}, MergeOptions{
		Strategy: "deny-wins",
		Annotate: true,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if len(result.Policy.Rules) != 1 {
		t.Fatalf("deny-wins rules = %d, want 1", len(result.Policy.Rules))
	}
	if result.Policy.Rules[0].Action != "deny" {
		t.Errorf("action = %q, want deny", result.Policy.Rules[0].Action)
	}
	if !strings.Contains(result.Policy.Rules[0].Reason, "deny wins") {
		t.Errorf("reason = %q, want 'deny wins' annotation", result.Policy.Rules[0].Reason)
	}
}

func TestMergeStrictestDefaultAction(t *testing.T) {
	a := &PolicyYAML{Name: "a", Version: 1, DefaultAction: "log", Rules: []RuleYAML{
		{Name: "r1", Event: "process", Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/a"}}}}, Action: "allow"},
	}}
	b := &PolicyYAML{Name: "b", Version: 1, DefaultAction: "deny", Rules: []RuleYAML{
		{Name: "r2", Event: "file", Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/b"}}}}, Action: "allow"},
	}}

	result, err := Merge([]*PolicyYAML{a, b}, nil, MergeOptions{Strategy: "union"})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if result.Policy.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want deny (strictest)", result.Policy.DefaultAction)
	}
}

func TestMergeThreePolicies(t *testing.T) {
	policies := make([]*PolicyYAML, 3)
	for i := range policies {
		policies[i] = &PolicyYAML{
			Name:          "p",
			Version:       1,
			DefaultAction: "deny",
			Rules: []RuleYAML{{
				Name:       "rule",
				Event:      "process",
				Conditions: ConditionsYAML{All: []map[string]any{{"path": map[string]any{"eq": "/bin/" + string(rune('a'+i))}}}},
				Action:     "allow",
			}},
		}
	}

	result, err := Merge(policies, nil, MergeOptions{Strategy: "union", Dedup: true})
	if err != nil {
		t.Fatalf("Merge 3 policies: %v", err)
	}
	if len(result.Policy.Rules) != 3 {
		t.Errorf("rules = %d, want 3", len(result.Policy.Rules))
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	content := `name: test-policy
version: 1
description: test
default_action: deny
rules:
  - name: allow-nginx
    event: process
    conditions:
      all:
        - path:
            eq: /usr/sbin/nginx
    action: allow
`
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.Name != "test-policy" {
		t.Errorf("name = %q, want test-policy", p.Name)
	}
	if len(p.Rules) != 1 {
		t.Errorf("rules = %d, want 1", len(p.Rules))
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()

	for i, name := range []string{"sbom.yaml", "audit.yml", "readme.txt"} {
		content := ""
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			content = "name: p" + string(rune('0'+i)) + "\nversion: 1\ndefault_action: deny\nrules:\n  - name: r\n    event: process\n    conditions:\n      all:\n        - path:\n            eq: /bin/x\n    action: allow\n"
		} else {
			content = "not a policy"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	policies, sources, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("policies = %d, want 2 (skipped .txt)", len(policies))
	}
	if len(sources) != 2 {
		t.Errorf("sources = %d, want 2", len(sources))
	}
}

func TestMergeTooFewPolicies(t *testing.T) {
	_, err := Merge([]*PolicyYAML{{Name: "a", Version: 1, DefaultAction: "deny"}}, nil, MergeOptions{})
	if err == nil {
		t.Fatal("expected error for single policy")
	}
}

func TestMarshal(t *testing.T) {
	p := &PolicyYAML{
		Name:          "test",
		Version:       1,
		DefaultAction: "deny",
		Rules: []RuleYAML{{
			Name:  "r1",
			Event: "process",
			Conditions: ConditionsYAML{
				All: []map[string]any{{"path": map[string]any{"eq": "/bin/sh"}}},
			},
			Action: "allow",
		}},
	}

	data, err := Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "name: test") {
		t.Error("missing name in output")
	}
	if !strings.Contains(out, "default_action: deny") {
		t.Error("missing default_action in output")
	}
}
