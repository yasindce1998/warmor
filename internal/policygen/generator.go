package policygen

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type GenerateOptions struct {
	PolicyName  string
	Description string
}

type PolicyYAML struct {
	Name          string                 `yaml:"name"`
	Version       int                    `yaml:"version"`
	Description   string                 `yaml:"description"`
	Variables     map[string]any `yaml:"variables,omitempty"`
	Rules         []RuleYAML             `yaml:"rules"`
	DefaultAction string                 `yaml:"default_action"`
}

type RuleYAML struct {
	Name       string                            `yaml:"name"`
	Event      string                            `yaml:"event"`
	Conditions ConditionsYAML                    `yaml:"conditions"`
	Action     string                            `yaml:"action"`
	Reason     string                            `yaml:"reason,omitempty"`
}

type ConditionsYAML struct {
	All []map[string]any `yaml:"all"`
}

func Generate(result *AggregateResult, opts GenerateOptions) ([]byte, error) {
	if opts.PolicyName == "" {
		opts.PolicyName = "generated-policy"
	}
	if opts.Description == "" {
		opts.Description = fmt.Sprintf("Auto-generated allowlist from audit log (%d events observed)", result.TotalEvents)
	}

	policy := &PolicyYAML{
		Name:          opts.PolicyName,
		Version:       1,
		Description:   opts.Description,
		DefaultAction: "deny",
	}

	variables := make(map[string]any)
	var rules []RuleYAML

	grouped := groupByCommAndType(result.Behaviors)

	for _, group := range grouped {
		groupRules := generateRulesForGroup(group, variables)
		rules = append(rules, groupRules...)
	}

	if len(variables) > 0 {
		policy.Variables = variables
	}
	policy.Rules = rules

	return yaml.Marshal(policy)
}

type behaviorGroup struct {
	Comm      string
	EventType string
	Behaviors []*Behavior
}

func groupByCommAndType(behaviors []*Behavior) []behaviorGroup {
	type groupKey struct {
		Comm      string
		EventType string
	}

	groupMap := make(map[groupKey][]*Behavior)
	var keys []groupKey

	for _, b := range behaviors {
		k := groupKey{Comm: b.Comm, EventType: b.EventType}
		if _, exists := groupMap[k]; !exists {
			keys = append(keys, k)
		}
		groupMap[k] = append(groupMap[k], b)
	}

	var groups []behaviorGroup
	for _, k := range keys {
		groups = append(groups, behaviorGroup{
			Comm:      k.Comm,
			EventType: k.EventType,
			Behaviors: groupMap[k],
		})
	}
	return groups
}

func generateRulesForGroup(group behaviorGroup, variables map[string]any) []RuleYAML {
	event := mapEventType(group.EventType)

	switch group.EventType {
	case "exec":
		return generateExecRules(group, variables)
	case "file":
		return generateFileRules(group, variables)
	case "network":
		return generateNetworkRules(group, event)
	default:
		return nil
	}
}

func generateExecRules(group behaviorGroup, variables map[string]any) []RuleYAML {
	var paths []string
	totalCount := 0
	for _, b := range group.Behaviors {
		if p, ok := b.Fields["path"].(string); ok && p != "" {
			paths = append(paths, p)
		}
		totalCount += b.Count
	}

	if len(paths) == 0 {
		return nil
	}

	sort.Strings(paths)
	name := sanitizeName(fmt.Sprintf("allow-%s-exec", group.Comm))
	reason := fmt.Sprintf("Observed %d times during audit", totalCount)

	conditions := []map[string]any{
		{"comm": map[string]any{"eq": group.Comm}},
	}

	if len(paths) == 1 {
		conditions = append(conditions, map[string]any{
			"path": map[string]any{"eq": paths[0]},
		})
	} else {
		varName := sanitizeName(fmt.Sprintf("%s_binaries", group.Comm))
		variables[varName] = paths
		conditions = append(conditions, map[string]any{
			"path": map[string]any{"any_of": fmt.Sprintf("$%s", varName)},
		})
	}

	return []RuleYAML{{
		Name:       name,
		Event:      "process",
		Conditions: ConditionsYAML{All: conditions},
		Action:     "allow",
		Reason:     reason,
	}}
}

func generateFileRules(group behaviorGroup, variables map[string]any) []RuleYAML {
	var allPaths []string
	totalCount := 0
	for _, b := range group.Behaviors {
		totalCount += b.Count
		if collapsed, ok := b.Fields["collapsed_paths"]; ok {
			switch v := collapsed.(type) {
			case string:
				allPaths = append(allPaths, v)
			case []string:
				allPaths = append(allPaths, v...)
			}
		} else if p, ok := b.Fields["path"].(string); ok && p != "" {
			allPaths = append(allPaths, p)
		}
	}

	if len(allPaths) == 0 {
		return nil
	}

	allPaths = dedup(allPaths)
	sort.Strings(allPaths)

	var globs, literals []string
	for _, p := range allPaths {
		if strings.Contains(p, "*") {
			globs = append(globs, p)
		} else {
			literals = append(literals, p)
		}
	}

	var rules []RuleYAML

	for _, g := range globs {
		name := sanitizeName(fmt.Sprintf("allow-%s-file-%s", group.Comm, shortPath(g)))
		conditions := []map[string]any{
			{"comm": map[string]any{"eq": group.Comm}},
			{"path": map[string]any{"glob": g}},
		}
		rules = append(rules, RuleYAML{
			Name:       name,
			Event:      "file",
			Conditions: ConditionsYAML{All: conditions},
			Action:     "allow",
			Reason:     fmt.Sprintf("Pattern-collapsed from audit (%d events)", totalCount),
		})
	}

	if len(literals) > 0 {
		name := sanitizeName(fmt.Sprintf("allow-%s-file-access", group.Comm))
		conditions := []map[string]any{
			{"comm": map[string]any{"eq": group.Comm}},
		}

		if len(literals) == 1 {
			conditions = append(conditions, map[string]any{
				"path": map[string]any{"eq": literals[0]},
			})
		} else {
			varName := sanitizeName(fmt.Sprintf("%s_files", group.Comm))
			variables[varName] = literals
			conditions = append(conditions, map[string]any{
				"path": map[string]any{"any_of": fmt.Sprintf("$%s", varName)},
			})
		}

		rules = append(rules, RuleYAML{
			Name:       name,
			Event:      "file",
			Conditions: ConditionsYAML{All: conditions},
			Action:     "allow",
			Reason:     fmt.Sprintf("Observed %d times during audit", totalCount),
		})
	}

	return rules
}

func generateNetworkRules(group behaviorGroup, _ string) []RuleYAML {
	var rules []RuleYAML

	for _, b := range group.Behaviors {
		conditions := []map[string]any{
			{"comm": map[string]any{"eq": group.Comm}},
		}

		if proto, ok := b.Fields["protocol"].(string); ok && proto != "" {
			conditions = append(conditions, map[string]any{
				"protocol": map[string]any{"eq": proto},
			})
		}

		if addr, ok := b.Fields["remote_addr"].(string); ok && addr != "" {
			conditions = append(conditions, map[string]any{
				"remote_addr": map[string]any{"eq": addr},
			})
		} else if subnet, ok := b.Fields["remote_subnet"].(string); ok && subnet != "" {
			prefix := strings.TrimSuffix(subnet, ".0/24")
			conditions = append(conditions, map[string]any{
				"remote_addr": map[string]any{"starts_with": prefix + "."},
			})
		}

		if port, ok := b.Fields["remote_port"].(uint16); ok && port > 0 {
			conditions = append(conditions, map[string]any{
				"remote_port": map[string]any{"eq": port},
			})
		}

		if lp, ok := b.Fields["local_port"].(uint16); ok && lp > 0 {
			conditions = append(conditions, map[string]any{
				"local_port": map[string]any{"eq": lp},
			})
		}

		proto := ""
		if p, ok := b.Fields["protocol"].(string); ok {
			proto = p
		}
		port := ""
		if p, ok := b.Fields["remote_port"].(uint16); ok && p > 0 {
			port = fmt.Sprintf("-%d", p)
		}
		name := sanitizeName(fmt.Sprintf("allow-%s-net-%s%s", group.Comm, proto, port))

		rules = append(rules, RuleYAML{
			Name:       name,
			Event:      "network",
			Conditions: ConditionsYAML{All: conditions},
			Action:     "allow",
			Reason:     fmt.Sprintf("Observed %d times during audit", b.Count),
		})
	}

	return rules
}

func mapEventType(t string) string {
	switch t {
	case "exec":
		return "process"
	case "file":
		return "file"
	case "network":
		return "network"
	default:
		return t
	}
}

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

func shortPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) <= 2 {
		return strings.ReplaceAll(p, "/", "")
	}
	last := parts[len(parts)-1]
	if last == "**" || last == "*" {
		if len(parts) >= 3 {
			return parts[len(parts)-2]
		}
	}
	return strings.TrimSuffix(last, ".*")
}

func dedup(items []string) []string {
	seen := make(map[string]bool, len(items))
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
