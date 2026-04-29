package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyRule represents a single policy rule from policy.yaml
type PolicyRule struct {
	UID     int    `yaml:"uid"`
	Process string `yaml:"process"`
	Action  string `yaml:"action"`
	Reason  string `yaml:"reason"`
}

// PolicyConfig represents the entire policy configuration
type PolicyConfig struct {
	Policies []PolicyRule `yaml:"policies"`
}

// ActionType represents the policy action
type ActionType int

const (
	ActionDeny ActionType = iota
	ActionAllow
	ActionLog
)

// String returns the string representation of ActionType
func (a ActionType) String() string {
	switch a {
	case ActionDeny:
		return "deny"
	case ActionAllow:
		return "allow"
	case ActionLog:
		return "log"
	default:
		return "unknown"
	}
}

// ParseAction converts string action to ActionType
func ParseAction(action string) (ActionType, error) {
	switch strings.ToLower(action) {
	case "deny":
		return ActionDeny, nil
	case "allow":
		return ActionAllow, nil
	case "log":
		return ActionLog, nil
	default:
		return ActionDeny, fmt.Errorf("invalid action: %s (must be deny, allow, or log)", action)
	}
}

// LoadPolicies loads and validates policies from a YAML file
func LoadPolicies(path string) (*PolicyConfig, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	// Parse YAML
	var config PolicyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	// Validate policies
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}

	return &config, nil
}

// Validate checks if the policy configuration is valid
func (pc *PolicyConfig) Validate() error {
	if len(pc.Policies) == 0 {
		return fmt.Errorf("no policies defined")
	}

	for i, rule := range pc.Policies {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("policy rule %d is invalid: %w", i, err)
		}
	}

	return nil
}

// Validate checks if a single policy rule is valid
func (pr *PolicyRule) Validate() error {
	// Validate UID (allow any valid int, including 0 for root)
	if pr.UID < 0 {
		return fmt.Errorf("UID must be non-negative, got %d", pr.UID)
	}

	// Validate process path
	if pr.Process == "" {
		return fmt.Errorf("process path cannot be empty")
	}

	// Validate action
	if _, err := ParseAction(pr.Action); err != nil {
		return err
	}

	// Reason is optional but recommended
	if pr.Reason == "" {
		// Just a warning, not an error
	}

	return nil
}

// GetActionType returns the ActionType for this rule
func (pr *PolicyRule) GetActionType() ActionType {
	action, _ := ParseAction(pr.Action)
	return action
}

// MatchesUID checks if the rule applies to the given UID
func (pr *PolicyRule) MatchesUID(uid int) bool {
	return pr.UID == uid
}

// MatchesProcess checks if the rule applies to the given process path
// Supports wildcard patterns: prefix*, *suffix, *contains*
func (pr *PolicyRule) MatchesProcess(processPath string) bool {
	pattern := pr.Process

	// Exact match
	if pattern == processPath {
		return true
	}

	// Wildcard matching
	if strings.Contains(pattern, "*") {
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			// *substring* - contains
			substring := pattern[1 : len(pattern)-1]
			return strings.Contains(processPath, substring)
		} else if strings.HasPrefix(pattern, "*") {
			// *suffix - ends with
			suffix := pattern[1:]
			return strings.HasSuffix(processPath, suffix)
		} else if strings.HasSuffix(pattern, "*") {
			// prefix* - starts with
			prefix := pattern[:len(pattern)-1]
			return strings.HasPrefix(processPath, prefix)
		}
	}

	return false
}

// Evaluate evaluates the policy rules against the given UID and process path
// Returns the action and the matching rule (or nil if no match)
func (pc *PolicyConfig) Evaluate(uid int, processPath string) (ActionType, *PolicyRule) {
	for i := range pc.Policies {
		rule := &pc.Policies[i]
		if rule.MatchesUID(uid) && rule.MatchesProcess(processPath) {
			return rule.GetActionType(), rule
		}
	}

	// Default: allow if no matching rule
	return ActionAllow, nil
}

// Count returns the number of policies
func (pc *PolicyConfig) Count() int {
	return len(pc.Policies)
}

// GetPoliciesByUID returns all policies for a specific UID
func (pc *PolicyConfig) GetPoliciesByUID(uid int) []PolicyRule {
	var result []PolicyRule
	for _, rule := range pc.Policies {
		if rule.MatchesUID(uid) {
			result = append(result, rule)
		}
	}
	return result
}

// GetPoliciesByAction returns all policies with a specific action
func (pc *PolicyConfig) GetPoliciesByAction(action ActionType) []PolicyRule {
	var result []PolicyRule
	for _, rule := range pc.Policies {
		if rule.GetActionType() == action {
			result = append(result, rule)
		}
	}
	return result
}

// Made with Bob
