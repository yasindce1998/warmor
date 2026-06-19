package policymerge

import (
	"fmt"
	"slices"
)

var validEvents = map[string]bool{"process": true, "file": true, "network": true}
var validActions = map[string]bool{"allow": true, "deny": true, "log": true}

var eventFields = map[string][]string{
	"process": {"pid", "uid", "gid", "comm", "path", "args"},
	"file":    {"pid", "uid", "gid", "comm", "path", "operation", "flags"},
	"network": {"pid", "uid", "gid", "comm", "operation", "protocol", "remote_addr", "remote_port", "local_port"},
}

func Validate(p *PolicyYAML) error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if p.Version < 1 {
		return fmt.Errorf("policy version must be >= 1")
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}
	if p.DefaultAction != "" && !validActions[p.DefaultAction] {
		return fmt.Errorf("invalid default_action %q (must be allow, deny, or log)", p.DefaultAction)
	}
	for i, r := range p.Rules {
		if err := validateRule(r, i); err != nil {
			return err
		}
	}
	return nil
}

func validateRule(r RuleYAML, idx int) error {
	if r.Name == "" {
		return fmt.Errorf("rule[%d]: name is required", idx)
	}
	if !validEvents[r.Event] {
		return fmt.Errorf("rule[%d] %q: invalid event %q (must be process, file, or network)", idx, r.Name, r.Event)
	}
	if !validActions[r.Action] {
		return fmt.Errorf("rule[%d] %q: invalid action %q (must be allow, deny, or log)", idx, r.Name, r.Action)
	}
	if r.Mode != "" && r.Mode != "enforce" && r.Mode != "audit" {
		return fmt.Errorf("rule[%d] %q: invalid mode %q (must be enforce or audit)", idx, r.Name, r.Mode)
	}
	if len(r.Conditions.All) == 0 && len(r.Conditions.Any) == 0 && len(r.Conditions.Not) == 0 {
		return fmt.Errorf("rule[%d] %q: must have at least one condition", idx, r.Name)
	}

	allowed := eventFields[r.Event]
	for _, cond := range r.Conditions.All {
		if err := validateConditionFields(cond, allowed, idx, r.Name); err != nil {
			return err
		}
	}
	for _, cond := range r.Conditions.Any {
		if err := validateConditionFields(cond, allowed, idx, r.Name); err != nil {
			return err
		}
	}
	for _, cond := range r.Conditions.Not {
		if err := validateConditionFields(cond, allowed, idx, r.Name); err != nil {
			return err
		}
	}
	return nil
}

func validateConditionFields(cond map[string]any, allowed []string, idx int, ruleName string) error {
	for field := range cond {
		if !slices.Contains(allowed, field) {
			return fmt.Errorf("rule[%d] %q: field %q is not valid for this event type", idx, ruleName, field)
		}
	}
	return nil
}
