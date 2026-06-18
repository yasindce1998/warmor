package sbompolicy

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type GenerateOptions struct {
	PolicyName          string
	Description         string
	SBOMName            string
	IncludeInterpreters bool
}

type PolicyYAML struct {
	Name          string         `yaml:"name"`
	Version       int            `yaml:"version"`
	Description   string         `yaml:"description"`
	Variables     map[string]any `yaml:"variables,omitempty"`
	Rules         []RuleYAML     `yaml:"rules"`
	DefaultAction string         `yaml:"default_action"`
}

type RuleYAML struct {
	Name       string         `yaml:"name"`
	Event      string         `yaml:"event"`
	Conditions ConditionsYAML `yaml:"conditions"`
	Action     string         `yaml:"action"`
	Reason     string         `yaml:"reason,omitempty"`
}

type ConditionsYAML struct {
	All []map[string]any `yaml:"all"`
}

var defaultInterpreters = []string{
	"/usr/bin/python3",
	"/usr/bin/python",
	"/usr/bin/node",
	"/usr/bin/ruby",
	"/usr/bin/perl",
	"/usr/bin/sh",
	"/usr/bin/bash",
	"/bin/sh",
	"/bin/bash",
}

func Generate(files []ResolvedFile, opts GenerateOptions) ([]byte, error) {
	if opts.PolicyName == "" {
		if opts.SBOMName != "" {
			opts.PolicyName = sanitizeName(opts.SBOMName + "-sbom-policy")
		} else {
			opts.PolicyName = "sbom-policy"
		}
	}

	var binaries []string
	var libraries []string
	pkgCount := make(map[string]bool)

	for _, f := range files {
		pkgCount[f.PackageName] = true
		switch f.FileType {
		case "binary":
			binaries = append(binaries, f.Path)
		case "library":
			libraries = append(libraries, f.Path)
		}
	}

	if opts.IncludeInterpreters {
		for _, interp := range defaultInterpreters {
			if !containsStr(binaries, interp) {
				binaries = append(binaries, interp)
			}
		}
	}

	sort.Strings(binaries)
	sort.Strings(libraries)
	binaries = dedup(binaries)
	libraries = dedup(libraries)

	if opts.Description == "" {
		opts.Description = fmt.Sprintf("SBOM-derived allowlist (%d packages, %d binaries)", len(pkgCount), len(binaries))
		if opts.SBOMName != "" {
			opts.Description += fmt.Sprintf(" from %s", opts.SBOMName)
		}
	}

	policy := &PolicyYAML{
		Name:          opts.PolicyName,
		Version:       1,
		Description:   opts.Description,
		DefaultAction: "deny",
	}

	variables := make(map[string]any)
	var rules []RuleYAML

	if len(binaries) > 0 {
		varName := "sbom-binaries"
		variables[varName] = binaries
		rules = append(rules, RuleYAML{
			Name:  "allow-sbom-binaries",
			Event: "process",
			Conditions: ConditionsYAML{
				All: []map[string]any{
					{"path": map[string]any{"any_of": "$" + varName}},
				},
			},
			Action: "allow",
			Reason: fmt.Sprintf("Binary declared in SBOM (%s)", opts.SBOMName),
		})
	}

	if len(libraries) > 0 {
		varName := "sbom-libraries"
		variables[varName] = libraries
		rules = append(rules, RuleYAML{
			Name:  "allow-sbom-libraries",
			Event: "file",
			Conditions: ConditionsYAML{
				All: []map[string]any{
					{"path": map[string]any{"any_of": "$" + varName}},
				},
			},
			Action: "allow",
			Reason: fmt.Sprintf("Library declared in SBOM (%s)", opts.SBOMName),
		})
	}

	if len(variables) > 0 {
		policy.Variables = variables
	}
	policy.Rules = rules

	return yaml.Marshal(policy)
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

func containsStr(sl []string, s string) bool {
	for _, v := range sl {
		if v == s {
			return true
		}
	}
	return false
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
