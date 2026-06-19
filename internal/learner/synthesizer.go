package learner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

// Synthesize converts a ContainerProfile into a PolicyYAML that allows all
// observed behavior and denies everything else.
func Synthesize(profile *ContainerProfile, name string) *policymerge.PolicyYAML {
	if name == "" {
		name = fmt.Sprintf("learned-policy-cgroup-%d", profile.CgroupID)
	}

	var rules []policymerge.RuleYAML

	rules = append(rules, synthesizeExecRules(profile.Execs)...)
	rules = append(rules, synthesizeFileRules(profile.Files)...)
	rules = append(rules, synthesizeNetworkRules(profile.Networks)...)
	rules = append(rules, synthesizeBindRules(profile.Binds)...)
	rules = append(rules, synthesizeListenRules(profile.Listens)...)
	rules = append(rules, synthesizeMountRules(profile.Mounts)...)
	rules = append(rules, synthesizePtraceRules(profile.Ptrace)...)

	return &policymerge.PolicyYAML{
		Name:          name,
		Version:       1,
		Description:   fmt.Sprintf("Auto-generated policy from observed behavior (cgroup %d)", profile.CgroupID),
		Rules:         rules,
		DefaultAction: "deny",
	}
}

// SynthesizeAll converts all profiles into a single merged policy.
func SynthesizeAll(profiles map[uint64]*ContainerProfile, name string) *policymerge.PolicyYAML {
	if name == "" {
		name = "learned-policy"
	}

	merged := newContainerProfile(0)
	for _, p := range profiles {
		for k, v := range p.Execs {
			merged.Execs[k] += v
		}
		for k, v := range p.Files {
			merged.Files[k] += v
		}
		for k, v := range p.Networks {
			merged.Networks[k] += v
		}
		for k, v := range p.Binds {
			merged.Binds[k] += v
		}
		for k, v := range p.Listens {
			merged.Listens[k] += v
		}
		for k, v := range p.Mounts {
			merged.Mounts[k] += v
		}
		for k, v := range p.Ptrace {
			merged.Ptrace[k] += v
		}
	}

	return Synthesize(merged, name)
}

func synthesizeExecRules(execs map[string]int) []policymerge.RuleYAML {
	paths := sortedKeys(execs)
	rules := make([]policymerge.RuleYAML, 0, len(paths))
	for _, path := range paths {
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-exec-%s", sanitizeName(path)),
			Event: "process",
			Conditions: policymerge.ConditionsYAML{
				All: []map[string]any{{"filename": path}},
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", execs[path]),
		})
	}
	return rules
}

func synthesizeFileRules(files map[string]int) []policymerge.RuleYAML {
	paths := sortedKeys(files)
	rules := make([]policymerge.RuleYAML, 0, len(paths))
	for _, path := range paths {
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-file-%s", sanitizeName(path)),
			Event: "file",
			Conditions: policymerge.ConditionsYAML{
				All: []map[string]any{{"filename": path}},
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", files[path]),
		})
	}
	return rules
}

func synthesizeNetworkRules(networks map[string]int) []policymerge.RuleYAML {
	keys := sortedKeys(networks)
	rules := make([]policymerge.RuleYAML, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, ":", 3)
		if len(parts) != 3 {
			continue
		}
		conds := []map[string]any{
			{"protocol": parts[0]},
			{"remote_addr": parts[1]},
			{"remote_port": parts[2]},
		}
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-connect-%s", sanitizeName(key)),
			Event: "network",
			Conditions: policymerge.ConditionsYAML{
				All: conds,
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", networks[key]),
		})
	}
	return rules
}

func synthesizeBindRules(binds map[string]int) []policymerge.RuleYAML {
	keys := sortedKeys(binds)
	rules := make([]policymerge.RuleYAML, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		conds := []map[string]any{
			{"protocol": parts[0]},
			{"local_port": parts[1]},
		}
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-bind-%s", sanitizeName(key)),
			Event: "bind",
			Conditions: policymerge.ConditionsYAML{
				All: conds,
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", binds[key]),
		})
	}
	return rules
}

func synthesizeListenRules(listens map[string]int) []policymerge.RuleYAML {
	keys := sortedKeys(listens)
	rules := make([]policymerge.RuleYAML, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		conds := []map[string]any{
			{"protocol": parts[0]},
			{"local_port": parts[1]},
		}
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-listen-%s", sanitizeName(key)),
			Event: "listen",
			Conditions: policymerge.ConditionsYAML{
				All: conds,
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", listens[key]),
		})
	}
	return rules
}

func synthesizeMountRules(mounts map[string]int) []policymerge.RuleYAML {
	keys := sortedKeys(mounts)
	rules := make([]policymerge.RuleYAML, 0, len(keys))
	for _, key := range keys {
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-mount-%s", sanitizeName(key)),
			Event: "mount",
			Conditions: policymerge.ConditionsYAML{
				All: []map[string]any{{"mount_type": key}},
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", mounts[key]),
		})
	}
	return rules
}

func synthesizePtraceRules(ptrace map[string]int) []policymerge.RuleYAML {
	keys := sortedKeys(ptrace)
	rules := make([]policymerge.RuleYAML, 0, len(keys))
	for _, key := range keys {
		rules = append(rules, policymerge.RuleYAML{
			Name:  fmt.Sprintf("allow-ptrace-%s", sanitizeName(key)),
			Event: "ptrace",
			Conditions: policymerge.ConditionsYAML{
				All: []map[string]any{{"ptrace_target_comm": key}},
			},
			Action: "allow",
			Reason: fmt.Sprintf("observed %d times during learning", ptrace[key]),
		})
	}
	return rules
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sanitizeName(s string) string {
	r := strings.NewReplacer("/", "-", ":", "-", ".", "-", " ", "-")
	name := r.Replace(s)
	if len(name) > 60 {
		name = name[:60]
	}
	return strings.Trim(name, "-")
}
