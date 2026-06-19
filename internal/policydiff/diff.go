package policydiff

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/yasindce1998/warmor/internal/policymerge"
)

type DiffResult struct {
	OnlyA []policymerge.RuleYAML
	OnlyB []policymerge.RuleYAML
	Both  []policymerge.RuleYAML
}

func Diff(a, b *policymerge.PolicyYAML) *DiffResult {
	fpA := fingerprints(a.Rules)
	fpB := fingerprints(b.Rules)

	result := &DiffResult{}

	for fp, rule := range fpA {
		if _, ok := fpB[fp]; ok {
			result.Both = append(result.Both, rule)
		} else {
			result.OnlyA = append(result.OnlyA, rule)
		}
	}
	for fp, rule := range fpB {
		if _, ok := fpA[fp]; !ok {
			result.OnlyB = append(result.OnlyB, rule)
		}
	}

	sort.Slice(result.OnlyA, func(i, j int) bool { return result.OnlyA[i].Name < result.OnlyA[j].Name })
	sort.Slice(result.OnlyB, func(i, j int) bool { return result.OnlyB[i].Name < result.OnlyB[j].Name })
	sort.Slice(result.Both, func(i, j int) bool { return result.Both[i].Name < result.Both[j].Name })

	return result
}

func fingerprints(rules []policymerge.RuleYAML) map[string]policymerge.RuleYAML {
	m := make(map[string]policymerge.RuleYAML, len(rules))
	for _, r := range rules {
		fp := fingerprint(r)
		m[fp] = r
	}
	return m
}

func fingerprint(r policymerge.RuleYAML) string {
	obj := struct {
		Event      string                    `json:"event"`
		Conditions policymerge.ConditionsYAML `json:"conditions"`
	}{Event: r.Event, Conditions: r.Conditions}
	data, _ := json.Marshal(obj)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:8])
}

func FormatSummary(r *DiffResult, nameA, nameB string) string {
	return fmt.Sprintf("Only in %s: %d rules\nOnly in %s: %d rules\nIn both:    %d rules\n",
		nameA, len(r.OnlyA), nameB, len(r.OnlyB), len(r.Both))
}

func FormatDetailed(r *DiffResult, nameA, nameB string) string {
	var b strings.Builder

	if len(r.OnlyA) > 0 {
		fmt.Fprintf(&b, "=== Only in %s (%d rules) ===\n", nameA, len(r.OnlyA))
		for _, rule := range r.OnlyA {
			fmt.Fprintf(&b, "  - [%s] %s (%s)\n", rule.Event, rule.Name, rule.Action)
		}
		b.WriteByte('\n')
	}

	if len(r.OnlyB) > 0 {
		fmt.Fprintf(&b, "=== Only in %s (%d rules) ===\n", nameB, len(r.OnlyB))
		for _, rule := range r.OnlyB {
			fmt.Fprintf(&b, "  - [%s] %s (%s)\n", rule.Event, rule.Name, rule.Action)
		}
		b.WriteByte('\n')
	}

	if len(r.Both) > 0 {
		fmt.Fprintf(&b, "=== In both (%d rules) ===\n", len(r.Both))
		for _, rule := range r.Both {
			fmt.Fprintf(&b, "  - [%s] %s (%s)\n", rule.Event, rule.Name, rule.Action)
		}
		b.WriteByte('\n')
	}

	return b.String()
}
