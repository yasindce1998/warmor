package attackgraph

import (
	"strings"
	"sync"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// MatchRule maps an event pattern to a MITRE technique.
type MatchRule struct {
	TechniqueID string
	EventType   string
	CommMatch   string
	PathMatch   string
}

// DefaultRules provides the built-in event-to-technique correlation rules.
var DefaultRules = []MatchRule{
	{TechniqueID: "T1059.004", EventType: "exec", CommMatch: "sh"},
	{TechniqueID: "T1059.004", EventType: "exec", CommMatch: "bash"},
	{TechniqueID: "T1059.004", EventType: "exec", CommMatch: "dash"},
	{TechniqueID: "T1105", EventType: "exec", CommMatch: "curl"},
	{TechniqueID: "T1105", EventType: "exec", CommMatch: "wget"},
	{TechniqueID: "T1046", EventType: "exec", CommMatch: "nmap"},
	{TechniqueID: "T1046", EventType: "network", PathMatch: "scan"},
	{TechniqueID: "T1021.004", EventType: "exec", CommMatch: "ssh"},
	{TechniqueID: "T1021.004", EventType: "network", PathMatch: ":22"},
	{TechniqueID: "T1053.003", EventType: "file", PathMatch: "/etc/crontab"},
	{TechniqueID: "T1053.003", EventType: "file", PathMatch: "/var/spool/cron"},
	{TechniqueID: "T1098", EventType: "file", PathMatch: "/etc/passwd"},
	{TechniqueID: "T1098", EventType: "file", PathMatch: "/etc/shadow"},
	{TechniqueID: "T1552.001", EventType: "file", PathMatch: ".ssh/id_rsa"},
	{TechniqueID: "T1552.001", EventType: "file", PathMatch: ".aws/credentials"},
	{TechniqueID: "T1552.001", EventType: "file", PathMatch: ".kube/config"},
	{TechniqueID: "T1611", EventType: "exec", CommMatch: "nsenter"},
	{TechniqueID: "T1611", EventType: "mount", PathMatch: "/"},
	{TechniqueID: "T1611", EventType: "file", PathMatch: "/var/run/docker.sock"},
	{TechniqueID: "T1613", EventType: "exec", CommMatch: "docker"},
	{TechniqueID: "T1613", EventType: "exec", CommMatch: "crictl"},
	{TechniqueID: "T1613", EventType: "exec", CommMatch: "kubectl"},
	{TechniqueID: "T1082", EventType: "exec", CommMatch: "uname"},
	{TechniqueID: "T1082", EventType: "file", PathMatch: "/etc/os-release"},
	{TechniqueID: "T1057", EventType: "file", PathMatch: "/proc"},
	{TechniqueID: "T1057", EventType: "exec", CommMatch: "ps"},
	{TechniqueID: "T1049", EventType: "exec", CommMatch: "netstat"},
	{TechniqueID: "T1049", EventType: "exec", CommMatch: "ss"},
	{TechniqueID: "T1083", EventType: "exec", CommMatch: "find"},
	{TechniqueID: "T1083", EventType: "exec", CommMatch: "ls"},
	{TechniqueID: "T1070.004", EventType: "exec", CommMatch: "rm"},
	{TechniqueID: "T1070.004", EventType: "exec", CommMatch: "shred"},
	{TechniqueID: "T1496", EventType: "exec", CommMatch: "xmrig"},
	{TechniqueID: "T1496", EventType: "exec", CommMatch: "minerd"},
	{TechniqueID: "T1489", EventType: "exec", CommMatch: "kill"},
	{TechniqueID: "T1489", EventType: "exec", CommMatch: "systemctl"},
	{TechniqueID: "T1548.001", EventType: "exec", PathMatch: "chmod +s"},
	{TechniqueID: "T1055", EventType: "ptrace"},
	{TechniqueID: "T1543.002", EventType: "file", PathMatch: "/etc/systemd"},
}

// Correlator maps security events to MITRE ATT&CK techniques.
type Correlator struct {
	mu    sync.RWMutex
	rules []MatchRule
}

// NewCorrelator creates a correlator with default rules.
func NewCorrelator() *Correlator {
	return &Correlator{
		rules: DefaultRules,
	}
}

// NewCorrelatorWithRules creates a correlator with custom rules.
func NewCorrelatorWithRules(rules []MatchRule) *Correlator {
	return &Correlator{
		rules: rules,
	}
}

// Correlate returns all matching technique IDs for the given event.
func (c *Correlator) Correlate(event *streaming.SecurityEvent) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	seen := make(map[string]bool)
	var techniques []string

	for _, rule := range c.rules {
		if c.matches(rule, event) {
			if !seen[rule.TechniqueID] {
				seen[rule.TechniqueID] = true
				techniques = append(techniques, rule.TechniqueID)
			}
		}
	}

	return techniques
}

// Enrich adds MITRE technique labels to the event (implements streaming.Enricher pattern).
func (c *Correlator) Enrich(event *streaming.SecurityEvent) {
	techniques := c.Correlate(event)
	if len(techniques) == 0 {
		return
	}

	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["mitre_techniques"] = strings.Join(techniques, ",")

	if len(techniques) > 0 {
		if tech, ok := TechniqueDB[techniques[0]]; ok {
			event.Labels["mitre_tactic"] = string(tech.Tactic)
		}
	}
}

func (c *Correlator) matches(rule MatchRule, event *streaming.SecurityEvent) bool {
	if rule.EventType != "" && rule.EventType != event.EventType {
		return false
	}

	if rule.CommMatch != "" && rule.CommMatch != event.Comm {
		return false
	}

	if rule.PathMatch != "" {
		target := event.Filename
		if target == "" {
			target = event.RemoteAddr
		}
		if !strings.Contains(target, rule.PathMatch) {
			return false
		}
	}

	return true
}
