package multi_test

import (
	"testing"

	policytest "github.com/yasindce1998/warmor/internal/testing"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestMultiPolicy(t *testing.T) {
	tests := []policytest.PolicyTest{
		// Process event tests
		{
			Name:     "Allow normal process execution",
			Event:    policytest.NewProcessEvent(1000, "/usr/bin/ls"),
			Expected: api.ActionAllow,
		},
		{
			Name:     "Deny root bash execution",
			Event:    policytest.NewProcessEvent(0, "/bin/bash"),
			Expected: api.ActionDeny,
		},
		{
			Name:     "Deny execution from /tmp",
			Event:    policytest.NewProcessEvent(1000, "/tmp/malware"),
			Expected: api.ActionDeny,
		},
		{
			Name:     "Log Python execution",
			Event:    policytest.NewProcessEvent(1000, "/usr/bin/python3"),
			Expected: api.ActionLog,
		},
		{
			Name:     "Deny network tools for non-root",
			Event:    policytest.NewProcessEvent(1000, "/usr/bin/nc"),
			Expected: api.ActionDeny,
		},

		// File event tests
		{
			Name:     "Log access to /etc/shadow",
			Event:    policytest.NewFileEvent(1000, "/etc/shadow", "read"),
			Expected: api.ActionLog,
		},
		{
			Name:     "Deny write to /etc by non-root",
			Event:    policytest.NewFileEvent(1000, "/etc/hosts", "write"),
			Expected: api.ActionDeny,
		},
		{
			Name:     "Allow read from /etc by non-root",
			Event:    policytest.NewFileEvent(1000, "/etc/hosts", "read"),
			Expected: api.ActionAllow,
		},
		{
			Name:     "Log access to /var/log",
			Event:    policytest.NewFileEvent(1000, "/var/log/syslog", "read"),
			Expected: api.ActionLog,
		},

		// Network event tests
		{
			Name:     "Deny SSH connection for non-root",
			Event:    policytest.NewNetworkEvent(1000, "192.168.1.100", 22),
			Expected: api.ActionDeny,
		},
		{
			Name:     "Log outbound connection",
			Event:    policytest.NewNetworkEvent(1000, "8.8.8.8", 443),
			Expected: api.ActionLog,
		},
		{
			Name:     "Allow root SSH connection",
			Event:    policytest.NewNetworkEvent(0, "192.168.1.100", 22),
			Expected: api.ActionLog, // Still logs for audit
		},
	}

	policytest.TestPolicy(t, "policy.wasm", tests)
}

func BenchmarkMultiPolicy(b *testing.B) {
	event := policytest.NewProcessEvent(1000, "/usr/bin/ls")
	policytest.BenchmarkPolicy(b, "policy.wasm", event)
}
