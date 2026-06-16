# Phase 8: Production Infrastructure

**Version:** 1.5.0-beta  
**Status:** Complete

---

## Overview

Phase 8 adds the infrastructure needed to run warmor in production at scale:

1. **mTLS & Policy Signing** — Secure agent↔server communication and tamper-proof policies
2. **warmorctl CLI** — Interactive terminal UI for fleet management
3. **Container Runtime Integration** — Per-container policy enforcement via containerd/CRI-O
4. **Enhanced Observability** — Prometheus metrics, Grafana dashboards, alerting rules

---

## mTLS & Policy Signing

### Certificate Authority

Warmor uses Ed25519 certificates for mutual TLS authentication between agents and the policy server.

```
┌────────────┐         ┌─────────────────┐         ┌──────────────┐
│   CA Key   │──signs──▶│  Server Cert    │         │  Agent Cert  │
│ (ed25519)  │         │  (warmor-server)│         │  (agent-01)  │
└────────────┘         └─────────────────┘         └──────────────┘
                              ▲                           ▲
                              │         mTLS              │
                              └───────────────────────────┘
```

**Generate certificates:**

```bash
# Via warmorctl
warmorctl certs generate --ca --out ./certs/
warmorctl certs generate --server --ca-cert ./certs/ca.crt --ca-key ./certs/ca.key --out ./certs/
warmorctl certs generate --agent --ca-cert ./certs/ca.crt --ca-key ./certs/ca.key --name agent-01 --out ./certs/

# Programmatic (Go)
ca, _ := crypto.GenerateCA()
serverCert, _ := crypto.IssueCertificate(ca, "warmor-server", crypto.ServerCert)
agentCert, _ := crypto.IssueCertificate(ca, "agent-01", crypto.AgentCert)
```

### Policy Signing

WASM policy bundles are signed with Ed25519 to prevent tampering:

```bash
# Sign a policy
warmor-server policy sign --key signing.key --policy policy.wasm --out policy.signed

# Verify on agent
warmor-daemon --verify-policy-sig --signing-pub signing.pub
```

The agent rejects any policy bundle with an invalid or missing signature when `--verify-policy-sig` is set.

### JWT Authentication

Two JWT algorithms are supported:

| Algorithm | Use Case | Key Type |
|-----------|----------|----------|
| HMAC-SHA256 | Shared-secret environments (single-team) | `[]byte` |
| EdDSA (Ed25519) | Zero-trust environments (multi-team) | `ed25519.PrivateKey` |

Tokens carry `sub` (agent ID), `role` (agent/admin), and `exp` claims.

---

## warmorctl CLI

Interactive terminal UI built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lipgloss](https://github.com/charmbracelet/lipgloss).

### Tabs

| Tab | Description |
|-----|-------------|
| **Dashboard** | Real-time event stream, deny/allow counts, latency sparklines |
| **Agents** | Connected agents with heartbeat status, labels, assigned policy |
| **Policies** | CRUD operations on fleet policies (YAML editor) |
| **Rollouts** | Create/manage A/B testing rollouts with percentage ramps |
| **Certs** | Generate and inspect mTLS certificates |

### Key Bindings

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch tabs |
| `j` / `k` | Navigate list items |
| `Enter` | Select / expand |
| `q` / `Ctrl+C` | Quit |

### Source

- `cmd/warmorctl/main.go` — Entry point
- `cmd/warmorctl/app.go` — Bubble Tea application model
- `cmd/warmorctl/dashboard.go` — Dashboard view
- `cmd/warmorctl/agents.go` — Agent management
- `cmd/warmorctl/policies.go` — Policy CRUD
- `cmd/warmorctl/rollouts.go` — Rollout management
- `cmd/warmorctl/certs.go` — Certificate generation
- `cmd/warmorctl/api.go` — HTTP client for warmor-server

---

## Container Runtime Integration

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Kubernetes Node                        │
│                                                          │
│  ┌──────────────┐      ┌─────────────────────────────┐  │
│  │  containerd  │─────▶│  warmor-daemon              │  │
│  │  (or CRI-O)  │      │  ┌─────────────────────┐    │  │
│  └──────────────┘      │  │ Container Detector   │    │  │
│                         │  │ (cgroup → container) │    │  │
│  ┌──────────────┐      │  ├─────────────────────┤    │  │
│  │ Container A  │      │  │ Policy Scope         │    │  │
│  │ policy: web  │      │  │ (container → policy) │    │  │
│  ├──────────────┤      │  └─────────────────────┘    │  │
│  │ Container B  │      └─────────────────────────────┘  │
│  │ policy: db   │                                        │
│  └──────────────┘                                        │
└─────────────────────────────────────────────────────────┘
```

### containerd Integration

The containerd monitor watches container lifecycle events via the containerd gRPC API:

```go
// internal/container/containerd_monitor.go
monitor := container.NewContainerdMonitor("/run/containerd/containerd.sock")
monitor.OnCreate(func(id, image string, labels map[string]string) {
    // Assign per-container policy based on labels
})
monitor.OnDelete(func(id string) {
    // Clean up policy scope
})
```

### CRI-O OCI Hooks

Install `deploy/crio/warmor-hook.json` to `/etc/containers/oci/hooks.d/`:

```json
{
  "version": "1.0.0",
  "hook": {
    "path": "/usr/local/bin/warmor-daemon",
    "args": ["warmor-daemon", "--oci-hook"]
  },
  "when": { "always": true },
  "stages": ["createRuntime"]
}
```

### Per-Container Policy Scoping

The `PolicyScope` maps container IDs to specific policies:

```go
// internal/container/policy_scope.go
scope := container.NewPolicyScope()
scope.Assign("container-abc123", "web-server-policy")
scope.Assign("container-def456", "database-policy")

// During evaluation, the daemon resolves:
// cgroup_id → container_id → policy_name → WASM binary
```

### Source Files

- `internal/container/detector.go` — Detects container runtime (containerd vs CRI-O)
- `internal/container/containerd_monitor.go` — containerd event watcher
- `internal/container/containerd_shim.go` — Shim plugin interface
- `internal/container/policy_scope.go` — Container→policy mapping

---

## Enhanced Observability

### Prometheus Metrics

Exported on `:9090/metrics`:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `warmor_lsm_decisions_total` | Counter | `hook`, `action` | Total LSM hook decisions |
| `warmor_lsm_decision_duration_seconds` | Histogram | `hook` | Decision latency |
| `warmor_policy_loads_total` | Counter | `policy_id`, `status` | Policy load attempts |
| `warmor_events_total` | Counter | `type`, `action` | All processed events |
| `warmor_cache_hits_total` | Counter | — | Decision cache hits |
| `warmor_cache_misses_total` | Counter | — | Decision cache misses |

### Grafana Dashboard

Pre-built dashboard at `deploy/grafana/warmor-dashboard.json`:

- **Row 1:** Event rates (allow/deny/audit) per hook type
- **Row 2:** Decision latency P50/P95/P99 over time
- **Row 3:** Policy load success/failure, cache hit ratio
- **Row 4:** Agent fleet health (heartbeats, connected count)

Auto-provisioned via Grafana sidecar or `deploy/grafana/provisioning/`.

### Alert Rules

Defined in `deploy/prometheus/alerts.yml`:

```yaml
groups:
  - name: warmor
    rules:
      - alert: WarmorHighDenyRate
        expr: rate(warmor_lsm_decisions_total{action="deny"}[5m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High deny rate on {{ $labels.instance }}"

      - alert: WarmorAgentDown
        expr: time() - warmor_agent_last_heartbeat_seconds > 300
        for: 1m
        labels:
          severity: critical

      - alert: WarmorPolicyLoadFailure
        expr: increase(warmor_policy_loads_total{status="error"}[5m]) > 0
        labels:
          severity: critical
```

### Docker Compose (Local Dev)

```bash
cd deploy/
docker compose -f docker-compose.monitoring.yml up -d
# Prometheus: http://localhost:9091
# Grafana:    http://localhost:3000 (admin/warmor)
```

---

## Kubernetes Deployment

The Helm chart includes all Phase 8 features:

```bash
helm install warmor deploy/helm/warmor \
  --namespace warmor-system --create-namespace \
  --set daemon.lsmEnforce=true \
  --set daemon.containerRuntime=containerd \
  --set daemon.perContainerPolicy=true \
  --set tls.enabled=true \
  --set tls.caSecret=warmor-ca \
  --set serviceMonitor.enabled=true \
  --set grafana.dashboardEnabled=true
```

The DaemonSet runs with:
- `privileged: true` (required for BPF)
- `hostPID: true` (process visibility)
- `hostNetwork: true` (network hook visibility)
- Volume mounts for containerd socket, BPF filesystem, policy directory
