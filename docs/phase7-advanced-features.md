# Phase 7: Advanced Features

**Version:** 1.4.0-beta  
**Status:** Complete

---

## Overview

Phase 7 adds enterprise-grade security infrastructure to warmor:

1. **Stateful Policy Engine** — Track process lineage for context-aware decisions
2. **Central Policy Management Server** — Multi-agent fleet management with REST API
3. **A/B Testing Framework** — Safe canary rollouts with consistent hashing
4. **Advanced Enforcement** — Network filtering, process sandboxing
5. **SIEM Integration** — CEF-formatted event streaming to syslog collectors

---

## Central Policy Management Server

The policy server (`cmd/warmor-server`) provides centralized management for a fleet of warmor agents.

### Starting the Server

```bash
warmor-server --listen :8443 --policy-dir ./policies
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/policies` | List all policies |
| POST | `/api/v1/policies` | Create policy |
| GET | `/api/v1/policies/{name}` | Get policy by name |
| PUT | `/api/v1/policies/{name}` | Update policy |
| DELETE | `/api/v1/policies/{name}` | Delete policy |
| POST | `/api/v1/agents/register` | Register agent |
| POST | `/api/v1/agents/{id}/heartbeat` | Agent heartbeat (returns assigned policy) |
| GET | `/admin/rollouts` | List active rollouts |
| POST | `/admin/rollouts` | Create rollout |
| GET | `/admin/rollouts/{id}` | Get rollout status |
| PUT | `/admin/rollouts/{id}` | Update rollout percentage |
| DELETE | `/admin/rollouts/{id}` | Abort rollout |

### Agent Registration

Agents register with labels that are matched against policy selectors:

```bash
curl -X POST http://server:8443/api/v1/agents/register \
  -d '{"id": "agent-prod-1", "labels": {"env": "production", "team": "payments"}}'
```

---

## A/B Testing & Canary Rollouts

Rollouts use consistent hashing (SHA-256 of `rolloutID:agentID` mod 100) for deterministic bucket assignment, ensuring an agent always gets the same policy version for a given rollout.

### Creating a Rollout

```bash
curl -X POST http://server:8443/admin/rollouts \
  -d '{
    "target_policy": "network-egress-v2",
    "percentage": 10,
    "labels": {"env": "production"}
  }'
```

### Ramping Up

```bash
curl -X PUT http://server:8443/admin/rollouts/{id} \
  -d '{"percentage": 50}'
```

### How It Works

1. Agent heartbeat includes its ID and labels
2. Server calls `RolloutManager.ResolvePolicy(agentID, labels)`
3. For each active rollout matching the agent's labels, consistent hash determines bucket
4. If agent's hash falls within rollout percentage, it receives the target policy
5. Otherwise, it receives the default matched policy

---

## Network Filtering

The `NetFilter` provides two enforcement mechanisms that run **before** WASM policy evaluation for performance:

### CIDR Blocklist

Block connections to/from IP ranges:

```go
opts := &enforcer.Options{
    NetFilterConfig: &enforcer.NetFilterConfig{
        BlockCIDRs: []string{
            "10.0.0.0/8",       // internal only
            "169.254.0.0/16",   // link-local
            "fc00::/7",         // IPv6 ULA
        },
        RateLimit: 100,
        Window:    time.Minute,
    },
}
```

### Per-Process Rate Limiting

Prevent connection floods from a single process:
- Sliding window tracks connection count per PID
- When the rate limit is exceeded, all further connections from that PID are denied until the window resets
- Expired windows are cleaned up by `CleanupStale()`

### Dynamic Management

CIDRs can be added/removed at runtime:

```go
enforcer.NetFilter().AddCIDR("192.168.100.0/24")
enforcer.NetFilter().RemoveCIDR("10.0.0.0/8")
```

---

## Process Sandboxing

The `SandboxManager` tracks process restrictions and enforces sandbox violations before policy evaluation.

### Built-in Profiles

| Profile | DenyNetwork | ReadOnlyFS | IsolatePID | Blocked Syscalls |
|---------|-------------|------------|------------|------------------|
| `strict` | Yes | Yes | Yes | All caps dropped |
| `network-deny` | Yes | No | No | — |
| `readonly` | No | Yes | No | — |
| `limited` | No | No | No | ptrace, mount, reboot, kexec_load |

### Applying Sandboxes

```go
sandbox := enforcer.Sandbox()
sandbox.ApplySandbox(pid, "strict")
sandbox.ApplySandbox(pid, "network-deny")
```

### Custom Profiles

```go
sandbox.RegisterProfile(&enforcer.SandboxProfile{
    Name:            "ci-runner",
    DenyNetwork:     false,
    ReadOnlyFS:      false,
    MaxOpenFiles:    256,
    MaxProcesses:    32,
    MaxMemoryMB:     1024,
    BlockedSyscalls: []string{"ptrace", "mount", "reboot"},
    DropCaps:        []string{"SYS_ADMIN", "NET_RAW"},
})
```

### Violation Flow

When a sandboxed process attempts a restricted action:
1. `handleEvent()` calls `sandbox.CheckViolation(pid, action)`
2. If violated, the event is immediately denied with a reason like `sandbox "strict": network access denied`
3. The deny result is logged, emitted to the streaming pipeline, and counted in metrics
4. No WASM policy evaluation occurs (fast path)

---

## SIEM Integration

Events are converted to **CEF (Common Event Format)** and shipped via syslog for SIEM ingestion (Splunk, QRadar, ArcSight, Elastic SIEM).

### CEF Format

```
CEF:0|Warmor|warmor-agent|1.0|file_open|file_open_deny|8|src=node-1 dvcpid=4321 duser=1000 cs1=malware cs1Label=comm filePath=/etc/shadow msg=policy violation rt=1705313400000
```

### Syslog Sink Configuration

```go
sink, err := streaming.NewSyslogSink(streaming.SyslogConfig{
    Network:  "udp",           // "udp" or "tcp"
    Addr:     "siem.corp:514", // syslog collector address
    Facility: 1,               // LOG_USER
})

opts := &enforcer.Options{
    StreamSinks: []streaming.Sink{sink},
}
```

### CEF Severity Mapping

| Decision | CEF Severity | Syslog Priority |
|----------|-------------|-----------------|
| deny | 8 (High) | LOG_CRIT (2) |
| log/audit | 4 (Medium) | LOG_NOTICE (5) |
| allow | 1 (Low) | LOG_INFO (6) |

### CEF Extension Fields

| Field | CEF Key | Description |
|-------|---------|-------------|
| Hostname | `src` | Agent hostname |
| PID | `dvcpid` | Process ID |
| UID | `duser` | User ID |
| Comm | `cs1` | Process command |
| Filename | `filePath` | File path (if applicable) |
| Remote IP | `dst` | Destination address |
| Remote Port | `dpt` | Destination port |
| Local Port | `spt` | Source port |
| Protocol | `proto` | Network protocol |
| Reason | `msg` | Enforcement reason |
| Timestamp | `rt` | Event time (epoch ms) |

### Custom CEF Sink

For file output or testing:

```go
sink := streaming.NewCEFSink("file", func(cef string) error {
    _, err := file.WriteString(cef + "\n")
    return err
})
```

---

## Configuration Example

Full daemon configuration with all Phase 7 features:

```go
enforcer.New(ctx, "policy.yaml", &enforcer.Options{
    AuditMode:    false,
    MetricsPort:  9090,
    LSMEnforce:   true,

    // Network filtering
    NetFilterConfig: &enforcer.NetFilterConfig{
        BlockCIDRs: []string{"169.254.0.0/16", "fc00::/7"},
        RateLimit:  200,
        Window:     time.Minute,
    },

    // Custom sandbox profiles (nil = use defaults)
    SandboxProfiles: nil,

    // SIEM streaming
    StreamSinks: []streaming.Sink{
        syslogSink,
        webhookSink,
    },
    Labels: map[string]string{
        "cluster": "prod-east",
        "team":    "platform",
    },
})
```
