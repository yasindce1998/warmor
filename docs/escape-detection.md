# Container Escape Detection

The escape detector correlates kernel-level security events against known container escape patterns, raising alerts (and optionally denying syscalls) when a breakout attempt is identified.

## Detected Escape Patterns

| Technique | MITRE ID | Severity | Description |
|-----------|----------|----------|-------------|
| nsenter from container | T1611.001 | Critical | Process executes `nsenter` to enter the host namespace |
| Host filesystem mount | T1611.002 | Critical | Container mounts host paths (`/`, `/etc`, `/var`, `/proc/1/root`) |
| Cross-cgroup ptrace | T1055.008 | Critical | Process attempts to ptrace a target in a different cgroup |
| /proc namespace access | T1611.003 | High | Access to `/proc/*/ns/*` indicating namespace manipulation |
| unshare + setns sequence | T1611.004 | Critical | `unshare` exec followed by namespace file access within 5 s |
| Docker socket access | T1610 | High | Read/write to `docker.sock` or `containerd.sock` |
| Sensitive binary execution | T1059.004 | High | Execution of escape tools (`runc`, `ctr`, `crictl`, `mount`, `chroot`, `capsh`, etc.) |

## How Detection Works

### Single-Step Patterns

Most patterns are single-step: one event matches one condition and immediately triggers an alert. Examples include `nsenter` execution or Docker socket access.

### Multi-Step Correlation (Sliding Window)

Some escape techniques require a sequence of operations. The detector maintains a **per-cgroup sliding window** (30-second buffer) of recent events and correlates them against multi-step patterns:

1. Each incoming event is checked against the **last step** of every multi-step pattern.
2. If the last step matches, the detector walks backward through the cgroup's event window looking for prior steps.
3. All prior steps must have occurred within the pattern's configured time window (e.g., 5 seconds for unshare + setns).
4. If every step is satisfied, an alert fires.

Events older than 30 seconds are automatically trimmed from the window.

### Event Fields Used for Matching

The detector inspects: `EventType`, `Comm`, `Filename`, `CgroupID`, `PID`, `PPID`, `UID`, `MountType`, `PtraceComm`, `RemoteAddr`, and `LocalPort`.

## Integration with Enforcer

The detector plugs into the enforcement pipeline in two ways:

**Inline enforcement** (`CheckEvent`) — called by the enforcer on every security event. When `DenyOnDetect` is enabled, the detector returns an `ActionDeny` result that blocks the syscall at the kernel level.

**Event enrichment** (`Enrich`) — tags events with `escape_technique` and `escape_name` labels for downstream consumers (logging, SIEM export, alerting dashboards).

### Configuration

```go
detector := escape.NewDetector(escape.DetectorConfig{
    Patterns:     escape.DefaultPatterns(), // or custom subset
    DenyOnDetect: true,                     // block syscall on match
    AlertCallback: func(a *escape.Alert) {
        log.Printf("escape: %s (pid=%d cgroup=%d)", a.Name, a.PID, a.CgroupID)
    },
})
```

Set `DenyOnDetect: false` to run in audit/alert-only mode without blocking.

## MITRE ATT&CK Mapping

| Warmor Technique | ATT&CK ID | ATT&CK Technique |
|------------------|-----------|-------------------|
| nsenter from container | T1611.001 | Escape to Host: nsenter |
| Host filesystem mount | T1611.002 | Escape to Host: Mount host FS |
| Cross-cgroup ptrace | T1055.008 | Process Injection: Ptrace |
| /proc namespace access | T1611.003 | Escape to Host: Namespace manipulation |
| unshare + setns sequence | T1611.004 | Escape to Host: Namespace attach |
| Docker socket access | T1610 | Deploy Container (lateral movement) |
| Sensitive binary execution | T1059.004 | Command and Scripting Interpreter |

## Tips

- **Start in audit mode** — set `DenyOnDetect: false` first to observe alerts without impacting workloads.
- **Combine with SBOM enforcement** — escape detection catches active breakout attempts while SBOM policies prevent unauthorized binaries from running in the first place.
- **Monitor alert callbacks** — feed alerts into your SIEM to correlate escape attempts with other cluster signals.
- **Custom patterns** — pass a filtered `Patterns` slice to scope detection to your threat model.
