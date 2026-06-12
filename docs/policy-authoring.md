# Policy Authoring Guide

Warmor policies are YAML files that define what process executions, file accesses, and network connections to allow, deny, or audit.

## Structure

```yaml
name: my-policy
version: 1
description: "What this policy enforces"

variables:
  my_list:
    - "/usr/bin/curl"
    - "/usr/bin/wget"

rules:
  - name: rule-name
    event: process | file | network
    conditions:
      all:         # AND — all must match
        - field: { operator: value }
      any:         # OR — at least one must match
        - field: { operator: value }
    action: allow | deny | audit
    reason: "Human-readable explanation"

default_action: allow | deny | audit
```

## Event Types

| Event | Description | Available Fields |
|-------|-------------|-----------------|
| `process` | Process execution (execve) | `path`, `uid`, `gid`, `comm` |
| `file` | File system access | `path`, `uid`, `operation` |
| `network` | Network connections | `uid`, `remote_port`, `remote_ip`, `protocol` |

## Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `glob` | Glob pattern match | `path: { glob: "/tmp/**" }` |
| `any_of` | Value in list | `path: { any_of: $my_list }` |
| `not` | Not equal to | `uid: { not: 0 }` |
| `equals` | Exact match | `comm: { equals: "python3" }` |
| `prefix` | String prefix | `path: { prefix: "/opt/app" }` |

## Variables

Variables let you reuse lists across rules. Reference them with `$variable_name`:

```yaml
variables:
  network_tools:
    - "/usr/bin/nc"
    - "/usr/bin/ncat"
    - "/usr/bin/curl"

rules:
  - name: block-net-tools
    event: process
    conditions:
      all:
        - path: { any_of: $network_tools }
    action: deny
```

## Actions

| Action | Audit Mode | Enforce Mode |
|--------|-----------|--------------|
| `allow` | Allow + no log | Allow + no log |
| `deny` | Allow + log | Block + log |
| `audit` | Allow + log | Allow + log |

## Tips

- Start with `default_action: allow` and explicit deny rules
- Use audit mode to validate before enforcing
- Keep rule names unique and descriptive (they appear in logs/metrics)
- Use variables for lists you reference in multiple rules
- Order rules from most specific to most general (first match wins)
- The `reason` field appears in deny logs — make it actionable

## LSM-BPF Kernel Enforcement

When running with `--lsm-enforce`, deny rules are enforced synchronously at the kernel level via LSM-BPF hooks. This means:

- **Denied exec operations return EPERM** — the process never starts
- **Denied file opens fail immediately** — the file is never accessed
- **Denied connections fail at connect()** — no network handshake occurs

### How It Works

1. The first time an event matches a deny rule, WASM evaluates it and the decision is compiled into a BPF hash map
2. On subsequent identical events, the kernel LSM hook looks up the hash map and returns `-EPERM` without any userspace round-trip
3. The hash key uses FNV-1a over the filename/pattern, scoped by cgroup ID and event type

### Policy Design for LSM

- **Glob patterns** (`/tmp/**`) are matched in userspace WASM on the first hit, then the specific filename that matched is hashed into the BPF map
- **`any_of` lists** each element is individually hashed into the map after first evaluation
- **Network rules** hash destination IP+port, so `remote_port: { any_of: [22, 4444] }` will populate map entries per observed connection
- **Cgroup scoping** — rules apply per-cgroup by default; set cgroup_id=0 in the map for global rules

### Audit vs Enforce Mode

| Flag | Behavior |
|------|----------|
| `--lsm-enforce=false` (default) | LSM programs load but never deny — all events are observed and logged |
| `--lsm-enforce=true` | LSM programs actively block denied operations in kernel |

Start with audit mode to validate your policy won't disrupt workloads, then enable enforcement.

### Requirements

- Linux kernel 5.7+ with `CONFIG_BPF_LSM=y`
- `/sys/kernel/security/lsm` must contain "bpf"
- `CAP_SYS_ADMIN` + `CAP_BPF` (or root)
- If requirements are not met, warmor falls back to tracepoint-only mode automatically

---

## Validation

Validate a policy locally before deploying:

```bash
make policy-check POLICY=path/to/policy.yaml
```

Or with the daemon directly:

```bash
./warmor-daemon --validate-policy path/to/policy.yaml
```
