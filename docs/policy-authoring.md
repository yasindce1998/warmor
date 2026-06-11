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

## Validation

Validate a policy locally before deploying:

```bash
make policy-check POLICY=path/to/policy.yaml
```

Or with the daemon directly:

```bash
./warmor-daemon --validate-policy path/to/policy.yaml
```
