# Policy Generation

`warmor-policy-gen` auto-generates allowlist policies from audit logs. Run your workload in audit mode, then generate a least-privilege policy from the observed behavior.

## Workflow

```
1. Record:   warmor-daemon --audit --event-sink=file:/tmp/audit.ndjson
2. Generate: warmor-policy-gen /tmp/audit.ndjson -o policy.yaml
3. Review:   inspect & tighten the generated policy
4. Compile:  warmor-compile policy.yaml -o policy.wasm
5. Enforce:  warmor-daemon --policy policy.wasm
```

## Installation

```bash
go install github.com/yasindce1998/warmor/cmd/warmor-policy-gen@latest
```

Or build from source:

```bash
cd cmd/warmor-policy-gen && go build -o warmor-policy-gen .
```

## Usage

```bash
warmor-policy-gen [flags] <audit-log.ndjson>
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-o` | stdout | Output YAML file path |
| `--name` | `generated-policy` | Policy name in the output |
| `--description` | auto-generated | Policy description |
| `--min-count` | `2` | Minimum observation count to include a behavior |
| `--comm-filter` | (all) | Only include events from these processes (comma-separated) |
| `--event-types` | `exec,file,network` | Event types to generate rules for |
| `--collapse-paths` | `true` | Collapse similar paths into glob patterns |
| `--network-group` | `subnet` | Network grouping: `exact`, `subnet`, or `any` |
| `--version` | — | Print version and exit |

### Examples

```bash
# Basic: generate from an audit log
warmor-policy-gen /var/log/warmor/events.ndjson

# Write to file with a custom name
warmor-policy-gen -o policy.yaml --name my-app audit.ndjson

# Filter to specific processes and require 5+ observations
warmor-policy-gen --comm-filter nginx,python3 --min-count 5 audit.ndjson

# Read from stdin (pipe from daemon or another tool)
cat audit.ndjson | warmor-policy-gen -

# Exact network addresses (no subnet grouping)
warmor-policy-gen --network-group exact audit.ndjson
```

## How It Works

### Step 1: Reading Events

The tool reads NDJSON lines produced by `warmor-daemon --event-sink=file:<path>`. Each line is a `SecurityEvent` with fields like `event_type`, `comm`, `filename`, `remote_addr`, etc. Malformed lines are skipped with a warning.

### Step 2: Behavior Aggregation

Events are deduplicated into "behavior fingerprints":

| Event Type | Fingerprint Key | Example |
|-----------|----------------|---------|
| `exec` | `(comm, filename)` | nginx executing `/usr/sbin/nginx` |
| `file` | `(comm, filename)` | nginx reading `/etc/nginx/nginx.conf` |
| `network` | `(comm, protocol, addr/subnet, port)` | curl connecting to `10.0.1.0/24:443` |

Behaviors seen fewer than `--min-count` times are discarded (filters startup noise and one-off events).

### Step 3: Path Collapsing

When `--collapse-paths` is enabled (default), similar file paths are collapsed into glob patterns:

- `/var/log/app-001.log`, `/var/log/app-002.log`, `/var/log/app-003.log` → `/var/log/app-*.log`
- `/tmp/build-abc123/main.go` → stays as-is (single occurrence)

The algorithm groups paths by parent directory. When 3+ paths in the same directory share a common prefix and suffix with only a varying middle segment, they collapse to a `*` glob.

### Step 4: Network Grouping

The `--network-group` flag controls how network connections are aggregated:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `exact` | One rule per unique `(addr, port)` | Tight lockdown, known endpoints |
| `subnet` | Collapse IPs in the same /24 | Service meshes, dynamic pod IPs |
| `any` | Group by `(protocol, port)` only | Broad network access patterns |

With `subnet` mode, addresses like `10.0.1.5`, `10.0.1.10`, `10.0.1.20` become a single rule using `starts_with: "10.0.1."`.

### Step 5: Policy Generation

The aggregated behaviors become `allow` rules in a YAML policy with `default_action: deny`:

- Single paths use `eq` operator
- Multiple paths use `any_of` with a variable reference
- Collapsed globs use the `glob` operator
- Subnet-grouped networks use `starts_with`

## Example Output

Given audit logs from an nginx workload:

```yaml
name: nginx-policy
version: 1
description: Auto-generated allowlist from audit log (1847 events observed)
variables:
  nginx-config-files:
    - /etc/nginx/conf.d/default.conf
    - /etc/nginx/mime.types
    - /etc/nginx/nginx.conf
rules:
  - name: allow-nginx-exec
    event: process
    conditions:
      all:
        - comm:
            eq: nginx
        - path:
            eq: /usr/sbin/nginx
    action: allow
    reason: Observed 12 times during audit
  - name: allow-nginx-file-access
    event: file
    conditions:
      all:
        - comm:
            eq: nginx
        - path:
            any_of: $nginx-config-files
    action: allow
    reason: Observed 47 times during audit
  - name: allow-nginx-net-tcp-443
    event: network
    conditions:
      all:
        - comm:
            eq: nginx
        - protocol:
            eq: tcp
        - remote_addr:
            starts_with: "10.0.1."
        - remote_port:
            eq: 443
    action: allow
    reason: Observed 203 times during audit
default_action: deny
```

## Refining Generated Policies

Generated policies are a starting point. Review and tighten them:

1. **Remove noise** — Delete rules for health checks or probes you don't care about
2. **Tighten globs** — Replace broad `*` patterns with more specific ones if you know the exact set
3. **Add deny rules** — Explicitly deny known-bad behaviors before the catch-all deny
4. **Set modes** — Add `mode: audit` to rules you're not confident about before enforcing
5. **Merge** — Combine generated policies from multiple recording sessions

## Tips

- **Record long enough** — Short recordings may miss infrequent but legitimate behaviors (log rotation, cron jobs). Aim for at least one full operational cycle.
- **Use `--min-count`** — Higher values (5-10) produce tighter policies but may miss legitimate infrequent operations.
- **Filter first** — Use `--comm-filter` to generate per-service policies rather than one monolithic policy.
- **Iterate** — Generate in audit mode first, review denials, re-record if needed, then enforce.
