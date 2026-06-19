# Policy Diff

`warmor-policy-diff` compares two warmor policy YAML files and shows which rules are unique to each source versus confirmed by both. This is useful for understanding the overlap between SBOM-derived and audit-derived policies.

## Installation

```bash
make build-policy-diff
```

## Usage

```bash
# Compare SBOM policy vs audit policy
warmor-policy-diff sbom-policy.yaml audit-policy.yaml

# Summary only (just counts)
warmor-policy-diff --summary sbom.yaml audit.yaml

# Save output to file
warmor-policy-diff sbom.yaml audit.yaml -o diff-report.txt
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| positional args | required | Exactly 2 policy YAML files to compare |
| `-o` | stdout | Output file path |
| `--summary` | `false` | Show only summary counts instead of rule details |
| `--version` | — | Print version and exit |

## Output Format

### Detailed (default)

```
=== Only in sbom-policy.yaml (3 rules) ===
  - [process] allow-dpkg (/usr/bin/dpkg) (allow)
  - [process] allow-apt-get (allow)
  - [file] allow-dpkg-db-access (allow)

=== Only in audit-policy.yaml (2 rules) ===
  - [network] allow-apt-repo-access (allow)
  - [process] allow-cron-job (allow)

=== In both (5 rules) ===
  - [process] allow-nginx (allow)
  - [process] allow-curl (allow)
  - [file] allow-nginx-conf-read (allow)
  - [file] allow-log-write (allow)
  - [network] allow-outbound-https (allow)
```

### Summary

```
Only in sbom-policy.yaml: 3 rules
Only in audit-policy.yaml: 2 rules
In both:    5 rules
```

## How It Works

Rules are fingerprinted by `(event, conditions)` — the same algorithm used by `warmor-policy-merge`. Two rules with the same event type and conditions are considered the same rule regardless of their name or action.

This means if one policy has `action: allow` and the other has `action: deny` for the same event+conditions, they are still considered "in both" — use `warmor-policy-merge --strategy deny-wins` to resolve the conflict.

## Typical Workflow

```bash
# Generate policies from different sources
warmor-sbom-policy --rootfs ./rootfs sbom.json -o sbom-policy.yaml
warmor-policy-gen audit.ndjson -o audit-policy.yaml

# See what each source uniquely contributes
warmor-policy-diff sbom-policy.yaml audit-policy.yaml

# Rules only in SBOM = declared but never observed (dead weight?)
# Rules only in audit = observed but undeclared (supply chain risk?)
# Rules in both = high confidence allowlist

# Merge with intersection for strict mode
warmor-policy-merge --strategy intersection sbom-policy.yaml audit-policy.yaml -o strict.yaml
```
