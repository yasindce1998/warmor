# Policy Merge

`warmor-policy-merge` combines multiple warmor policy YAML files into a single unified policy. Use it to flatten SBOM-derived and audit-derived policies before compiling, or to merge any collection of policies from a directory.

## Installation

```bash
make build-policy-merge
```

## Usage

```bash
# Merge two specific policy files
warmor-policy-merge sbom-policy.yaml audit-policy.yaml -o merged.yaml

# Merge all policies in a directory
warmor-policy-merge --dir ./policies -o merged.yaml

# Combine directory + extra files
warmor-policy-merge --dir ./base-policies extra-hardening.yaml -o merged.yaml

# Strict mode: only keep rules confirmed by multiple sources
warmor-policy-merge --strategy intersection sbom.yaml audit.yaml -o strict.yaml

# Deny wins: any deny rule takes precedence over allow
warmor-policy-merge --strategy deny-wins baseline.yaml overrides.yaml -o final.yaml
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| positional args | — | Input policy YAML files to merge |
| `--dir` | — | Directory of `.yaml`/`.yml` policy files to merge |
| `-o` | stdout | Output file path |
| `--name` | `merged-policy` | Name for the merged policy |
| `--description` | auto-generated | Description for the merged policy |
| `--strategy` | `union` | Merge strategy (see below) |
| `--annotate` | `true` | Add source provenance to rule reasons |
| `--dedup` | `true` | Deduplicate identical rules and variable entries |
| `--validate` | `false` | Validate merged policy against the compiler schema |
| `--version` | — | Print version and exit |

## Merge Strategies

### `union` (default)

Keep all rules from all inputs. If both policies allow the same behavior, the duplicate is removed (when `--dedup` is enabled). This is the most permissive strategy — allow if *any* input allows.

Best for: combining SBOM + audit policies where both represent legitimate behaviors.

### `intersection`

Only keep rules whose fingerprint (event + conditions) appears in at least two source policies. Rules unique to a single source are dropped.

Best for: strict enforcement where only behaviors confirmed by multiple sources are allowed.

### `deny-wins`

Keep all unique rules, but if the same fingerprint appears with both `allow` and `deny` actions across inputs, the merged rule uses `deny`.

Best for: layering a hardening policy on top of a permissive baseline.

## How Merge Works

**Variables:** Same-named variables are merged (union of values, sorted, deduplicated). Different variable names are preserved as-is.

**Rules:** Rules are fingerprinted by `(event, conditions)`. The rule name and action are not part of the fingerprint — two rules with the same event and conditions but different names are considered duplicates.

**Default action:** The strictest `default_action` wins (`deny` > `log` > `allow`).

**Version:** Takes the maximum version number across all inputs.

**Name collisions:** If two distinct rules have the same name, a numeric suffix is added (`-2`, `-3`, etc.).

## Typical Workflow

```bash
# 1. Generate policy from SBOM
warmor-sbom-policy --rootfs ./rootfs sbom.json -o sbom-policy.yaml

# 2. Generate policy from audit logs
warmor-policy-gen audit.ndjson -o audit-policy.yaml

# 3. Merge into a single deployment policy (with validation)
warmor-policy-merge --validate sbom-policy.yaml audit-policy.yaml -o merged.yaml

# 4. Compile for enforcement
warmor-compile merged.yaml -o policy.wasm
```

## Directory Mode

Point `--dir` at a folder containing any number of `.yaml` or `.yml` policy files:

```bash
policies/
  sbom-nginx.yaml
  audit-nginx.yaml
  hardening-baseline.yaml

warmor-policy-merge --dir ./policies -o merged.yaml
```

All valid policy files in the directory are loaded and merged together. Non-YAML files are ignored. You can also combine `--dir` with positional file arguments — the directory policies are loaded first, then any additional files are appended.
