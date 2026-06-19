# Supply Chain Integrity

`warmor-integrity-scan` builds a cryptographic allowlist of container binaries and enforces it at runtime via eBPF LSM hooks. Any exec of a tampered or undeclared binary is denied before it runs.

## Architecture

```
+---------------------+          +----------------------------+
| User Space          |          | Kernel Space (eBPF LSM)    |
|                     |          |                            |
| warmor-integrity-   |  load    | integrity_map              |
|   scan              | -------> | (path_hash -> content_hash)|
|                     |          |                            |
| Checker (runtime)   |  lookup  | bprm_check_security hook   |
|   SHA-256 verify    | <------> |   FNV-1a fast path check   |
+---------------------+          +----------------------------+
```

**User-space components** (`internal/integrity/`):

| File | Role |
|------|------|
| `hasher.go` | SHA-256 (full verification) + FNV-1a of first 4 KB (fast BPF key) |
| `scanner.go` | Walks rootfs `{,usr/}{,s}bin` dirs, builds JSON allowlist database |
| `checker.go` | Runtime exec-time verification with result caching and violation recording |

**Kernel-space**: The BPF integrity map stores FNV-1a path hashes as keys. The LSM `bprm_check_security` hook does a fast map lookup on exec; if the entry exists, user-space performs the full SHA-256 verification before allowing execution.

## CLI Usage

```bash
warmor-integrity-scan [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--rootfs` | (required) | Path to extracted container rootfs |
| `-o` | `integrity-db.json` | Output database file |
| `--verify` | — | Verify binaries against an existing database |
| `--version` | — | Print version and exit |

### Examples

```bash
# Scan a container rootfs and produce an integrity database
warmor-integrity-scan --rootfs /var/lib/containers/overlay/merged -o db.json

# Verify current binaries against a known-good baseline
warmor-integrity-scan --verify db.json --rootfs /var/lib/containers/overlay/merged
```

Verification output:

```
FAIL     /usr/bin/curl
MISSING  /usr/sbin/nginx (open: no such file)

Results: 142 passed, 1 failed, 1 missing
```

Exit code is non-zero if any binary fails or is missing.

## Integration Workflow

```
1. Build:    docker build -t myapp .
2. Export:   docker export $(docker create myapp) | tar -C ./rootfs -xf -
3. Scan:     warmor-integrity-scan --rootfs ./rootfs -o integrity-db.json
4. Deploy:   warmor-daemon --integrity-db integrity-db.json
```

At runtime the `Checker` intercepts exec events from the streaming pipeline:

- **PASS** — SHA-256 matches the database entry; execution proceeds.
- **FAIL** — hash mismatch; exec is denied with reason `integrity violation: <path> hash mismatch`.
- **UNKNOWN** — binary not in database; denied by default (configurable with `WithAllowUnknown`).

Results are cached per-path until `ClearCache()` is called (e.g., after a legitimate image update).

The `Enricher` can also annotate events with an `integrity` label for audit-mode deployments where you want visibility without enforcement.

## Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Full SHA-256 on every exec | Result cache — each path is hashed once per container lifetime |
| Large binaries | FNV-1a fast-path uses only the first 4 KB; full hash runs only when the path is in the allowlist |
| Scan time | Only walks standard executable dirs (`bin`, `sbin`, `usr/bin`, `usr/sbin`, `usr/local/bin`, `usr/local/sbin`) |
| Memory | BPF map keyed by 32-bit FNV-1a hash; user-space cache is a simple `map[string]CheckResult` |

For containers with hundreds of binaries, the initial scan completes in under a second on typical hardware. Runtime verification adds sub-millisecond latency to exec after the first invocation (cache hit path).

## Tips

- **Scan at build time** in CI so the integrity database ships alongside the image.
- **Start in audit mode** using the `Enricher` to label events before switching to enforcement.
- **Re-scan on image updates** — any base image change invalidates the database.
- **Use `WithAllowUnknown(true)`** during rollout to permit binaries not yet catalogued, then tighten once coverage is confirmed.
