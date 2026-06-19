# Live Policy Synthesis (Learning Mode)

`warmor-learn` observes running containers in real time via the eBPF streaming pipeline and synthesizes a least-privilege policy YAML that allows only the behavior seen during the learning window.

## How It Works

```
Container Events (eBPF)
        |
        v
  Streaming Pipeline
        |
        v
    Recorder (sink)  -- records per-cgroup profiles
        |
        v
    Synthesizer      -- converts profiles to allow rules
        |
        v
   Policy YAML (deny-all-else)
```

1. **Recorder** -- implements `streaming.Sink`. For each security event it updates a `ContainerProfile` tracking execs, file accesses, network connections, binds, listens, mounts, and ptrace targets.
2. **Session** -- orchestrator that owns the recorder, runs for a configured duration (or until interrupted), then calls the synthesizer.
3. **Synthesizer** -- iterates the profile maps and emits one `allow` rule per unique behavior. Merges profiles across containers when multiple cgroup IDs are observed. Sets `default_action: deny`.

## Installation

```bash
go install github.com/yasindce1998/warmor/cmd/warmor-learn@latest
```

## CLI Usage

```bash
warmor-learn [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-duration` | `30m` | Learning window (e.g. `5m`, `1h`) |
| `-cgroup` | (all) | Comma-separated cgroup IDs to observe |
| `-o` | stdout | Output file for the generated policy YAML |
| `-name` | auto | Name field in the generated policy |
| `-version` | -- | Print version and exit |

Press Ctrl+C to stop early; the policy is generated from whatever was observed up to that point.

### Examples

```bash
# Learn for 5 minutes from a specific container, write policy to file
warmor-learn -duration 5m -cgroup 12345 -o policy.yaml

# Learn from all containers for 1 hour
warmor-learn -duration 1h -o learned.yaml

# Learn indefinitely (stop with Ctrl+C)
warmor-learn -duration 0 -o policy.yaml
```

## API Integration

The `learner` package can be embedded in the policy server or daemon:

```go
session := learner.NewSession(learner.Config{
    Duration:  5 * time.Minute,
    CgroupIDs: []uint64{12345},
    Name:      "my-app",
})

// Attach session.Recorder() to the streaming pipeline as a sink
pipeline.AddSink(session.Recorder())

// Block until duration elapses or context is cancelled
session.Run(ctx)

// Retrieve stats and policy
fmt.Println(session.Stats())
data, _ := session.MarshalPolicy()
```

## Example Workflow

```
1. Deploy:    run your workload in the cluster
2. Learn:    warmor-learn -duration 10m -cgroup <id> -o learned.yaml
3. Review:   inspect learned.yaml, remove noise, tighten rules
4. Merge:    warmor-policy-merge base.yaml learned.yaml -o final.yaml
5. Enforce:  warmor-daemon --policy final.wasm
```

## Recorded Behavior Categories

| Category | Profile Key | Example |
|----------|-------------|---------|
| Process execution | `binary path` | `/usr/bin/curl` |
| File access | `file path` | `/etc/resolv.conf` |
| Outbound connections | `proto:addr:port` | `tcp:10.0.1.5:443` |
| Socket binds | `proto:port` | `tcp:8080` |
| Socket listens | `proto:port` | `tcp:8080` |
| Mounts | `mount type` | `proc` |
| Ptrace | `target comm` | `node` |

## Tips

- **Record a full operational cycle** -- short windows miss infrequent behaviors like log rotation or cron jobs.
- **Filter by cgroup** -- targeting specific containers produces tighter policies than learning everything at once.
- **Combine with policy-gen** -- use `warmor-policy-gen` for offline audit-log analysis and `warmor-learn` for live observation; merge results with `warmor-policy-merge`.
