# Security Posture: Fail-Open vs Fail-Closed

For a security control, *what happens when something fails* matters as much as
what happens when everything works. This document states Warmor's behavior at
each layer explicitly, so operators can choose a posture deliberately.

## The two enforcement layers

Warmor enforces in two places, and they have **different** failure modes by
design.

### 1. Kernel fast-path (BPF-LSM)

Each LSM hook consults the kernel `policy_map`:

- **Explicit `DENY` rule present + enforce mode on** → blocked in-kernel
  (`-EPERM`).
- **No matching rule (miss)** → **allowed**, and the event is emitted to
  userspace for evaluation. This is *allow-on-miss*.
- **Failure to read the subject** (e.g. a `bpf_probe_read` returns nothing) →
  **allowed**. The kernel path deliberately fails *open* on transient read
  errors so a single unreadable argument cannot wedge every `exec`/`open` on the
  host.

> **Async gap (known limitation).** Because the kernel cannot call into the WASM
> policy synchronously, the *first* occurrence of an action that has no rule yet
> is allowed and reported; once userspace evaluates it and writes a `DENY` rule,
> *subsequent* identical actions are blocked. Warmor is therefore not a
> synchronous gate for never-before-seen actions. Mitigations: pre-seed deny
> rules for known-bad patterns, and scope enforcement to specific cgroups so the
> rule set converges quickly.

### 2. Userspace policy (WASM)

When an event reaches the WASM evaluator and evaluation **errors**, Warmor fails
**closed** — the decision becomes `DENY` (`internal/enforcer/enforcer.go`). A
broken or misbehaving policy denies rather than silently allows.

## Enforcement modes

| Mode | How to select | Behavior |
|---|---|---|
| **Observe-only** | default (no `--lsm-enforce`, or LSM unavailable), or `--no-lsm` | Events logged/evaluated; nothing blocked in-kernel. |
| **Audit** | LSM loaded, `--audit` | Would-be denials are logged (`audit` events) but not enforced. |
| **Enforce** | `--lsm-enforce` | `DENY` rules are blocked in-kernel. |

The daemon prints a one-line **Security posture** summary at startup so the
active mode is unambiguous in logs.

## Startup fail-safety: `--require-lsm`

By default, if BPF-LSM cannot be established (unsupported kernel, missing BTF,
verifier rejection), Warmor logs a warning and **degrades to observe-only** —
it keeps running so you still get telemetry. This is a *fail-open startup*: good
for rollout and for mixed fleets, but it means "the daemon is up" does not by
itself guarantee kernel enforcement.

For environments that must not run without kernel enforcement, start with:

```sh
warmor-daemon --lsm-enforce --require-lsm ...
```

With `--require-lsm`, the daemon **refuses to start** (non-zero exit) if it
cannot load and arm the LSM programs — a *fail-closed startup*. This is the
recommended posture for production enforcement nodes, typically paired with
`--lsm-enforce`.

| Flag | Default | Effect |
|---|---|---|
| `--lsm-enforce` | `false` | Arm kernel blocking for `DENY` rules. Without it, LSM runs audit-only. |
| `--require-lsm` | `false` | Fail to start unless LSM enforcement loads. Without it, degrade to observe-only. |
| `--no-lsm` | `false` | Skip LSM-BPF loading entirely. Tracepoint-only observe mode — useful for environments where the verifier hangs or LSM is unsupported. |
| `--audit` | `false` | Log would-be denials instead of enforcing them (userspace actions). |

## Recommended postures

- **Production enforcement node:** `--lsm-enforce --require-lsm`. Fail-closed
  startup; deny rules blocked in-kernel; no silent downgrade.
- **Rollout / canary:** `--lsm-enforce` (no `--require-lsm`). Enforces where the
  kernel supports it, degrades gracefully elsewhere while you assess coverage.
- **Pure monitoring:** defaults. Observe and evaluate, block nothing.

See [BPF_COMPATIBILITY.md](BPF_COMPATIBILITY.md) for the kernel requirements
that determine whether LSM enforcement can load at all.
