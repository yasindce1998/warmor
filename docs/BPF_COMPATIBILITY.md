# BPF / Kernel Compatibility

Warmor's enforcement layer is BPF-LSM programs loaded into the running kernel.
Because those programs read kernel-internal structures, kernel-version
portability is the single most important reliability property of the project.
This document describes how that portability is achieved, what the kernel must
provide, and which kernels are tested.

## How portability works (CO-RE)

The kernel structs we read (`linux_binprm`, `dentry`, `socket`, `sock`,
`task_struct`, …) are not part of any userspace header, and their field offsets
differ between kernel versions and configs. We rely on **CO-RE** (Compile Once –
Run Everywhere):

- `bpf/vmlinux_minimal.h` declares **only the fields we touch**, each struct
  tagged `__attribute__((preserve_access_index))`.
- At load time, `cilium/ebpf` reads the running kernel's own BTF
  (`/sys/kernel/btf/vmlinux`) and **relocates** every field access to the
  correct offset for that kernel.

This means a single compiled `.o` runs across kernels — *provided the field
actually exists and our declared shape matches the kernel's*.

### Rule: read nested fields with `BPF_CORE_READ`, never copy whole structs

CO-RE relocates the offset of a field, but it does **not** rewrite the *layout*
of a struct we copy wholesale. If we declare a partial struct and
`bpf_probe_read` the whole thing, our layout assumption can disagree with the
kernel's and we read garbage.

Concretely, this bit us with `struct qstr` (the `d_name` of a dentry): copying
the struct assumed a layout that did not hold on all kernels. The fix — and the
standing rule — is to walk pointers field-by-field:

```c
// Good: each step is individually relocated by CO-RE.
const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);

// Avoid: copies a struct whose full layout we don't actually control.
struct qstr q;
bpf_probe_read_kernel(&q, sizeof(q), &dentry->d_name);
```

When adding a hook that reaches into a new struct, add the minimal field(s) to
`vmlinux_minimal.h` and access them with `BPF_CORE_READ`.

## Kernel requirements

| Requirement | Why | How to check |
|---|---|---|
| Linux ≥ 5.7 (5.8+ recommended) | `lsm/*` attach type; ring buffer maps land in 5.8 | `uname -r` |
| `CONFIG_BPF_LSM=y` | enables BPF programs on LSM hooks | `zgrep BPF_LSM /proc/config.gz` |
| `bpf` in the active LSM list | the BPF LSM must be enabled at boot | `cat /sys/kernel/security/lsm` |
| `CONFIG_DEBUG_INFO_BTF=y` | CO-RE relocations need kernel BTF | `ls /sys/kernel/btf/vmlinux` |

If `bpf` is not in `/sys/kernel/security/lsm`, add it via the kernel command
line, e.g. `lsm=lockdown,capability,...,bpf`.

Warmor checks these at startup:

- `IsLSMSupported()` verifies `bpf` is in the active LSM list.
- `LoadLSM()` verifies `/sys/kernel/btf/vmlinux` exists and returns an
  actionable error (rather than an opaque verifier failure) if BTF is missing.

What happens when a requirement is unmet depends on the startup posture — see
[SECURITY_POSTURE.md](SECURITY_POSTURE.md). By default Warmor degrades to
observe-only; `--require-lsm` makes any of these failures fatal.

## Tested kernel matrix

CI (`.github/workflows/lsm-test.yml`) loads and exercises every LSM program in
a VM (via [vimto](https://lmb.io/vimto)) across multiple kernels, using
[`cilium/ci-kernels`](https://github.com/cilium/ci-kernels) `-selftests` images.
The `-selftests` config is the one built with `CONFIG_BPF_LSM=y` and BTF, and
upstream only builds it for the three release **channels** — not for the numeric
version tags (`5.15`, `6.1`, …), which ship without BPF LSM. So these three are
the only BPF-LSM-capable images available off the shelf:

| Channel | Role | Approx. version | Blocking |
|---|---|---|---|
| `longterm-selftests` | oldest of the three | ~6.18 | yes |
| `stable-selftests` | current stable — the primary gate | ~6.19 | yes |
| `mainline-selftests` | newest / release-candidate — early warning | ~7.0 | no (`continue-on-error`) |

`fail-fast` is disabled so one kernel's failure doesn't mask the others.
`mainline` is allowed to fail because bleeding-edge kernels churn; a red
`mainline` is a heads-up to investigate before it reaches `stable`, not a merge
blocker.

> **Limitation: the version spread is narrow.** Because only the channel images
> carry BPF LSM, today's matrix spans roughly 6.18–7.0 — it does **not** exercise
> older LTS kernels (5.10/5.15/6.1) where struct layouts most differ. To cover
> those, build a selftests-enabled image for a specific version (ci-kernels'
> `buildx.sh <version>` plus the `selftests-bpf` target) and add it to the
> matrix. This is the highest-value next step for CO-RE confidence.

To reproduce a single kernel locally:

```sh
go install lmb.io/vimto@latest
# generate real bpf2go bindings first (see the CI "Generate BPF bindings" step)
vimto -kernel ghcr.io/cilium/ci-kernels:stable-selftests -- \
  go test -v -count 1 -tags integration ./internal/ebpf/
```

## Known risks / limitations

- **`vmlinux_minimal.h` is maintained by hand.** Adding a field that doesn't
  exist on an older kernel, or assuming a struct layout, can silently misread.
  Mitigation: minimal field set + `BPF_CORE_READ` + the kernel matrix above.
- **Old LTS kernels are not yet tested.** Upstream only ships `-selftests`
  (BPF-LSM-enabled) images for release channels, so the matrix currently spans
  ~6.18–7.0. Building selftests images for 5.15/6.1 and adding them is the
  biggest open coverage gap (see the matrix section above).
- **Policy matching is exact-hash (FNV-1a).** No prefix/glob matching, and hash
  collisions are theoretically possible. This is an architectural property of
  the current policy map, not a kernel-compat issue — noted here for awareness.
