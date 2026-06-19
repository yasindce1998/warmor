# Policy Bundle (OCI)

`warmor-policy-bundle` packages compiled `.wasm` policies as OCI artifacts and pushes/pulls them to/from container registries. This enables versioned policy distribution using the same infrastructure as container images.

## Installation

```bash
make build-policy-bundle
```

## Usage

### Push a policy to a registry

```bash
warmor-policy-bundle --push \
  --ref ghcr.io/myorg/warmor-policies/nginx:v1.0.0 \
  --wasm policy.wasm \
  --name nginx-hardening \
  --policy-version 1.0.0 \
  --description "Nginx container hardening policy"
```

### Pull a policy from a registry

```bash
warmor-policy-bundle --pull \
  --ref ghcr.io/myorg/warmor-policies/nginx:v1.0.0 \
  --wasm ./downloaded-policy.wasm
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--push` | — | Push a .wasm policy to the registry |
| `--pull` | — | Pull a .wasm policy from the registry |
| `--ref` | required | OCI reference (e.g., `ghcr.io/org/policy:tag`) |
| `--wasm` | required | Path to .wasm file (input for push, output for pull) |
| `--name` | `warmor-policy` | Policy name stored in artifact metadata |
| `--policy-version` | `1.0.0` | Policy version stored in artifact metadata |
| `--description` | — | Policy description stored in artifact metadata |
| `--version` | — | Print tool version and exit |

## OCI Artifact Structure

The bundle uses standard OCI image manifest format:

- **Config**: `application/vnd.warmor.policy.config.v1+json` — JSON with policy name, version, description
- **Layer**: `application/vnd.warmor.policy.wasm.v1` — The compiled .wasm policy binary

## Authentication

The tool uses the standard Docker/OCI credential chain:
- `~/.docker/config.json` (Docker login)
- Environment variables (`REGISTRY_TOKEN`, etc.)
- Platform-specific credential helpers

For GitHub Container Registry:
```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

## Typical Workflow

```bash
# 1. Generate and merge policies
warmor-sbom-policy --rootfs ./rootfs sbom.json -o sbom-policy.yaml
warmor-policy-gen audit.ndjson -o audit-policy.yaml
warmor-policy-merge --validate sbom-policy.yaml audit-policy.yaml -o merged.yaml

# 2. Compile to wasm
warmor-compile merged.yaml -o policy.wasm

# 3. Push to registry
warmor-policy-bundle --push \
  --ref ghcr.io/myorg/warmor-policies/myapp:v1.0.0 \
  --wasm policy.wasm \
  --name myapp-policy \
  --policy-version 1.0.0

# 4. Pull on deployment nodes
warmor-policy-bundle --pull \
  --ref ghcr.io/myorg/warmor-policies/myapp:v1.0.0 \
  --wasm /etc/warmor/policy.wasm

# 5. Enforce
sudo warmor-daemon --policy /etc/warmor/policy.wasm
```

## CI/CD Integration

In a GitHub Actions workflow:
```yaml
- name: Bundle and push policy
  run: |
    warmor-policy-bundle --push \
      --ref ghcr.io/${{ github.repository }}/policy:${{ github.sha }} \
      --wasm policy.wasm \
      --name "${{ github.repository }}-policy" \
      --policy-version "${{ github.ref_name }}"
```
