package policybundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	WasmMediaType   = "application/vnd.warmor.policy.wasm.v1"
	ConfigMediaType = "application/vnd.warmor.policy.config.v1+json"
)

type BundleConfig struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

func Push(ctx context.Context, ref string, wasmPath string, cfg BundleConfig) (ocispec.Descriptor, error) {
	wasmData, err := os.ReadFile(wasmPath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("read wasm: %w", err)
	}

	store := memory.New()

	wasmDesc, err := pushBlob(ctx, store, WasmMediaType, wasmData)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push wasm blob: %w", err)
	}
	wasmDesc.Annotations = map[string]string{
		ocispec.AnnotationTitle: "policy.wasm",
	}

	configData, err := json.Marshal(cfg)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal config: %w", err)
	}
	configDesc, err := pushBlob(ctx, store, ConfigMediaType, configData)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push config blob: %w", err)
	}

	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{wasmDesc},
		Annotations: map[string]string{
			ocispec.AnnotationTitle:   cfg.Name,
			"org.warmor.policy.name": cfg.Name,
		},
	}

	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestDesc, err := pushBlob(ctx, store, ocispec.MediaTypeImageManifest, manifestData)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push manifest: %w", err)
	}

	if err := store.Tag(ctx, manifestDesc, ref); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("tag: %w", err)
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse reference %q: %w", ref, err)
	}

	desc, err := oras.Copy(ctx, store, ref, repo, ref, oras.DefaultCopyOptions)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push to %s: %w", ref, err)
	}

	return desc, nil
}

func Pull(ctx context.Context, ref string, outputPath string) error {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return fmt.Errorf("parse reference %q: %w", ref, err)
	}

	store := memory.New()

	desc, err := oras.Copy(ctx, repo, ref, store, ref, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("pull from %s: %w", ref, err)
	}

	manifestData, err := store.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}
	defer manifestData.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(manifestData).Decode(&manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}

	for _, layer := range manifest.Layers {
		if layer.MediaType == WasmMediaType {
			reader, err := store.Fetch(ctx, layer)
			if err != nil {
				return fmt.Errorf("fetch wasm layer: %w", err)
			}
			defer reader.Close()

			data, err := io.ReadAll(reader)
			if err != nil {
				return fmt.Errorf("read wasm: %w", err)
			}
			return os.WriteFile(outputPath, data, 0644)
		}
	}

	return fmt.Errorf("no wasm layer found in manifest")
}

func pushBlob(ctx context.Context, store *memory.Store, mediaType string, data []byte) (ocispec.Descriptor, error) {
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
	if err := store.Push(ctx, desc, bytes.NewReader(data)); err != nil {
		return ocispec.Descriptor{}, err
	}
	return desc, nil
}

