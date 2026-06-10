package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/yasindce1998/warmor/internal/compiler"
)

// Runtime wraps the WASM runtime
type Runtime struct {
	runtime wazero.Runtime
	module  wazero.CompiledModule
	config  wazero.ModuleConfig
}

// NewRuntime creates a new WASM runtime
func NewRuntime(ctx context.Context) (*Runtime, error) {
	// Create runtime with default configuration
	r := wazero.NewRuntime(ctx)

	// Instantiate WASI
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		r.Close(ctx)
		return nil, fmt.Errorf("instantiate WASI: %w", err)
	}

	return &Runtime{
		runtime: r,
		config:  wazero.NewModuleConfig(),
	}, nil
}

// LoadPolicy loads a WASM policy module from file
func (r *Runtime) LoadPolicy(ctx context.Context, path string) error {
	// Read WASM file
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	// Compile module
	compiled, err := r.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("compile module: %w", err)
	}

	r.module = compiled
	return nil
}

// LoadPolicyFromYAML compiles a YAML policy to WASM and loads it.
// If a pre-compiled .wasm file exists next to the .yaml with the same base name,
// it is loaded directly. Otherwise the YAML is compiled via the Rust toolchain.
func (r *Runtime) LoadPolicyFromYAML(ctx context.Context, yamlPath string) error {
	ext := filepath.Ext(yamlPath)
	wasmPath := strings.TrimSuffix(yamlPath, ext) + ".wasm"

	if _, err := os.Stat(wasmPath); err == nil {
		return r.LoadPolicy(ctx, wasmPath)
	}

	policy, err := compiler.ParseFile(yamlPath)
	if err != nil {
		return fmt.Errorf("parse YAML policy: %w", err)
	}

	result, err := compiler.Build(policy, compiler.BuildOptions{
		OutputPath: wasmPath,
	})
	if err != nil {
		return fmt.Errorf("compile YAML policy: %w", err)
	}
	compiler.Cleanup(result)

	return r.LoadPolicy(ctx, wasmPath)
}

// IsYAMLPolicy returns true if the path has a .yaml or .yml extension.
func IsYAMLPolicy(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// Close cleans up the runtime
func (r *Runtime) Close(ctx context.Context) error {
	if r.module != nil {
		if err := r.module.Close(ctx); err != nil {
			return fmt.Errorf("close module: %w", err)
		}
	}

	if r.runtime != nil {
		if err := r.runtime.Close(ctx); err != nil {
			return fmt.Errorf("close runtime: %w", err)
		}
	}

	return nil
}
