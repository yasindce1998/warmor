package wasm

import (
	"context"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
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


