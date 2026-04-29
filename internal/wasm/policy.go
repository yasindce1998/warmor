package wasm

import (
	"context"
	"encoding/json"
	"fmt"

	wazeroapi "github.com/tetratelabs/wazero/api"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Policy represents a loaded WASM policy
type Policy struct {
	runtime  *Runtime
	instance wazeroapi.Module
}

// NewPolicy creates a new policy instance
func NewPolicy(ctx context.Context, runtime *Runtime) (*Policy, error) {
	// Instantiate the module
	instance, err := runtime.runtime.InstantiateModule(ctx, runtime.module, runtime.config)
	if err != nil {
		return nil, fmt.Errorf("instantiate module: %w", err)
	}

	return &Policy{
		runtime:  runtime,
		instance: instance,
	}, nil
}

// Evaluate evaluates an event against the policy
func (p *Policy) Evaluate(ctx context.Context, event *api.Event) (api.Action, error) {
	// Serialize event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return api.ActionDeny, fmt.Errorf("marshal event: %w", err)
	}

	// Allocate memory in WASM for the event
	malloc := p.instance.ExportedFunction("malloc")
	if malloc == nil {
		return api.ActionDeny, fmt.Errorf("malloc function not found")
	}

	results, err := malloc.Call(ctx, uint64(len(eventJSON)))
	if err != nil {
		return api.ActionDeny, fmt.Errorf("malloc failed: %w", err)
	}
	ptr := uint32(results[0])

	// Write event data to WASM memory
	if !p.instance.Memory().Write(ptr, eventJSON) {
		return api.ActionDeny, fmt.Errorf("failed to write event to WASM memory")
	}

	// Call evaluate_syscall function
	evaluateFn := p.instance.ExportedFunction("evaluate_syscall")
	if evaluateFn == nil {
		return api.ActionDeny, fmt.Errorf("evaluate_syscall function not found")
	}

	results, err = evaluateFn.Call(ctx, uint64(ptr), uint64(len(eventJSON)))
	if err != nil {
		return api.ActionDeny, fmt.Errorf("evaluate_syscall failed: %w", err)
	}

	action := api.Action(results[0])
	return action, nil
}

// Close cleans up the policy instance
func (p *Policy) Close(ctx context.Context) error {
	if p.instance != nil {
		return p.instance.Close(ctx)
	}
	return nil
}

// Made with Bob
