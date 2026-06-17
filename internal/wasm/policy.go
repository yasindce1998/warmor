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
	// Serialize event to the flat JSON format the Rust WASM module expects
	eventJSON, err := marshalEventForWASM(event)
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

	// Ensure memory is freed even on error
	defer func() {
		if freeFn := p.instance.ExportedFunction("free"); freeFn != nil {
			_, _ = freeFn.Call(ctx, uint64(ptr), uint64(len(eventJSON)))
		}
	}()

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

// marshalEventForWASM produces the flat JSON structure the Rust serde enum expects.
// The Rust code uses #[serde(tag = "type")] with variants PROCESS/FILE/NETWORK,
// where all fields must be at the top level (no nested sub-objects).
func marshalEventForWASM(event *api.Event) ([]byte, error) {
	m := map[string]any{
		"pid":  event.PID,
		"uid":  event.UID,
		"gid":  event.GID,
		"comm": event.Comm,
	}

	switch event.GetType() {
	case api.EventTypeProcess:
		m["type"] = "PROCESS"
		m["filename"] = event.Filename
		if event.Process != nil {
			m["filename"] = event.Process.Filename
		}
	case api.EventTypeFile:
		m["type"] = "FILE"
		if event.File != nil {
			m["operation"] = event.File.Operation
			m["path"] = event.File.Path
			m["flags"] = event.File.Flags
		} else {
			m["operation"] = "open"
			m["path"] = event.Filename
			m["flags"] = uint32(0)
		}
	case api.EventTypeNetwork:
		m["type"] = "NETWORK"
		if event.Network != nil {
			m["operation"] = event.Network.Operation
			m["protocol"] = event.Network.Protocol
			m["remote_addr"] = event.Network.RemoteAddr
			m["remote_port"] = event.Network.RemotePort
			m["local_port"] = event.Network.LocalPort
		} else {
			m["operation"] = "connect"
			m["protocol"] = "tcp"
			m["remote_addr"] = ""
			m["remote_port"] = uint16(0)
			m["local_port"] = uint16(0)
		}
	default:
		m["type"] = "PROCESS"
		m["filename"] = event.Filename
	}

	return json.Marshal(m)
}

// Close cleans up the policy instance
func (p *Policy) Close(ctx context.Context) error {
	if p.instance != nil {
		return p.instance.Close(ctx)
	}
	return nil
}
