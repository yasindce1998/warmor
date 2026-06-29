package wasm

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Pool manages a set of pre-instantiated WASM policy instances for
// lock-free parallel evaluation.
type Pool struct {
	instances chan *Policy
	runtime   *Runtime
	size      int
	counter   atomic.Uint64
}

// NewPool creates a pool of WASM policy instances from a compiled module.
func NewPool(ctx context.Context, runtime *Runtime, size int) (*Pool, error) {
	if size <= 0 {
		size = 1
	}
	if runtime.module == nil {
		return nil, fmt.Errorf("runtime has no compiled module")
	}

	p := &Pool{
		instances: make(chan *Policy, size),
		runtime:   runtime,
		size:      size,
	}

	for i := 0; i < size; i++ {
		policy, err := p.instantiate(ctx)
		if err != nil {
			p.Close(ctx)
			return nil, fmt.Errorf("instantiate pool member %d: %w", i, err)
		}
		p.instances <- policy
	}

	return p, nil
}

func (p *Pool) instantiate(ctx context.Context) (*Policy, error) {
	n := p.counter.Add(1)
	modConfig := p.runtime.config.WithName(fmt.Sprintf("policy_%d", n))
	instance, err := p.runtime.runtime.InstantiateModule(ctx, p.runtime.module, modConfig)
	if err != nil {
		return nil, err
	}

	pol := &Policy{runtime: p.runtime, instance: instance}

	if instance.ExportedFunction("evaluate_event") != nil {
		pol.useBinaryABI = true
		malloc := instance.ExportedFunction("malloc")
		if malloc == nil {
			instance.Close(ctx)
			return nil, fmt.Errorf("binary ABI module missing malloc export")
		}
		results, err := malloc.Call(ctx, uint64(eventStructSize))
		if err != nil {
			instance.Close(ctx)
			return nil, fmt.Errorf("malloc for event buffer: %w", err)
		}
		pol.eventBufPtr = uint32(results[0])
	}

	return pol, nil
}

// Get retrieves a policy instance from the pool. Blocks if all instances are in use.
func (p *Pool) Get(ctx context.Context) (*Policy, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case policy := <-p.instances:
		return policy, nil
	}
}

// Put returns a policy instance to the pool.
func (p *Pool) Put(policy *Policy) {
	if policy == nil {
		return
	}
	select {
	case p.instances <- policy:
	default:
		// Pool is full (shouldn't happen normally), close the extra instance
		policy.Close(context.Background())
	}
}

// Size returns the pool capacity.
func (p *Pool) Size() int {
	return p.size
}

// Close drains and closes all instances in the pool.
func (p *Pool) Close(ctx context.Context) error {
	close(p.instances)
	var firstErr error
	for policy := range p.instances {
		if err := policy.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
