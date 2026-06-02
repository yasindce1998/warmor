package main

import (
	"context"
	"log"
	"time"

	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

func main() {
	log.Println("warmor WASM Test Tool")
	log.Println("Testing WASM policy evaluation...")

	ctx := context.Background()

	// Create runtime
	log.Println("Creating WASM runtime...")
	runtime, err := wasm.NewRuntime(ctx)
	if err != nil {
		log.Fatalf("Failed to create runtime: %v", err)
	}
	defer runtime.Close(ctx)
	log.Println("✓ WASM runtime created")

	// Load policy
	policyPath := "policies/example/policy.wasm"
	log.Printf("Loading policy from: %s", policyPath)
	if err := runtime.LoadPolicy(ctx, policyPath); err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	log.Println("✓ Policy loaded")

	// Create policy instance
	log.Println("Creating policy instance...")
	policy, err := wasm.NewPolicy(ctx, runtime)
	if err != nil {
		log.Fatalf("Failed to create policy: %v", err)
	}
	defer policy.Close(ctx)
	log.Println("✓ Policy instance created")

	log.Println("")
	log.Println("Testing policy evaluation with sample events:")
	log.Println("")

	// Test events
	testEvents := []api.Event{
		{
			PID:       1234,
			UID:       0,
			GID:       0,
			Comm:      "bash",
			Filename:  "/bin/bash",
			Timestamp: time.Now(),
		},
		{
			PID:       1235,
			UID:       1000,
			GID:       1000,
			Comm:      "python3",
			Filename:  "/usr/bin/python3",
			Timestamp: time.Now(),
		},
		{
			PID:       1236,
			UID:       1000,
			GID:       1000,
			Comm:      "ls",
			Filename:  "/usr/bin/ls",
			Timestamp: time.Now(),
		},
		{
			PID:       1237,
			UID:       0,
			GID:       0,
			Comm:      "sudo",
			Filename:  "/usr/bin/sudo",
			Timestamp: time.Now(),
		},
		{
			PID:       1238,
			UID:       1000,
			GID:       1000,
			Comm:      "node",
			Filename:  "/usr/bin/node",
			Timestamp: time.Now(),
		},
	}

	var totalDuration time.Duration
	successCount := 0

	for i, event := range testEvents {
		start := time.Now()
		action, err := policy.Evaluate(ctx, &event)
		duration := time.Since(start)
		totalDuration += duration

		if err != nil {
			log.Printf("[%d] ❌ Error evaluating event: %v", i+1, err)
			continue
		}

		successCount++

		// Format output based on action
		var emoji string
		switch action {
		case api.ActionAllow:
			emoji = "✓"
		case api.ActionDeny:
			emoji = "✗"
		case api.ActionLog:
			emoji = "📝"
		default:
			emoji = "?"
		}

		log.Printf("[%d] %s [%s] PID=%d UID=%d COMM=%-10s FILE=%-20s (eval_time=%v)",
			i+1,
			emoji,
			action,
			event.PID,
			event.UID,
			event.Comm,
			event.Filename,
			duration)
	}

	log.Println("")
	log.Println("=== Test Summary ===")
	log.Printf("Total Events: %d", len(testEvents))
	log.Printf("Successful Evaluations: %d", successCount)
	log.Printf("Failed Evaluations: %d", len(testEvents)-successCount)
	log.Printf("Average Evaluation Time: %v", totalDuration/time.Duration(len(testEvents)))
	log.Printf("Total Time: %v", totalDuration)
	log.Println("====================")

	if successCount == len(testEvents) {
		log.Println("")
		log.Println("✓ All tests passed!")
	} else {
		log.Println("")
		log.Println("✗ Some tests failed")
	}
}


