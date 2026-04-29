package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/enforcer/bridge"
	"github.com/yasindce1998/warmor/enforcer/logging"
	"github.com/yasindce1998/warmor/enforcer/policy"
)

const (
	defaultPolicyPath = "enforcer/policy.yaml"
	defaultLogLevel   = "info"
	defaultLogFormat  = "json"
)

var (
	policyPath    = flag.String("policy", defaultPolicyPath, "Path to policy.yaml file")
	logLevel      = flag.String("log-level", defaultLogLevel, "Log level (debug, info, warn, error)")
	logFormat     = flag.String("log-format", defaultLogFormat, "Log format (json, console)")
	statsInterval = flag.Duration("stats-interval", 30*time.Second, "Statistics reporting interval")
)

func main() {
	flag.Parse()

	// Initialize logging
	logConfig := &logging.Config{
		Level:      *logLevel,
		Format:     *logFormat,
		Output:     "stdout",
		TimeFormat: time.RFC3339,
	}

	if err := logging.Init(logConfig); err != nil {
		log.Fatalf("Failed to initialize logging: %v", err)
	}

	logging.Logger.Info().
		Str("version", "0.1.0").
		Str("policy_path", *policyPath).
		Msg("Warmor Enforcer starting...")

	// Load policies
	policies, err := policy.LoadPolicies(*policyPath)
	if err != nil {
		logging.Logger.Fatal().
			Err(err).
			Str("policy_path", *policyPath).
			Msg("Failed to load policies")
	}

	logging.Logger.Info().
		Int("policy_count", policies.Count()).
		Msg("Policies loaded successfully")

	// Create enforcer
	enforcer, err := bridge.NewEnforcer(*policyPath, policies)
	if err != nil {
		logging.Logger.Fatal().
			Err(err).
			Msg("Failed to create enforcer")
	}
	defer enforcer.Close()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start statistics reporter
	statsTicker := time.NewTicker(*statsInterval)
	defer statsTicker.Stop()

	// Start policy reload watcher
	reloadTicker := time.NewTicker(30 * time.Second)
	defer reloadTicker.Stop()

	logging.Logger.Info().Msg("Warmor Enforcer is running. Press Ctrl+C to stop.")

	// Simulate some events for demonstration
	// In production, this would be replaced with actual eBPF event processing
	go simulateEvents(enforcer)

	// Main event loop
	for {
		select {
		case <-sigChan:
			logging.Logger.Info().Msg("Received shutdown signal")
			printFinalStats(enforcer)
			return

		case <-statsTicker.C:
			printStats(enforcer)

		case <-reloadTicker.C:
			if err := enforcer.ReloadPolicies(); err != nil {
				logging.Logger.Error().
					Err(err).
					Msg("Failed to reload policies")
			}
		}
	}
}

// simulateEvents simulates eBPF events for demonstration
// In production, this would be replaced with actual eBPF event processing
func simulateEvents(enforcer *bridge.Enforcer) {
	events := []bridge.ExecEvent{
		{PID: 1234, UID: 0, ProcessPath: "/bin/bash", Timestamp: time.Now()},
		{PID: 1235, UID: 1000, ProcessPath: "/usr/bin/python3", Timestamp: time.Now()},
		{PID: 1236, UID: 1001, ProcessPath: "/usr/bin/node", Timestamp: time.Now()},
		{PID: 1237, UID: 1000, ProcessPath: "/tmp/go-build123", Timestamp: time.Now()},
		{PID: 1238, UID: 2000, ProcessPath: "/usr/sbin/nginx", Timestamp: time.Now()},
		{PID: 1239, UID: 1000, ProcessPath: "/usr/bin/gcc", Timestamp: time.Now()},
		{PID: 1240, UID: 3000, ProcessPath: "/bin/sh", Timestamp: time.Now()},
		{PID: 1241, UID: 1000, ProcessPath: "/usr/bin/ls", Timestamp: time.Now()},
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	eventIndex := 0
	for range ticker.C {
		if eventIndex >= len(events) {
			eventIndex = 0
		}

		event := events[eventIndex]
		decision, err := enforcer.Evaluate(&event)
		if err != nil {
			logging.Logger.Error().
				Err(err).
				Int("pid", event.PID).
				Msg("Failed to evaluate policy")
			continue
		}

		// Log the decision result
		logging.Logger.Info().
			Int("pid", event.PID).
			Int("uid", event.UID).
			Str("process", event.ProcessPath).
			Str("decision", decision.Action.String()).
			Dur("duration", decision.Duration).
			Msg("Event processed")

		eventIndex++
	}
}

// printStats prints current enforcement statistics
func printStats(enforcer *bridge.Enforcer) {
	stats := enforcer.GetStats()

	logging.Logger.Info().
		Int64("total_evaluations", stats.TotalEvaluations).
		Int64("allowed", stats.AllowedActions).
		Int64("denied", stats.DeniedActions).
		Int64("logged", stats.LoggedActions).
		Dur("avg_duration", stats.AverageDuration).
		Msg("Enforcement statistics")

	// Calculate percentages
	if stats.TotalEvaluations > 0 {
		allowedPct := float64(stats.AllowedActions) / float64(stats.TotalEvaluations) * 100
		deniedPct := float64(stats.DeniedActions) / float64(stats.TotalEvaluations) * 100
		loggedPct := float64(stats.LoggedActions) / float64(stats.TotalEvaluations) * 100

		fmt.Printf("\n=== Warmor Statistics ===\n")
		fmt.Printf("Total Evaluations: %d\n", stats.TotalEvaluations)
		fmt.Printf("Allowed: %d (%.1f%%)\n", stats.AllowedActions, allowedPct)
		fmt.Printf("Denied: %d (%.1f%%)\n", stats.DeniedActions, deniedPct)
		fmt.Printf("Logged: %d (%.1f%%)\n", stats.LoggedActions, loggedPct)
		fmt.Printf("Average Duration: %v\n", stats.AverageDuration)
		fmt.Printf("========================\n\n")
	}
}

// printFinalStats prints final statistics before shutdown
func printFinalStats(enforcer *bridge.Enforcer) {
	stats := enforcer.GetStats()

	logging.Logger.Info().
		Int64("total_evaluations", stats.TotalEvaluations).
		Int64("allowed", stats.AllowedActions).
		Int64("denied", stats.DeniedActions).
		Int64("logged", stats.LoggedActions).
		Dur("total_duration", stats.TotalDuration).
		Dur("avg_duration", stats.AverageDuration).
		Msg("Final enforcement statistics")

	fmt.Printf("\n=== Final Warmor Statistics ===\n")
	fmt.Printf("Total Evaluations: %d\n", stats.TotalEvaluations)
	fmt.Printf("Allowed: %d\n", stats.AllowedActions)
	fmt.Printf("Denied: %d\n", stats.DeniedActions)
	fmt.Printf("Logged: %d\n", stats.LoggedActions)
	fmt.Printf("Total Duration: %v\n", stats.TotalDuration)
	fmt.Printf("Average Duration: %v\n", stats.AverageDuration)
	fmt.Printf("===============================\n")
}

// Made with Bob
