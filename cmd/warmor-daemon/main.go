package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/internal/enforcer"
)

var (
	policyPath    = flag.String("policy", "policies/example/policy.wasm", "Path to WASM policy file")
	statsInterval = flag.Duration("stats-interval", 30*time.Second, "Statistics reporting interval")
	logLevel      = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	metricsPort   = flag.Int("metrics-port", 9090, "Prometheus metrics port")
	showVersion   = flag.Bool("version", false, "Show version and exit")
)

const Version = "1.1.0-beta"

func main() {
	flag.Parse()

	// Handle version flag
	if *showVersion {
		log.Printf("warmor version %s", Version)
		return
	}

	// Print banner
	printBanner()

	// Check for elevated privileges (root on Unix, Administrator on Windows)
	if !isElevated() {
		log.Fatal("❌ This program must be run with elevated privileges (root on Linux/macOS, Administrator on Windows)")
	}

	log.Printf("Policy: %s", *policyPath)
	log.Printf("Stats Interval: %v", *statsInterval)
	log.Printf("Log Level: %s", *logLevel)
	log.Printf("Metrics Port: %d", *metricsPort)
	log.Println("")

	ctx := context.Background()

	// Create enforcer with metrics port
	enf, err := enforcer.New(ctx, *policyPath, *metricsPort)
	if err != nil {
		log.Fatalf("❌ Failed to create enforcer: %v", err)
	}
	defer enf.Close()

	log.Println("")
	log.Println("✓ warmor enforcer initialized successfully")
	log.Println("")

	// Start enforcer
	if err := enf.Start(); err != nil {
		log.Fatalf("❌ Failed to start enforcer: %v", err)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	// Print stats periodically
	statsTicker := time.NewTicker(*statsInterval)
	defer statsTicker.Stop()

	log.Println("🚀 warmor is running. Press Ctrl+C to stop.")
	log.Println("")

	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGHUP:
				// Reload policy on SIGHUP
				log.Println("")
				log.Println("📥 Received SIGHUP signal, reloading policy...")
				if err := enf.ReloadPolicy(); err != nil {
					log.Printf("❌ Failed to reload policy: %v", err)
				}
				log.Println("")

			case os.Interrupt, syscall.SIGTERM:
				// Shutdown on SIGINT/SIGTERM
				log.Println("")
				log.Println("📥 Received shutdown signal")
				enf.Stop()
				log.Println("")
				log.Println("=== Final Statistics ===")
				enf.PrintStats()
				log.Println("")
				log.Println("👋 warmor shutdown complete")
				return
			}

		case <-statsTicker.C:
			log.Println("")
			enf.PrintStats()
			log.Println("")
		}
	}
}

func printBanner() {
	banner := `
╦ ╦╔═╗╦═╗╔╦╗╔═╗╦═╗
║║║╠═╣╠╦╝║║║║ ║╠╦╝
╚╩╝╩ ╩╩╚═╩ ╩╚═╝╩╚═
WASM-Powered Security Enforcer
Version: 1.1.0-beta
`
	log.Println(banner)
}
