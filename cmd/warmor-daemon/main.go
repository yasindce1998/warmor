package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/version"
)

var (
	policyPath    = flag.String("policy", "policies/example/policy.wasm", "Path to WASM policy file")
	statsInterval = flag.Duration("stats-interval", 30*time.Second, "Statistics reporting interval")
	logLevel      = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	metricsPort   = flag.Int("metrics-port", 9090, "Prometheus metrics port")
	auditMode     = flag.Bool("audit", false, "Audit mode: log deny decisions without enforcing")
	cgroupFilter  = flag.String("cgroup-filter", "", "Cgroup paths to filter (comma-separated, or 'auto' for K8s pod discovery)")
	lsmEnforce    = flag.Bool("lsm-enforce", false, "Enable LSM-BPF kernel-level blocking (requires CONFIG_BPF_LSM)")
	requireLSM    = flag.Bool("require-lsm", false, "Fail to start unless BPF-LSM kernel enforcement can be loaded (fail-closed; default is to degrade to observe-only)")
	showVersion   = flag.Bool("version", false, "Show version and exit")
)


func main() {
	flag.Parse()

	// Handle version flag
	if *showVersion {
		log.Printf("warmor version %s", version.Version)
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
	log.Printf("Audit Mode: %v", *auditMode)
	log.Printf("LSM Enforce: %v", *lsmEnforce)
	log.Printf("Require LSM: %v", *requireLSM)
	if *cgroupFilter != "" {
		log.Printf("Cgroup Filter: %s", *cgroupFilter)
	}
	log.Println("")

	ctx := context.Background()

	// Build cgroup filter list
	var cgroupPaths []string
	if *cgroupFilter != "" {
		for _, p := range strings.Split(*cgroupFilter, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				cgroupPaths = append(cgroupPaths, trimmed)
			}
		}
	}

	// Create enforcer with options
	enf, err := enforcer.New(ctx, *policyPath, &enforcer.Options{
		AuditMode:    *auditMode,
		CgroupFilter: cgroupPaths,
		MetricsPort:  *metricsPort,
		LogLevel:     *logLevel,
		LSMEnforce:   *lsmEnforce,
		RequireLSM:   *requireLSM,
	})
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
	banner := fmt.Sprintf(`
╦ ╦╔═╗╦═╗╔╦╗╔═╗╦═╗
║║║╠═╣╠╦╝║║║║ ║╠╦╝
╚╩╝╩ ╩╩╚═╩ ╩╚═╝╩╚═
WASM-Powered Security Enforcer
Version: %s
`, version.Version)
	log.Println(banner)
}
