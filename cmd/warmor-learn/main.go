package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/internal/learner"
)

var version = "dev"

func main() {
	duration := flag.Duration("duration", 30*time.Minute, "Learning duration (e.g. 5m, 1h)")
	cgroups := flag.String("cgroup", "", "Comma-separated cgroup IDs to observe (empty = all)")
	output := flag.String("o", "", "Output file (default: stdout)")
	name := flag.String("name", "", "Name for the generated policy")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-learn [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Observe container behavior and generate a deny-all-else policy.\n\n")
		fmt.Fprintf(os.Stderr, "The learner records all syscall events from targeted containers,\n")
		fmt.Fprintf(os.Stderr, "then synthesizes a policy that allows only observed behavior.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-learn --duration 5m --cgroup 12345 -o policy.yaml\n")
		fmt.Fprintf(os.Stderr, "  warmor-learn --duration 1h -o learned.yaml\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("warmor-learn %s\n", version)
		os.Exit(0)
	}

	var cgroupIDs []uint64
	if *cgroups != "" {
		for s := range strings.SplitSeq(*cgroups, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			id, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid cgroup ID %q: %v\n", s, err)
				os.Exit(1)
			}
			cgroupIDs = append(cgroupIDs, id)
		}
	}

	cfg := learner.Config{
		Duration:  *duration,
		CgroupIDs: cgroupIDs,
		Name:      *name,
	}

	session := learner.NewSession(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nStopping learning session...\n")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "Starting learning session (duration: %s, cgroups: %v)\n", *duration, cgroupIDs)
	fmt.Fprintf(os.Stderr, "Recorder sink name: %s\n", session.Recorder().Name())
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop early and generate policy.\n\n")

	if err := session.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	stats := session.Stats()
	fmt.Fprintf(os.Stderr, "\nLearning complete: %s\n", stats)

	data, err := session.MarshalPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Policy written to %s\n", *output)
	} else {
		os.Stdout.Write(data)
	}
}
