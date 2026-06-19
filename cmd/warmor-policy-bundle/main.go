package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/yasindce1998/warmor/internal/policybundle"
)

var version = "dev"

func main() {
	push := flag.Bool("push", false, "Push .wasm policy to OCI registry")
	pull := flag.Bool("pull", false, "Pull .wasm policy from OCI registry")
	ref := flag.String("ref", "", "OCI reference (e.g., ghcr.io/org/policy:v1)")
	wasmFile := flag.String("wasm", "", "Path to .wasm file (push: input, pull: output)")
	name := flag.String("name", "warmor-policy", "Policy name metadata")
	policyVersion := flag.String("policy-version", "1.0.0", "Policy version metadata")
	description := flag.String("description", "", "Policy description metadata")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-policy-bundle [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Package compiled .wasm policies as OCI artifacts for registry push/pull.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-bundle --push --ref ghcr.io/org/policy:v1 --wasm policy.wasm\n")
		fmt.Fprintf(os.Stderr, "  warmor-policy-bundle --pull --ref ghcr.io/org/policy:v1 --wasm policy.wasm\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("warmor-policy-bundle %s\n", version)
		os.Exit(0)
	}

	if !*push && !*pull {
		fmt.Fprintf(os.Stderr, "error: specify --push or --pull\n")
		flag.Usage()
		os.Exit(1)
	}
	if *push && *pull {
		fmt.Fprintf(os.Stderr, "error: specify only one of --push or --pull\n")
		os.Exit(1)
	}
	if *ref == "" {
		fmt.Fprintf(os.Stderr, "error: --ref is required\n")
		os.Exit(1)
	}
	if *wasmFile == "" {
		fmt.Fprintf(os.Stderr, "error: --wasm is required\n")
		os.Exit(1)
	}

	ctx := context.Background()

	if *push {
		cfg := policybundle.BundleConfig{
			Name:        *name,
			Version:     *policyVersion,
			Description: *description,
		}
		desc, err := policybundle.Push(ctx, *ref, *wasmFile, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: push: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Pushed %s → %s (digest: %s)\n", *wasmFile, *ref, desc.Digest)
	}

	if *pull {
		if err := policybundle.Pull(ctx, *ref, *wasmFile); err != nil {
			fmt.Fprintf(os.Stderr, "error: pull: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Pulled %s → %s\n", *ref, *wasmFile)
	}
}
