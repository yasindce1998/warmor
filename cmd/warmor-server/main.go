package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yasindce1998/warmor/internal/policyserver"
)

var (
	addr = flag.String("addr", ":8443", "Server listen address")
)

func main() {
	flag.Parse()

	srv := policyserver.NewServer(policyserver.ServerConfig{
		Addr: *addr,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("shutting down policy server...")
		srv.Shutdown(ctx)
		cancel()
	}()

	if err := srv.Start(); err != nil {
		log.Fatalf("policy server: %v", err)
	}
}
