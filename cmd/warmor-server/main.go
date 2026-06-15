package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yasindce1998/warmor/internal/crypto"
	"github.com/yasindce1998/warmor/internal/policyserver"
)

var (
	addr      = flag.String("addr", ":8443", "Server listen address")
	caCert    = flag.String("ca-cert", "", "CA certificate PEM path (enables mTLS)")
	tlsCert   = flag.String("tls-cert", "", "Server TLS certificate PEM path")
	tlsKey    = flag.String("tls-key", "", "Server TLS private key PEM path")
	jwtSecret = flag.String("jwt-secret", "", "JWT secret for admin API auth")
)

func main() {
	flag.Parse()

	cfg := policyserver.ServerConfig{
		Addr: *addr,
	}

	if *caCert != "" && *tlsCert != "" && *tlsKey != "" {
		certPEM, err := os.ReadFile(*tlsCert)
		if err != nil {
			log.Fatalf("read tls cert: %v", err)
		}
		keyPEM, err := os.ReadFile(*tlsKey)
		if err != nil {
			log.Fatalf("read tls key: %v", err)
		}
		caPEM, err := os.ReadFile(*caCert)
		if err != nil {
			log.Fatalf("read ca cert: %v", err)
		}

		tlsCfg, err := crypto.NewServerTLSConfig(certPEM, keyPEM, caPEM)
		if err != nil {
			log.Fatalf("configure mTLS: %v", err)
		}
		cfg.TLSConfig = tlsCfg
		log.Println("mTLS enabled")
	}

	if *jwtSecret != "" {
		cfg.JWTSecret = []byte(*jwtSecret)
		log.Println("JWT admin auth enabled")
	}

	srv := policyserver.NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("shutting down policy server...")
		_ = srv.Shutdown(ctx)
		cancel()
	}()

	if err := srv.Start(); err != nil {
		log.Fatalf("policy server: %v", err)
	}
}
