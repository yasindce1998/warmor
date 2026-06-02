package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yasindce1998/warmor/internal/ebpf"
)

func main() {
	// Check for root privileges
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (eBPF requires elevated privileges)")
	}

	log.Println("warmor eBPF Test Tool")
	log.Println("Testing eBPF event capture...")

	// Load eBPF program
	loader, err := ebpf.Load()
	if err != nil {
		log.Fatalf("Failed to load eBPF: %v", err)
	}
	defer loader.Close()

	log.Println("✓ eBPF program loaded and attached successfully")
	log.Println("Monitoring execve syscalls... Press Ctrl+C to stop")
	log.Println("")

	// Set up signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Statistics
	var eventCount int

	// Read events
	go func() {
		for {
			event, err := loader.ReadEvent()
			if err != nil {
				log.Printf("Error reading event: %v", err)
				continue
			}

			eventCount++
			log.Printf("[%d] PID=%d UID=%d GID=%d COMM=%s FILENAME=%s TIME=%s",
				eventCount,
				event.PID,
				event.UID,
				event.GID,
				event.Comm,
				event.Filename,
				event.Timestamp.Format("15:04:05.000"))
		}
	}()

	<-ctx.Done()
	log.Println("")
	log.Println("Shutting down...")
	log.Printf("Total events captured: %d", eventCount)
}


