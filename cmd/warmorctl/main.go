package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	serverURL = flag.String("server", "http://localhost:8443", "Policy server URL")
	jwtToken  = flag.String("token", "", "JWT auth token for admin API")
)

func main() {
	flag.Parse()

	if *jwtToken == "" {
		*jwtToken = os.Getenv("WARMOR_TOKEN")
	}

	p := tea.NewProgram(
		newApp(*serverURL, *jwtToken),
		tea.WithAltScreen(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
