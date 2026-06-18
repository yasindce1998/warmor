package policygen

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/yasindce1998/warmor/internal/streaming"
)

type ReadOptions struct {
	CommFilter []string
	EventTypes []string
}

func ReadEvents(r io.Reader, opts ReadOptions) ([]streaming.SecurityEvent, error) {
	var events []streaming.SecurityEvent
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	commSet := toSet(opts.CommFilter)
	typeSet := toSet(opts.EventTypes)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev streaming.SecurityEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping malformed line %d: %v\n", lineNum, err)
			continue
		}

		if len(commSet) > 0 && !commSet[ev.Comm] {
			continue
		}
		if len(typeSet) > 0 && !typeSet[ev.EventType] {
			continue
		}

		events = append(events, ev)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	return events, nil
}

func ReadFile(path string, opts ReadOptions) ([]streaming.SecurityEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadEvents(f, opts)
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, item := range items {
		if item != "" {
			m[item] = true
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
