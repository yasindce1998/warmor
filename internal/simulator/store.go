package simulator

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// EventStore is an append-only ndjson event store that implements streaming.Sink.
// Events are stored in daily-rotated files for replay.
type EventStore struct {
	dir     string
	file    *os.File
	enc     *json.Encoder
	mu      sync.Mutex
	curDate string
}

// NewEventStore creates or opens an event store in the given directory.
func NewEventStore(dir string) (*EventStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create event store dir: %w", err)
	}
	s := &EventStore{dir: dir}
	if err := s.rotateIfNeeded(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *EventStore) rotateIfNeeded() error {
	today := time.Now().UTC().Format("2006-01-02")
	if today == s.curDate && s.file != nil {
		return nil
	}

	if s.file != nil {
		_ = s.file.Close()
	}

	path := filepath.Join(s.dir, fmt.Sprintf("events-%s.ndjson", today))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open event file: %w", err)
	}
	s.file = f
	s.enc = json.NewEncoder(f)
	s.curDate = today
	return nil
}

func (s *EventStore) Write(_ context.Context, event *streaming.SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.rotateIfNeeded(); err != nil {
		return err
	}
	return s.enc.Encode(event)
}

func (s *EventStore) Flush(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Sync()
	}
	return nil
}

func (s *EventStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func (s *EventStore) Name() string { return "event-store:" + s.dir }

// ReadEvents reads all events from the store directory that fall within
// the given time range.
func ReadEvents(dir string, since time.Time) ([]*streaming.SecurityEvent, error) {
	pattern := filepath.Join(dir, "events-*.ndjson")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob event files: %w", err)
	}

	var events []*streaming.SecurityEvent
	for _, path := range files {
		fileEvents, err := readEventFile(path, since)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		events = append(events, fileEvents...)
	}
	return events, nil
}

func readEventFile(path string, since time.Time) ([]*streaming.SecurityEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []*streaming.SecurityEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		var event streaming.SecurityEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if !event.Timestamp.Before(since) {
			events = append(events, &event)
		}
	}
	return events, scanner.Err()
}
