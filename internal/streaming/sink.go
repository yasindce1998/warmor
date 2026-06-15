package streaming

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Sink consumes SecurityEvents. Implementations must be safe for concurrent use.
type Sink interface {
	Write(ctx context.Context, event *SecurityEvent) error
	Flush(ctx context.Context) error
	Close() error
	Name() string
}

// StdoutSink writes newline-delimited JSON to stdout.
type StdoutSink struct {
	enc *json.Encoder
	mu  sync.Mutex
}

func NewStdoutSink() *StdoutSink {
	return &StdoutSink{enc: json.NewEncoder(os.Stdout)}
}

func (s *StdoutSink) Write(_ context.Context, event *SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(event)
}

func (s *StdoutSink) Flush(_ context.Context) error { return nil }
func (s *StdoutSink) Close() error                  { return nil }
func (s *StdoutSink) Name() string                  { return "stdout" }

// FileSink writes newline-delimited JSON to a file with rotation support.
type FileSink struct {
	path       string
	maxBytes   int64
	file       *os.File
	enc        *json.Encoder
	written    int64
	mu         sync.Mutex
}

func NewFileSink(path string, maxBytes int64) (*FileSink, error) {
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024 // 100MB default
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open event log: %w", err)
	}
	info, _ := f.Stat()
	written := int64(0)
	if info != nil {
		written = info.Size()
	}
	return &FileSink{
		path:     path,
		maxBytes: maxBytes,
		file:     f,
		enc:      json.NewEncoder(f),
		written:  written,
	}, nil
}

func (s *FileSink) Write(_ context.Context, event *SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.written >= s.maxBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := s.file.Write(data)
	s.written += int64(n)
	return err
}

func (s *FileSink) rotate() error {
	_ = s.file.Close()
	rotated := fmt.Sprintf("%s.%d", s.path, time.Now().UnixMilli())
	_ = os.Rename(s.path, rotated)
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	s.file = f
	s.enc = json.NewEncoder(f)
	s.written = 0
	return nil
}

func (s *FileSink) Flush(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Sync()
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}

func (s *FileSink) Name() string { return "file:" + s.path }

// WebhookSink POSTs batches of events to an HTTP endpoint.
type WebhookSink struct {
	url        string
	client     *http.Client
	headers    map[string]string
	batch      []*SecurityEvent
	batchSize  int
	flushEvery time.Duration
	mu         sync.Mutex
	lastFlush  time.Time
}

type WebhookConfig struct {
	URL        string
	Headers    map[string]string
	BatchSize  int
	FlushEvery time.Duration
	Timeout    time.Duration
}

func NewWebhookSink(cfg WebhookConfig) *WebhookSink {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &WebhookSink{
		url:        cfg.URL,
		client:     &http.Client{Timeout: cfg.Timeout},
		headers:    cfg.Headers,
		batchSize:  cfg.BatchSize,
		flushEvery: cfg.FlushEvery,
		lastFlush:  time.Now(),
	}
}

func (s *WebhookSink) Write(ctx context.Context, event *SecurityEvent) error {
	s.mu.Lock()
	s.batch = append(s.batch, event)
	shouldFlush := len(s.batch) >= s.batchSize || time.Since(s.lastFlush) >= s.flushEvery
	s.mu.Unlock()

	if shouldFlush {
		return s.Flush(ctx)
	}
	return nil
}

func (s *WebhookSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	if len(s.batch) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.batch
	s.batch = nil
	s.lastFlush = time.Now()
	s.mu.Unlock()

	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func (s *WebhookSink) Close() error {
	return s.Flush(context.Background())
}

func (s *WebhookSink) Name() string { return "webhook:" + s.url }
