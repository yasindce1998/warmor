package dashboard

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPublish_BroadcastsToClients(t *testing.T) {
	h := New(100)

	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/dashboard/events")
	if err != nil {
		t.Fatalf("GET /dashboard/events: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("Content-Type = %s, want text/event-stream", resp.Header.Get("Content-Type"))
	}

	e := Event{Time: time.Now(), PID: 42, Comm: "test", Action: "ALLOW", Reason: "policy"}
	h.Publish(e)

	scanner := bufio.NewScanner(resp.Body)
	var dataLine string
	deadline := time.After(2 * time.Second)
	done := make(chan struct{})

	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				dataLine = strings.TrimPrefix(line, "data: ")
				close(done)
				return
			}
		}
	}()

	select {
	case <-done:
	case <-deadline:
		t.Fatal("timed out waiting for SSE event")
	}

	var got Event
	if err := json.Unmarshal([]byte(dataLine), &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if got.PID != 42 {
		t.Errorf("PID = %d, want 42", got.PID)
	}
	if got.Action != "ALLOW" {
		t.Errorf("Action = %s, want ALLOW", got.Action)
	}
}

func TestHistory_ReturnsBufferedEvents(t *testing.T) {
	h := New(5)

	for i := range 7 {
		h.Publish(Event{PID: uint32(i), Action: "ALLOW"})
	}

	hist := h.History()
	if len(hist) != 5 {
		t.Fatalf("len(History) = %d, want 5", len(hist))
	}

	// Should be in chronological order: 2,3,4,5,6
	if hist[0].PID != 2 {
		t.Errorf("hist[0].PID = %d, want 2", hist[0].PID)
	}
	if hist[4].PID != 6 {
		t.Errorf("hist[4].PID = %d, want 6", hist[4].PID)
	}
}

func TestHistory_UnderCapacity(t *testing.T) {
	h := New(10)

	h.Publish(Event{PID: 1, Action: "DENY"})
	h.Publish(Event{PID: 2, Action: "ALLOW"})

	hist := h.History()
	if len(hist) != 2 {
		t.Fatalf("len(History) = %d, want 2", len(hist))
	}
	if hist[0].PID != 1 || hist[1].PID != 2 {
		t.Errorf("unexpected order: %+v", hist)
	}
}

func TestServeHTTP_Dashboard(t *testing.T) {
	h := New(10)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Warmor") {
		t.Error("response does not contain 'Warmor'")
	}
	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %s", w.Header().Get("Content-Type"))
	}
}

func TestServeHTTP_NotFound(t *testing.T) {
	h := New(10)

	req := httptest.NewRequest("GET", "/dashboard/unknown", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestConcurrentPublishAndRead(t *testing.T) {
	h := New(50)

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 20 {
				h.Publish(Event{PID: uint32(id*100 + j), Action: "ALLOW"})
			}
		}(i)
	}

	// Concurrent reads
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				_ = h.History()
			}
		}()
	}

	wg.Wait()

	hist := h.History()
	if len(hist) != 50 {
		t.Errorf("len(History) = %d, want 50", len(hist))
	}
}

func TestNewClient_GetsHistory(t *testing.T) {
	h := New(100)

	h.Publish(Event{PID: 1, Action: "DENY", Reason: "blocked"})
	h.Publish(Event{PID: 2, Action: "ALLOW", Reason: "ok"})

	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/dashboard/events")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	var events []Event
	deadline := time.After(2 * time.Second)
	done := make(chan struct{})

	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				var e Event
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err != nil {
					continue
				}
				events = append(events, e)
				if len(events) >= 2 {
					close(done)
					return
				}
			}
		}
	}()

	select {
	case <-done:
	case <-deadline:
		t.Fatal("timed out waiting for historical events")
	}

	if len(events) < 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].PID != 1 {
		t.Errorf("events[0].PID = %d, want 1", events[0].PID)
	}
	if events[1].PID != 2 {
		t.Errorf("events[1].PID = %d, want 2", events[1].PID)
	}
}
