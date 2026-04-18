package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestClient_ShipsBatches(t *testing.T) {
	var received atomic.Int64
	var gotToken string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotToken = r.Header.Get("X-Portal-Token")
		mu.Unlock()
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received.Add(int64(len(req.Entries)))
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(req.Entries)})
	}))
	defer srv.Close()

	c := New(Config{
		URL:           srv.URL,
		Token:         "tok",
		MaxBatch:      3,
		FlushInterval: 50 * time.Millisecond,
	}, silentLogger())

	for i := 0; i < 7; i++ {
		c.Submit(Entry{Timestamp: time.Now(), Username: "alice", Query: "SELECT 1"})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	if got := received.Load(); got != 7 {
		t.Errorf("received=%d want 7", got)
	}
	sent, failed, dropped := c.Stats()
	if sent != 7 || failed != 0 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d", sent, failed, dropped)
	}
	mu.Lock()
	if gotToken != "tok" {
		t.Errorf("token=%q want tok", gotToken)
	}
	mu.Unlock()
}

func TestClient_NoopWhenURLEmpty(t *testing.T) {
	c := New(Config{URL: "", BufferSize: 4}, silentLogger())
	for i := 0; i < 3; i++ {
		c.Submit(Entry{Query: "SELECT 1"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	// Noop client drains to the dropped counter.
	_, _, dropped := c.Stats()
	if dropped != 3 {
		t.Errorf("dropped=%d want 3", dropped)
	}
}

func TestClient_BufferFull_DropsWithCount(t *testing.T) {
	// Slow server: 200ms per request so the buffer fills while the shipper is blocked.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := New(Config{
		URL:           srv.URL,
		BufferSize:    2,
		MaxBatch:      1,
		FlushInterval: 10 * time.Millisecond,
	}, silentLogger())

	for i := 0; i < 100; i++ {
		c.Submit(Entry{Query: "SELECT 1"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = c.Shutdown(ctx)

	_, _, dropped := c.Stats()
	if dropped == 0 {
		t.Error("expected some drops under back-pressure")
	}
}

func TestClient_NonRetryableStopsImmediately(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := New(Config{
		URL:           srv.URL,
		MaxBatch:      1,
		FlushInterval: 10 * time.Millisecond,
		MaxRetries:    5,
	}, silentLogger())

	c.Submit(Entry{Query: "x"})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = c.Shutdown(ctx)

	if n := attempts.Load(); n != 1 {
		t.Errorf("403 retried: %d attempts (want 1)", n)
	}
	_, failed, _ := c.Stats()
	if failed != 1 {
		t.Errorf("failed=%d want 1", failed)
	}
}

func TestClient_RetriesOn5xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := New(Config{
		URL:           srv.URL,
		MaxBatch:      1,
		FlushInterval: 10 * time.Millisecond,
		MaxRetries:    5,
	}, silentLogger())

	c.Submit(Entry{Query: "y"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = c.Shutdown(ctx)

	if n := attempts.Load(); n < 3 {
		t.Errorf("expected ≥3 attempts with retries, got %d", n)
	}
	sent, _, _ := c.Stats()
	if sent != 1 {
		t.Errorf("sent=%d want 1", sent)
	}
}

func TestClient_NilClientSafe(t *testing.T) {
	var c *Client
	c.Submit(Entry{Query: "x"}) // must not panic
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, f, d := c.Stats()
	if s+f+d != 0 {
		t.Errorf("nil client stats non-zero")
	}
}
