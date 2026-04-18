package obs

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startSidecar attaches a sidecar to a caller-owned listener, atomically avoiding
// the close/reopen race present in earlier versions.
func startSidecar(t *testing.T, stats StatsFn) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer("", slog.New(slog.NewJSONHandler(io.Discard, nil)),
		BuildInfo{Version: "test"}, stats)
	if err := s.StartWithListener(ln); err != nil {
		t.Fatal(err)
	}
	s.MarkReady()
	base := "http://" + s.Addr().String()
	waitForHealthz(t, base, http.StatusOK)
	return s, base
}

func waitForHealthz(t *testing.T, base string, wantStatus int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == wantStatus {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for /healthz to return %d", wantStatus)
}

func TestSidecar_Healthz(t *testing.T) {
	s, _ := startSidecar(t, nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()
}

func TestSidecar_Metrics(t *testing.T) {
	stats := func() (uint64, uint64, uint64) { return 7, 3, 2 }
	s, base := startSidecar(t, stats)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()

	resp, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	for _, want := range []string{
		"proxy_connections_accepted_total 7",
		"proxy_connections_rejected_total 3",
		"proxy_connections_active 2",
		"proxy_build_info",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q, body:\n%s", want, text)
		}
	}
}

func TestSidecar_HealthzStartingBeforeReady(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer("", slog.New(slog.NewJSONHandler(io.Discard, nil)), BuildInfo{}, nil)
	if err := s.StartWithListener(ln); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()

	base := "http://" + s.Addr().String()
	waitForHealthz(t, base, http.StatusServiceUnavailable)
}
