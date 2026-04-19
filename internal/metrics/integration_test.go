package metrics_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/internal/obs"
)

// TestScrapeAfterActivity is the acceptance test called out in the spec:
// simulate one proxy connection (dial + handshake) and one portal auth call,
// then scrape /metrics through the obs sidecar and assert every histogram
// we advertised has at least one observation.
func TestScrapeAfterActivity(t *testing.T) {
	reg := metrics.New(time.Now())

	// Wire a sidecar backed by the registry. StartWithListener mirrors the
	// pattern used throughout the repo to avoid the "bind a port then close
	// and reopen" race in older tests.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := obs.NewServer("", slog.New(slog.NewJSONHandler(io.Discard, nil)),
		obs.BuildInfo{Version: "test", Commit: "c0ffee", BuildTimestamp: "now", Builder: "unit"},
		func() (uint64, uint64, uint64) { return 1, 0, 0 })
	s.SetRegistry(reg)
	if err := s.StartWithListener(ln); err != nil {
		t.Fatal(err)
	}
	s.MarkReady()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})

	// Simulate one proxy connection: dial + handshake + lifetime observation.
	reg.AuthLookup("mysql").Observe(3 * time.Millisecond)
	reg.BackendDial("mysql").Observe(7 * time.Millisecond)
	reg.Handshake("mysql").Observe(15 * time.Millisecond)
	reg.Connection("mysql").Observe(120 * time.Millisecond)

	// Simulate one portal auth request.
	reg.PortalRequest("/api/v1/auth", "200").Observe(8 * time.Millisecond)

	resp, err := http.Get("http://" + s.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// Each histogram exposes _count / _sum / _bucket series. Asserting the
	// _count != 0 line is the cheapest way to prove an Observe landed.
	wantNonZero := []string{
		`proxy_auth_lookup_duration_seconds_count{proxy="mysql"} 1`,
		`proxy_backend_dial_duration_seconds_count{proxy="mysql"} 1`,
		`proxy_handshake_duration_seconds_count{proxy="mysql"} 1`,
		`proxy_connection_duration_seconds_count{proxy="mysql"} 1`,
		`portal_request_duration_seconds_count{path="/api/v1/auth",status="200"} 1`,
	}
	for _, w := range wantNonZero {
		if !strings.Contains(text, w) {
			t.Errorf("expected line %q, not found in /metrics body:\n%s", w, text)
		}
	}

	// Classic names must still be present so alerts keep firing.
	for _, legacy := range []string{
		"proxy_uptime_seconds",
		"proxy_connections_accepted_total",
		"proxy_build_info",
	} {
		if !strings.Contains(text, legacy) {
			t.Errorf("legacy metric %q missing", legacy)
		}
	}
}
