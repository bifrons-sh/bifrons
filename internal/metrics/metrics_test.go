package metrics

import (
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNew_RegistersAllCollectors(t *testing.T) {
	r := New(time.Now())

	// Seed each labelled histogram so the scrape actually emits them —
	// HistogramVec is lazy: no series until the first Observe for a given
	// label set.
	r.AuthLookup("mysql").Observe(1 * time.Millisecond)
	r.BackendDial("mysql").Observe(1 * time.Millisecond)
	r.Handshake("mysql").Observe(1 * time.Millisecond)
	r.Connection("mysql").Observe(1 * time.Millisecond)
	r.PortalRequest("/api/v1/auth", "200").Observe(1 * time.Millisecond)
	r.SetBuildInfo("v", "c", "b", "u")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	r.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()

	wanted := []string{
		"proxy_auth_lookup_duration_seconds",
		"proxy_backend_dial_duration_seconds",
		"proxy_handshake_duration_seconds",
		"proxy_connection_duration_seconds",
		"portal_request_duration_seconds",
		"proxy_uptime_seconds",
		"proxy_connections_accepted_total",
		"proxy_connections_rejected_total",
		"proxy_connections_active",
		"proxy_build_info",
		"audit_entries_total",
		"audit_entries_pruned_total",
		"grants_expired_total",
	}
	for _, w := range wanted {
		if !strings.Contains(body, w) {
			t.Errorf("metric %q missing from /metrics output", w)
		}
	}
}

func TestObserver_UpdatesHistogram(t *testing.T) {
	r := New(time.Now())

	r.AuthLookup("mysql").Observe(10 * time.Millisecond)
	r.BackendDial("postgres").Observe(20 * time.Millisecond)
	r.Handshake("mongo").Observe(30 * time.Millisecond)
	r.Connection("mysql").Observe(time.Second)
	r.PortalRequest("/api/v1/auth", "200").Observe(5 * time.Millisecond)

	// CollectAndCount counts the number of metrics emitted for a histogram.
	// For a labelled histogram with one series, that's 1.
	cases := map[string]int{
		"proxy_auth_lookup_duration_seconds":  1,
		"proxy_backend_dial_duration_seconds": 1,
		"proxy_handshake_duration_seconds":    1,
		"proxy_connection_duration_seconds":   1,
		"portal_request_duration_seconds":     1,
	}
	for name, want := range cases {
		if got := testutil.CollectAndCount(r.Prom(), name); got < want {
			t.Errorf("%s: count %d, want ≥ %d", name, got, want)
		}
	}
}

func TestObserver_NilSafe(t *testing.T) {
	// A zero-value observer (Observer interface with nil underlying) must not
	// panic on Observe — that's the contract handlers rely on when
	// WithMetrics isn't called.
	var o Observer = observer{}
	o.Observe(42 * time.Millisecond)
}

func TestSetConnCounters_DeltaTracking(t *testing.T) {
	r := New(time.Now())

	// First snapshot seeds the delta tracker; second pushes the delta.
	r.SetConnCounters(10, 3, 2)
	r.SetConnCounters(15, 5, 4)

	if got := testutil.ToFloat64(r.connsAccepted); got != 15 {
		t.Errorf("connsAccepted = %v, want 15", got)
	}
	if got := testutil.ToFloat64(r.connsRejected); got != 5 {
		t.Errorf("connsRejected = %v, want 5", got)
	}
	if got := testutil.ToFloat64(r.connsActive); got != 4 {
		t.Errorf("connsActive = %v, want 4", got)
	}

	// Counter reset (process restart in source of truth) — delta tracker
	// must not decrement the Prom counter.
	r.SetConnCounters(2, 1, 1)
	if got := testutil.ToFloat64(r.connsAccepted); got < 15 {
		t.Errorf("reset caused counter to decrement: %v", got)
	}
}

func TestSetBuildInfo(t *testing.T) {
	r := New(time.Now())
	r.SetBuildInfo("v1.2.3", "abc123", "2026-04-18T00:00:00Z", "tester")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	r.Handler().ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), `version="v1.2.3"`) {
		t.Errorf("build info missing version label in body:\n%s", rr.Body.String())
	}
}

func TestSetAuditAndGrantStats(t *testing.T) {
	r := New(time.Now())
	r.SetAuditStats(100, 10)
	r.SetAuditStats(95, 20) // total is a gauge; pruned is a counter delta
	r.SetGrantStats(7)
	r.SetGrantStats(12)

	if got := testutil.ToFloat64(r.auditEntriesTotal); got != 95 {
		t.Errorf("auditEntriesTotal = %v, want 95", got)
	}
	if got := testutil.ToFloat64(r.auditEntriesPruned); got != 20 {
		t.Errorf("auditEntriesPruned = %v, want 20", got)
	}
	if got := testutil.ToFloat64(r.grantsExpired); got != 12 {
		t.Errorf("grantsExpired = %v, want 12", got)
	}
}

// TestPromtool validates the emitted text format against upstream promtool
// when the binary is available on PATH. Skipped cleanly otherwise so CI in
// bare containers doesn't spuriously fail.
func TestPromtool(t *testing.T) {
	bin, err := exec.LookPath("promtool")
	if err != nil {
		t.Skip("promtool not on PATH — skipping Prom text validation")
	}

	r := New(time.Now())
	r.AuthLookup("mysql").Observe(5 * time.Millisecond)
	r.SetConnCounters(1, 0, 1)
	r.SetBuildInfo("v", "c", "b", "u")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	r.Handler().ServeHTTP(rr, req)

	cmd := exec.Command(bin, "check", "metrics")
	cmd.Stdin = strings.NewReader(rr.Body.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("promtool check metrics failed: %v\n%s", err, out)
	}
}
