package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

func newEvent() Event {
	return Event{
		User:    domain.User{Username: "alice"},
		Backend: domain.Backend{Host: "h", Port: 1, Name: "pg"},
		Grant: domain.Grant{
			ID: "g-1", Role: domain.RoleApp, Reason: "ticket-42",
			RequestedBy: "sub-alice", RequestedAt: time.Now().UTC(),
		},
	}
}

// TestWebhook_HappyPath: POST lands on the target, body decodes, HMAC header
// matches the secret + body, Wait() blocks until goroutine done.
func TestWebhook_HappyPath(t *testing.T) {
	const secret = "shh"
	var hits atomic.Uint64
	var gotSig, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Portal-Signature")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		hits.Add(1)
	}))
	defer srv.Close()

	w := NewWebhookNotifier(srv.URL, secret, srv.Client(), silentLogger())
	if err := w.OnGrantCreated(context.Background(), newEvent()); err != nil {
		t.Fatal(err)
	}
	w.Wait()

	if hits.Load() != 1 {
		t.Fatalf("hits=%d want 1", hits.Load())
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type=%q", gotCT)
	}
	// HMAC-SHA256 over raw body, hex-encoded, with "sha256=" prefix.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Errorf("signature=%q want %q", gotSig, want)
	}
	var decoded map[string]any
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if decoded["grant_id"] != "g-1" || decoded["user"] != "alice" {
		t.Errorf("body missing expected fields: %+v", decoded)
	}
}

// TestWebhook_NoSecret_UnsignedDelivery confirms an empty secret produces no
// X-Portal-Signature header (matches the "empty secret = unsigned" contract).
func TestWebhook_NoSecret_UnsignedDelivery(t *testing.T) {
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get("X-Portal-Signature")
	}))
	defer srv.Close()

	w := NewWebhookNotifier(srv.URL, "", srv.Client(), silentLogger())
	_ = w.OnGrantCreated(context.Background(), newEvent())
	w.Wait()
	if sig != "" {
		t.Errorf("unsigned delivery should leave X-Portal-Signature empty, got %q", sig)
	}
}

// TestWebhook_RetryOn5xx: the first 500 triggers a retry; the second 200
// stops the loop. Validates the "bounded retry" contract.
func TestWebhook_RetryOn5xx(t *testing.T) {
	var hits atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Tight client + test — the real 500ms sleep between retries would drag
	// the suite; we accept it here since the test is small.
	w := NewWebhookNotifier(srv.URL, "", srv.Client(), silentLogger())
	_ = w.OnGrantCreated(context.Background(), newEvent())
	w.Wait()
	if hits.Load() != 2 {
		t.Errorf("hits=%d want 2 (1 fail + 1 retry success)", hits.Load())
	}
}

// TestWebhook_NoopOnNonCreatedEvents: the webhook only cares about creation;
// other lifecycle methods are explicit no-ops.
func TestWebhook_NoopOnNonCreatedEvents(t *testing.T) {
	var hits atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	w := NewWebhookNotifier(srv.URL, "", srv.Client(), silentLogger())
	_ = w.OnManagerApproved(context.Background(), newEvent())
	_ = w.OnApproved(context.Background(), newEvent())
	_ = w.OnDenied(context.Background(), newEvent())
	w.Wait()
	if hits.Load() != 0 {
		t.Errorf("non-created events should not fire webhook; got %d hits", hits.Load())
	}
}

// TestWebhook_EmptyURL_NoOp: an empty URL disables the notifier cleanly
// (matches how the router wires it when no webhook is configured).
func TestWebhook_EmptyURL_NoOp(t *testing.T) {
	w := NewWebhookNotifier("", "", nil, silentLogger())
	if err := w.OnGrantCreated(context.Background(), newEvent()); err != nil {
		t.Errorf("empty URL should no-op, got %v", err)
	}
	w.Wait()
}
